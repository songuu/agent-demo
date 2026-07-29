from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import text

from agent_platform.domain.enums import RiskLevel
from agent_platform.infrastructure.observability.metrics import PlatformMetrics
from agent_platform.infrastructure.persistence.session import AsyncSessionFactory

_KNOWN_RISKS = tuple(risk.value for risk in RiskLevel)
_KNOWN_OUTBOX_STATES = ("pending", "retry")
_KNOWN_WEBHOOK_STATUSES = ("pending", "retry", "delivering", "dead_letter")
_KNOWN_QUANTILES = ("0.50", "0.95", "0.99")

_OPERATIONAL_SNAPSHOT_QUERY = text(
    """
    WITH pending AS (
        SELECT action_id, tenant_id, risk::text AS risk, created_at, expires_at
        FROM prepared_actions
        WHERE status = 'pending_approval'
    ),
    approval_deliveries AS (
        SELECT
            delivery.status,
            delivery.delivered_at,
            approval_event.created_at AS event_created_at
        FROM webhook_deliveries AS delivery
        JOIN outbox_events AS approval_event
          ON approval_event.outbox_id = delivery.outbox_id
        WHERE approval_event.event_type = 'action.approval_required'
    ),
    unnotified_pending AS (
        SELECT pending.action_id, pending.created_at
        FROM pending
        WHERE NOT EXISTS (
            SELECT 1
            FROM outbox_events AS approval_event
            JOIN webhook_deliveries AS delivery
              ON approval_event.outbox_id = delivery.outbox_id
            WHERE approval_event.event_type = 'action.approval_required'
              AND approval_event.tenant_id = pending.tenant_id
              AND approval_event.payload ->> 'action_id' = pending.action_id::text
              AND delivery.status = 'delivered'
        )
    ),
    notification_latency AS (
        SELECT EXTRACT(EPOCH FROM (delivered_at - event_created_at)) AS seconds
        FROM approval_deliveries
        WHERE status = 'delivered'
          AND delivered_at IS NOT NULL
          AND delivered_at >= :notification_window_start
          AND delivered_at >= event_created_at
    )
    SELECT
        (SELECT COUNT(*) FROM pending) AS pending_total,
        (SELECT COUNT(*) FROM pending WHERE risk = 'low') AS pending_low,
        (SELECT COUNT(*) FROM pending WHERE risk = 'medium') AS pending_medium,
        (SELECT COUNT(*) FROM pending WHERE risk = 'high') AS pending_high,
        (SELECT COUNT(*) FROM pending WHERE risk = 'critical') AS pending_critical,
        COALESCE(
            (SELECT EXTRACT(EPOCH FROM (:sampled_at - MIN(created_at))) FROM pending),
            0
        ) AS pending_oldest_age_seconds,
        COALESCE(
            (
                SELECT EXTRACT(EPOCH FROM (:sampled_at - MIN(expires_at)))
                FROM pending
                WHERE expires_at < :sampled_at
            ),
            0
        ) AS overdue_cleanup_lag_seconds,
        (
            SELECT COUNT(*) FROM outbox_events
            WHERE published_at IS NULL AND attempts = 0
        ) AS outbox_pending,
        (
            SELECT COUNT(*) FROM outbox_events
            WHERE published_at IS NULL AND attempts > 0
        ) AS outbox_retry,
        (
            SELECT COUNT(*) FROM webhook_deliveries WHERE status = 'pending'
        ) AS webhook_pending,
        (
            SELECT COUNT(*) FROM webhook_deliveries WHERE status = 'retry'
        ) AS webhook_retry,
        (
            SELECT COUNT(*) FROM webhook_deliveries WHERE status = 'delivering'
        ) AS webhook_delivering,
        (
            SELECT COUNT(*) FROM webhook_deliveries WHERE status = 'dead_letter'
        ) AS webhook_dead_letter,
        (
            SELECT COUNT(*) FROM approval_deliveries WHERE status = 'pending'
        ) AS approval_webhook_pending,
        (
            SELECT COUNT(*) FROM approval_deliveries WHERE status = 'retry'
        ) AS approval_webhook_retry,
        (
            SELECT COUNT(*) FROM approval_deliveries WHERE status = 'delivering'
        ) AS approval_webhook_delivering,
        (
            SELECT COUNT(*) FROM approval_deliveries WHERE status = 'dead_letter'
        ) AS approval_webhook_dead_letter,
        (SELECT COUNT(*) FROM unnotified_pending) AS missing_notification_count,
        COALESCE(
            (
                SELECT EXTRACT(EPOCH FROM (:sampled_at - MIN(created_at)))
                FROM unnotified_pending
            ),
            0
        ) AS missing_notification_oldest_age_seconds,
        COALESCE(
            (SELECT percentile_cont(0.50) WITHIN GROUP (ORDER BY seconds)
             FROM notification_latency),
            0
        ) AS notification_p50_seconds,
        COALESCE(
            (SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY seconds)
             FROM notification_latency),
            0
        ) AS notification_p95_seconds,
        COALESCE(
            (SELECT percentile_cont(0.99) WITHIN GROUP (ORDER BY seconds)
             FROM notification_latency),
            0
        ) AS notification_p99_seconds,
        (SELECT COUNT(*) FROM notification_latency) AS notification_sample_count
    """
)


@dataclass(frozen=True, slots=True)
class OperationalMetricsSnapshot:
    pending_by_risk: Mapping[str, int]
    pending_total: int
    pending_oldest_age_seconds: float
    overdue_cleanup_lag_seconds: float
    outbox_by_state: Mapping[str, int]
    webhook_by_status: Mapping[str, int]
    approval_webhook_by_status: Mapping[str, int]
    missing_notification_count: int
    missing_notification_oldest_age_seconds: float
    notification_latency_quantiles: Mapping[str, float]
    notification_sample_count: int

    @classmethod
    def empty(cls) -> OperationalMetricsSnapshot:
        return cls(
            pending_by_risk={},
            pending_total=0,
            pending_oldest_age_seconds=0.0,
            overdue_cleanup_lag_seconds=0.0,
            outbox_by_state={},
            webhook_by_status={},
            approval_webhook_by_status={},
            missing_notification_count=0,
            missing_notification_oldest_age_seconds=0.0,
            notification_latency_quantiles={},
            notification_sample_count=0,
        )


SnapshotReader = Callable[[], Awaitable[OperationalMetricsSnapshot]]


class OperationalMetricsCollector:
    """Refresh low-cardinality operational metrics from a privileged read model.

    The production reader only executes aggregate queries in a read-only transaction.
    A process-local lock and refresh floor prevent probe/scrape fan-out from multiplying
    the percentile query within one API replica.
    """

    def __init__(
        self,
        sessions: AsyncSessionFactory | None,
        metrics: PlatformMetrics,
        *,
        environment: str,
        snapshot_reader: SnapshotReader | None = None,
        min_refresh_interval_seconds: float = 15.0,
        notification_window_seconds: float = 3600.0,
        monotonic_clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        if min_refresh_interval_seconds <= 0:
            raise ValueError("OPERATIONAL_METRICS_REFRESH_INTERVAL_MUST_BE_POSITIVE")
        if notification_window_seconds <= 0:
            raise ValueError("OPERATIONAL_METRICS_NOTIFICATION_WINDOW_MUST_BE_POSITIVE")
        self._sessions = sessions
        self._metrics = metrics
        self._environment = environment
        self._min_refresh_interval_seconds = min_refresh_interval_seconds
        self._notification_window_seconds = notification_window_seconds
        self._monotonic_clock = monotonic_clock
        self._wall_clock = wall_clock
        self._snapshot_reader = snapshot_reader or self._read_postgres_snapshot
        self._lock = asyncio.Lock()
        self._last_attempt_monotonic: float | None = None
        self._last_result = False
        self._role_verified = False
        self._metrics.agent_operational_metrics_collector_up.labels(
            environment=self._environment
        ).set(0)
        self._metrics.agent_operational_metrics_last_success_timestamp_seconds.labels(
            environment=self._environment
        ).set(0)

    async def collect(self) -> bool:
        now = self._monotonic_clock()
        if self._fresh_enough(now) and not self._lock.locked():
            return self._last_result
        async with self._lock:
            now = self._monotonic_clock()
            if self._fresh_enough(now):
                return self._last_result
            self._last_attempt_monotonic = now
            try:
                snapshot = await self._snapshot_reader()
            except Exception:
                self._last_result = False
                self._metrics.agent_operational_metrics_collector_up.labels(
                    environment=self._environment
                ).set(0)
                return False
            self.record_snapshot(snapshot)
            self._last_result = True
            self._metrics.agent_operational_metrics_collector_up.labels(
                environment=self._environment
            ).set(1)
            self._metrics.agent_operational_metrics_last_success_timestamp_seconds.labels(
                environment=self._environment
            ).set(self._wall_clock())
            return True

    def record_snapshot(self, snapshot: OperationalMetricsSnapshot) -> None:
        labels = {"environment": self._environment}
        for risk in _KNOWN_RISKS:
            self._metrics.agent_pending_approvals.labels(**labels, risk=risk).set(
                max(int(snapshot.pending_by_risk.get(risk, 0)), 0)
            )
        self._metrics.agent_pending_approvals.labels(**labels, risk="all").set(
            max(int(snapshot.pending_total), 0)
        )
        self._metrics.agent_pending_approval_oldest_age_seconds.labels(**labels).set(
            max(float(snapshot.pending_oldest_age_seconds), 0.0)
        )
        self._metrics.agent_pending_approval_overdue_cleanup_lag_seconds.labels(**labels).set(
            max(float(snapshot.overdue_cleanup_lag_seconds), 0.0)
        )
        for state in _KNOWN_OUTBOX_STATES:
            self._metrics.agent_outbox_events_current.labels(**labels, state=state).set(
                max(int(snapshot.outbox_by_state.get(state, 0)), 0)
            )
        for status in _KNOWN_WEBHOOK_STATUSES:
            self._metrics.agent_webhook_deliveries_current.labels(**labels, status=status).set(
                max(int(snapshot.webhook_by_status.get(status, 0)), 0)
            )
            self._metrics.agent_approval_webhook_deliveries_current.labels(
                **labels, status=status
            ).set(max(int(snapshot.approval_webhook_by_status.get(status, 0)), 0))
        self._metrics.agent_pending_approval_notifications_missing.labels(**labels).set(
            max(int(snapshot.missing_notification_count), 0)
        )
        self._metrics.agent_pending_approval_notification_oldest_missing_age_seconds.labels(
            **labels
        ).set(max(float(snapshot.missing_notification_oldest_age_seconds), 0.0))
        for quantile in _KNOWN_QUANTILES:
            self._metrics.agent_approval_notification_latency_seconds.labels(
                **labels, quantile=quantile
            ).set(max(float(snapshot.notification_latency_quantiles.get(quantile, 0.0)), 0.0))
        self._metrics.agent_approval_notification_samples.labels(**labels).set(
            max(int(snapshot.notification_sample_count), 0)
        )

    def _fresh_enough(self, now: float) -> bool:
        return (
            self._last_attempt_monotonic is not None
            and now - self._last_attempt_monotonic < self._min_refresh_interval_seconds
        )

    async def _read_postgres_snapshot(self) -> OperationalMetricsSnapshot:
        if self._sessions is None:
            raise RuntimeError("OPERATIONAL_METRICS_SESSION_FACTORY_REQUIRED")
        sampled_at = datetime.now(UTC)
        window_start = sampled_at - timedelta(seconds=self._notification_window_seconds)
        async with self._sessions() as session, session.begin():
            await session.execute(text("SET TRANSACTION READ ONLY"))
            if not self._role_verified:
                allowed = await session.scalar(
                    text(
                        "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user"
                    )
                )
                if allowed is not True:
                    raise RuntimeError("OPERATIONAL_METRICS_ROLE_MUST_BYPASS_RLS")
                self._role_verified = True
            row = (
                (
                    await session.execute(
                        _OPERATIONAL_SNAPSHOT_QUERY,
                        {
                            "sampled_at": sampled_at,
                            "notification_window_start": window_start,
                        },
                    )
                )
                .mappings()
                .one()
            )
        return OperationalMetricsSnapshot(
            pending_by_risk={
                "low": int(row["pending_low"]),
                "medium": int(row["pending_medium"]),
                "high": int(row["pending_high"]),
                "critical": int(row["pending_critical"]),
            },
            pending_total=int(row["pending_total"]),
            pending_oldest_age_seconds=float(row["pending_oldest_age_seconds"]),
            overdue_cleanup_lag_seconds=float(row["overdue_cleanup_lag_seconds"]),
            outbox_by_state={
                "pending": int(row["outbox_pending"]),
                "retry": int(row["outbox_retry"]),
            },
            webhook_by_status={
                "pending": int(row["webhook_pending"]),
                "retry": int(row["webhook_retry"]),
                "delivering": int(row["webhook_delivering"]),
                "dead_letter": int(row["webhook_dead_letter"]),
            },
            approval_webhook_by_status={
                "pending": int(row["approval_webhook_pending"]),
                "retry": int(row["approval_webhook_retry"]),
                "delivering": int(row["approval_webhook_delivering"]),
                "dead_letter": int(row["approval_webhook_dead_letter"]),
            },
            missing_notification_count=int(row["missing_notification_count"]),
            missing_notification_oldest_age_seconds=float(
                row["missing_notification_oldest_age_seconds"]
            ),
            notification_latency_quantiles={
                "0.50": float(row["notification_p50_seconds"]),
                "0.95": float(row["notification_p95_seconds"]),
                "0.99": float(row["notification_p99_seconds"]),
            },
            notification_sample_count=int(row["notification_sample_count"]),
        )
