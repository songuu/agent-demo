from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

import pytest
from prometheus_client import CollectorRegistry

from agent_platform.infrastructure.observability.metrics import PlatformMetrics
from agent_platform.infrastructure.observability.operational_metrics import (
    _OPERATIONAL_SNAPSHOT_QUERY,
    OperationalMetricsCollector,
    OperationalMetricsSnapshot,
)


def _value(
    registry: CollectorRegistry,
    name: str,
    labels: dict[str, str],
) -> float | None:
    return registry.get_sample_value(name, labels)


def _snapshot(*, high_pending: int = 7) -> OperationalMetricsSnapshot:
    return OperationalMetricsSnapshot(
        pending_by_risk={"high": high_pending},
        pending_total=high_pending,
        pending_oldest_age_seconds=42.0,
        overdue_cleanup_lag_seconds=12.0,
        outbox_by_state={"pending": 3, "retry": 2},
        webhook_by_status={"pending": 4, "retry": 2, "dead_letter": 1},
        approval_webhook_by_status={
            "pending": 3,
            "retry": 2,
            "delivering": 1,
            "dead_letter": 1,
        },
        missing_notification_count=3,
        missing_notification_oldest_age_seconds=37.0,
        notification_latency_quantiles={"0.50": 4.0, "0.95": 12.5, "0.99": 14.0},
        notification_sample_count=8,
    )


def test_snapshot_metrics_are_current_gauges_and_clear_stale_labels() -> None:
    registry = CollectorRegistry()
    metrics = PlatformMetrics(registry)
    collector = OperationalMetricsCollector(
        None,
        metrics,
        environment="test",
        snapshot_reader=None,
    )

    collector.record_snapshot(_snapshot())

    assert (
        _value(
            registry,
            "agent_approval_webhook_deliveries_current",
            {"environment": "test", "status": "retry"},
        )
        == 2
    )
    assert (
        _value(
            registry,
            "agent_pending_approval_notifications_missing",
            {"environment": "test"},
        )
        == 3
    )
    assert (
        _value(
            registry,
            "agent_pending_approval_notification_oldest_missing_age_seconds",
            {"environment": "test"},
        )
        == 37
    )

    collector.record_snapshot(OperationalMetricsSnapshot.empty())

    assert (
        _value(
            registry,
            "agent_pending_approvals",
            {"environment": "test", "risk": "high"},
        )
        == 0
    )
    assert (
        _value(
            registry,
            "agent_pending_approvals",
            {"environment": "test", "risk": "critical"},
        )
        == 0
    )
    assert (
        _value(
            registry,
            "agent_pending_approvals",
            {"environment": "test", "risk": "all"},
        )
        == 0
    )
    assert (
        _value(
            registry,
            "agent_outbox_events_current",
            {"environment": "test", "state": "retry"},
        )
        == 0
    )
    assert (
        _value(
            registry,
            "agent_webhook_deliveries_current",
            {"environment": "test", "status": "dead_letter"},
        )
        == 0
    )
    assert (
        _value(
            registry,
            "agent_approval_webhook_deliveries_current",
            {"environment": "test", "status": "retry"},
        )
        == 0
    )
    assert (
        _value(
            registry,
            "agent_pending_approval_notifications_missing",
            {"environment": "test"},
        )
        == 0
    )
    assert (
        _value(
            registry,
            "agent_pending_approval_notification_oldest_missing_age_seconds",
            {"environment": "test"},
        )
        == 0
    )
    assert (
        _value(
            registry,
            "agent_approval_notification_samples",
            {"environment": "test"},
        )
        == 0
    )


def test_snapshot_query_scopes_approval_delivery_and_missing_notification_state() -> None:
    query = " ".join(_OPERATIONAL_SNAPSHOT_QUERY.text.split())

    assert (
        "JOIN outbox_events AS approval_event ON approval_event.outbox_id = delivery.outbox_id"
    ) in query
    assert "approval_event.event_type = 'action.approval_required'" in query
    assert ("approval_event.payload ->> 'action_id' = pending.action_id::text") in query
    assert "approval_event.tenant_id = pending.tenant_id" in query
    assert "delivery.status = 'delivered'" in query


@pytest.mark.asyncio
async def test_collector_singleflights_and_honors_minimum_refresh_interval() -> None:
    registry = CollectorRegistry()
    metrics = PlatformMetrics(registry)
    monotonic_now = [100.0]
    calls = 0

    async def reader() -> OperationalMetricsSnapshot:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0)
        return _snapshot()

    collector = OperationalMetricsCollector(
        None,
        metrics,
        environment="test",
        snapshot_reader=reader,
        min_refresh_interval_seconds=30.0,
        monotonic_clock=lambda: monotonic_now[0],
        wall_clock=lambda: 1_700_000_000.0,
    )

    results = await asyncio.gather(*(collector.collect() for _ in range(12)))
    await collector.collect()
    monotonic_now[0] += 31.0
    await collector.collect()

    assert all(results)
    assert calls == 2
    assert (
        _value(
            registry,
            "agent_operational_metrics_collector_up",
            {"environment": "test"},
        )
        == 1
    )
    assert (
        _value(
            registry,
            "agent_operational_metrics_last_success_timestamp_seconds",
            {"environment": "test"},
        )
        == 1_700_000_000.0
    )


@pytest.mark.asyncio
async def test_collector_failure_marks_health_without_refreshing_success_timestamp() -> None:
    registry = CollectorRegistry()
    metrics = PlatformMetrics(registry)
    readers: list[Callable[[], Awaitable[OperationalMetricsSnapshot]]] = []

    async def success() -> OperationalMetricsSnapshot:
        return _snapshot()

    async def failure() -> OperationalMetricsSnapshot:
        raise RuntimeError("database unavailable")

    readers.extend((success, failure))

    async def reader() -> OperationalMetricsSnapshot:
        return await readers.pop(0)()

    monotonic_now = [10.0]
    wall_now = [1_700_000_000.0]
    collector = OperationalMetricsCollector(
        None,
        metrics,
        environment="test",
        snapshot_reader=reader,
        min_refresh_interval_seconds=1.0,
        monotonic_clock=lambda: monotonic_now[0],
        wall_clock=lambda: wall_now[0],
    )

    assert await collector.collect() is True
    monotonic_now[0] += 2.0
    wall_now[0] += 2.0
    assert await collector.collect() is False

    assert (
        _value(
            registry,
            "agent_operational_metrics_collector_up",
            {"environment": "test"},
        )
        == 0
    )
    assert (
        _value(
            registry,
            "agent_operational_metrics_last_success_timestamp_seconds",
            {"environment": "test"},
        )
        == 1_700_000_000.0
    )
    assert (
        _value(
            registry,
            "agent_pending_approvals",
            {"environment": "test", "risk": "high"},
        )
        == 7
    )
