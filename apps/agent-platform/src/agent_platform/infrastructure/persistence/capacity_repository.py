"""PostgreSQL source of truth for tenant capacity reservations and cost."""

from __future__ import annotations

import hashlib
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from typing import Any, ClassVar
from uuid import UUID

from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from agent_platform.application.errors import PlatformError
from agent_platform.infrastructure.capacity_cost import (
    AdmissionDecision,
    BudgetControlLevel,
    CapacityControlConfig,
    CostBreakdown,
    CostComponent,
    CostSettlement,
    ReservationView,
    RunPriority,
)
from agent_platform.infrastructure.persistence.capacity_models import (
    CostLedgerEntry,
    RunCapacityReservation,
)
from agent_platform.infrastructure.persistence.session import (
    AsyncSessionFactory,
    tenant_session,
)


class PostgresCapacityCostRepository:
    """Serialize per-tenant admission with a transaction-scoped advisory lock."""

    COST_COMPONENTS: ClassVar[frozenset[str]] = frozenset(
        component.value for component in CostComponent
    )

    def __init__(
        self,
        session_factory: AsyncSessionFactory,
        *,
        config: CapacityControlConfig | None = None,
        clock: Any | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._config = config or CapacityControlConfig()
        self._clock = clock or (lambda: datetime.now(UTC))

    async def find_reservation(
        self,
        tenant_id: str,
        reservation_key: str,
    ) -> ReservationView | None:
        try:
            async with tenant_session(self._session_factory, tenant_id) as session:
                now = self._now()
                row = await session.get(
                    RunCapacityReservation,
                    (tenant_id, reservation_key),
                )
                if row is None:
                    return None
                daily, monthly = await self._utilization(session, tenant_id, now)
                return ReservationView(
                    active=row.status == "active" and row.expires_at > now,
                    run_id=str(row.run_id) if row.run_id else None,
                    budget_control_level=self._control_level(max(daily, monthly)),
                    daily_utilization=daily,
                    monthly_utilization=monthly,
                )
        except PlatformError:
            raise
        except SQLAlchemyError as exc:
            raise self._unavailable() from exc

    async def reserve(
        self,
        *,
        tenant_id: str,
        reservation_key: str,
        requested_cost_usd: Decimal,
        priority: RunPriority,
        lease_seconds: int,
        config: CapacityControlConfig,
    ) -> AdmissionDecision:
        self._require_matching_config(config)
        try:
            async with tenant_session(self._session_factory, tenant_id) as session:
                await self._tenant_lock(session, tenant_id)
                now = self._now()
                await session.execute(
                    update(RunCapacityReservation)
                    .where(
                        RunCapacityReservation.tenant_id == tenant_id,
                        RunCapacityReservation.status == "active",
                        RunCapacityReservation.expires_at <= now,
                    )
                    .values(status="released", updated_at=now)
                )
                existing = await session.scalar(
                    select(RunCapacityReservation)
                    .where(
                        RunCapacityReservation.tenant_id == tenant_id,
                        RunCapacityReservation.reservation_key == reservation_key,
                    )
                    .with_for_update()
                )
                if existing is not None:
                    self._require_matching_reservation_request(
                        existing,
                        requested_cost_usd=requested_cost_usd,
                        priority=priority,
                    )
                active_runs = await self._active_runs(session, tenant_id, now)
                daily, monthly = await self._utilization(session, tenant_id, now)
                reactivate_existing = existing is not None and self._can_reactivate(existing)
                if existing is not None and not reactivate_existing:
                    await session.commit()
                    return AdmissionDecision(
                        newly_reserved=False,
                        active_runs=active_runs,
                        budget_control_level=self._control_level(max(daily, monthly)),
                        daily_utilization=daily,
                        monthly_utilization=monthly,
                    )
                if active_runs >= config.tenant_max_active_runs:
                    raise PlatformError(
                        "TENANT_CONCURRENCY_EXHAUSTED",
                        "Tenant active Run capacity is exhausted",
                        retryable=True,
                        http_status=503,
                        context={
                            "active_runs": active_runs,
                            "limit": config.tenant_max_active_runs,
                        },
                    )

                projected_daily = daily + (requested_cost_usd / config.tenant_daily_budget_usd)
                projected_monthly = monthly + (
                    requested_cost_usd / config.tenant_monthly_budget_usd
                )
                projected_level = self._control_level(max(projected_daily, projected_monthly))
                self._require_budget_admission(
                    priority,
                    projected_level,
                    projected_daily,
                    projected_monthly,
                )
                daily_period = now.date()
                monthly_period = date(now.year, now.month, 1)
                if existing is None:
                    session.add(
                        RunCapacityReservation(
                            tenant_id=tenant_id,
                            reservation_key=reservation_key,
                            requested_cost_usd=requested_cost_usd,
                            settled_cost_usd=None,
                            priority=priority.value,
                            status="active",
                            daily_period=daily_period,
                            monthly_period=monthly_period,
                            expires_at=now + timedelta(seconds=lease_seconds),
                            rate_catalog_id=None,
                            breakdown=None,
                            created_at=now,
                            updated_at=now,
                        )
                    )
                else:
                    existing.requested_cost_usd = requested_cost_usd
                    existing.settled_cost_usd = None
                    existing.priority = priority.value
                    existing.status = "active"
                    existing.daily_period = daily_period
                    existing.monthly_period = monthly_period
                    existing.expires_at = now + timedelta(seconds=lease_seconds)
                    existing.rate_catalog_id = None
                    existing.breakdown = None
                    existing.updated_at = now
                await session.commit()
                return AdmissionDecision(
                    newly_reserved=True,
                    active_runs=active_runs + 1,
                    budget_control_level=projected_level,
                    daily_utilization=projected_daily,
                    monthly_utilization=projected_monthly,
                )
        except PlatformError:
            raise
        except SQLAlchemyError as exc:
            raise self._unavailable() from exc

    async def bind_run(
        self,
        *,
        tenant_id: str,
        reservation_key: str,
        run_id: object,
    ) -> None:
        parsed_run_id = self._run_id(run_id)
        try:
            async with tenant_session(self._session_factory, tenant_id) as session:
                await self._tenant_lock(session, tenant_id)
                row = await session.scalar(
                    select(RunCapacityReservation)
                    .where(
                        RunCapacityReservation.tenant_id == tenant_id,
                        RunCapacityReservation.reservation_key == reservation_key,
                    )
                    .with_for_update()
                )
                if row is None or row.status != "active":
                    raise PlatformError(
                        "CAPACITY_RESERVATION_NOT_ACTIVE",
                        "Run admission reservation is not active",
                        http_status=503,
                    )
                if row.run_id not in {None, parsed_run_id}:
                    raise PlatformError(
                        "CAPACITY_RESERVATION_BINDING_CONFLICT",
                        "Run admission reservation is bound to another Run",
                        http_status=409,
                    )
                row.run_id = parsed_run_id
                row.updated_at = self._now()
                await session.commit()
        except PlatformError:
            raise
        except SQLAlchemyError as exc:
            raise self._unavailable() from exc

    async def release(
        self,
        *,
        tenant_id: str,
        reservation_key: str,
        only_if_unbound: bool,
    ) -> None:
        try:
            async with tenant_session(self._session_factory, tenant_id) as session:
                await self._tenant_lock(session, tenant_id)
                row = await session.scalar(
                    select(RunCapacityReservation)
                    .where(
                        RunCapacityReservation.tenant_id == tenant_id,
                        RunCapacityReservation.reservation_key == reservation_key,
                    )
                    .with_for_update()
                )
                if row is None or row.status != "active":
                    await session.commit()
                    return
                if only_if_unbound and row.run_id is not None:
                    return
                row.status = "released"
                row.updated_at = self._now()
                await session.commit()
        except PlatformError:
            raise
        except SQLAlchemyError as exc:
            raise self._unavailable() from exc

    async def settle(
        self,
        *,
        tenant_id: str,
        reservation_key: str,
        run_id: object,
        run_limit_usd: Decimal,
        breakdown: CostBreakdown,
        config: CapacityControlConfig,
    ) -> CostSettlement:
        self._require_matching_config(config)
        if {component.value for component in breakdown.components} != self.COST_COMPONENTS:
            raise ValueError("COST_LEDGER_COMPONENTS_INCOMPLETE")
        parsed_run_id = self._run_id(run_id)
        try:
            async with tenant_session(self._session_factory, tenant_id) as session:
                await self._tenant_lock(session, tenant_id)
                row = await session.scalar(
                    select(RunCapacityReservation)
                    .where(
                        RunCapacityReservation.tenant_id == tenant_id,
                        RunCapacityReservation.reservation_key == reservation_key,
                    )
                    .with_for_update()
                )
                if row is None:
                    raise PlatformError(
                        "CAPACITY_RESERVATION_NOT_FOUND",
                        "Run has no durable admission reservation",
                        http_status=503,
                    )
                if row.run_id not in {None, parsed_run_id}:
                    raise PlatformError(
                        "CAPACITY_RESERVATION_BINDING_CONFLICT",
                        "Cost settlement does not match the reserved Run",
                        http_status=409,
                    )
                now = self._now()
                for component, amount in sorted(
                    breakdown.components.items(),
                    key=lambda item: item[0].value,
                ):
                    event_id = hashlib.sha256(
                        (
                            f"{parsed_run_id}:{breakdown.rate_catalog_id}:{component.value}:final"
                        ).encode()
                    ).hexdigest()
                    await session.execute(
                        pg_insert(CostLedgerEntry)
                        .values(
                            tenant_id=tenant_id,
                            event_id=event_id,
                            run_id=parsed_run_id,
                            component=component.value,
                            amount_usd=amount,
                            rate_catalog_id=breakdown.rate_catalog_id,
                            source_units={
                                "source_counts": breakdown.source_counts,
                                "reconciled_at": breakdown.reconciled_at.isoformat(),
                            },
                            occurred_at=breakdown.reconciled_at,
                            created_at=now,
                        )
                        .on_conflict_do_nothing(
                            index_elements=[
                                CostLedgerEntry.tenant_id,
                                CostLedgerEntry.event_id,
                            ]
                        )
                    )
                await session.flush()
                daily, monthly = await self._utilization(
                    session,
                    tenant_id,
                    now,
                    exclude_reservation_key=reservation_key,
                )
                run_exceeded = breakdown.total_usd > run_limit_usd
                daily_exceeded = daily > Decimal("1")
                monthly_exceeded = monthly > Decimal("1")
                level = self._control_level(max(daily, monthly))
                row.run_id = parsed_run_id
                row.settled_cost_usd = breakdown.total_usd
                row.rate_catalog_id = breakdown.rate_catalog_id
                row.breakdown = breakdown.model_dump(mode="json")
                row.status = (
                    "settled_over_budget"
                    if run_exceeded or daily_exceeded or monthly_exceeded
                    else "settled"
                )
                row.updated_at = now
                await session.commit()
                return CostSettlement(
                    breakdown=breakdown,
                    run_limit_exceeded=run_exceeded,
                    tenant_daily_limit_exceeded=daily_exceeded,
                    tenant_monthly_limit_exceeded=monthly_exceeded,
                    budget_control_level=level,
                    daily_utilization=daily,
                    monthly_utilization=monthly,
                )
        except PlatformError:
            raise
        except SQLAlchemyError as exc:
            raise self._unavailable() from exc

    async def _utilization(
        self,
        session: AsyncSession,
        tenant_id: str,
        now: datetime,
        *,
        exclude_reservation_key: str | None = None,
    ) -> tuple[Decimal, Decimal]:
        day_start = datetime.combine(now.date(), time.min, tzinfo=UTC)
        day_end = day_start + timedelta(days=1)
        month_start = datetime(now.year, now.month, 1, tzinfo=UTC)
        month_end = (
            datetime(now.year + 1, 1, 1, tzinfo=UTC)
            if now.month == 12
            else datetime(now.year, now.month + 1, 1, tzinfo=UTC)
        )
        day_spent = await self._spent(session, tenant_id, day_start, day_end)
        month_spent = await self._spent(session, tenant_id, month_start, month_end)
        reservation_filters = [
            RunCapacityReservation.tenant_id == tenant_id,
            RunCapacityReservation.status == "active",
            RunCapacityReservation.expires_at > now,
        ]
        if exclude_reservation_key is not None:
            reservation_filters.append(
                RunCapacityReservation.reservation_key != exclude_reservation_key
            )
        day_reserved = await session.scalar(
            select(func.coalesce(func.sum(RunCapacityReservation.requested_cost_usd), 0)).where(
                *reservation_filters,
                RunCapacityReservation.daily_period == now.date(),
            )
        )
        month_reserved = await session.scalar(
            select(func.coalesce(func.sum(RunCapacityReservation.requested_cost_usd), 0)).where(
                *reservation_filters,
                RunCapacityReservation.monthly_period == date(now.year, now.month, 1),
            )
        )
        daily_total = Decimal(day_spent or 0) + Decimal(day_reserved or 0)
        monthly_total = Decimal(month_spent or 0) + Decimal(month_reserved or 0)
        return (
            daily_total / self._config.tenant_daily_budget_usd,
            monthly_total / self._config.tenant_monthly_budget_usd,
        )

    @staticmethod
    async def _spent(
        session: AsyncSession,
        tenant_id: str,
        start: datetime,
        end: datetime,
    ) -> Decimal:
        value = await session.scalar(
            select(func.coalesce(func.sum(CostLedgerEntry.amount_usd), 0)).where(
                CostLedgerEntry.tenant_id == tenant_id,
                CostLedgerEntry.occurred_at >= start,
                CostLedgerEntry.occurred_at < end,
            )
        )
        return Decimal(value or 0)

    @staticmethod
    async def _active_runs(
        session: AsyncSession,
        tenant_id: str,
        now: datetime,
    ) -> int:
        value = await session.scalar(
            select(func.count())
            .select_from(RunCapacityReservation)
            .where(
                RunCapacityReservation.tenant_id == tenant_id,
                RunCapacityReservation.status == "active",
                RunCapacityReservation.expires_at > now,
            )
        )
        return int(value or 0)

    @staticmethod
    async def _tenant_lock(session: AsyncSession, tenant_id: str) -> None:
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:capacity_lock_key, 739391))"),
            {"capacity_lock_key": tenant_id},
        )

    def _require_matching_config(self, config: CapacityControlConfig) -> None:
        if config != self._config:
            raise ValueError("CAPACITY_CONTROL_CONFIG_MISMATCH")

    @staticmethod
    def _require_matching_reservation_request(
        existing: RunCapacityReservation,
        *,
        requested_cost_usd: Decimal,
        priority: RunPriority,
    ) -> None:
        if (
            Decimal(existing.requested_cost_usd) == requested_cost_usd
            and existing.priority == priority.value
        ):
            return
        raise PlatformError(
            "CAPACITY_RESERVATION_REQUEST_CONFLICT",
            "Reservation key was already used with different admission parameters",
            http_status=409,
            context={
                "existing_requested_cost_usd": str(existing.requested_cost_usd),
                "requested_cost_usd": str(requested_cost_usd),
                "existing_priority": existing.priority,
                "priority": priority.value,
            },
        )

    @staticmethod
    def _can_reactivate(existing: RunCapacityReservation) -> bool:
        return (
            existing.status == "released"
            and existing.run_id is None
            and existing.settled_cost_usd is None
            and existing.rate_catalog_id is None
            and existing.breakdown is None
        )

    def _require_budget_admission(
        self,
        priority: RunPriority,
        level: BudgetControlLevel,
        daily: Decimal,
        monthly: Decimal,
    ) -> None:
        if level is BudgetControlLevel.STOP:
            raise PlatformError(
                "TENANT_BUDGET_EXHAUSTED",
                "Tenant daily or monthly cost budget is exhausted",
                retryable=False,
                http_status=429,
                context={
                    "daily_utilization": str(daily),
                    "monthly_utilization": str(monthly),
                },
            )
        if level is BudgetControlLevel.CRITICAL_ONLY and priority is not RunPriority.CRITICAL:
            raise PlatformError(
                "TENANT_BUDGET_BACKPRESSURE",
                "Only Critical reconciliation work is admitted near the tenant budget",
                retryable=True,
                http_status=429,
                context={"control_level": level.value},
            )
        if level is BudgetControlLevel.RESTRICT and priority is RunPriority.LOW:
            raise PlatformError(
                "TENANT_BUDGET_BACKPRESSURE",
                "Low-priority Runs are paused near the tenant budget",
                retryable=True,
                http_status=429,
                context={"control_level": level.value},
            )

    def _control_level(self, utilization: Decimal) -> BudgetControlLevel:
        if utilization >= Decimal("1"):
            return BudgetControlLevel.STOP
        if utilization >= self._config.critical_only_ratio:
            return BudgetControlLevel.CRITICAL_ONLY
        if utilization >= self._config.restrict_ratio:
            return BudgetControlLevel.RESTRICT
        if utilization >= self._config.midpoint_ratio:
            return BudgetControlLevel.MIDPOINT
        return BudgetControlLevel.NORMAL

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("CAPACITY_CONTROL_CLOCK_MUST_BE_TIMEZONE_AWARE")
        return value.astimezone(UTC)

    @staticmethod
    def _run_id(value: object) -> UUID:
        try:
            return value if isinstance(value, UUID) else UUID(str(value))
        except (TypeError, ValueError) as exc:
            raise ValueError("CAPACITY_RUN_ID_INVALID") from exc

    @staticmethod
    def _unavailable() -> PlatformError:
        return PlatformError(
            "CAPACITY_COST_STORE_UNAVAILABLE",
            "Durable tenant capacity and cost state is unavailable",
            retryable=True,
            http_status=503,
        )
