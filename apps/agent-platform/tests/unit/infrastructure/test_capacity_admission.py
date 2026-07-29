from __future__ import annotations

from decimal import Decimal
from typing import Any
from uuid import uuid4

import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.infrastructure.capacity_cost import (
    AdmissionDecision,
    BudgetControlLevel,
    CapacityCostController,
    CostSettlement,
    QueueBacklog,
    ReservationView,
    RunPriority,
)


class _AdmissionRepository:
    def __init__(self, existing: ReservationView | None = None) -> None:
        self.existing = existing
        self.reservations: list[dict[str, Any]] = []
        self.bindings: list[tuple[str, str, object]] = []
        self.releases: list[tuple[str, str, bool]] = []

    async def find_reservation(
        self, tenant_id: str, reservation_key: str
    ) -> ReservationView | None:
        return self.existing

    async def reserve(self, **values: Any) -> AdmissionDecision:
        self.reservations.append(values)
        return AdmissionDecision(
            newly_reserved=True,
            active_runs=4,
            budget_control_level=BudgetControlLevel.MIDPOINT,
            daily_utilization=Decimal("0.55"),
            monthly_utilization=Decimal("0.42"),
        )

    async def bind_run(self, *, tenant_id: str, reservation_key: str, run_id: object) -> None:
        self.bindings.append((tenant_id, reservation_key, run_id))

    async def release(
        self,
        *,
        tenant_id: str,
        reservation_key: str,
        only_if_unbound: bool,
    ) -> None:
        self.releases.append((tenant_id, reservation_key, only_if_unbound))

    async def settle(self, **values: Any) -> CostSettlement:
        raise AssertionError("not used")


class _QueueProbe:
    def __init__(self, state: QueueBacklog) -> None:
        self.state = state
        self.calls = 0

    async def snapshot(self) -> QueueBacklog:
        self.calls += 1
        return self.state


@pytest.mark.asyncio
async def test_capacity_admission_is_idempotent_before_probing_temporal() -> None:
    existing = ReservationView(
        active=True,
        run_id=str(uuid4()),
        budget_control_level=BudgetControlLevel.RESTRICT,
        daily_utilization=Decimal("0.82"),
        monthly_utilization=Decimal("0.70"),
    )
    repository = _AdmissionRepository(existing)
    queue = _QueueProbe(QueueBacklog(backlog=999, oldest_age_seconds=999))
    control = CapacityCostController(
        repository,
        queue_probe=queue,
        key_hmac_secret=b"k" * 32,
    )

    decision = await control.admit_run(
        tenant_id="tenant-a",
        idempotency_key="request-1",
        requested_cost_usd=Decimal("5"),
        max_duration_seconds=300,
        priority=RunPriority.NORMAL,
    )

    assert decision.newly_reserved is False
    assert decision.budget_control_level is BudgetControlLevel.RESTRICT
    assert queue.calls == 0
    assert repository.reservations == []


@pytest.mark.asyncio
async def test_queue_backpressure_rejects_normal_but_allows_bounded_critical_work() -> None:
    normal_repository = _AdmissionRepository()
    normal = CapacityCostController(
        normal_repository,
        queue_probe=_QueueProbe(QueueBacklog(backlog=600, oldest_age_seconds=70)),
        key_hmac_secret=b"k" * 32,
    )
    with pytest.raises(PlatformError) as rejected:
        await normal.admit_run(
            tenant_id="tenant-a",
            idempotency_key="request-1",
            requested_cost_usd=Decimal("5"),
            max_duration_seconds=300,
            priority=RunPriority.NORMAL,
        )
    assert rejected.value.code == "RUN_QUEUE_BACKPRESSURE"

    critical_repository = _AdmissionRepository()
    critical = CapacityCostController(
        critical_repository,
        queue_probe=_QueueProbe(QueueBacklog(backlog=600, oldest_age_seconds=70)),
        key_hmac_secret=b"k" * 32,
    )
    decision = await critical.admit_run(
        tenant_id="tenant-a",
        idempotency_key="request-2",
        requested_cost_usd=Decimal("5"),
        max_duration_seconds=300,
        priority=RunPriority.CRITICAL,
    )
    assert decision.newly_reserved is True
    assert decision.queue_backlog == 600
    assert normal_repository.reservations == []
    assert critical_repository.reservations[0]["lease_seconds"] == 600
    assert "tenant-a" not in critical_repository.reservations[0]["reservation_key"]


@pytest.mark.asyncio
async def test_critical_work_is_still_rejected_at_hard_queue_limit() -> None:
    control = CapacityCostController(
        _AdmissionRepository(),
        queue_probe=_QueueProbe(QueueBacklog(backlog=1001, oldest_age_seconds=121)),
        key_hmac_secret=b"k" * 32,
    )

    with pytest.raises(PlatformError) as rejected:
        await control.admit_run(
            tenant_id="tenant-a",
            idempotency_key="request-1",
            requested_cost_usd=Decimal("5"),
            max_duration_seconds=300,
            priority=RunPriority.CRITICAL,
        )

    assert rejected.value.code == "RUN_QUEUE_HARD_LIMIT"
