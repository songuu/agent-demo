from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.exc import SQLAlchemyError

from agent_platform.application.errors import PlatformError
from agent_platform.infrastructure.capacity_cost import (
    BudgetControlLevel,
    CapacityControlConfig,
    CostBreakdown,
    CostComponent,
    RunPriority,
)
from agent_platform.infrastructure.persistence import capacity_repository as repository_module
from agent_platform.infrastructure.persistence.capacity_repository import (
    PostgresCapacityCostRepository,
)

NOW = datetime(2026, 7, 27, 12, tzinfo=UTC)


class _Session:
    def __init__(
        self,
        *,
        scalar_values: list[Any] | None = None,
        get_value: Any = None,
        get_error: Exception | None = None,
    ) -> None:
        self.scalar_values = list(scalar_values or [])
        self.get_value = get_value
        self.get_error = get_error
        self.executed: list[Any] = []
        self.added: list[Any] = []
        self.commits = 0
        self.flushes = 0

    async def get(self, model: object, key: object) -> Any:
        del model, key
        if self.get_error is not None:
            raise self.get_error
        return self.get_value

    async def scalar(self, statement: object) -> Any:
        del statement
        return self.scalar_values.pop(0)

    async def execute(
        self,
        statement: object,
        parameters: object | None = None,
    ) -> None:
        self.executed.append((statement, parameters))

    def add(self, value: object) -> None:
        self.added.append(value)

    async def commit(self) -> None:
        self.commits += 1

    async def flush(self) -> None:
        self.flushes += 1


def _install_session(
    monkeypatch: pytest.MonkeyPatch,
    session: _Session,
) -> None:
    @asynccontextmanager
    async def fake_tenant_session(
        factory: object,
        tenant_id: str,
    ) -> AsyncIterator[_Session]:
        del factory
        assert tenant_id == "tenant-a"
        yield session

    monkeypatch.setattr(repository_module, "tenant_session", fake_tenant_session)


def _config() -> CapacityControlConfig:
    return CapacityControlConfig(
        tenant_max_active_runs=2,
        tenant_daily_budget_usd=Decimal("1"),
        tenant_monthly_budget_usd=Decimal("10"),
    )


def _repository() -> PostgresCapacityCostRepository:
    return PostgresCapacityCostRepository(
        object(),  # type: ignore[arg-type]
        config=_config(),
        clock=lambda: NOW,
    )


@pytest.mark.asyncio
async def test_reserve_serializes_tenant_and_persists_projected_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _Session(
        scalar_values=[
            None,  # no existing reservation
            0,  # active Run count
            Decimal("0"),  # daily ledger spend
            Decimal("0"),  # monthly ledger spend
            Decimal("0"),  # daily active reservations
            Decimal("0"),  # monthly active reservations
        ]
    )
    _install_session(monkeypatch, session)
    repository = _repository()

    result = await repository.reserve(
        tenant_id="tenant-a",
        reservation_key="reservation-1",
        requested_cost_usd=Decimal("0.6"),
        priority=RunPriority.NORMAL,
        lease_seconds=300,
        config=_config(),
    )

    assert result.newly_reserved is True
    assert result.active_runs == 1
    assert result.budget_control_level is BudgetControlLevel.MIDPOINT
    assert result.daily_utilization == Decimal("0.6")
    assert len(session.added) == 1
    assert session.added[0].expires_at == NOW + timedelta(seconds=300)
    assert session.commits == 1
    assert session.executed  # expired reservation cleanup and advisory lock


@pytest.mark.asyncio
async def test_released_unbound_reservation_is_reactivated_after_rechecking_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = SimpleNamespace(
        status="released",
        run_id=None,
        requested_cost_usd=Decimal("0.6"),
        settled_cost_usd=None,
        priority=RunPriority.NORMAL.value,
        daily_period=NOW.date(),
        monthly_period=NOW.date().replace(day=1),
        expires_at=NOW - timedelta(seconds=1),
        rate_catalog_id=None,
        breakdown=None,
        updated_at=NOW - timedelta(seconds=1),
    )
    session = _Session(
        scalar_values=[
            row,
            0,
            Decimal("0"),
            Decimal("0"),
            Decimal("0"),
            Decimal("0"),
        ]
    )
    _install_session(monkeypatch, session)

    result = await _repository().reserve(
        tenant_id="tenant-a",
        reservation_key="reservation-1",
        requested_cost_usd=Decimal("0.6"),
        priority=RunPriority.NORMAL,
        lease_seconds=300,
        config=_config(),
    )

    assert result.newly_reserved is True
    assert result.active_runs == 1
    assert row.status == "active"
    assert row.expires_at == NOW + timedelta(seconds=300)
    assert row.updated_at == NOW
    assert session.added == []
    assert session.commits == 1


@pytest.mark.asyncio
async def test_reservation_key_reuse_with_different_parameters_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = SimpleNamespace(
        status="released",
        run_id=None,
        requested_cost_usd=Decimal("0.6"),
        settled_cost_usd=None,
        priority=RunPriority.NORMAL.value,
        rate_catalog_id=None,
        breakdown=None,
    )
    session = _Session(scalar_values=[row])
    _install_session(monkeypatch, session)

    with pytest.raises(PlatformError) as caught:
        await _repository().reserve(
            tenant_id="tenant-a",
            reservation_key="reservation-1",
            requested_cost_usd=Decimal("0.7"),
            priority=RunPriority.NORMAL,
            lease_seconds=300,
            config=_config(),
        )

    assert caught.value.code == "CAPACITY_RESERVATION_REQUEST_CONFLICT"
    assert caught.value.http_status == 409
    assert session.commits == 0


@pytest.mark.asyncio
async def test_released_bound_reservation_is_never_reactivated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = uuid4()
    row = SimpleNamespace(
        status="released",
        run_id=run_id,
        requested_cost_usd=Decimal("0.6"),
        settled_cost_usd=None,
        priority=RunPriority.NORMAL.value,
        rate_catalog_id=None,
        breakdown=None,
    )
    session = _Session(
        scalar_values=[
            row,
            0,
            Decimal("0"),
            Decimal("0"),
            Decimal("0"),
            Decimal("0"),
        ]
    )
    _install_session(monkeypatch, session)

    result = await _repository().reserve(
        tenant_id="tenant-a",
        reservation_key="reservation-1",
        requested_cost_usd=Decimal("0.6"),
        priority=RunPriority.NORMAL,
        lease_seconds=300,
        config=_config(),
    )

    assert result.newly_reserved is False
    assert row.status == "released"
    assert row.run_id == run_id
    assert session.commits == 1


@pytest.mark.asyncio
async def test_bind_release_and_find_are_idempotent_and_tenant_scoped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = uuid4()
    row = SimpleNamespace(
        status="active",
        expires_at=NOW + timedelta(minutes=5),
        run_id=None,
        updated_at=NOW,
    )
    session = _Session(scalar_values=[row])
    _install_session(monkeypatch, session)
    repository = _repository()

    await repository.bind_run(
        tenant_id="tenant-a",
        reservation_key="reservation-1",
        run_id=run_id,
    )

    assert row.run_id == run_id
    assert session.commits == 1

    release_session = _Session(scalar_values=[row])
    _install_session(monkeypatch, release_session)
    await repository.release(
        tenant_id="tenant-a",
        reservation_key="reservation-1",
        only_if_unbound=False,
    )
    assert row.status == "released"
    assert release_session.commits == 1

    active_row = SimpleNamespace(
        status="active",
        expires_at=NOW + timedelta(minutes=5),
        run_id=run_id,
    )
    find_session = _Session(
        get_value=active_row,
        scalar_values=[
            Decimal("0.4"),
            Decimal("2"),
            Decimal("0.1"),
            Decimal("1"),
        ],
    )
    _install_session(monkeypatch, find_session)
    found = await repository.find_reservation("tenant-a", "reservation-1")
    assert found is not None
    assert found.active is True
    assert found.run_id == str(run_id)
    assert found.budget_control_level is BudgetControlLevel.MIDPOINT


@pytest.mark.asyncio
async def test_settlement_appends_six_immutable_components_and_releases_reservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = uuid4()
    row = SimpleNamespace(
        status="active",
        run_id=run_id,
        settled_cost_usd=None,
        rate_catalog_id=None,
        breakdown=None,
        updated_at=NOW,
    )
    session = _Session(
        scalar_values=[
            row,
            Decimal("0.6"),
            Decimal("0.6"),
            Decimal("0"),
            Decimal("0"),
        ]
    )
    _install_session(monkeypatch, session)
    repository = _repository()
    breakdown = CostBreakdown(
        rate_catalog_id="rates-v1",
        components={component: Decimal("0.1") for component in CostComponent},
        total_usd=Decimal("0.6"),
        source_counts={
            "artifacts": 1,
            "events": 2,
            "sandbox_tasks": 0,
            "tool_invocations": 1,
        },
        reconciled_at=NOW,
    )

    result = await repository.settle(
        tenant_id="tenant-a",
        reservation_key="reservation-1",
        run_id=run_id,
        run_limit_usd=Decimal("1"),
        breakdown=breakdown,
        config=_config(),
    )

    # One advisory lock plus six conflict-safe ledger inserts.
    assert len(session.executed) == 7
    assert session.flushes == 1
    assert session.commits == 1
    assert row.status == "settled"
    assert row.settled_cost_usd == Decimal("0.6")
    assert result.daily_utilization == Decimal("0.6")
    assert result.monthly_utilization == Decimal("0.06")
    assert result.run_limit_exceeded is False


def test_budget_thresholds_and_input_validation_fail_closed() -> None:
    repository = _repository()

    with pytest.raises(PlatformError, match="Tenant daily or monthly"):
        repository._require_budget_admission(
            RunPriority.CRITICAL,
            BudgetControlLevel.STOP,
            Decimal("1"),
            Decimal("0.1"),
        )
    with pytest.raises(PlatformError, match="Only Critical"):
        repository._require_budget_admission(
            RunPriority.NORMAL,
            BudgetControlLevel.CRITICAL_ONLY,
            Decimal("0.96"),
            Decimal("0.1"),
        )
    with pytest.raises(PlatformError, match="Low-priority"):
        repository._require_budget_admission(
            RunPriority.LOW,
            BudgetControlLevel.RESTRICT,
            Decimal("0.81"),
            Decimal("0.1"),
        )
    repository._require_budget_admission(
        RunPriority.CRITICAL,
        BudgetControlLevel.CRITICAL_ONLY,
        Decimal("0.96"),
        Decimal("0.1"),
    )

    with pytest.raises(ValueError, match="CAPACITY_CONTROL_CONFIG_MISMATCH"):
        repository._require_matching_config(CapacityControlConfig())
    with pytest.raises(ValueError, match="CAPACITY_RUN_ID_INVALID"):
        repository._run_id("not-a-uuid")
    with pytest.raises(ValueError, match="CAPACITY_CONTROL_CLOCK_MUST_BE_TIMEZONE_AWARE"):
        PostgresCapacityCostRepository(
            object(),  # type: ignore[arg-type]
            config=_config(),
            clock=lambda: datetime(2026, 7, 27),
        )._now()


@pytest.mark.asyncio
async def test_database_errors_are_wrapped_with_retryable_capacity_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_session(
        monkeypatch,
        _Session(get_error=SQLAlchemyError("database unavailable")),
    )

    with pytest.raises(PlatformError) as caught:
        await _repository().find_reservation("tenant-a", "reservation-1")

    assert caught.value.code == "CAPACITY_COST_STORE_UNAVAILABLE"
    assert caught.value.retryable is True
