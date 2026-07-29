from __future__ import annotations

from decimal import Decimal

import pytest
from prometheus_client import CollectorRegistry, generate_latest

from agent_platform.api.schemas import (
    BudgetRequest,
    CreateRunRequest,
    RequestedOutput,
    SuccessCriterionRequest,
)
from agent_platform.application.errors import PlatformError
from agent_platform.application.run_service import RunService
from agent_platform.domain.enums import RunStatus
from agent_platform.domain.models import DataScope, Principal
from agent_platform.infrastructure.capacity_cost import (
    AdmissionDecision,
    BudgetControlLevel,
    CostBreakdown,
    CostComponent,
    CostSettlement,
    RunPriority,
)
from agent_platform.infrastructure.memory_store import InMemoryPlatformStore
from agent_platform.infrastructure.observability.metrics import PlatformMetrics
from agent_platform.infrastructure.observability.runtime import RuntimeObservability


class _Workflow:
    def __init__(self) -> None:
        self.started: list[object] = []

    async def start(self, run_id: object, *args: object, **kwargs: object) -> None:
        self.started.append(run_id)


class _Capacity:
    def __init__(self, *, run_limit_exceeded: bool = False) -> None:
        self.run_limit_exceeded = run_limit_exceeded
        self.admissions: list[dict[str, object]] = []
        self.bindings: list[dict[str, object]] = []
        self.releases: list[dict[str, object]] = []
        self.settled: list[object] = []

    async def admit_run(self, **values: object) -> AdmissionDecision:
        self.admissions.append(values)
        return AdmissionDecision(
            newly_reserved=True,
            active_runs=1,
            budget_control_level=BudgetControlLevel.RESTRICT,
            daily_utilization=Decimal("0.81"),
            monthly_utilization=Decimal("0.60"),
        )

    async def bind_run(self, **values: object) -> None:
        self.bindings.append(values)

    async def release_if_unbound(self, **values: object) -> None:
        self.releases.append(values)

    async def settle_run(self, run: object) -> CostSettlement:
        self.settled.append(run)
        breakdown = CostBreakdown(
            rate_catalog_id="rates-v1",
            components={component: Decimal("0.1") for component in CostComponent},
            total_usd=Decimal("0.6"),
            source_counts={
                "artifacts": 0,
                "events": 3,
                "sandbox_tasks": 0,
                "tool_invocations": 0,
            },
            reconciled_at="2026-07-27T00:00:00Z",
        )
        return CostSettlement(
            breakdown=breakdown,
            run_limit_exceeded=self.run_limit_exceeded,
            tenant_daily_limit_exceeded=False,
            tenant_monthly_limit_exceeded=False,
            budget_control_level=BudgetControlLevel.RESTRICT,
            daily_utilization=Decimal("0.81"),
            monthly_utilization=Decimal("0.60"),
        )


def _principal() -> Principal:
    return Principal(
        user_id="user-1",
        tenant_id="tenant-a",
        roles=frozenset({"analyst"}),
        scopes=frozenset({"runs:create"}),
        auth_strength="mfa",
        session_id="session-1",
    )


def _scope() -> DataScope:
    return DataScope(
        tenant_id="tenant-a",
        resource_types=frozenset({"knowledge"}),
        classifications=frozenset({"internal"}),
    )


def _request(*, priority: str = "normal") -> CreateRunRequest:
    return CreateRunRequest(
        goal="Build a verified report",
        success_criteria=[
            SuccessCriterionRequest(
                id="must-1",
                description="Report is verified",
                severity="must",
            )
        ],
        allowed_capabilities=["knowledge.search"],
        constraints={"priority": priority},
        budget=BudgetRequest(
            max_cost_usd=Decimal("5"),
            max_duration_seconds=300,
            max_tool_calls=3,
        ),
        external_write_policy="deny",
        requested_output=RequestedOutput(format="report@1.0"),
    )


@pytest.mark.asyncio
async def test_create_reserves_and_binds_shared_capacity_before_workflow_start() -> None:
    store = InMemoryPlatformStore()
    workflow = _Workflow()
    capacity = _Capacity()
    service = RunService(
        store.runs,
        store.actions,
        workflow,
        capacity_cost=capacity,
    )

    run, created = await service.create(
        _request(priority="high"),
        _principal(),
        _scope(),
        idempotency_key="request-1",
        correlation_id="corr-1",
    )

    assert created is True
    assert capacity.admissions[0]["priority"] is RunPriority.HIGH
    assert capacity.admissions[0]["requested_cost_usd"] == Decimal("5")
    assert capacity.bindings == [
        {
            "tenant_id": "tenant-a",
            "idempotency_key": "request-1",
            "run_id": run.run_id,
        }
    ]
    assert run.contract.constraints["_platform_budget_control"] == "restrict"
    assert workflow.started == [run.run_id]


@pytest.mark.asyncio
async def test_completed_run_is_blocked_when_full_platform_cost_exceeds_run_limit() -> None:
    store = InMemoryPlatformStore()
    capacity = _Capacity(run_limit_exceeded=True)
    service = RunService(
        store.runs,
        store.actions,
        _Workflow(),
        capacity_cost=capacity,
    )
    run, _ = await service.create(
        _request(),
        _principal(),
        _scope(),
        idempotency_key="request-2",
        correlation_id="corr-1",
    )
    current = RunStatus.RECEIVED
    for target in (
        RunStatus.CLASSIFIED,
        RunStatus.PLANNING,
        RunStatus.AUTHORIZED,
        RunStatus.EXECUTING,
        RunStatus.VERIFYING,
    ):
        await service.transition(run.run_id, "tenant-a", target, "corr-1", expected={current})
        current = target

    with pytest.raises(PlatformError) as caught:
        await service.transition(
            run.run_id,
            "tenant-a",
            RunStatus.COMPLETED,
            "corr-1",
            expected={RunStatus.VERIFYING},
        )

    assert caught.value.code == "BUDGET_EXHAUSTED"
    assert (await store.runs.get(run.run_id, "tenant-a")).status is RunStatus.VERIFYING
    assert len(capacity.settled) == 1


@pytest.mark.asyncio
async def test_terminal_settlement_records_full_cost_and_tenant_budget_metrics() -> None:
    store = InMemoryPlatformStore()
    registry = CollectorRegistry()
    service = RunService(
        store.runs,
        store.actions,
        _Workflow(),
        capacity_cost=_Capacity(),
        observability=RuntimeObservability(
            PlatformMetrics(registry),
            environment="test",
        ),
    )
    run, _ = await service.create(
        _request(),
        _principal(),
        _scope(),
        idempotency_key="request-3",
        correlation_id="corr-1",
    )
    current = RunStatus.RECEIVED
    for target in (
        RunStatus.CLASSIFIED,
        RunStatus.PLANNING,
        RunStatus.AUTHORIZED,
        RunStatus.EXECUTING,
        RunStatus.VERIFYING,
        RunStatus.COMPLETED,
    ):
        await service.transition(
            run.run_id,
            "tenant-a",
            target,
            "corr-1",
            expected={current},
        )
        current = target

    output = generate_latest(registry).decode()
    assert (
        'agent_platform_cost_usd_total{component="artifact",environment="test",'
        'tenant_tier="unknown",use_case="other"} 0.1'
    ) in output
    assert (
        'agent_tenant_budget_utilization_ratio_count{control_level="restrict",'
        'environment="test",period="daily",tenant_tier="unknown"} 1.0'
    ) in output
    assert (
        'agent_success_cost_usd_count{environment="test",tenant_tier="unknown",'
        'use_case="other"} 1.0'
    ) in output
