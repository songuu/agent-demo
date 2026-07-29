from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

import pytest
from temporalio.exceptions import ApplicationError

from agent_platform.application.records import RunRecord
from agent_platform.domain.enums import RiskLevel, RunStatus
from agent_platform.domain.models import (
    CriterionVerification,
    DataScope,
    ExecutionPlan,
    Principal,
    SuccessCriterion,
    TaskContract,
    TaskSpec,
    WorkerOutput,
)
from agent_platform.infrastructure.memory_store import InMemoryPlatformStore
from agent_platform.workflows.activities import ActivityDependencies, TemporalActivities


def _contract(*, max_cost_usd: str = "1", max_tool_calls: int = 10) -> TaskContract:
    return TaskContract(
        goal="Keep actual usage within the durable budget.",
        success_criteria=[
            SuccessCriterion(
                id="sc-1",
                description="Usage is durable.",
                verification="schema",
            )
        ],
        principal=Principal(
            user_id="user",
            tenant_id="tenant-a",
            auth_strength="mfa",
        ),
        data_scope=DataScope(tenant_id="tenant-a", resource_types={"document"}),
        risk=RiskLevel.MEDIUM,
        max_cost_usd=Decimal(max_cost_usd),
        max_duration_seconds=120,
        max_tool_calls=max_tool_calls,
    )


def _plan() -> ExecutionPlan:
    task = TaskSpec(
        id="final",
        kind="analysis",
        objective="Return a result.",
        output_schema="WorkerOutput@1.0",
        risk=RiskLevel.MEDIUM,
        estimated_cost_usd=Decimal("0.1"),
    )
    return ExecutionPlan(
        plan_version=1,
        tasks=[task],
        final_task_id=task.id,
        expected_total_cost_usd=task.estimated_cost_usd,
    )


class _UsageRuntime:
    def __init__(self, plan: ExecutionPlan) -> None:
        self._plan = plan

    @staticmethod
    def audit_metadata(
        role: str,
        contract: TaskContract,
        *,
        task: TaskSpec | None = None,
        retry_count: int = 0,
    ) -> dict[str, object]:
        del role, contract, task, retry_count
        return {
            "model_name": "usage-test-model",
            "model_settings": {"deterministic": True},
            "prompt_id": "usage-test-planner",
            "prompt_version": "1.0",
        }

    async def plan(self, context: object, contract: TaskContract) -> ExecutionPlan:
        del contract
        context.budget.record_model_usage(
            input_tokens=800_000,
            output_tokens=0,
            cost_usd=Decimal("0.8"),
            pricing_catalog_version="catalog-v1",
        )
        return self._plan


@pytest.mark.asyncio
async def test_actual_model_usage_is_saved_and_crossing_80_percent_emits_immutable_warning() -> (
    None
):
    store = InMemoryPlatformStore()
    run_id = uuid4()
    run, _ = await store.runs.create_once(
        RunRecord(
            run_id=run_id,
            tenant_id="tenant-a",
            principal_id="user",
            contract=_contract(),
            idempotency_key="request-1",
            request_hash="a" * 64,
            workflow_id=f"agent-run-{run_id}",
            status=RunStatus.PLANNING,
        )
    )
    activities = TemporalActivities(
        ActivityDependencies(
            store=store,
            runtime=_UsageRuntime(_plan()),
            gateway=object(),
            run_service=object(),
            commit_service=object(),
        )
    )

    await activities.create_plan(
        {
            "run_id": str(run.run_id),
            "tenant_id": run.tenant_id,
            "correlation_id": "corr-1",
        }
    )

    saved = await store.runs.get(run.run_id, run.tenant_id)
    events = await store.runs.events_after(run.run_id, run.tenant_id, 0)
    warning = next(event for event in events if event.event_type == "budget.warning")
    assert saved.token_input == 800_000
    assert saved.token_output == 0
    assert saved.cost_actual_usd == Decimal("0.8")
    assert warning.payload["utilization"] == "0.8"
    assert warning.payload["pricing_catalog_version"] == "catalog-v1"
    audit = await store.audit.export_run(run.run_id, run.tenant_id)
    assert audit["plans"][0]["planner_model"] == "usage-test-model"
    assert audit["plans"][0]["prompt_id"] == "usage-test-planner"
    assert next(
        event for event in audit["events"] if event["event_type"] == "plan.created"
    )["payload"]["plan_hash"] == audit["plans"][0]["plan_hash"]


class _OverToolBudgetRuntime:
    def __init__(self) -> None:
        self.tool_invocations = 0

    @staticmethod
    def audit_metadata(
        role: str,
        contract: TaskContract,
        *,
        task: TaskSpec | None = None,
        retry_count: int = 0,
    ) -> dict[str, object]:
        del role, contract, task, retry_count
        return {
            "model_name": "tool-budget-test-model",
            "model_settings": {"deterministic": True},
            "prompt_id": "tool-budget-test-worker",
            "prompt_version": "1.0",
        }

    async def execute_task(
        self,
        context: object,
        task: TaskSpec,
        dependencies: dict[str, object],
    ) -> object:
        del task, dependencies
        context.budget.assert_can_invoke("tool")
        context.budget.record_tool_call()
        self.tool_invocations += 1
        context.budget.assert_can_invoke("tool")
        self.tool_invocations += 1
        raise AssertionError("the second fake tool must not run")


@pytest.mark.asyncio
async def test_actual_tool_usage_is_saved_even_when_next_tool_is_stopped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = InMemoryPlatformStore()
    plan = _plan()
    run_id = uuid4()
    run, _ = await store.runs.create_once(
        RunRecord(
            run_id=run_id,
            tenant_id="tenant-a",
            principal_id="user",
            contract=_contract(max_cost_usd="10", max_tool_calls=1),
            idempotency_key="request-2",
            request_hash="b" * 64,
            workflow_id=f"agent-run-{run_id}",
            status=RunStatus.EXECUTING,
            plan=plan,
            current_plan_version=1,
        )
    )
    runtime = _OverToolBudgetRuntime()
    activities = TemporalActivities(
        ActivityDependencies(
            store=store,
            runtime=runtime,
            gateway=object(),
            run_service=object(),
            commit_service=object(),
        )
    )

    monkeypatch.setattr(
        "agent_platform.workflows.activities.activity.heartbeat",
        lambda details: None,
    )
    with pytest.raises(ApplicationError) as error:
        await activities.execute_task(
            {
                "run_id": str(run.run_id),
                "tenant_id": run.tenant_id,
                "correlation_id": "corr-2",
                "task": plan.tasks[0].model_dump(mode="json"),
                "dependencies": {},
            }
        )

    saved = await store.runs.get(run.run_id, run.tenant_id)
    assert error.value.type == "BUDGET_EXHAUSTED"
    assert runtime.tool_invocations == 1
    assert saved.tool_call_count == 1
    assert saved.outputs == {}


@pytest.mark.asyncio
async def test_final_response_does_not_replace_actual_cost_with_plan_estimate() -> None:
    store = InMemoryPlatformStore()
    plan = _plan()
    run_id = uuid4()
    run, _ = await store.runs.create_once(
        RunRecord(
            run_id=run_id,
            tenant_id="tenant-a",
            principal_id="user",
            contract=_contract(max_cost_usd="10"),
            idempotency_key="request-3",
            request_hash="c" * 64,
            workflow_id=f"agent-run-{run_id}",
            status=RunStatus.VERIFYING,
            plan=plan,
            current_plan_version=1,
            cost_actual_usd=Decimal("0.42"),
            token_input=123,
            token_output=45,
        )
    )
    activities = TemporalActivities(
        ActivityDependencies(
            store=store,
            runtime=object(),
            gateway=object(),
            run_service=object(),
            commit_service=object(),
        )
    )

    await activities._store_final_response(
        run,
        plan,
        {
            "final": WorkerOutput(
                summary="final",
                criterion_verifications=[
                    CriterionVerification(
                        criterion_id="sc-1",
                        method="schema",
                        passed=True,
                        checked_at=datetime.now(UTC),
                        verifier_version="test@1",
                    )
                ],
            )
        },
    )

    saved = await store.runs.get(run.run_id, run.tenant_id)
    assert saved.cost_actual_usd == Decimal("0.42")
    assert saved.token_input == 123
    assert saved.token_output == 45
