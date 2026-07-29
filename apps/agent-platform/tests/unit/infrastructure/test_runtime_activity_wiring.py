from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

import pytest
from prometheus_client import CollectorRegistry, generate_latest
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
from agent_platform.infrastructure.observability.metrics import PlatformMetrics
from agent_platform.infrastructure.observability.runtime import RuntimeObservability
from agent_platform.workflows.activities import ActivityDependencies, TemporalActivities


class _Runtime:
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
            "model_name": "activity-test-model",
            "model_settings": {"deterministic": True},
            "prompt_id": "activity-test-worker",
            "prompt_version": "1.0",
        }

    async def execute_task(
        self,
        context: object,
        task: TaskSpec,
        dependencies: dict[str, WorkerOutput],
    ) -> WorkerOutput:
        del context, task, dependencies
        return WorkerOutput(summary="bounded output")


def _contract() -> TaskContract:
    return TaskContract(
        goal="Produce a bounded output",
        success_criteria=[
            SuccessCriterion(
                id="sc-1",
                description="Output exists",
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
        max_cost_usd=Decimal("1"),
        max_duration_seconds=60,
    )


@pytest.mark.asyncio
async def test_temporal_execute_task_records_real_task_duration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = CollectorRegistry()
    observability = RuntimeObservability(PlatformMetrics(registry), environment="test")
    store = InMemoryPlatformStore()
    task = TaskSpec(
        id="analysis",
        kind="analysis",
        objective="Analyze bounded input",
        output_schema="WorkerOutput@1.0",
        risk=RiskLevel.MEDIUM,
        timeout_seconds=30,
        estimated_cost_usd=Decimal("0.1"),
    )
    plan = ExecutionPlan(
        plan_version=1,
        tasks=[task],
        final_task_id=task.id,
        expected_total_cost_usd=task.estimated_cost_usd,
    )
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
            status=RunStatus.EXECUTING,
            plan=plan,
            current_plan_version=1,
        )
    )
    activities = TemporalActivities(
        ActivityDependencies(
            store=store,
            runtime=_Runtime(),
            gateway=object(),
            run_service=object(),
            commit_service=object(),
            observability=observability,
        )
    )
    monkeypatch.setattr(
        "agent_platform.workflows.activities.activity.heartbeat",
        lambda details: None,
    )

    output = await activities.execute_task(
        {
            "run_id": str(run.run_id),
            "tenant_id": run.tenant_id,
            "correlation_id": "corr-1",
            "task": task.model_dump(mode="json"),
            "dependencies": {},
        }
    )

    assert output["summary"] == "bounded output"
    audit = await store.audit.export_run(run.run_id, run.tenant_id)
    execution = audit["task_executions"][0]
    assert execution["status"] == "succeeded"
    assert execution["model_name"] == "activity-test-model"
    assert execution["prompt_id"] == "activity-test-worker"
    assert execution["output"]["summary"] == "bounded output"
    assert [event["event_type"] for event in audit["events"]] == [
        "task.started",
        "task.completed",
    ]
    rendered = generate_latest(registry).decode()
    assert (
        'agent_task_duration_seconds_count{environment="test",kind="analysis",'
        'model="activity-test-model",status="completed"} 1.0'
    ) in rendered


@pytest.mark.asyncio
async def test_temporal_finalizer_persists_criterion_verifications() -> None:
    store = InMemoryPlatformStore()
    task = TaskSpec(
        id="analysis",
        kind="analysis",
        objective="Analyze bounded input",
        output_schema="WorkerOutput@1.0",
        risk=RiskLevel.MEDIUM,
        timeout_seconds=30,
        estimated_cost_usd=Decimal("0.1"),
    )
    plan = ExecutionPlan(
        plan_version=1,
        tasks=[task],
        final_task_id=task.id,
        expected_total_cost_usd=task.estimated_cost_usd,
    )
    run_id = uuid4()
    run, _ = await store.runs.create_once(
        RunRecord(
            run_id=run_id,
            tenant_id="tenant-a",
            principal_id="user",
            contract=_contract(),
            idempotency_key="finalizer-1",
            request_hash="b" * 64,
            workflow_id=f"agent-run-{run_id}",
            status=RunStatus.VERIFYING,
            plan=plan,
            current_plan_version=1,
        )
    )
    output = WorkerOutput(
        summary="Schema-valid final output.",
        criterion_verifications=[
            CriterionVerification(
                criterion_id="sc-1",
                method="schema",
                passed=True,
                checked_at=datetime.now(UTC),
                verifier_version="schema-validator@1",
            )
        ],
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

    await activities._store_final_response(run, plan, {task.id: output})

    stored = await store.runs.get(run_id, "tenant-a")
    assert stored.result is not None
    assert stored.result.criterion_verifications == output.criterion_verifications


@pytest.mark.asyncio
async def test_temporal_finalizer_rejects_non_pass_report() -> None:
    store = InMemoryPlatformStore()
    task = TaskSpec(
        id="analysis",
        kind="analysis",
        objective="Analyze bounded input",
        output_schema="WorkerOutput@1.0",
        risk=RiskLevel.MEDIUM,
        timeout_seconds=30,
        estimated_cost_usd=Decimal("0.1"),
    )
    plan = ExecutionPlan(
        plan_version=1,
        tasks=[task],
        final_task_id=task.id,
        expected_total_cost_usd=task.estimated_cost_usd,
    )
    run_id = uuid4()
    run, _ = await store.runs.create_once(
        RunRecord(
            run_id=run_id,
            tenant_id="tenant-a",
            principal_id="user",
            contract=_contract(),
            idempotency_key="finalizer-2",
            request_hash="c" * 64,
            workflow_id=f"agent-run-{run_id}",
            status=RunStatus.VERIFYING,
            plan=plan,
            current_plan_version=1,
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

    with pytest.raises(ApplicationError) as caught:
        await activities.finalize_run(
            {
                "run_id": str(run.run_id),
                "tenant_id": run.tenant_id,
                "correlation_id": "corr-finalizer",
                "plan": plan.model_dump(mode="json"),
                "outputs": {task.id: WorkerOutput(summary="incomplete").model_dump(mode="json")},
                "report": {
                    "verdict": "revise",
                    "failed_criteria": ["sc-1"],
                    "repair_instructions": ["Produce the required schema check."],
                },
            }
        )

    assert caught.value.type == "FINALIZATION_REQUIRES_VERIFICATION_PASS"
