from __future__ import annotations

from decimal import Decimal
from uuid import uuid4

import pytest

from agent_platform.agents.deterministic_runtime import (
    DeterministicAgentRuntime,
    RuntimeExecutionContext,
)
from agent_platform.domain.enums import DataClassification, RiskLevel
from agent_platform.domain.models import (
    DataScope,
    Principal,
    SuccessCriterion,
    TaskContract,
    WorkerOutput,
)
from agent_platform.infrastructure.credentials import EphemeralCredentialBroker
from agent_platform.infrastructure.memory_store import InMemoryPlatformStore
from agent_platform.tools.catalog import build_reference_registry
from agent_platform.tools.gateway import ToolGateway
from agent_platform.tools.policy import BuiltinPolicyEngine


def contract(*, with_action: bool = False) -> TaskContract:
    capabilities = {"knowledge.search", "artifact.create"}
    if with_action:
        capabilities.add("email.prepare")
    return TaskContract(
        goal="Compare SG and JP markets with evidence",
        success_criteria=[
            SuccessCriterion(
                id="sc-1",
                description="Claims cite evidence",
                severity="must",
                verification="evidence",
                evidence_required=True,
            )
        ],
        principal=Principal(
            user_id="user-1",
            tenant_id="tenant-a",
            roles={"analyst"},
            scopes={"knowledge:read", "email:prepare"},
            auth_strength="mfa",
        ),
        data_scope=DataScope(
            tenant_id="tenant-a",
            resource_types={"knowledge", "artifact", "email"},
            classifications={
                DataClassification.PUBLIC,
                DataClassification.INTERNAL,
            },
        ),
        risk=RiskLevel.HIGH if with_action else RiskLevel.MEDIUM,
        allowed_capabilities=capabilities,
        constraints={
            "markets": ["SG", "JP"],
            "recipients": ["leader@example.test"],
        },
        max_cost_usd=Decimal("5"),
        max_duration_seconds=300,
        max_parallelism=2,
        max_replans=2,
        external_write_policy="approval" if with_action else "deny",
    )


def runtime_context(value: TaskContract) -> tuple[RuntimeExecutionContext, InMemoryPlatformStore]:
    store = InMemoryPlatformStore()
    registry = build_reference_registry()
    gateway = ToolGateway(
        registry,
        BuiltinPolicyEngine(),
        EphemeralCredentialBroker(),
        store.actions,
        store.artifacts,
    )
    return (
        RuntimeExecutionContext(
            run_id=uuid4(),
            contract=value,
            correlation_id="corr-1",
            gateway=gateway,
            artifact_store=store.artifacts,
        ),
        store,
    )


@pytest.mark.asyncio
async def test_runtime_generates_valid_parallel_dag_and_source_backed_outputs() -> None:
    value = contract()
    context, store = runtime_context(value)
    runtime = DeterministicAgentRuntime()
    plan = await runtime.plan(context, value)

    assert plan.parallel_width() == 2
    assert plan.final_task_id == "synthesize_report"
    outputs: dict[str, WorkerOutput] = {}
    for task in plan.tasks:
        if set(task.depends_on) <= set(outputs):
            outputs[task.id] = await runtime.execute_task(
                context, task, {dep: outputs[dep] for dep in task.depends_on}
            )
    final_task = next(item for item in plan.tasks if item.id == plan.final_task_id)
    if final_task.id not in outputs:
        outputs[final_task.id] = await runtime.execute_task(
            context,
            final_task,
            {dep: outputs[dep] for dep in final_task.depends_on},
        )
    report = await runtime.verify(context, value, plan, outputs)

    assert report.verdict == "pass"
    assert outputs["synthesize_report"].claims
    assert outputs["synthesize_report"].evidence
    artifact_id = outputs["synthesize_report"].artifacts[0]
    artifact = await store.artifacts.get(artifact_id, "tenant-a")
    assert artifact.scan_status == "trusted_generated"
    assert artifact.scan_provenance["trusted_generated"]["source"] == "deterministic_runtime"


@pytest.mark.asyncio
async def test_action_task_only_prepares_and_requires_human_approval() -> None:
    value = contract(with_action=True)
    context, store = runtime_context(value)
    runtime = DeterministicAgentRuntime()
    plan = await runtime.plan(context, value)
    assert plan.final_task_id == "prepare_email"

    outputs: dict[str, WorkerOutput] = {}
    pending = list(plan.tasks)
    while pending:
        ready = [task for task in pending if set(task.depends_on) <= set(outputs)]
        for task in ready:
            outputs[task.id] = await runtime.execute_task(
                context, task, {dep: outputs[dep] for dep in task.depends_on}
            )
            pending.remove(task)

    actions = await store.actions.list_for_run(context.run_id, "tenant-a")
    assert len(actions) == 1
    assert actions[0].status.value == "pending_approval"
    assert outputs["prepare_email"].action_proposals
