from __future__ import annotations

import asyncio
from decimal import Decimal

import pytest

from agent_platform.agents.deterministic_runtime import DeterministicAgentRuntime
from agent_platform.api.schemas import (
    BudgetRequest,
    CreateRunRequest,
    RequestedOutput,
    SuccessCriterionRequest,
)
from agent_platform.application.action_service import ActionService
from agent_platform.application.commit_service import CommitService
from agent_platform.application.run_service import RunService
from agent_platform.domain.enums import RunStatus
from agent_platform.domain.models import DataScope, Principal
from agent_platform.infrastructure.credentials import EphemeralCredentialBroker
from agent_platform.infrastructure.memory_store import InMemoryPlatformStore
from agent_platform.tools.catalog import build_reference_registry
from agent_platform.tools.gateway import ToolGateway
from agent_platform.tools.policy import BuiltinPolicyEngine
from agent_platform.workflows.inline import InlineWorkflowStarter


def principal(*, user_id: str = "requester", roles: set[str] | None = None) -> Principal:
    return Principal(
        user_id=user_id,
        tenant_id="tenant-a",
        roles=roles or {"analyst"},
        scopes={
            "runs:create",
            "knowledge:read",
            "email:prepare",
            "actions:approve",
        },
        auth_strength="mfa",
    )


def data_scope() -> DataScope:
    return DataScope(
        tenant_id="tenant-a",
        resource_types={"knowledge", "artifact", "email"},
        classifications={"public", "internal"},
    )


def request(*, with_action: bool) -> CreateRunRequest:
    capabilities = ["knowledge.search", "artifact.create"]
    if with_action:
        capabilities.append("email.prepare")
    return CreateRunRequest(
        goal="Compare SG and JP with source-backed conclusions",
        success_criteria=[
            SuccessCriterionRequest(
                id="sc-1",
                description="Must cite accessible evidence",
                severity="must",
                verification="evidence",
            )
        ],
        allowed_capabilities=capabilities,
        constraints={
            "markets": ["SG", "JP"],
            "recipients": ["leader@example.test"],
        },
        budget=BudgetRequest(
            max_cost_usd=Decimal("5"),
            max_duration_seconds=120,
            max_tool_calls=10,
        ),
        external_write_policy="approval" if with_action else "deny",
        requested_output=RequestedOutput(format="market_report@1.0"),
    )


def services() -> tuple[
    InMemoryPlatformStore,
    RunService,
    ActionService,
    InlineWorkflowStarter,
]:
    store = InMemoryPlatformStore()
    registry = build_reference_registry()
    policy = BuiltinPolicyEngine()
    credentials = EphemeralCredentialBroker()
    gateway = ToolGateway(registry, policy, credentials, store.actions, store.artifacts)
    commit = CommitService(store.actions, store.runs, registry, policy, credentials)
    workflow = InlineWorkflowStarter(
        store=store,
        runtime=DeterministicAgentRuntime(),
        gateway=gateway,
        commit_service=commit,
    )
    run_service = RunService(store.runs, store.actions, workflow)
    workflow.bind(run_service)
    action_service = ActionService(store.actions, workflow)
    return store, run_service, action_service, workflow


@pytest.mark.asyncio
async def test_read_only_workflow_completes_with_evidence_artifact_and_events() -> None:
    store, run_service, _, workflow = services()
    run, _ = await run_service.create(
        request(with_action=False),
        principal(),
        data_scope(),
        idempotency_key="read-only-1",
        correlation_id="corr-read",
    )

    final = await workflow.wait_until_terminal(run.run_id, timeout_seconds=5)

    assert final.status == RunStatus.COMPLETED
    assert final.result.claims
    assert final.result.evidence
    assert final.result.criterion_verifications
    assert final.result.criterion_verifications[0].criterion_id == "sc-1"
    assert final.result.criterion_verifications[0].passed is True
    assert final.result.artifacts
    events = await store.runs.events_after(run.run_id, "tenant-a", 0)
    event_types = [item.event_type for item in events]
    assert "plan.created" in event_types
    assert "task.completed" in event_types
    assert event_types[-1] == "run.completed"


@pytest.mark.asyncio
async def test_action_workflow_waits_for_distinct_approval_then_commits_once() -> None:
    store, run_service, action_service, workflow = services()
    run, _ = await run_service.create(
        request(with_action=True),
        principal(),
        data_scope(),
        idempotency_key="action-1",
        correlation_id="corr-action",
    )
    for _ in range(100):
        current = await store.runs.get(run.run_id, "tenant-a")
        if current.status == RunStatus.WAITING_APPROVAL:
            break
        await asyncio.sleep(0.01)
    else:
        pytest.fail("workflow did not reach waiting_approval")
    actions = await store.actions.list_for_run(run.run_id, "tenant-a")
    assert len(actions) == 1
    action = actions[0]

    await action_service.decide(
        action.action_id,
        tenant_id="tenant-a",
        actor_id="approver",
        actor_roles=frozenset({"approver"}),
        auth_strength="phishing_resistant",
        decision="approved",
        expected_payload_hash=action.payload_hash,
        comment="approved sandbox delivery",
    )
    final = await workflow.wait_until_terminal(run.run_id, timeout_seconds=5)

    assert final.status == RunStatus.COMPLETED
    committed = await store.actions.get(action.action_id, "tenant-a")
    assert committed.status.value == "committed"
    assert committed.verification["passed"] is True
    assert len(final.result.receipts) == 1
