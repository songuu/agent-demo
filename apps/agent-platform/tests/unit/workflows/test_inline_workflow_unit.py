from __future__ import annotations

import asyncio
from decimal import Decimal
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

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
from agent_platform.application.errors import PlatformError
from agent_platform.application.run_service import RunService
from agent_platform.domain.enums import RunStatus
from agent_platform.domain.models import DataScope, Principal, VerificationReport
from agent_platform.infrastructure.credentials import EphemeralCredentialBroker
from agent_platform.infrastructure.memory_store import InMemoryPlatformStore
from agent_platform.tools.catalog import build_reference_registry
from agent_platform.tools.gateway import ToolGateway
from agent_platform.tools.policy import BuiltinPolicyEngine
from agent_platform.workflows.inline import InlineWorkflowStarter, _Checkpoint


def _principal() -> Principal:
    return Principal(
        user_id="requester",
        tenant_id="tenant-a",
        roles={"analyst"},
        scopes={
            "runs:create",
            "knowledge:read",
            "email:prepare",
            "actions:approve",
        },
        auth_strength="mfa",
    )


def _data_scope() -> DataScope:
    return DataScope(
        tenant_id="tenant-a",
        resource_types={"knowledge", "artifact", "email"},
        classifications={"public", "internal"},
    )


def _request(*, with_action: bool = False) -> CreateRunRequest:
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


def _services(
    runtime: Any | None = None,
) -> tuple[
    InMemoryPlatformStore,
    RunService,
    ActionService,
    InlineWorkflowStarter,
]:
    store = InMemoryPlatformStore()
    registry = build_reference_registry()
    policy = BuiltinPolicyEngine()
    credentials = EphemeralCredentialBroker()
    gateway = ToolGateway(
        registry,
        policy,
        credentials,
        store.actions,
        store.artifacts,
    )
    commit = CommitService(
        store.actions,
        store.runs,
        registry,
        policy,
        credentials,
    )
    workflow = InlineWorkflowStarter(
        store=store,
        runtime=runtime or DeterministicAgentRuntime(),
        gateway=gateway,
        commit_service=commit,
    )
    run_service = RunService(store.runs, store.actions, workflow)
    workflow.bind(run_service)
    return store, run_service, ActionService(store.actions, workflow), workflow


async def _wait_for_status(
    store: InMemoryPlatformStore,
    run_id: UUID,
    expected: RunStatus,
) -> Any:
    for _ in range(200):
        run = await store.runs.get(run_id, "tenant-a")
        if run.status is expected:
            return run
        await asyncio.sleep(0.005)
    pytest.fail(f"run did not reach {expected.value}")


async def _failure_reason(
    store: InMemoryPlatformStore,
    run_id: UUID,
) -> str:
    events = await store.runs.events_after(run_id, "tenant-a", 0)
    failed = next(event for event in events if event.event_type == "run.failed")
    return str(failed.payload["reason_code"])


@pytest.mark.asyncio
async def test_inline_read_only_run_persists_plan_tasks_final_artifact_and_audit() -> None:
    store, run_service, _, workflow = _services()
    run, _ = await run_service.create(
        _request(),
        _principal(),
        _data_scope(),
        idempotency_key="inline-unit-read",
        correlation_id="corr-inline-read",
    )

    final = await workflow.wait_until_terminal(run.run_id, timeout_seconds=5)

    assert final.status is RunStatus.COMPLETED
    assert final.result.claims
    assert final.result.evidence
    assert final.result.artifacts
    assert final.result.criterion_verifications[0].passed is True
    assert final.progress == 1
    audit = await store.audit.export_run(run.run_id, run.tenant_id)
    assert len(audit["plans"]) == 1
    assert all(item["status"] == "succeeded" for item in audit["task_executions"])
    completed_events = [
        event for event in audit["events"] if event["event_type"] == "task.completed"
    ]
    assert len(completed_events) == len(final.plan.tasks)


@pytest.mark.asyncio
async def test_inline_approved_action_commits_once_and_finalizes_receipt() -> None:
    store, run_service, action_service, workflow = _services()
    run, _ = await run_service.create(
        _request(with_action=True),
        _principal(),
        _data_scope(),
        idempotency_key="inline-unit-approved",
        correlation_id="corr-inline-approved",
    )
    await _wait_for_status(store, run.run_id, RunStatus.WAITING_APPROVAL)
    action = (await store.actions.list_for_run(run.run_id, run.tenant_id))[0]

    await action_service.decide(
        action.action_id,
        tenant_id=run.tenant_id,
        actor_id="approver",
        actor_roles=frozenset({"approver"}),
        auth_strength="phishing_resistant",
        decision="approved",
        expected_payload_hash=action.payload_hash,
        comment="approved bounded commit",
    )
    final = await workflow.wait_until_terminal(run.run_id, timeout_seconds=5)

    committed = await store.actions.get(action.action_id, run.tenant_id)
    assert final.status is RunStatus.COMPLETED
    assert committed.status.value == "committed"
    assert committed.receipt is not None
    assert committed.verification["passed"] is True
    assert len(final.result.receipts) == 1
    assert final.result.receipts[0].verification.passed is True


@pytest.mark.asyncio
async def test_inline_rejected_action_fails_closed_without_commit() -> None:
    store, run_service, action_service, workflow = _services()
    run, _ = await run_service.create(
        _request(with_action=True),
        _principal(),
        _data_scope(),
        idempotency_key="inline-unit-rejected",
        correlation_id="corr-inline-rejected",
    )
    await _wait_for_status(store, run.run_id, RunStatus.WAITING_APPROVAL)
    action = (await store.actions.list_for_run(run.run_id, run.tenant_id))[0]

    await action_service.decide(
        action.action_id,
        tenant_id=run.tenant_id,
        actor_id="approver",
        actor_roles=frozenset({"approver"}),
        auth_strength="phishing_resistant",
        decision="rejected",
        expected_payload_hash=action.payload_hash,
        comment="unsafe destination",
    )
    final = await workflow.wait_until_terminal(run.run_id, timeout_seconds=5)

    rejected = await store.actions.get(action.action_id, run.tenant_id)
    assert final.status is RunStatus.FAILED
    assert await _failure_reason(store, run.run_id) == "ACTION_NOT_APPROVED"
    assert rejected.status.value == "rejected"
    assert rejected.receipt is None


class _ReviseRuntime(DeterministicAgentRuntime):
    async def verify(self, *args: Any, **kwargs: Any) -> VerificationReport:
        report = await super().verify(*args, **kwargs)
        return report.model_copy(update={"verdict": "revise"})


@pytest.mark.asyncio
async def test_inline_non_pass_verification_marks_run_failed() -> None:
    store, run_service, _, workflow = _services(_ReviseRuntime())
    run, _ = await run_service.create(
        _request(),
        _principal(),
        _data_scope(),
        idempotency_key="inline-unit-revise",
        correlation_id="corr-inline-revise",
    )

    final = await workflow.wait_until_terminal(run.run_id, timeout_seconds=5)

    assert final.status is RunStatus.FAILED
    assert await _failure_reason(store, run.run_id) == "VERIFICATION_FAILED"
    assert final.result is None


class _TaskFailureRuntime(DeterministicAgentRuntime):
    async def execute_task(self, *_: Any, **__: Any) -> Any:
        raise PlatformError(
            "WORKER_DEPENDENCY_REJECTED",
            "bounded dependency rejected the task",
            retryable=False,
        )


@pytest.mark.asyncio
async def test_inline_platform_task_failure_is_audited_and_terminal() -> None:
    store, run_service, _, workflow = _services(_TaskFailureRuntime())
    run, _ = await run_service.create(
        _request(),
        _principal(),
        _data_scope(),
        idempotency_key="inline-unit-task-fail",
        correlation_id="corr-inline-task-fail",
    )

    final = await workflow.wait_until_terminal(run.run_id, timeout_seconds=5)

    assert final.status is RunStatus.FAILED
    assert await _failure_reason(store, run.run_id) == "WORKER_DEPENDENCY_REJECTED"
    audit = await store.audit.export_run(run.run_id, run.tenant_id)
    failed = [item for item in audit["task_executions"] if item["status"] == "failed"]
    assert failed
    assert {item["error_code"] for item in failed} == {"WORKER_DEPENDENCY_REJECTED"}
    assert any(event["event_type"] == "task.failed" for event in audit["events"])


class _PlanCrashRuntime(DeterministicAgentRuntime):
    async def plan(self, *_: Any, **__: Any) -> Any:
        raise RuntimeError("planner transport failed")


@pytest.mark.asyncio
async def test_inline_unexpected_dependency_failure_is_persisted_and_rethrown() -> None:
    store, run_service, _, workflow = _services(_PlanCrashRuntime())
    run, _ = await run_service.create(
        _request(),
        _principal(),
        _data_scope(),
        idempotency_key="inline-unit-plan-crash",
        correlation_id="corr-inline-plan-crash",
    )

    with pytest.raises(RuntimeError, match="planner transport failed"):
        await workflow.wait_until_terminal(run.run_id, timeout_seconds=5)

    failed = await store.runs.get(run.run_id, run.tenant_id)
    assert failed.status is RunStatus.FAILED
    assert await _failure_reason(store, run.run_id) == "DEPENDENCY_FAILURE"


@pytest.mark.asyncio
async def test_inline_control_methods_are_safe_before_start_and_start_requires_binding() -> None:
    store = InMemoryPlatformStore()
    workflow = InlineWorkflowStarter(
        store=store,
        runtime=object(),
        gateway=object(),
        commit_service=object(),
    )
    run_id = uuid4()

    with pytest.raises(RuntimeError, match="INLINE_WORKFLOW_NOT_BOUND"):
        await workflow.start(run_id, "tenant-a", "corr-unbound")

    await workflow.cancel(run_id, "tenant-a", "not started")
    await workflow.pause(run_id, "tenant-a", "not started")
    await workflow.resume(run_id, "tenant-a")
    await workflow.notify_action(uuid4(), "tenant-a", "approved")


@pytest.mark.parametrize(
    ("runtime", "error"),
    [
        (object(), "RUNTIME_AUDIT_METADATA_REQUIRED"),
        (
            SimpleNamespace(audit_metadata=lambda *_args, **_kwargs: "invalid"),
            "RUNTIME_AUDIT_METADATA_INVALID",
        ),
        (
            SimpleNamespace(
                audit_metadata=lambda *_args, **_kwargs: {
                    "model_name": "",
                    "model_settings": [],
                    "prompt_id": "",
                    "prompt_version": "",
                }
            ),
            "RUNTIME_AUDIT_METADATA_INVALID",
        ),
    ],
)
def test_inline_runtime_audit_metadata_is_fail_closed(
    runtime: Any,
    error: str,
) -> None:
    workflow = InlineWorkflowStarter(
        store=object(),
        runtime=runtime,
        gateway=object(),
        commit_service=object(),
    )

    with pytest.raises(PlatformError, match=error):
        workflow._runtime_audit_metadata(
            "worker",
            SimpleNamespace(contract=object()),
        )


@pytest.mark.asyncio
async def test_checkpoint_ignores_failure_before_task_started() -> None:
    run_id = uuid4()
    workflow = InlineWorkflowStarter(
        store=object(),
        runtime=object(),
        gateway=object(),
        commit_service=object(),
    )

    await _Checkpoint(workflow, run_id, "tenant-a").task_failed(
        SimpleNamespace(id="unknown"),
        RuntimeError("not started"),
    )


def test_inline_tenant_lookup_rejects_unknown_run() -> None:
    workflow = InlineWorkflowStarter(
        store=SimpleNamespace(runs=SimpleNamespace(_runs={})),
        runtime=object(),
        gateway=object(),
        commit_service=object(),
    )

    with pytest.raises(KeyError):
        workflow._tenant(uuid4())
