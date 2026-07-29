from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from temporalio.exceptions import ApplicationError

from agent_platform.application.errors import PlatformError
from agent_platform.application.records import ActionRecord, RunRecord
from agent_platform.application.run_service import RunService
from agent_platform.domain.enums import ActionStatus, RiskLevel, RunStatus
from agent_platform.domain.hashing import payload_hash
from agent_platform.domain.models import (
    CriterionVerification,
    DataScope,
    ExecutionPlan,
    Principal,
    SuccessCriterion,
    TaskContract,
    TaskSpec,
    VerificationReport,
    WorkerOutput,
)
from agent_platform.infrastructure.memory_store import InMemoryPlatformStore
from agent_platform.workflows.activities import ActivityDependencies, TemporalActivities


def _contract() -> TaskContract:
    return TaskContract(
        goal="Produce one schema-verified bounded result.",
        success_criteria=[
            SuccessCriterion(
                id="sc-1",
                description="The final result satisfies its schema.",
                verification="schema",
            )
        ],
        principal=Principal(
            user_id="user-1",
            tenant_id="tenant-a",
            scopes={"knowledge:read", "email:prepare"},
            auth_strength="mfa",
        ),
        data_scope=DataScope(
            tenant_id="tenant-a",
            resource_types={"knowledge", "email"},
        ),
        risk=RiskLevel.MEDIUM,
        allowed_capabilities={"knowledge.search", "email.prepare"},
        max_cost_usd=Decimal("5"),
        max_duration_seconds=120,
        max_tool_calls=5,
    )


def _plan() -> ExecutionPlan:
    task = TaskSpec(
        id="final",
        kind="analysis",
        objective="Return a bounded result.",
        output_schema="WorkerOutput@1.0",
        risk=RiskLevel.MEDIUM,
        timeout_seconds=30,
        estimated_cost_usd=Decimal("0.1"),
    )
    return ExecutionPlan(
        plan_version=1,
        tasks=[task],
        final_task_id=task.id,
        expected_total_cost_usd=task.estimated_cost_usd,
    )


def _output() -> WorkerOutput:
    return WorkerOutput(
        summary="bounded result",
        criterion_verifications=[
            CriterionVerification(
                criterion_id="sc-1",
                method="schema",
                passed=True,
                checked_at=datetime.now(UTC),
                verifier_version="activity-test@1",
            )
        ],
    )


class _Runtime:
    def __init__(self) -> None:
        self.plan_calls = 0
        self.task_calls = 0
        self.verify_calls = 0

    @staticmethod
    def audit_metadata(
        role: str,
        contract: TaskContract,
        *,
        task: TaskSpec | None = None,
        retry_count: int = 0,
    ) -> dict[str, Any]:
        del contract, task
        return {
            "model_name": f"activity-{role}-model",
            "model_settings": {"retry_count": retry_count},
            "prompt_id": f"activity-{role}",
            "prompt_version": "1.0.0",
        }

    async def plan(self, context: Any, contract: TaskContract) -> ExecutionPlan:
        del context, contract
        self.plan_calls += 1
        return _plan()

    async def execute_task(
        self,
        context: Any,
        task: TaskSpec,
        dependencies: dict[str, WorkerOutput],
    ) -> WorkerOutput:
        del context, task, dependencies
        self.task_calls += 1
        return _output()

    async def verify(
        self,
        context: Any,
        contract: TaskContract,
        plan: ExecutionPlan,
        outputs: dict[str, WorkerOutput],
    ) -> VerificationReport:
        del context, contract, plan, outputs
        self.verify_calls += 1
        return VerificationReport(verdict="pass")


async def _seed_run(
    store: InMemoryPlatformStore,
    *,
    status: RunStatus = RunStatus.RECEIVED,
    key: str = "activity-lifecycle",
) -> RunRecord:
    run_id = uuid4()
    run, _ = await store.runs.create_once(
        RunRecord(
            run_id=run_id,
            tenant_id="tenant-a",
            principal_id="user-1",
            contract=_contract(),
            idempotency_key=key,
            request_hash=payload_hash({"key": key}),
            workflow_id=f"agent-run-{run_id}",
            status=status,
        )
    )
    return run


def _activities(
    store: InMemoryPlatformStore,
    runtime: Any,
    *,
    commit_service: Any | None = None,
    commit_scopes: frozenset[str] = frozenset(),
    trajectory_guard: Any | None = None,
) -> TemporalActivities:
    run_service = RunService(
        store.runs,
        store.actions,
        SimpleNamespace(),
    )
    return TemporalActivities(
        ActivityDependencies(
            store=store,
            runtime=runtime,
            gateway=object(),
            run_service=run_service,
            commit_service=commit_service or object(),
            commit_scopes=commit_scopes,
            trajectory_guard=trajectory_guard,
        )
    )


def _payload(run: RunRecord, **values: Any) -> dict[str, Any]:
    return {
        "run_id": str(run.run_id),
        "tenant_id": run.tenant_id,
        "correlation_id": "activity-corr",
        **values,
    }


@pytest.mark.asyncio
async def test_activity_lifecycle_is_idempotent_and_persists_revised_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = InMemoryPlatformStore()
    runtime = _Runtime()
    run = await _seed_run(store)
    activities = _activities(store, runtime)
    monkeypatch.setattr(
        "agent_platform.workflows.activities.activity.heartbeat",
        lambda _: None,
    )
    base = _payload(run)

    assert await activities.classify_contract(base) == {"status": "classified"}
    assert await activities.classify_contract(base) == {"status": "classified"}
    plan_v1 = await activities.create_plan(base)
    assert await activities.create_plan(base) == plan_v1
    assert runtime.plan_calls == 1
    assert await activities.authorize_plan({**base, "plan": plan_v1}) == {"status": "authorized"}
    assert await activities.authorize_plan({**base, "plan": plan_v1}) == {"status": "authorized"}
    assert await activities.mark_executing(base) == {"status": "executing"}
    assert await activities.mark_executing(base) == {"status": "executing"}

    task_payload = {
        **base,
        "task": plan_v1["tasks"][0],
        "dependencies": {},
        "attempt": 2,
    }
    output_v1 = await activities.execute_task(task_payload)
    assert await activities.execute_task(task_payload) == output_v1
    assert runtime.task_calls == 1
    report = await activities.verify_run({**base, "plan": plan_v1, "outputs": {"final": output_v1}})
    assert report["verdict"] == "pass"

    plan_v2 = await activities.revise_plan(
        {
            **base,
            "plan": plan_v1,
            "report": {
                "verdict": "revise",
                "repair_instructions": ["tighten schema validation"],
            },
            "replan_count": 1,
        }
    )
    assert plan_v2["plan_version"] == 2
    assert (
        await activities.revise_plan(
            {
                **base,
                "plan": plan_v1,
                "report": {"verdict": "revise"},
                "replan_count": 1,
            }
        )
        == plan_v2
    )
    assert runtime.plan_calls == 2

    assert await activities.mark_executing(base) == {"status": "executing"}
    task_v2 = {**task_payload, "task": plan_v2["tasks"][0]}
    output_v2 = await activities.execute_task(task_v2)
    report_v2 = await activities.verify_run(
        {**base, "plan": plan_v2, "outputs": {"final": output_v2}}
    )
    assert report_v2["verdict"] == "pass"
    assert await activities.list_actions(base) == []

    finalized = await activities.finalize_run(
        {
            **base,
            "plan": plan_v2,
            "outputs": {"final": output_v2},
            "report": report_v2,
        }
    )
    assert finalized == {"status": "completed"}
    assert await activities.finalize_run(
        {
            **base,
            "plan": plan_v2,
            "outputs": {"final": output_v2},
            "report": report_v2,
        }
    ) == {"status": "completed"}

    saved = await store.runs.get(run.run_id, run.tenant_id)
    audit = await store.audit.export_run(run.run_id, run.tenant_id)
    assert saved.status is RunStatus.COMPLETED
    assert saved.current_plan_version == 2
    assert saved.result.summary == "bounded result"
    assert len(audit["plans"]) == 2
    assert [item["plan_version"] for item in audit["plans"]] == [1, 2]
    assert len(audit["task_executions"]) == 2


def _action(run: RunRecord, *, key: str, status: ActionStatus) -> ActionRecord:
    return ActionRecord(
        action_id=uuid4(),
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        principal_id=run.principal_id,
        action_type="email.prepare",
        tool_name="email.prepare",
        tool_version="1.0.0",
        canonical_payload={"subject": key},
        payload_hash=payload_hash({"subject": key}),
        preview={"subject": key},
        risk=RiskLevel.HIGH,
        approval_policy="human",
        required_approvals=1,
        idempotency_key=key,
        policy_version="builtin-1",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        status=status,
    )


@pytest.mark.asyncio
async def test_action_listing_expiration_and_commit_use_worker_owned_scope() -> None:
    store = InMemoryPlatformStore()
    run = await _seed_run(
        store,
        status=RunStatus.VERIFYING,
        key="activity-actions",
    )
    pending, _ = await store.actions.create_once(
        _action(run, key="pending-action", status=ActionStatus.PENDING_APPROVAL)
    )
    approved, _ = await store.actions.create_once(
        _action(run, key="approved-action", status=ActionStatus.APPROVED)
    )
    commit_calls: list[dict[str, Any]] = []

    class _Commit:
        async def commit(self, **kwargs: Any) -> dict[str, Any]:
            commit_calls.append(kwargs)
            return {"action_id": str(kwargs["action_id"]), "committed": True}

    activities = _activities(
        store,
        _Runtime(),
        commit_service=_Commit(),
        commit_scopes=frozenset({"business:commit"}),
    )
    base = _payload(run)

    listed = await activities.list_actions(base)
    assert {item["action_id"] for item in listed} == {
        str(pending.action_id),
        str(approved.action_id),
    }
    assert await activities.mark_waiting_approval(base) == {"status": "waiting_approval"}
    assert await activities.expire_actions(base) == {
        "expired": 1,
        "statuses": {
            str(pending.action_id): "expired",
            str(approved.action_id): "approved",
        },
    }
    assert await activities.expire_actions(base) == {
        "expired": 0,
        "statuses": {
            str(pending.action_id): "expired",
            str(approved.action_id): "approved",
        },
    }
    assert (
        await store.actions.get(pending.action_id, run.tenant_id)
    ).status is ActionStatus.EXPIRED
    expired_events = [
        event
        for event in await store.runs.events_after(run.run_id, run.tenant_id, 0)
        if event.event_type == "action.expired"
    ]
    assert len(expired_events) == 1
    assert expired_events[0].action_id == pending.action_id
    assert expired_events[0].payload == {
        "run_id": str(run.run_id),
        "action_id": str(pending.action_id),
        "payload_hash": pending.payload_hash,
        "previous_status": "pending_approval",
        "scheduled_expires_at": pending.expires_at.isoformat(),
        "expired_at": expired_events[0].payload["expired_at"],
        "reason": "workflow_approval_timeout",
    }
    assert (
        await store.actions.get(approved.action_id, run.tenant_id)
    ).status is ActionStatus.APPROVED

    result = await activities.commit_action({**base, "action_id": str(approved.action_id)})

    assert result["committed"] is True
    assert commit_calls[0]["principal_id"] == "commit-worker"
    assert commit_calls[0]["principal_scopes"] == frozenset({"business:commit"})
    assert (await store.runs.get(run.run_id, run.tenant_id)).status is RunStatus.COMMITTING


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status",
    [
        RunStatus.COMPLETED,
        RunStatus.FAILED,
        RunStatus.CANCELLED,
        RunStatus.EXECUTING,
    ],
)
async def test_commit_action_rejects_runs_outside_the_commit_gate(status: RunStatus) -> None:
    store = InMemoryPlatformStore()
    run = await _seed_run(
        store,
        status=status,
        key=f"activity-commit-gate-{status.value}",
    )
    action, _ = await store.actions.create_once(
        _action(run, key=f"action-{status.value}", status=ActionStatus.APPROVED)
    )
    commit_calls: list[dict[str, Any]] = []

    class _Commit:
        async def commit(self, **kwargs: Any) -> dict[str, Any]:
            commit_calls.append(kwargs)
            return {"committed": True}

    activities = _activities(store, _Runtime(), commit_service=_Commit())

    with pytest.raises(ApplicationError) as error:
        await activities.commit_action(
            {
                **_payload(run),
                "action_id": str(action.action_id),
            }
        )

    assert error.value.type == "RUN_NOT_COMMITTABLE"
    assert commit_calls == []


@pytest.mark.asyncio
async def test_cancel_and_fail_activities_are_idempotent_terminal_transitions() -> None:
    store = InMemoryPlatformStore()
    cancel_run = await _seed_run(
        store,
        status=RunStatus.EXECUTING,
        key="activity-cancel",
    )
    fail_run = await _seed_run(
        store,
        status=RunStatus.VERIFYING,
        key="activity-fail",
    )
    activities = _activities(store, _Runtime())

    assert await activities.cancel_run(_payload(cancel_run, reason="operator cancelled")) == {
        "status": "cancelled"
    }
    assert await activities.cancel_run(_payload(cancel_run)) == {"status": "cancelled"}
    assert await activities.fail_run(_payload(fail_run)) == {
        "status": "failed",
        "reason": "DEPENDENCY_FAILURE",
    }
    assert await activities.fail_run(_payload(fail_run, reason="ignored")) == {
        "status": "failed",
        "reason": "ignored",
    }
    assert (
        await store.runs.get(cancel_run.run_id, cancel_run.tenant_id)
    ).status is RunStatus.CANCELLED
    assert (await store.runs.get(fail_run.run_id, fail_run.tenant_id)).status is RunStatus.FAILED


@pytest.mark.asyncio
async def test_finalize_requires_explicit_verification_pass() -> None:
    store = InMemoryPlatformStore()
    run = await _seed_run(
        store,
        status=RunStatus.VERIFYING,
        key="activity-finalize-fail",
    )
    activities = _activities(store, _Runtime())

    with pytest.raises(ApplicationError) as error:
        await activities.finalize_run(
            {
                **_payload(run),
                "plan": _plan().model_dump(mode="json"),
                "outputs": {"final": _output().model_dump(mode="json")},
                "report": {"verdict": "revise"},
            }
        )

    assert error.value.type == "FINALIZATION_REQUIRES_VERIFICATION_PASS"


@pytest.mark.asyncio
async def test_runtime_failure_records_trajectory_outcome_and_propagates() -> None:
    store = InMemoryPlatformStore()
    run = await _seed_run(
        store,
        status=RunStatus.EXECUTING,
        key="activity-trajectory-fail",
    )
    check = object()

    class _Guard:
        def __init__(self) -> None:
            self.outcomes: list[dict[str, Any]] = []

        async def preflight(self, **_: Any) -> Any:
            return check

        async def record_outcome(
            self,
            candidate: Any,
            **outcome: Any,
        ) -> None:
            assert candidate is check
            self.outcomes.append(outcome)

    guard = _Guard()
    activities = _activities(store, _Runtime(), trajectory_guard=guard)

    async def fail(_: Any) -> None:
        raise PlatformError("MODEL_REJECTED", "model rejected request")

    with pytest.raises(PlatformError, match="MODEL_REJECTED"):
        await activities._invoke_runtime(
            _payload(run, retry_count="invalid"),
            run,
            fail,
            role="worker",
            task_id="task-1",
        )

    assert guard.outcomes == [{"status": "failed", "error_code": "MODEL_REJECTED"}]


@pytest.mark.parametrize(
    ("runtime", "error_type"),
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
def test_activity_runtime_audit_metadata_is_fail_closed(
    runtime: Any,
    error_type: str,
) -> None:
    activities = TemporalActivities(
        ActivityDependencies(
            store=object(),
            runtime=runtime,
            gateway=object(),
            run_service=object(),
            commit_service=object(),
        )
    )

    with pytest.raises(PlatformError, match=error_type):
        activities._runtime_audit_metadata(
            "worker",
            SimpleNamespace(contract=object()),
        )


def test_activity_helpers_bound_attempts_budget_and_plain_results() -> None:
    assert TemporalActivities._activity_attempt({"attempt": -2}) == 1
    assert TemporalActivities._dump({"ok": True}) == {"ok": True}
    assert TemporalActivities._dump("value") == {"value": "value"}
    assert TemporalActivities._budget_utilization(
        cost_usd=Decimal("0"),
        max_cost_usd=Decimal("5"),
        tool_calls=1,
        max_tool_calls=0,
    ) == Decimal("1")
    assert TemporalActivities._budget_utilization(
        cost_usd=Decimal("0"),
        max_cost_usd=Decimal("5"),
        tool_calls=0,
        max_tool_calls=0,
    ) == Decimal("0")
    assert TemporalActivities._decimal_string(Decimal("0.8000")) == "0.8"
