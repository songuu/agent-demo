from __future__ import annotations

from collections import deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from decimal import Decimal
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from agent_platform.application.errors import Conflict, NotFound
from agent_platform.application.records import (
    AuditEvent,
    EventRecord,
    PlanExecutionRecord,
    RunRecord,
    TaskExecutionRecord,
    ToolInvocationRecord,
)
from agent_platform.domain.enums import (
    ActionStatus,
    RiskLevel,
    RunStatus,
    ToolEffect,
)
from agent_platform.domain.models import (
    DataScope,
    Principal,
    SuccessCriterion,
    TaskContract,
)
from agent_platform.infrastructure.persistence import audit
from agent_platform.infrastructure.persistence.audit import (
    PostgresAuditRepository,
    _json_value,
    _unwrapped_json,
    append_tool_invocation,
)
from agent_platform.infrastructure.persistence.models import (
    ApprovalDecision,
    TaskStatus,
)


class _Rows:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return self._rows


class _Session:
    def __init__(
        self,
        *,
        scalar_results: list[Any] | None = None,
        scalars_results: list[list[Any]] | None = None,
    ) -> None:
        self.scalar_results = deque(scalar_results or [])
        self.scalars_results = deque(scalars_results or [])
        self.commits = 0

    async def scalar(self, _statement: Any) -> Any:
        if not self.scalar_results:
            raise AssertionError("unexpected scalar query")
        return self.scalar_results.popleft()

    async def scalars(self, _statement: Any) -> _Rows:
        if not self.scalars_results:
            raise AssertionError("unexpected scalars query")
        return _Rows(self.scalars_results.popleft())

    async def commit(self) -> None:
        self.commits += 1


def _patch_session(monkeypatch: pytest.MonkeyPatch, session: _Session) -> None:
    @asynccontextmanager
    async def fake_tenant_session(
        _factory: Any,
        tenant_id: str,
    ) -> AsyncIterator[_Session]:
        assert tenant_id == "tenant-a"
        yield session

    monkeypatch.setattr(audit, "tenant_session", fake_tenant_session)


def _contract() -> TaskContract:
    return TaskContract(
        goal="Export an audit record",
        success_criteria=[
            SuccessCriterion(
                id="traceable",
                description="Every effect is traceable",
                verification="environment",
            )
        ],
        principal=Principal(
            user_id="user-1",
            tenant_id="tenant-a",
            auth_strength="mfa",
        ),
        data_scope=DataScope(
            tenant_id="tenant-a",
            resource_types=frozenset({"documents"}),
        ),
        risk=RiskLevel.HIGH,
        max_cost_usd=Decimal("5"),
        max_duration_seconds=300,
    )


def _run() -> RunRecord:
    now = datetime.now(UTC)
    return RunRecord(
        run_id=uuid4(),
        tenant_id="tenant-a",
        principal_id="user-1",
        contract=_contract(),
        idempotency_key=f"run-{uuid4()}",
        request_hash="a" * 64,
        workflow_id=f"workflow-{uuid4()}",
        status=RunStatus.EXECUTING,
        current_plan_version=1,
        version=3,
        created_at=now,
        updated_at=now,
    )


def _task(run: RunRecord, *, status: str = "running") -> TaskExecutionRecord:
    now = datetime.now(UTC)
    return TaskExecutionRecord(
        task_execution_id=uuid4(),
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        plan_version=1,
        task_id="analyze",
        task_kind="analysis",
        attempt=1,
        status=status,
        model_name="gpt-5.6-terra",
        model_settings={"reasoning": "medium"},
        prompt_id="worker",
        prompt_version="1.0.0",
        input_refs=[{"artifact_id": "input-1"}],
        output_json={"summary": "done"} if status == "succeeded" else None,
        usage_json={"input_tokens": 10, "output_tokens": 5},
        started_at=now,
        completed_at=now if status == "succeeded" else None,
        created_at=now,
    )


def _tool(run: RunRecord) -> ToolInvocationRecord:
    now = datetime.now(UTC)
    return ToolInvocationRecord(
        invocation_id=uuid4(),
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        plan_version=1,
        task_id="analyze",
        tool_name="knowledge.search",
        tool_version="1.0.0",
        effect=ToolEffect.READ,
        args_hash="1" * 64,
        args_redacted={"query": "bounded"},
        data_scope_hash="2" * 64,
        policy_decision_id="decision-1",
        policy_version="bundle-7",
        status="succeeded",
        result_hash="3" * 64,
        latency_ms=12,
        provider_request_id="provider-1",
        created_at=now,
        completed_at=now,
    )


def _event(run: RunRecord, event_type: str) -> AuditEvent:
    return AuditEvent(
        event_type=event_type,
        payload={"run_id": str(run.run_id)},
        correlation_id=f"correlation-{event_type}",
        actor_type="runtime",
        actor_id="worker-1",
        task_id="analyze",
    )


def _event_record(run: RunRecord, event_type: str) -> EventRecord:
    return EventRecord(
        event_id="1",
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        sequence_no=1,
        event_type=event_type,
        payload={"run_id": str(run.run_id)},
        correlation_id=f"correlation-{event_type}",
    )


def test_audit_json_compatibility_helpers_preserve_plain_values() -> None:
    assert _json_value({"amount": Decimal("1.20")}) == {"amount": "1.20"}
    assert _unwrapped_json(None) is None
    assert _unwrapped_json({"kind": "json", "value": {"ok": True}}) == {"ok": True}
    assert _unwrapped_json({"legacy": True}) == {"legacy": True}


@pytest.mark.asyncio
async def test_append_tool_invocation_reports_insert_and_duplicate() -> None:
    run = _run()
    invocation = _tool(run)
    assert (
        await append_tool_invocation(
            cast(Any, _Session(scalar_results=[invocation.invocation_id])),
            invocation,
        )
        is True
    )
    assert (
        await append_tool_invocation(
            cast(Any, _Session(scalar_results=[None])),
            invocation,
        )
        is False
    )


@pytest.mark.asyncio
async def test_plan_save_accepts_idempotent_hash_and_rejects_version_reuse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _run()
    now = datetime.now(UTC)
    plan = PlanExecutionRecord(
        plan_id=uuid4(),
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        plan_version=1,
        schema_version="1.0",
        plan_json={"tasks": [{"id": "analyze"}]},
        plan_hash="b" * 64,
        planner_model="gpt-5.6-sol",
        prompt_id="planner",
        prompt_version="1.0.0",
        created_at=now,
    )
    recorded = _event_record(run, "plan.created")
    runs = SimpleNamespace(
        _save_in_session=AsyncMock(return_value=run),
        _append_event_in_session=AsyncMock(return_value=recorded),
    )
    repository = PostgresAuditRepository(cast(Any, object()), runs)

    created = _Session(scalar_results=[plan.plan_id])
    _patch_session(monkeypatch, created)
    assert await repository.save_plan_with_run(
        run,
        3,
        plan,
        _event(run, "plan.created"),
    ) == (run, recorded)
    assert created.commits == 1

    duplicate = _Session(scalar_results=[None, plan.plan_hash])
    _patch_session(monkeypatch, duplicate)
    assert await repository.save_plan_with_run(
        run,
        3,
        plan,
        _event(run, "plan.created"),
    ) == (run, recorded)

    conflict = _Session(scalar_results=[None, "different"])
    _patch_session(monkeypatch, conflict)
    with pytest.raises(Conflict) as reused:
        await repository.save_plan_with_run(
            run,
            3,
            plan,
            _event(run, "plan.created"),
        )
    assert reused.value.code == "PLAN_VERSION_CONFLICT"


@pytest.mark.asyncio
async def test_task_start_is_idempotent_and_records_only_new_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _run()
    execution = _task(run)
    recorded = _event_record(run, "task.started")
    runs = SimpleNamespace(
        _require_run=AsyncMock(),
        _get_in_session=AsyncMock(return_value=run),
        _append_event_in_session=AsyncMock(return_value=recorded),
    )
    repository = PostgresAuditRepository(cast(Any, object()), runs)

    inserted = _Session(scalar_results=[execution.task_execution_id])
    _patch_session(monkeypatch, inserted)
    assert await repository.start_task(execution, _event(run, "task.started")) is recorded
    assert inserted.commits == 1

    duplicate = _Session(scalar_results=[None])
    _patch_session(monkeypatch, duplicate)
    assert await repository.start_task(execution, _event(run, "task.started")) is None
    assert duplicate.commits == 1
    assert runs._get_in_session.await_count == 1


@pytest.mark.asyncio
async def test_task_completion_and_finish_update_snapshot_before_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _run()
    execution = _task(run, status="succeeded")
    completed = _event_record(run, "task.completed")
    runs = SimpleNamespace(
        _save_in_session=AsyncMock(return_value=run),
        _require_run=AsyncMock(),
        _get_in_session=AsyncMock(return_value=run),
        _append_event_in_session=AsyncMock(return_value=completed),
    )
    repository = PostgresAuditRepository(cast(Any, object()), runs)
    update_task = AsyncMock()
    monkeypatch.setattr(repository, "_update_task", update_task)

    complete_session = _Session()
    _patch_session(monkeypatch, complete_session)
    assert await repository.complete_task_with_run(
        run,
        3,
        execution,
        _event(run, "task.completed"),
    ) == (run, completed)

    finish_session = _Session()
    _patch_session(monkeypatch, finish_session)
    assert (
        await repository.finish_task(
            execution,
            _event(run, "task.completed"),
        )
        is completed
    )
    assert update_task.await_count == 2
    assert complete_session.commits == finish_session.commits == 1


@pytest.mark.asyncio
async def test_tool_record_rejects_duplicate_identity_and_commits_new_fact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _run()
    invocation = _tool(run)
    recorded = _event_record(run, "tool.completed")
    runs = SimpleNamespace(
        _get_in_session=AsyncMock(return_value=run),
        _append_event_in_session=AsyncMock(return_value=recorded),
    )
    repository = PostgresAuditRepository(cast(Any, object()), runs)
    append = AsyncMock(side_effect=[False, True])
    monkeypatch.setattr(audit, "append_tool_invocation", append)

    duplicate = _Session()
    _patch_session(monkeypatch, duplicate)
    with pytest.raises(Conflict) as conflict:
        await repository.record_tool(invocation, _event(run, "tool.completed"))
    assert conflict.value.code == "TOOL_INVOCATION_CONFLICT"

    inserted = _Session()
    _patch_session(monkeypatch, inserted)
    assert (
        await repository.record_tool(
            invocation,
            _event(run, "tool.completed"),
        )
        is recorded
    )
    assert inserted.commits == 1


def _export_rows(run: RunRecord) -> list[list[Any]]:
    now = datetime.now(UTC)
    receipt_id = uuid4()
    action_id = uuid4()
    plan = SimpleNamespace(
        plan_id=uuid4(),
        plan_version=1,
        schema_version="1.0",
        plan_json={"tasks": []},
        plan_hash="1" * 64,
        planner_model="gpt-5.6-sol",
        prompt_id="planner",
        prompt_version="1.0.0",
        validation_status="validated",
        created_at=now,
    )
    task = SimpleNamespace(
        task_execution_id=uuid4(),
        plan_version=1,
        task_id="analyze",
        task_kind="analysis",
        attempt=1,
        status=TaskStatus.SUCCEEDED,
        model_name="gpt-5.6-terra",
        model_settings={"reasoning": "medium"},
        prompt_id="worker",
        prompt_version="1.0.0",
        input_refs=[],
        output_json={"summary": "done"},
        output_artifact_id=uuid4(),
        error_code=None,
        usage_json={"input_tokens": 10},
        started_at=now,
        completed_at=now,
    )
    tool = SimpleNamespace(
        invocation_id=uuid4(),
        plan_version=1,
        task_id="analyze",
        tool_name="knowledge.search",
        tool_version="1.0.0",
        effect=ToolEffect.READ,
        args_hash="2" * 64,
        args_redacted={},
        data_scope_hash="3" * 64,
        policy_decision_id="decision-1",
        policy_version="bundle-7",
        status="succeeded",
        result_hash="4" * 64,
        result_artifact_id=uuid4(),
        error_code=None,
        latency_ms=10,
        provider_request_id="provider-1",
        created_at=now,
        completed_at=now,
    )
    action = SimpleNamespace(
        action_id=action_id,
        action_type="email.send",
        tool_name="email.commit",
        tool_version="1.0.0",
        payload_hash="5" * 64,
        preview_json={"summary": "send"},
        risk=RiskLevel.HIGH,
        approval_policy="two-person",
        required_approvals=2,
        status=ActionStatus.COMMITTED,
        idempotency_key="email-1",
        policy_version="bundle-7",
        receipt_json={"kind": "json", "value": {"provider": "mail"}},
        receipt_artifact_id=receipt_id,
        verification_json={"kind": "json", "value": {"passed": True}},
        failure_code=None,
        created_at=now,
        updated_at=now,
    )
    approval = SimpleNamespace(
        approval_id=uuid4(),
        action_id=action_id,
        actor_id="approver-1",
        actor_roles=["approver"],
        auth_strength="mfa",
        decision=ApprovalDecision.APPROVED,
        payload_hash="5" * 64,
        comment="approved",
        policy_version="bundle-7",
        created_at=now,
    )
    artifact = SimpleNamespace(
        artifact_id=receipt_id,
        task_id="analyze",
        kind="receipt",
        uri="s3://artifacts/receipt",
        media_type="application/json",
        size_bytes=20,
        sha256="6" * 64,
        classification="internal",
        source_json={"scanner": "clamav"},
        created_by="commit-worker",
        retention_policy="default",
        expires_at=now,
        deleted_at=now,
        created_at=now,
    )
    event = SimpleNamespace(
        sequence_no=1,
        event_type="action.committed",
        schema_version="1.0",
        actor_type="commit-worker",
        actor_id="commit-worker",
        task_id="analyze",
        action_id=action_id,
        payload={"action_id": str(action_id)},
        payload_hash="7" * 64,
        correlation_id="correlation-commit",
        created_at=now,
    )
    return [[plan], [task], [tool], [action], [approval], [artifact], [event]]


@pytest.mark.asyncio
async def test_export_run_materializes_complete_cross_table_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _run()
    session = _Session(scalars_results=_export_rows(run))
    _patch_session(monkeypatch, session)
    repository = PostgresAuditRepository(
        cast(Any, object()),
        SimpleNamespace(_get_in_session=AsyncMock(return_value=run)),
    )

    exported = await repository.export_run(run.run_id, run.tenant_id)

    assert exported["contract"]["goal"] == run.contract.goal
    assert exported["plans"][0]["planner_model"] == "gpt-5.6-sol"
    assert exported["task_executions"][0]["output"]["summary"] == "done"
    assert exported["tool_invocations"][0]["provider_request_id"] == "provider-1"
    assert exported["actions"][0]["approvals"][0]["actor_id"] == "approver-1"
    assert exported["actions"][0]["receipt"] == {"provider": "mail"}
    assert exported["artifacts"][0]["created_by"] == "commit-worker"
    assert exported["events"][0]["event_type"] == "action.committed"


@pytest.mark.asyncio
async def test_task_update_requires_existing_execution() -> None:
    run = _run()
    execution = _task(run, status="succeeded")
    values = PostgresAuditRepository._task_values(execution)
    assert values["status"] is TaskStatus.SUCCEEDED
    assert values["model_settings"] == {"reasoning": "medium"}
    assert values["output_json"] == {"summary": "done"}

    await PostgresAuditRepository._update_task(
        cast(Any, _Session(scalar_results=[execution.task_execution_id])),
        execution,
    )
    with pytest.raises(NotFound):
        await PostgresAuditRepository._update_task(
            cast(Any, _Session(scalar_results=[None])),
            execution,
        )
