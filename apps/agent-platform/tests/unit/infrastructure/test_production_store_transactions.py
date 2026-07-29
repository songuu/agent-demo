from __future__ import annotations

from collections import deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from agent_platform.application.errors import Conflict, NotFound
from agent_platform.application.records import (
    ActionRecord,
    AuditEvent,
    EventRecord,
    RunRecord,
    ToolInvocationRecord,
)
from agent_platform.domain.enums import ActionStatus, RiskLevel, RunStatus, ToolEffect
from agent_platform.domain.models import (
    DataScope,
    Principal,
    SuccessCriterion,
    TaskContract,
)
from agent_platform.infrastructure.persistence import production_store
from agent_platform.infrastructure.persistence.models import (
    AgentRun,
    PreparedAction,
    RunEvent,
)
from agent_platform.infrastructure.persistence.production_store import (
    AesGcmActionPayloadCipher,
    PostgresActionRepository,
    PostgresRunRepository,
)
from agent_platform.infrastructure.persistence.runtime_models import RunRuntimeSnapshot


class _Rows:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return self._rows


class _Result:
    def __init__(self, value: Any) -> None:
        self._value = value

    def one_or_none(self) -> Any:
        return self._value


class _Session:
    def __init__(
        self,
        *,
        scalar_results: list[Any] | None = None,
        execute_results: list[Any] | None = None,
        scalars_results: list[list[Any]] | None = None,
    ) -> None:
        self.scalar_results = deque(scalar_results or [])
        self.execute_results = deque(execute_results or [])
        self.scalars_results = deque(scalars_results or [])
        self.commits = 0

    async def scalar(self, _statement: Any) -> Any:
        if not self.scalar_results:
            raise AssertionError("unexpected scalar query")
        return self.scalar_results.popleft()

    async def execute(self, _statement: Any, _parameters: Any = None) -> _Result:
        value = self.execute_results.popleft() if self.execute_results else None
        return value if isinstance(value, _Result) else _Result(value)

    async def scalars(self, _statement: Any) -> _Rows:
        if not self.scalars_results:
            raise AssertionError("unexpected scalars query")
        return _Rows(self.scalars_results.popleft())

    async def commit(self) -> None:
        self.commits += 1

    async def flush(self) -> None:
        return None


def _patch_sessions(monkeypatch: pytest.MonkeyPatch, *sessions: _Session) -> None:
    queued = deque(sessions)

    @asynccontextmanager
    async def fake_tenant_session(
        _factory: Any,
        tenant_id: str,
    ) -> AsyncIterator[_Session]:
        assert tenant_id
        yield queued.popleft()

    monkeypatch.setattr(production_store, "tenant_session", fake_tenant_session)


def _contract() -> TaskContract:
    return TaskContract(
        goal="Exercise transaction behavior",
        success_criteria=[
            SuccessCriterion(
                id="transactional",
                description="Writes are atomic",
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
        risk=RiskLevel.MEDIUM,
        max_cost_usd=Decimal("5"),
        max_duration_seconds=300,
    )


def _run(*, status: RunStatus = RunStatus.EXECUTING) -> RunRecord:
    now = datetime.now(UTC)
    return RunRecord(
        run_id=uuid4(),
        tenant_id="tenant-a",
        principal_id="user-1",
        contract=_contract(),
        idempotency_key=f"run-{uuid4()}",
        request_hash="a" * 64,
        workflow_id=f"workflow-{uuid4()}",
        status=status,
        version=2,
        created_at=now,
        updated_at=now,
    )


def _action(run: RunRecord) -> ActionRecord:
    now = datetime.now(UTC)
    return ActionRecord(
        action_id=uuid4(),
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        principal_id=run.principal_id,
        action_type="email.send",
        tool_name="email.prepare",
        tool_version="1.0.0",
        canonical_payload={"to": "reviewer@example.test"},
        payload_hash="b" * 64,
        preview={"summary": "send"},
        risk=RiskLevel.HIGH,
        approval_policy="two-person",
        required_approvals=2,
        idempotency_key=f"action-{uuid4()}",
        policy_version="bundle-7",
        expires_at=now + timedelta(minutes=10),
        created_at=now,
        updated_at=now,
    )


def _event_row(
    run: RunRecord, sequence_no: int, event_type: str, payload: dict[str, Any]
) -> RunEvent:
    return RunEvent(
        event_id=sequence_no,
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        sequence_no=sequence_no,
        event_type=event_type,
        schema_version="1.0",
        actor_type="application",
        actor_id=run.principal_id,
        task_id=None,
        action_id=None,
        correlation_id=f"correlation-{sequence_no}",
        payload=payload,
        payload_hash=str(sequence_no) * 64,
        created_at=datetime.now(UTC),
    )


def _invocation(run: RunRecord) -> ToolInvocationRecord:
    return ToolInvocationRecord(
        invocation_id=uuid4(),
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        plan_version=1,
        task_id="analyze",
        tool_name="email.prepare",
        tool_version="1.0.0",
        effect=ToolEffect.PREPARE,
        args_hash="1" * 64,
        data_scope_hash="2" * 64,
        policy_decision_id="decision-1",
        policy_version="bundle-7",
        status="succeeded",
    )


def _database_run(run: RunRecord) -> AgentRun:
    return AgentRun(
        **PostgresRunRepository._insert_values(run, cast(TaskContract, run.contract)),
        version=run.version,
    )


@pytest.mark.asyncio
async def test_run_history_and_trajectory_transaction_use_ordered_immutable_events(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _run()
    first = _event_row(run, 1, "run.created", {})
    second = _event_row(run, 2, "trajectory.decision", {"decision": "continue"})
    history_session = _Session(scalars_results=[[first, second]])
    trajectory_session = _Session(scalars_results=[[first, second]])
    _patch_sessions(monkeypatch, history_session, trajectory_session)
    repository = PostgresRunRepository(cast(Any, object()))
    require = AsyncMock()
    get = AsyncMock(return_value=run)
    monkeypatch.setattr(repository, "_require_run", require)
    monkeypatch.setattr(repository, "_get_in_session", get)

    events = await repository.events_after(run.run_id, run.tenant_id, 0)
    assert [event.sequence_no for event in events] == [1, 2]

    async with repository.trajectory_transaction(run.run_id, run.tenant_id) as transaction:
        assert transaction.run is run
        assert [event.sequence_no for event in transaction.events] == [1, 2]
    assert trajectory_session.commits == 1
    assert require.await_args_list[-1].kwargs == {"lock": True}


@pytest.mark.asyncio
async def test_pause_origin_rebuild_ignores_invalid_and_nested_pause_events() -> None:
    run = _run(status=RunStatus.PAUSED)
    invalid = _event_row(
        run,
        4,
        "trajectory.decision",
        {"run_status": "paused", "paused_from": "not-a-status"},
    )
    nested_pause = _event_row(
        run,
        3,
        "run.status_changed",
        {"to": "paused", "from": "paused"},
    )
    valid = _event_row(
        run,
        2,
        "run.status_changed",
        {"to": "paused", "from": "executing"},
    )
    irrelevant = _event_row(run, 1, "run.status_changed", {"to": "completed"})
    session = _Session(scalars_results=[[invalid, nested_pause, irrelevant, valid]])

    origin = await PostgresRunRepository._pause_origin_from_events(
        cast(Any, session),
        run.run_id,
        run.tenant_id,
    )
    assert origin is RunStatus.EXECUTING

    no_origin = await PostgresRunRepository._pause_origin_from_events(
        cast(Any, _Session(scalars_results=[[]])),
        run.run_id,
        run.tenant_id,
    )
    assert no_origin is None


@pytest.mark.asyncio
async def test_paused_run_projection_restores_origin_and_contract_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _run(status=RunStatus.PAUSED)
    database_run = _database_run(run)
    snapshot = RunRuntimeSnapshot(
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        plan_json=None,
        outputs_json={},
        result_json=None,
        progress=Decimal("0"),
        pause_requested=True,
        created_at=run.created_at,
        updated_at=run.updated_at,
    )
    pause_event = _event_row(
        run,
        1,
        "trajectory.decision",
        {"run_status": "paused", "paused_from": "executing"},
    )
    session = _Session(
        execute_results=[_Result((database_run, snapshot))],
        scalars_results=[[pause_event]],
    )
    repository = PostgresRunRepository(cast(Any, object()))
    projected = await repository._get_in_session(
        cast(Any, session),
        run.run_id,
        run.tenant_id,
    )
    assert projected.paused_from is RunStatus.EXECUTING

    get = AsyncMock(return_value=run)
    monkeypatch.setattr(repository, "get", get)
    assert await repository.resolve_contract(run.run_id, run.tenant_id) == run.contract


@pytest.mark.asyncio
async def test_action_create_once_covers_created_duplicate_and_conflict_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _run()
    action = _action(run)
    repository = PostgresActionRepository(
        cast(Any, object()),
        AesGcmActionPayloadCipher(b"k" * 32),
    )
    require = AsyncMock()
    replace = AsyncMock()
    get = AsyncMock(return_value=action)
    monkeypatch.setattr(repository, "_require_run", require)
    monkeypatch.setattr(repository, "_replace_approvals", replace)
    monkeypatch.setattr(repository, "_get_in_session", get)

    created_session = _Session(scalar_results=[action.action_id])
    _patch_sessions(monkeypatch, created_session)
    assert await repository.create_once(action) == (action, True)
    assert created_session.commits == 1

    existing = SimpleNamespace(
        action_id=action.action_id,
        payload_hash=action.payload_hash,
    )
    duplicate_session = _Session(scalar_results=[None, existing])
    _patch_sessions(monkeypatch, duplicate_session)
    assert await repository.create_once(action) == (action, False)

    _patch_sessions(monkeypatch, _Session(scalar_results=[None, None]))
    with pytest.raises(Conflict) as missing:
        await repository.create_once(action)
    assert missing.value.code == "ACTION_CREATE_CONFLICT"

    mismatched = SimpleNamespace(action_id=action.action_id, payload_hash="different")
    _patch_sessions(monkeypatch, _Session(scalar_results=[None, mismatched]))
    with pytest.raises(Conflict) as reused:
        await repository.create_once(action)
    assert reused.value.code == "ACTION_IDEMPOTENCY_CONFLICT"


@pytest.mark.asyncio
async def test_action_create_with_event_is_atomic_and_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _run()
    action = _action(run)
    invocation = _invocation(run)
    event = AuditEvent(
        event_type="action.prepared",
        payload={"action_id": str(action.action_id)},
        correlation_id="correlation-prepare",
    )
    recorded = EventRecord(
        event_id="1",
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        sequence_no=1,
        event_type=event.event_type,
        payload=event.payload,
        correlation_id=event.correlation_id,
    )
    repository = PostgresActionRepository(
        cast(Any, object()),
        AesGcmActionPayloadCipher(b"k" * 32),
    )
    load_run = AsyncMock(return_value=run)
    append_event = AsyncMock(return_value=recorded)
    replace = AsyncMock()
    get = AsyncMock(return_value=action)
    append_invocation = AsyncMock()
    monkeypatch.setattr(repository._runs, "_get_in_session", load_run)
    monkeypatch.setattr(repository._runs, "_append_event_in_session", append_event)
    monkeypatch.setattr(repository, "_replace_approvals", replace)
    monkeypatch.setattr(repository, "_get_in_session", get)
    monkeypatch.setattr(production_store, "append_tool_invocation", append_invocation)

    created_session = _Session(scalar_results=[action.action_id])
    _patch_sessions(monkeypatch, created_session)
    assert await repository.create_once_with_event(action, event, invocation) == (
        action,
        True,
        recorded,
    )
    append_invocation.assert_awaited_once_with(created_session, invocation)
    append_event.assert_awaited_once()

    existing = SimpleNamespace(
        action_id=action.action_id,
        payload_hash=action.payload_hash,
    )
    duplicate_session = _Session(scalar_results=[None, existing])
    _patch_sessions(monkeypatch, duplicate_session)
    assert await repository.create_once_with_event(action, event) == (
        action,
        False,
        None,
    )

    _patch_sessions(monkeypatch, _Session(scalar_results=[None, None]))
    with pytest.raises(Conflict) as missing:
        await repository.create_once_with_event(action, event)
    assert missing.value.code == "ACTION_CREATE_CONFLICT"

    mismatched = SimpleNamespace(action_id=action.action_id, payload_hash="different")
    _patch_sessions(monkeypatch, _Session(scalar_results=[None, mismatched]))
    with pytest.raises(Conflict) as reused:
        await repository.create_once_with_event(action, event)
    assert reused.value.code == "ACTION_IDEMPOTENCY_CONFLICT"


@pytest.mark.asyncio
async def test_action_transaction_context_persists_on_success_and_recovery_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _run()
    action = _action(run)
    row = SimpleNamespace(version=1)
    repository = PostgresActionRepository(
        cast(Any, object()),
        AesGcmActionPayloadCipher(b"k" * 32),
    )
    record = AsyncMock(return_value=action)
    persist = AsyncMock()
    monkeypatch.setattr(repository, "_record_from_row", record)
    monkeypatch.setattr(repository, "_persist_audit_transaction", persist)

    _patch_sessions(monkeypatch, _Session(scalar_results=[None]))
    with pytest.raises(NotFound):
        async with repository.transaction(action.action_id, action.tenant_id):
            pass

    successful = _Session(scalar_results=[row])
    _patch_sessions(monkeypatch, successful)
    async with repository.transaction(action.action_id, action.tenant_id) as transaction:
        transaction.action.status = ActionStatus.APPROVED
    assert successful.commits == 1

    recovery = _Session(scalar_results=[row])
    _patch_sessions(monkeypatch, recovery)
    with pytest.raises(RuntimeError, match="ambiguous commit"):
        async with repository.transaction(action.action_id, action.tenant_id) as transaction:
            transaction.action.status = ActionStatus.UNKNOWN
            raise RuntimeError("ambiguous commit")
    assert recovery.commits == 1
    assert persist.await_count == 2


@pytest.mark.asyncio
async def test_action_get_list_save_and_locked_update_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _run()
    action = _action(run)
    row = PreparedAction(
        **PostgresActionRepository(
            cast(Any, object()),
            AesGcmActionPayloadCipher(b"k" * 32),
        )._action_values(action)
    )
    repository = PostgresActionRepository(
        cast(Any, object()),
        AesGcmActionPayloadCipher(b"k" * 32),
    )
    record = AsyncMock(return_value=action)
    require = AsyncMock()
    replace = AsyncMock()
    monkeypatch.setattr(repository, "_record_from_row", record)
    monkeypatch.setattr(repository, "_require_run", require)
    monkeypatch.setattr(repository, "_replace_approvals", replace)

    get_session = _Session(scalar_results=[row])
    list_session = _Session(scalars_results=[[row, row]])
    save_session = _Session(scalar_results=[2, row])
    _patch_sessions(monkeypatch, get_session, list_session, save_session)
    assert await repository.get(action.action_id, action.tenant_id) is action
    assert len(await repository.list_for_run(run.run_id, run.tenant_id)) == 2
    assert await repository.save(action, 1) is action
    assert action.version == 2
    assert save_session.commits == 1

    with pytest.raises(NotFound):
        await repository._get_in_session(
            cast(Any, _Session(scalar_results=[None])),
            action.action_id,
            action.tenant_id,
        )

    locked_session = _Session(scalar_results=[3])
    await repository._persist_locked(cast(Any, locked_session), action, 2)
    assert action.version == 3
