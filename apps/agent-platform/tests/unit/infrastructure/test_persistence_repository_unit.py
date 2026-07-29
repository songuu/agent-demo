from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

import pytest

from agent_platform.infrastructure.persistence.models import (
    ActionStatus,
    AgentRun,
    PreparedAction,
    RunStatus,
)
from agent_platform.infrastructure.persistence.repositories import (
    ActionRepository,
    IdempotencyConflictError,
    IdempotencyRepository,
    OptimisticConcurrencyError,
    RunRepository,
)
from agent_platform.infrastructure.persistence.session import tenant_session
from agent_platform.infrastructure.persistence.unit_of_work import SqlAlchemyUnitOfWork


class _Mappings:
    def __init__(self, row: dict[str, Any]) -> None:
        self._row = row

    def one(self) -> dict[str, Any]:
        return self._row


class _Result:
    def __init__(self, value: Any) -> None:
        self._value = value

    def scalar_one_or_none(self) -> Any:
        return self._value

    def mappings(self) -> _Mappings:
        return _Mappings(cast(dict[str, Any], self._value))


class _Session:
    def __init__(
        self,
        *,
        scalar_results: list[Any] | None = None,
        execute_results: list[Any] | None = None,
        get_result: Any = None,
        in_transaction: bool = True,
    ) -> None:
        self.scalar_results = list(scalar_results or [])
        self.execute_results = list(execute_results or [])
        self.get_result = get_result
        self.added: list[Any] = []
        self.added_many: list[Any] = []
        self.flushes = 0
        self.begins = 0
        self.commits = 0
        self.rollbacks = 0
        self.closes = 0
        self.execute_calls: list[tuple[Any, Any]] = []
        self._in_transaction = in_transaction

    def add(self, value: Any) -> None:
        self.added.append(value)

    def add_all(self, values: list[Any]) -> None:
        self.added_many.extend(values)

    async def flush(self) -> None:
        self.flushes += 1

    async def scalar(self, _statement: Any) -> Any:
        if not self.scalar_results:
            raise AssertionError("unexpected scalar query")
        return self.scalar_results.pop(0)

    async def execute(self, statement: Any, parameters: Any = None) -> _Result:
        self.execute_calls.append((statement, parameters))
        value = self.execute_results.pop(0) if self.execute_results else None
        return value if isinstance(value, _Result) else _Result(value)

    async def get(self, _model: Any, _identity: Any) -> Any:
        return self.get_result

    async def begin(self) -> None:
        self.begins += 1
        self._in_transaction = True

    def in_transaction(self) -> bool:
        return self._in_transaction

    async def commit(self) -> None:
        self.commits += 1
        self._in_transaction = False

    async def rollback(self) -> None:
        self.rollbacks += 1
        self._in_transaction = False

    async def close(self) -> None:
        self.closes += 1


def _database_run() -> AgentRun:
    now = datetime.now(UTC)
    return AgentRun(
        run_id=uuid4(),
        tenant_id="tenant-a",
        principal_id="user-1",
        use_case="agent.run",
        status=RunStatus.EXECUTING,
        risk="medium",
        contract_schema_version="1.0",
        contract_json={"goal": "test"},
        current_plan_version=1,
        workflow_id=f"workflow-{uuid4()}",
        workflow_run_id=None,
        idempotency_key=f"run-{uuid4()}",
        request_hash="a" * 64,
        cost_limit_usd=Decimal("5"),
        cost_actual_usd=Decimal("0"),
        token_input=0,
        token_output=0,
        tool_call_count=0,
        deadline_at=now + timedelta(minutes=5),
        cancel_requested_at=None,
        failure_code=None,
        failure_detail_ref=None,
        final_artifact_id=None,
        version=1,
        created_at=now,
        updated_at=now,
        completed_at=None,
    )


def _prepared_action(run: AgentRun) -> PreparedAction:
    now = datetime.now(UTC)
    return PreparedAction(
        action_id=uuid4(),
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        principal_id=run.principal_id,
        action_type="email.send",
        tool_name="email.commit",
        tool_version="1.0.0",
        payload_encrypted=b"encrypted",
        payload_hash="b" * 64,
        preview_json={"summary": "send"},
        risk="high",
        approval_policy="two-person",
        required_approvals=2,
        status=ActionStatus.APPROVED,
        idempotency_key=f"action-{uuid4()}",
        policy_version="bundle-7",
        receipt_json=None,
        receipt_artifact_id=None,
        verification_json=None,
        failure_code=None,
        expires_at=now + timedelta(minutes=5),
        approved_at=now,
        committing_at=None,
        committed_at=None,
        created_at=now,
        updated_at=now,
        version=1,
    )


@pytest.mark.asyncio
async def test_run_repository_snapshot_transition_and_audit_append() -> None:
    run = _database_run()
    session = _Session(
        scalar_results=[2, 7],
        execute_results=[
            _Result(run),
            _Result({"run_version": 3, "event_sequence": 4}),
            _Result(None),
        ],
    )
    repository = RunRepository(cast(Any, session))

    await repository.add(run)
    assert session.added == [run]
    assert await repository.get(run.run_id, run.tenant_id) is run
    assert (
        await repository.update_snapshot(
            run_id=run.run_id,
            tenant_id=run.tenant_id,
            expected_version=1,
            values={"status": RunStatus.VERIFYING},
        )
        == 2
    )
    with pytest.raises(ValueError, match="protected fields"):
        await repository.update_snapshot(
            run_id=run.run_id,
            tenant_id=run.tenant_id,
            expected_version=2,
            values={"tenant_id": "tenant-b"},
        )

    transitioned = await repository.transition(
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        expected=(RunStatus.EXECUTING,),
        target=RunStatus.VERIFYING,
        expected_version=2,
        event_type="run.status_changed",
        actor_type="worker",
        actor_id="worker-1",
        correlation_id="correlation-1",
        payload={"to": "verifying"},
        payload_hash="c" * 64,
    )
    assert transitioned == {"run_version": 3, "event_sequence": 4}
    with pytest.raises(ValueError, match="expected statuses cannot be empty"):
        await repository.transition(
            run_id=run.run_id,
            tenant_id=run.tenant_id,
            expected=(),
            target=RunStatus.VERIFYING,
            expected_version=2,
            event_type="run.status_changed",
            actor_type="worker",
            actor_id=None,
            correlation_id="correlation-2",
            payload={},
            payload_hash="d" * 64,
        )

    event = await repository.append_event_and_outbox(
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        event_type="run.updated",
        actor_type="worker",
        actor_id=None,
        correlation_id="correlation-3",
        payload={"progress": 1},
        payload_hash="e" * 64,
        event_key="run-1:7",
    )
    assert event.sequence_no == 7
    assert len(session.added_many) == 2


@pytest.mark.asyncio
async def test_run_repository_rejects_stale_snapshot_and_defaults_first_sequence() -> None:
    run = _database_run()
    stale = RunRepository(cast(Any, _Session(scalar_results=[None])))
    with pytest.raises(OptimisticConcurrencyError):
        await stale.update_snapshot(
            run_id=run.run_id,
            tenant_id=run.tenant_id,
            expected_version=1,
            values={"status": RunStatus.FAILED},
        )

    session = _Session(scalar_results=[None], execute_results=[_Result(None)])
    event = await RunRepository(cast(Any, session)).append_event_and_outbox(
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        event_type="run.created",
        actor_type="api",
        actor_id="user-1",
        correlation_id="correlation-first",
        payload={},
        payload_hash="f" * 64,
        event_key="run:first",
    )
    assert event.sequence_no == 1


@pytest.mark.asyncio
async def test_action_repository_lock_and_mark_committing_paths() -> None:
    run = _database_run()
    action = _prepared_action(run)
    session = _Session(
        scalar_results=[2],
        execute_results=[_Result(action)],
    )
    repository = ActionRepository(cast(Any, session))

    await repository.add(action)
    assert await repository.get_for_commit(action.action_id, action.tenant_id) is action
    assert (
        await repository.mark_committing(
            action_id=action.action_id,
            tenant_id=action.tenant_id,
            expected_version=1,
        )
        == 2
    )

    stale = ActionRepository(cast(Any, _Session(scalar_results=[None])))
    with pytest.raises(OptimisticConcurrencyError):
        await stale.mark_committing(
            action_id=action.action_id,
            tenant_id=action.tenant_id,
            expected_version=1,
        )


@pytest.mark.asyncio
async def test_idempotency_repository_claim_semantics() -> None:
    now = datetime.now(UTC)
    inserted = IdempotencyRepository(cast(Any, _Session(scalar_results=["key-1"])))
    assert await inserted.claim(
        tenant_id="tenant-a",
        scope="run.create",
        key="key-1",
        request_hash="a" * 64,
        resource_type="run",
        resource_id=str(uuid4()),
        expires_at=now + timedelta(hours=1),
    )

    same_record = cast(Any, SimpleNamespace(request_hash="a" * 64))
    duplicate_session = _Session(scalar_results=[None], get_result=same_record)
    duplicate = IdempotencyRepository(cast(Any, duplicate_session))
    assert (
        await duplicate.claim(
            tenant_id="tenant-a",
            scope="run.create",
            key="key-1",
            request_hash="a" * 64,
            resource_type="run",
            resource_id=str(uuid4()),
            expires_at=now + timedelta(hours=1),
        )
        is False
    )
    assert (
        await duplicate.get(
            tenant_id="tenant-a",
            scope="run.create",
            key="key-1",
        )
        is same_record
    )

    conflicting_session = _Session(
        scalar_results=[None],
        get_result=SimpleNamespace(request_hash="different"),
    )
    with pytest.raises(IdempotencyConflictError):
        await IdempotencyRepository(cast(Any, conflicting_session)).claim(
            tenant_id="tenant-a",
            scope="run.create",
            key="key-1",
            request_hash="a" * 64,
            resource_type="run",
            resource_id=str(uuid4()),
            expires_at=now + timedelta(hours=1),
        )

    missing_session = _Session(scalar_results=[None], get_result=None)
    assert (
        await IdempotencyRepository(cast(Any, missing_session)).claim(
            tenant_id="tenant-a",
            scope="run.create",
            key="key-2",
            request_hash="a" * 64,
            resource_type="run",
            resource_id=str(uuid4()),
            expires_at=now + timedelta(hours=1),
        )
        is False
    )


@pytest.mark.asyncio
async def test_unit_of_work_scopes_repositories_and_never_implicitly_commits() -> None:
    with pytest.raises(ValueError, match="tenant_id is required"):
        SqlAlchemyUnitOfWork(cast(Any, object()), "")

    session = _Session()
    unit = SqlAlchemyUnitOfWork(cast(Any, lambda: session), "tenant-a")
    with pytest.raises(RuntimeError, match="has not been entered"):
        await unit.commit()
    with pytest.raises(RuntimeError, match="has not been entered"):
        await unit.rollback()

    entered = await unit.__aenter__()
    assert entered is unit
    assert isinstance(unit.runs, RunRepository)
    assert isinstance(unit.actions, ActionRepository)
    assert isinstance(unit.idempotency, IdempotencyRepository)
    assert session.begins == 1
    assert session.execute_calls[0][1] == {"tenant_id": "tenant-a"}

    await unit.rollback()
    await unit.__aexit__(None, None, None)
    assert session.rollbacks == 1
    assert session.closes == 1
    assert unit.session is None

    clean_session = _Session()
    clean = SqlAlchemyUnitOfWork(cast(Any, lambda: clean_session), "tenant-a")
    await clean.__aenter__()
    await clean.commit()
    await clean.__aexit__(None, None, None)
    assert clean_session.commits == 1
    assert clean_session.rollbacks == 0


@pytest.mark.asyncio
async def test_tenant_session_validates_identity_and_rolls_back_on_exit() -> None:
    factory = cast(Any, lambda: _Session())
    for invalid in ("", "tenant\x00a"):
        with pytest.raises(ValueError, match="non-empty verified identifier"):
            async with tenant_session(factory, invalid):
                pass

    session = _Session()
    async with tenant_session(cast(Any, lambda: session), "tenant-a") as yielded:
        assert cast(Any, yielded) is session
        assert session.begins == 1
    assert session.rollbacks == 1
    assert session.closes == 1
