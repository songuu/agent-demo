from __future__ import annotations

import asyncio
import json
from collections import deque
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import boto3
import pytest

from agent_platform.infrastructure import retention_worker as module
from agent_platform.infrastructure.retention_worker import (
    ActionExpiryBatchProbe,
    ActionExpiryBatchResult,
    ActionExpiryOutcomeUnknown,
    PostgresRetentionWorker,
    RetentionSweepReport,
)


class _AsyncContext:
    def __init__(self, value: object | None = None) -> None:
        self.value = value

    async def __aenter__(self) -> object | None:
        return self.value

    async def __aexit__(self, *args: object) -> None:
        return None


class _Rows:
    def __init__(self, values: list[object]) -> None:
        self.values = values

    def all(self) -> list[object]:
        return self.values


class _Session:
    def __init__(
        self,
        *,
        scalar_rows: list[object] | None = None,
        execute_rows: list[object] | None = None,
        role_allowed: bool = True,
    ) -> None:
        self.scalar_rows = scalar_rows or []
        self.execute_rows = execute_rows or []
        self.role_allowed = role_allowed
        self.executed: list[object] = []
        self.added: list[object] = []
        self.role_checks = 0

    def begin(self) -> _AsyncContext:
        return _AsyncContext()

    async def scalar(self, statement: object) -> bool:
        self.role_checks += 1
        return self.role_allowed

    async def scalars(self, statement: object) -> _Rows:
        self.executed.append(statement)
        return _Rows(self.scalar_rows)

    async def execute(self, statement: object) -> _Rows:
        self.executed.append(statement)
        if len(self.executed) == 1:
            return _Rows(self.execute_rows)
        return _Rows([])

    def add(self, value: object) -> None:
        self.added.append(value)


class _SessionFactory:
    def __init__(self, *sessions: _Session) -> None:
        self.sessions = deque(sessions)

    def __call__(self) -> _AsyncContext:
        return _AsyncContext(self.sessions.popleft())


def _worker(*sessions: _Session) -> PostgresRetentionWorker:
    async def delete_artifact(artifact: object) -> None:
        return None

    return PostgresRetentionWorker(
        session_factory=_SessionFactory(*sessions),
        delete_artifact=delete_artifact,
    )


@pytest.mark.asyncio
async def test_run_once_aggregates_base_and_lifecycle_reports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lifecycle = SimpleNamespace(
        run_once=AsyncMock(
            return_value=SimpleNamespace(
                archived_runs=5,
                purged_runs=4,
                archived_event_streams=3,
                held_resources=2,
                failures=1,
            )
        )
    )
    worker = PostgresRetentionWorker(
        session_factory=SimpleNamespace(),
        delete_artifact=AsyncMock(),
        lifecycle=lifecycle,
    )
    monkeypatch.setattr(
        worker,
        "_expire_actions",
        AsyncMock(
            side_effect=[
                ActionExpiryBatchResult(selected=11, expired=11),
                ActionExpiryBatchResult(selected=0, expired=0),
                ActionExpiryBatchResult(selected=0, expired=0),
                ActionExpiryBatchResult(selected=0, expired=0),
            ]
        ),
    )
    monkeypatch.setattr(worker, "_delete_idempotency", AsyncMock(return_value=12))
    monkeypatch.setattr(worker, "_expire_memories", AsyncMock(return_value=13))
    monkeypatch.setattr(worker, "_delete_artifacts", AsyncMock(return_value=14))

    report = await worker.run_once(batch_size=17)

    assert report == RetentionSweepReport(
        expired_actions=11,
        deleted_idempotency_records=12,
        expired_memories=13,
        deleted_artifacts=14,
        archived_runs=5,
        purged_runs=4,
        archived_event_streams=3,
        held_resources=2,
        lifecycle_failures=1,
    )
    lifecycle.run_once.assert_awaited_once()

    worker._lifecycle = None
    report_without_lifecycle = await worker.run_once(batch_size=1)
    assert report_without_lifecycle.archived_runs == 0
    assert report_without_lifecycle.lifecycle_failures == 0


@pytest.mark.asyncio
async def test_action_expiry_handles_empty_batch_without_writes() -> None:
    empty = _Session(scalar_rows=[])
    worker = _worker(empty)

    assert await worker._expire_actions(
        module.datetime.now(module.UTC), 2
    ) == ActionExpiryBatchResult(selected=0, expired=0)
    assert len(empty.executed) == 1
    assert empty.role_checks == 1
    assert empty.added == []


@pytest.mark.asyncio
async def test_idempotency_and_memory_expiry_are_bounded_and_audited() -> None:
    idempotency = _Session(
        execute_rows=[
            ("tenant-a", "run", "key-1"),
            ("tenant-a", "action", "key-2"),
        ]
    )
    worker = _worker(idempotency)
    assert await worker._delete_idempotency(module.datetime.now(module.UTC), 10) == 2
    assert len(idempotency.executed) == 3

    record = SimpleNamespace(
        memory_id=uuid4(),
        tenant_id="tenant-a",
        content_hash="a" * 64,
        deleted_at=None,
    )
    memories = _Session(scalar_rows=[record])
    worker = _worker(memories)
    now = module.datetime.now(module.UTC)

    assert await worker._expire_memories(now, 10) == 1
    assert record.deleted_at == now
    assert len(memories.added) == 1
    event = memories.added[0]
    assert event.event_type == "expired"
    assert event.actor_id == "retention-worker"


@pytest.mark.asyncio
async def test_retention_role_must_explicitly_bypass_rls() -> None:
    session = _Session(role_allowed=False)
    worker = _worker(session)

    with pytest.raises(RuntimeError, match="RETENTION_ROLE_MUST_BYPASS_RLS"):
        await worker._expire_actions(module.datetime.now(module.UTC), 1)


def _report() -> RetentionSweepReport:
    return RetentionSweepReport(
        expired_actions=1,
        deleted_idempotency_records=2,
        expired_memories=3,
        deleted_artifacts=4,
        archived_runs=5,
        purged_runs=6,
        archived_event_streams=7,
        held_resources=8,
        lifecycle_failures=9,
    )


def test_main_prints_complete_machine_readable_report(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def run_once() -> RetentionSweepReport:
        return _report()

    monkeypatch.setattr(module, "_run_once", run_once)

    module.main()

    assert json.loads(capsys.readouterr().out) == {
        "expired_actions": 1,
        "deleted_idempotency_records": 2,
        "expired_memories": 3,
        "deleted_artifacts": 4,
        "archived_runs": 5,
        "purged_runs": 6,
        "archived_event_streams": 7,
        "held_resources": 8,
        "lifecycle_failures": 9,
    }


class _Secret:
    def get_secret_value(self) -> str:
        return "postgresql+asyncpg://retention@database/platform"


class _Client:
    def __init__(self) -> None:
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


@pytest.mark.asyncio
async def test_run_once_builds_governed_adapters_and_always_disposes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _Client()
    sessions = object()
    disposed: list[object] = []
    built: dict[str, object] = {}

    class FakeSettings:
        database_dsn = _Secret()
        artifact_region = "ap-southeast-1"
        artifact_endpoint_url = "https://s3.example.test"
        artifact_kms_key = "arn:aws:kms:ap-southeast-1:111122223333:key/archive"
        artifact_bucket = "agent-platform-prod"
        environment = "prod"

        def __init__(self, *, process_role: str) -> None:
            assert process_role == "retention-worker"

    class FakeArchive:
        def __init__(self, **kwargs: object) -> None:
            built["archive"] = kwargs

    class FakeLifecycle:
        def __init__(self, **kwargs: object) -> None:
            built["lifecycle"] = kwargs

    class FakeDeleter:
        def __init__(self, **kwargs: object) -> None:
            built["deleter"] = kwargs

    class FakeWorker:
        def __init__(self, **kwargs: object) -> None:
            built["worker"] = kwargs

        async def run_once(self) -> RetentionSweepReport:
            return _report()

    async def dispose(value: object) -> None:
        disposed.append(value)

    monkeypatch.setattr(module, "Settings", FakeSettings)
    monkeypatch.setattr(module, "create_session_factory", lambda dsn: sessions)
    monkeypatch.setattr(module, "dispose_session_factory", dispose)
    monkeypatch.setattr(module, "S3ImmutableArchiveAdapter", FakeArchive)
    monkeypatch.setattr(module, "PostgresLifecycleRetention", FakeLifecycle)
    monkeypatch.setattr(module, "S3ArtifactDeleter", FakeDeleter)
    monkeypatch.setattr(module, "PostgresRetentionWorker", FakeWorker)
    monkeypatch.setattr(boto3, "client", lambda service, **kwargs: client)

    report = await module._run_once()

    assert report == _report()
    assert built["archive"] == {
        "client": client,
        "bucket": "agent-platform-prod",
        "environment": "prod",
        "kms_key_id": "arn:aws:kms:ap-southeast-1:111122223333:key/archive",
    }
    assert disposed == [sessions]
    assert client.closed == 1


@pytest.mark.asyncio
async def test_run_once_rejects_production_archive_without_kms_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _Client()
    sessions = object()
    disposed: list[object] = []

    class FakeSettings:
        database_dsn = _Secret()
        artifact_region = ""
        artifact_endpoint_url = ""
        artifact_kms_key = ""
        artifact_bucket = "agent-platform-prod"
        environment = "prod"

        def __init__(self, *, process_role: str) -> None:
            return None

    async def dispose(value: object) -> None:
        disposed.append(value)

    monkeypatch.setattr(module, "Settings", FakeSettings)
    monkeypatch.setattr(module, "create_session_factory", lambda dsn: sessions)
    monkeypatch.setattr(module, "dispose_session_factory", dispose)
    monkeypatch.setattr(boto3, "client", lambda service, **kwargs: client)

    with pytest.raises(RuntimeError, match="RETENTION_ARCHIVE_KMS_KEY_REQUIRED"):
        await module._run_once()

    assert client.closed == 1
    assert disposed == [sessions]


@pytest.mark.asyncio
async def test_run_once_drains_thousand_actions_until_idle_within_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = PostgresRetentionWorker(
        session_factory=SimpleNamespace(),
        delete_artifact=AsyncMock(),
    )
    expire = AsyncMock(
        side_effect=[
            *[ActionExpiryBatchResult(selected=100, expired=100)] * 10,
            ActionExpiryBatchResult(selected=0, expired=0),
            ActionExpiryBatchResult(selected=0, expired=0),
        ]
    )
    monkeypatch.setattr(worker, "_expire_actions", expire)
    monkeypatch.setattr(worker, "_delete_idempotency", AsyncMock(return_value=0))
    monkeypatch.setattr(worker, "_expire_memories", AsyncMock(return_value=0))
    monkeypatch.setattr(worker, "_delete_artifacts", AsyncMock(return_value=0))

    report = await worker.run_once(
        batch_size=100,
        max_action_batches=20,
        action_time_budget_seconds=30.0,
    )

    assert report.expired_actions == 1000
    assert expire.await_count == 12


@pytest.mark.asyncio
async def test_action_expiry_atomically_adds_audit_event_and_outbox() -> None:
    from agent_platform.infrastructure.persistence.models import (
        ActionStatus,
        OutboxEvent,
        RunEvent,
    )

    now = module.datetime.now(module.UTC)
    action = SimpleNamespace(
        action_id=uuid4(),
        run_id=uuid4(),
        tenant_id="tenant-a",
        payload_hash="a" * 64,
        status=ActionStatus.PENDING_APPROVAL,
        expires_at=now,
        failure_code=None,
        updated_at=now,
        version=3,
    )

    class SequenceResult:
        def scalar_one(self) -> int:
            return 41

    class AtomicSession:
        def __init__(self) -> None:
            self.added: list[object] = []
            self.executed: list[tuple[str, object]] = []
            self.role_checks = 0
            self.flushes = 0

        def begin(self) -> _AsyncContext:
            return _AsyncContext()

        async def scalar(self, statement: object) -> bool:
            self.role_checks += 1
            return True

        async def scalars(self, statement: object) -> _Rows:
            return _Rows([action])

        async def execute(self, statement: object, parameters: object = None) -> SequenceResult:
            self.executed.append((str(statement), parameters))
            return SequenceResult()

        def add(self, value: object) -> None:
            self.added.append(value)

        async def flush(self) -> None:
            self.flushes += 1

    session = AtomicSession()
    worker = PostgresRetentionWorker(
        session_factory=_SessionFactory(session),  # type: ignore[arg-type]
        delete_artifact=AsyncMock(),
    )
    operation_id = uuid4()
    probe = ActionExpiryBatchProbe(operation_id=operation_id)

    assert await worker._expire_actions(
        now,
        100,
        timeout_seconds=0.25,
        probe=probe,
    ) == ActionExpiryBatchResult(selected=1, expired=1)

    assert action.status is ActionStatus.EXPIRED
    assert action.failure_code == "ACTION_EXPIRED"
    assert action.version == 4
    event = next(item for item in session.added if isinstance(item, RunEvent))
    outbox = next(item for item in session.added if isinstance(item, OutboxEvent))
    assert event.event_type == "action.expired"
    assert event.sequence_no == 41
    assert event.action_id == action.action_id
    assert event.correlation_id.endswith(f":operation:{operation_id}")
    assert outbox.event_key.startswith(event.correlation_id)
    assert probe.selected_action_ids == (action.action_id,)
    assert event.payload == {
        "run_id": str(action.run_id),
        "action_id": str(action.action_id),
        "payload_hash": action.payload_hash,
        "previous_status": "pending_approval",
        "scheduled_expires_at": action.expires_at.isoformat(),
        "expired_at": now.isoformat(),
        "reason": "retention_fallback",
    }
    assert outbox.event_type == event.event_type
    assert outbox.payload == event.payload
    assert outbox.payload_hash == event.payload_hash
    assert session.flushes == 1
    assert session.executed[:2] == [
        (
            "SELECT set_config(:setting, :timeout, true)",
            {"setting": "statement_timeout", "timeout": "250ms"},
        ),
        (
            "SELECT set_config(:setting, :timeout, true)",
            {"setting": "lock_timeout", "timeout": "250ms"},
        ),
    ]


@pytest.mark.asyncio
async def test_action_expiry_defers_locked_run_and_rejects_missing_run() -> None:
    from agent_platform.infrastructure.persistence.models import ActionStatus

    now = module.datetime.now(module.UTC)
    action = SimpleNamespace(
        action_id=uuid4(),
        run_id=uuid4(),
        tenant_id="tenant-a",
        payload_hash="a" * 64,
        status=ActionStatus.PENDING_APPROVAL,
        expires_at=now,
        failure_code=None,
        updated_at=now,
        version=3,
    )

    class LockedRunSession:
        def __init__(self, *, existing_run: object | None = action.run_id) -> None:
            self.scalar_statements: list[object] = []
            self.added: list[object] = []
            self.flushes = 0
            self.existing_run = existing_run

        def begin(self) -> _AsyncContext:
            return _AsyncContext()

        async def scalar(self, statement: object) -> object:
            self.scalar_statements.append(statement)
            if len(self.scalar_statements) == 1:
                return True
            if len(self.scalar_statements) == 2:
                return None
            return self.existing_run

        async def scalars(self, statement: object) -> _Rows:
            return _Rows([action])

        async def execute(self, statement: object, parameters: object = None) -> object:
            raise AssertionError("a locked Run must be deferred before sequence allocation")

        def add(self, value: object) -> None:
            self.added.append(value)

        async def flush(self) -> None:
            self.flushes += 1

    session = LockedRunSession()
    worker = PostgresRetentionWorker(
        session_factory=_SessionFactory(session),  # type: ignore[arg-type]
        delete_artifact=AsyncMock(),
    )

    assert await worker._expire_actions(now, 100) == ActionExpiryBatchResult(
        selected=1,
        expired=0,
        deferred_action_ids=(action.action_id,),
    )

    run_lock = session.scalar_statements[1]._for_update_arg  # type: ignore[attr-defined]
    assert run_lock.skip_locked is True
    assert action.status is ActionStatus.PENDING_APPROVAL
    assert session.added == []
    assert session.flushes == 1

    missing_session = LockedRunSession(existing_run=None)
    missing_worker = PostgresRetentionWorker(
        session_factory=_SessionFactory(missing_session),  # type: ignore[arg-type]
        delete_artifact=AsyncMock(),
    )
    with pytest.raises(RuntimeError, match="ACTION_EXPIRY_RUN_NOT_FOUND"):
        await missing_worker._expire_actions(now, 100)
    assert missing_session.added == []


@pytest.mark.asyncio
async def test_action_drain_stops_at_batch_and_time_budgets() -> None:
    max_bounded = PostgresRetentionWorker(
        session_factory=SimpleNamespace(),
        delete_artifact=AsyncMock(),
        monotonic_clock=lambda: 0.0,
    )
    max_expire = AsyncMock(return_value=ActionExpiryBatchResult(selected=100, expired=100))
    max_bounded._expire_actions = max_expire  # type: ignore[method-assign]

    assert (
        await max_bounded._drain_expired_actions(
            module.datetime.now(module.UTC),
            batch_size=100,
            max_batches=10,
            time_budget_seconds=30.0,
        )
        == 1000
    )
    assert max_expire.await_count == 10
    assert {attempt.kwargs["timeout_seconds"] for attempt in max_expire.await_args_list} == {29.0}

    ticks = deque([0.0, 0.0, 31.0])
    time_bounded = PostgresRetentionWorker(
        session_factory=SimpleNamespace(),
        delete_artifact=AsyncMock(),
        monotonic_clock=ticks.popleft,
    )
    time_expire = AsyncMock(return_value=ActionExpiryBatchResult(selected=100, expired=100))
    time_bounded._expire_actions = time_expire  # type: ignore[method-assign]

    assert (
        await time_bounded._drain_expired_actions(
            module.datetime.now(module.UTC),
            batch_size=100,
            max_batches=20,
            time_budget_seconds=30.0,
        )
        == 100
    )
    assert time_expire.await_count == 1
    assert time_expire.await_args.kwargs["timeout_seconds"] == 29.0


@pytest.mark.asyncio
async def test_action_drain_rechecks_an_underfilled_scan_for_released_row_locks() -> None:
    worker = PostgresRetentionWorker(
        session_factory=SimpleNamespace(),
        delete_artifact=AsyncMock(),
        monotonic_clock=lambda: 0.0,
    )
    expire = AsyncMock(
        side_effect=[
            ActionExpiryBatchResult(selected=0, expired=0),
            ActionExpiryBatchResult(selected=1, expired=1),
            ActionExpiryBatchResult(selected=0, expired=0),
        ]
    )
    worker._expire_actions = expire  # type: ignore[method-assign]

    assert (
        await worker._drain_expired_actions(
            module.datetime.now(module.UTC),
            batch_size=100,
            max_batches=3,
            time_budget_seconds=30.0,
        )
        == 1
    )
    assert expire.await_count == 3


@pytest.mark.asyncio
async def test_action_drain_reduces_each_batch_to_the_remaining_budget() -> None:
    ticks = deque([0.0, 0.0, 10.0, 31.0])
    worker = PostgresRetentionWorker(
        session_factory=SimpleNamespace(),
        delete_artifact=AsyncMock(),
        monotonic_clock=ticks.popleft,
    )
    expire = AsyncMock(return_value=ActionExpiryBatchResult(selected=100, expired=100))
    worker._expire_actions = expire  # type: ignore[method-assign]

    assert (
        await worker._drain_expired_actions(
            module.datetime.now(module.UTC),
            batch_size=100,
            max_batches=20,
            time_budget_seconds=30.0,
        )
        == 200
    )
    assert [attempt.kwargs["timeout_seconds"] for attempt in expire.await_args_list] == [29.0, 19.0]


@pytest.mark.asyncio
async def test_action_drain_retries_locked_rows_after_reaching_later_backlog() -> None:
    deferred = tuple(uuid4() for _ in range(100))
    worker = PostgresRetentionWorker(
        session_factory=SimpleNamespace(),
        delete_artifact=AsyncMock(),
        monotonic_clock=lambda: 0.0,
    )
    expire = AsyncMock(
        side_effect=[
            ActionExpiryBatchResult(
                selected=100,
                expired=0,
                deferred_action_ids=deferred,
            ),
            ActionExpiryBatchResult(selected=1, expired=1),
            ActionExpiryBatchResult(selected=1, expired=1),
        ]
    )
    worker._expire_actions = expire  # type: ignore[method-assign]

    assert (
        await worker._drain_expired_actions(
            module.datetime.now(module.UTC),
            batch_size=100,
            max_batches=2,
            time_budget_seconds=30.0,
        )
        == 2
    )
    assert expire.await_count == 3
    assert set(expire.await_args_list[1].kwargs["excluded_action_ids"]) == set(deferred)
    assert set(expire.await_args_list[2].kwargs["included_action_ids"]) == set(deferred)


@pytest.mark.asyncio
async def test_action_drain_retries_every_deferred_chunk_with_a_separate_bound() -> None:
    first = tuple(uuid4() for _ in range(100))
    second = tuple(uuid4() for _ in range(100))
    worker = PostgresRetentionWorker(
        session_factory=SimpleNamespace(),
        delete_artifact=AsyncMock(),
        monotonic_clock=lambda: 0.0,
    )
    expire = AsyncMock(
        side_effect=[
            ActionExpiryBatchResult(
                selected=100,
                expired=0,
                deferred_action_ids=first,
            ),
            ActionExpiryBatchResult(
                selected=100,
                expired=0,
                deferred_action_ids=second,
            ),
            ActionExpiryBatchResult(selected=100, expired=100),
            ActionExpiryBatchResult(selected=100, expired=100),
        ]
    )
    worker._expire_actions = expire  # type: ignore[method-assign]

    assert (
        await worker._drain_expired_actions(
            module.datetime.now(module.UTC),
            batch_size=100,
            max_batches=2,
            time_budget_seconds=30.0,
        )
        == 200
    )
    assert expire.await_count == 4
    retried = {
        action_id
        for attempt in expire.await_args_list[2:]
        for action_id in attempt.kwargs["included_action_ids"]
    }
    assert retried == set(first) | set(second)


@pytest.mark.asyncio
async def test_action_drain_cancels_inflight_batch_at_overall_deadline() -> None:
    entered = asyncio.Event()
    cancelled = asyncio.Event()
    worker = PostgresRetentionWorker(
        session_factory=SimpleNamespace(),
        delete_artifact=AsyncMock(),
    )

    async def blocked_batch(*args: object, **kwargs: object) -> ActionExpiryBatchResult:
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()
        raise AssertionError("unreachable")

    worker._expire_actions = blocked_batch  # type: ignore[method-assign]

    with pytest.raises(ActionExpiryOutcomeUnknown) as captured:
        await worker._drain_expired_actions(
            module.datetime.now(module.UTC),
            batch_size=100,
            max_batches=20,
            time_budget_seconds=0.02,
        )
    assert entered.is_set()
    assert cancelled.is_set()
    assert captured.value.batch_number == 1
    assert captured.value.filter_mode == "all"
    assert captured.value.filter_count == 0
    assert captured.value.candidate_action_ids == ()
    assert f"operation_id={captured.value.operation_id}" in str(captured.value)


@pytest.mark.asyncio
async def test_action_drain_uses_overall_timeout_during_slow_cancellation() -> None:
    cancellations = 0
    worker = PostgresRetentionWorker(
        session_factory=SimpleNamespace(),
        delete_artifact=AsyncMock(),
    )

    async def slow_cancellation(*args: object, **kwargs: object) -> ActionExpiryBatchResult:
        nonlocal cancellations
        while True:
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancellations += 1
                if cancellations > 1:
                    raise

    worker._expire_actions = slow_cancellation  # type: ignore[method-assign]

    with pytest.raises(ActionExpiryOutcomeUnknown):
        await worker._drain_expired_actions(
            module.datetime.now(module.UTC),
            batch_size=100,
            max_batches=1,
            time_budget_seconds=0.3,
        )
    assert cancellations == 2


@pytest.mark.asyncio
async def test_action_drain_rejects_a_result_returned_after_operation_timeout() -> None:
    worker = PostgresRetentionWorker(
        session_factory=SimpleNamespace(),
        delete_artifact=AsyncMock(),
    )

    async def swallowed_cancellation(*args: object, **kwargs: object) -> ActionExpiryBatchResult:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            return ActionExpiryBatchResult(selected=0, expired=0)

    worker._expire_actions = swallowed_cancellation  # type: ignore[method-assign]

    with pytest.raises(ActionExpiryOutcomeUnknown):
        await worker._drain_expired_actions(
            module.datetime.now(module.UTC),
            batch_size=100,
            max_batches=1,
            time_budget_seconds=0.02,
        )


@pytest.mark.asyncio
async def test_action_drain_does_not_swallow_an_inner_timeout() -> None:
    worker = PostgresRetentionWorker(
        session_factory=SimpleNamespace(),
        delete_artifact=AsyncMock(),
        monotonic_clock=lambda: 0.0,
    )

    async def driver_timeout(*args: object, **kwargs: object) -> ActionExpiryBatchResult:
        raise TimeoutError("driver timeout")

    worker._expire_actions = driver_timeout  # type: ignore[method-assign]

    with pytest.raises(TimeoutError, match="driver timeout"):
        await worker._drain_expired_actions(
            module.datetime.now(module.UTC),
            batch_size=100,
            max_batches=1,
            time_budget_seconds=30.0,
        )
