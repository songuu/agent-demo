from __future__ import annotations

import hashlib
import json
from collections import deque
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from pydantic import BaseModel

from agent_platform.application.errors import Conflict, NotFound, PlatformError
from agent_platform.application.records import (
    ActionAuditTransaction,
    ActionRecord,
    ArtifactDownload,
    ArtifactRecord,
    AuditEvent,
    CapabilityRecord,
    EventRecord,
    RunRecord,
    ToolInvocationRecord,
)
from agent_platform.domain.enums import ActionStatus, RiskLevel, RunStatus, ToolEffect
from agent_platform.domain.models import (
    DataScope,
    ExecutionPlan,
    FinalResponse,
    Principal,
    SuccessCriterion,
    TaskContract,
    TaskSpec,
    VerificationReport,
    WorkerOutput,
)
from agent_platform.infrastructure.persistence import production_store
from agent_platform.infrastructure.persistence.models import (
    ActionStatus as DatabaseActionStatus,
)
from agent_platform.infrastructure.persistence.models import (
    AgentRun,
    Approval,
    ApprovalDecision,
    Artifact,
    PreparedAction,
    RunEvent,
)
from agent_platform.infrastructure.persistence.production_store import (
    AesGcmActionPayloadCipher,
    PostgresActionRepository,
    PostgresArtifactStore,
    PostgresCapabilityStore,
    PostgresPlatformStore,
    PostgresRunRepository,
    _action_aad,
    _artifact_scan_provenance,
    _dump_outputs,
    _load_outputs,
    _parse_datetime,
    _PostgresRunTrajectoryTransaction,
    _receipt_artifact_id,
    _typed_dump,
    _typed_load,
    _unwrapped_json,
    _wrapped_json,
)
from agent_platform.infrastructure.persistence.runtime_models import (
    CapabilityRecordRow,
    RunRuntimeSnapshot,
)


class _ScalarRows:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return self._rows


class _Result:
    def __init__(self, value: Any) -> None:
        self._value = value

    def one_or_none(self) -> Any:
        return self._value

    def scalar_one(self) -> Any:
        if self._value is None:
            raise AssertionError("expected one scalar result")
        return self._value


class _FakeSession:
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
        self.added: list[Any] = []
        self.executed_statements: list[Any] = []
        self.commit_count = 0
        self.flush_count = 0

    async def scalar(self, _statement: Any) -> Any:
        if not self.scalar_results:
            raise AssertionError("unexpected scalar query")
        return self.scalar_results.popleft()

    async def execute(self, _statement: Any, _parameters: Any = None) -> _Result:
        self.executed_statements.append(_statement)
        value = self.execute_results.popleft() if self.execute_results else None
        return value if isinstance(value, _Result) else _Result(value)

    async def scalars(self, _statement: Any) -> _ScalarRows:
        if not self.scalars_results:
            raise AssertionError("unexpected scalars query")
        return _ScalarRows(self.scalars_results.popleft())

    def add(self, value: Any) -> None:
        self.added.append(value)

    async def commit(self) -> None:
        self.commit_count += 1

    async def flush(self) -> None:
        self.flush_count += 1
        for value in self.added:
            if isinstance(value, RunEvent):
                if getattr(value, "event_id", None) is None:
                    value.event_id = 1
                if getattr(value, "created_at", None) is None:
                    value.created_at = datetime.now(UTC)


def _patch_tenant_sessions(
    monkeypatch: pytest.MonkeyPatch,
    *sessions: _FakeSession,
) -> None:
    queued = deque(sessions)

    @asynccontextmanager
    async def fake_tenant_session(
        _factory: Any,
        tenant_id: str,
    ) -> AsyncIterator[_FakeSession]:
        assert tenant_id
        if not queued:
            raise AssertionError("unexpected tenant session")
        yield queued.popleft()

    monkeypatch.setattr(production_store, "tenant_session", fake_tenant_session)


class _FakeContentStore:
    def __init__(self) -> None:
        self.put_calls: list[ArtifactRecord] = []
        self.delete_calls: list[tuple[UUID, str]] = []
        self.delete_errors: deque[Exception] = deque()
        self.delete_observer: Callable[[], None] | None = None
        self.get_result: ArtifactRecord | None = None
        self.download_result: ArtifactDownload | None = None

    async def put(self, artifact: ArtifactRecord) -> ArtifactRecord:
        self.put_calls.append(artifact)
        return artifact

    async def get(self, artifact_id: UUID, tenant_id: str) -> ArtifactRecord:
        if self.get_result is None:
            raise AssertionError("get_result was not configured")
        assert self.get_result.artifact_id == artifact_id
        assert self.get_result.tenant_id == tenant_id
        return self.get_result

    async def delete(self, artifact_id: UUID, tenant_id: str) -> None:
        self.delete_calls.append((artifact_id, tenant_id))
        if self.delete_observer is not None:
            self.delete_observer()
        if self.delete_errors:
            raise self.delete_errors.popleft()

    def uri_for(self, artifact: ArtifactRecord) -> str:
        return f"s3://artifacts/{artifact.tenant_id}/{artifact.artifact_id}"

    async def create_download(
        self,
        artifact: ArtifactRecord,
        *,
        principal_id: str,
        tenant_id: str,
        purpose: str,
        expires_in_seconds: int,
    ) -> ArtifactDownload:
        assert artifact.tenant_id == tenant_id
        assert principal_id
        assert purpose
        assert expires_in_seconds > 0
        if self.download_result is None:
            raise AssertionError("download_result was not configured")
        return self.download_result


class _ReceiptModel(BaseModel):
    receipt_artifact_id: UUID


def _contract() -> TaskContract:
    return TaskContract(
        goal="Persist a bounded run",
        success_criteria=[
            SuccessCriterion(
                id="persisted",
                description="The run is durably persisted",
                verification="environment",
            )
        ],
        principal=Principal(
            user_id="user-1",
            tenant_id="tenant-a",
            roles=frozenset({"operator"}),
            scopes=frozenset({"agent.run"}),
            auth_strength="mfa",
        ),
        data_scope=DataScope(
            tenant_id="tenant-a",
            resource_types=frozenset({"documents"}),
        ),
        risk=RiskLevel.MEDIUM,
        constraints={"use_case": "document-review"},
        max_cost_usd=Decimal("10"),
        max_duration_seconds=600,
    )


def _plan() -> ExecutionPlan:
    return ExecutionPlan(
        plan_version=1,
        tasks=[
            TaskSpec(
                id="analyze",
                kind="analysis",
                objective="Analyze the document",
                output_schema="WorkerOutput@1.0",
                risk=RiskLevel.MEDIUM,
                estimated_cost_usd=Decimal("1"),
            )
        ],
        final_task_id="analyze",
        expected_total_cost_usd=Decimal("1"),
    )


def _run(*, with_runtime_values: bool = True) -> RunRecord:
    now = datetime.now(UTC)
    run = RunRecord(
        run_id=uuid4(),
        tenant_id="tenant-a",
        principal_id="user-1",
        contract=_contract(),
        idempotency_key=f"run-{uuid4()}",
        request_hash="a" * 64,
        workflow_id=f"workflow-{uuid4()}",
        status=RunStatus.EXECUTING,
        version=3,
        current_plan_version=1,
        cancellation_requested=True,
        pause_requested=True,
        created_at=now,
        updated_at=now,
    )
    if with_runtime_values:
        run.plan = _plan()
        run.outputs = {"analyze": WorkerOutput(summary="done"), "raw": {"count": 1}}
        run.result = FinalResponse(summary="complete")
        run.progress = 0.75
    return run


def _action(run: RunRecord | None = None) -> ActionRecord:
    selected_run = run or _run()
    now = datetime.now(UTC)
    return ActionRecord(
        action_id=uuid4(),
        run_id=selected_run.run_id,
        tenant_id=selected_run.tenant_id,
        principal_id=selected_run.principal_id,
        action_type="email.send",
        tool_name="email.prepare",
        tool_version="1.0.0",
        canonical_payload={"to": "reviewer@example.test", "subject": "Review"},
        payload_hash="b" * 64,
        preview={"summary": "Send review request"},
        risk=RiskLevel.HIGH,
        approval_policy="two-person",
        required_approvals=2,
        idempotency_key=f"action-{uuid4()}",
        policy_version="bundle-7",
        expires_at=now + timedelta(minutes=10),
        created_at=now,
        updated_at=now,
    )


def _artifact(*, run_id: UUID | None = None, expires: bool = False) -> ArtifactRecord:
    content = b"verified artifact bytes"
    return ArtifactRecord(
        artifact_id=uuid4(),
        tenant_id="tenant-a",
        run_id=run_id,
        kind="report",
        media_type="application/pdf",
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        classification="internal",
        created_by="worker-1",
        expires_at=datetime.now(UTC) + timedelta(days=7) if expires else None,
        scan_status="malware_clean",
        scan_provenance={"scanner": "clamav", "signature_version": "20260724"},
    )


def _artifact_row(record: ArtifactRecord) -> Artifact:
    return Artifact(
        artifact_id=record.artifact_id,
        run_id=record.run_id,
        tenant_id=record.tenant_id,
        task_id=None,
        kind=record.kind,
        uri=f"s3://artifacts/{record.tenant_id}/{record.artifact_id}",
        media_type=record.media_type,
        size_bytes=record.size_bytes,
        sha256=record.sha256,
        classification=record.classification.value,
        source_json={
            "scan_status": record.scan_status,
            "scan_provenance": record.scan_provenance,
        },
        created_by=record.created_by,
        retention_policy=record.retention_policy,
        encryption_key_ref=record.encryption_key_ref,
        object_version_id=record.object_version_id,
        object_retain_until=record.object_retain_until,
        legal_hold_status=record.legal_hold_status,
        expires_at=record.expires_at,
        deleted_at=record.deleted_at,
        lifecycle_status=record.lifecycle_status,
        delete_requested_at=record.delete_requested_at,
        delete_attempts=record.delete_attempts,
        delete_last_error_code=record.delete_last_error_code,
        created_at=record.created_at,
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


def test_cipher_and_serialization_boundaries_round_trip_domain_values() -> None:
    with pytest.raises(ValueError, match="ACTION_PAYLOAD_KEY_MUST_BE_32_BYTES"):
        AesGcmActionPayloadCipher(b"short")

    cipher = AesGcmActionPayloadCipher(b"k" * 32)
    with pytest.raises(ValueError, match="ACTION_PAYLOAD_CIPHERTEXT_INVALID"):
        cipher.decrypt(b"invalid", associated_data=b"tenant-a:action")

    plan = _plan()
    values: list[Any] = [
        None,
        plan,
        WorkerOutput(summary="worker output"),
        FinalResponse(summary="final output"),
        VerificationReport(verdict="pass"),
        {"plain": True},
    ]
    for value in values:
        assert _typed_load(_typed_dump(value)) == value

    unknown = {"kind": "future-envelope", "value": {"field": "value"}}
    assert _typed_load(unknown) == unknown
    assert _typed_load({"kind": "json", "value": [1, 2]}) == [1, 2]
    assert _load_outputs({"typed": _typed_dump(plan), "raw": 7}) == {
        "typed": plan,
        "raw": 7,
    }
    assert _dump_outputs({"worker": WorkerOutput(summary="done")}) == {
        "worker": {
            "kind": "worker_output",
            "value": WorkerOutput(summary="done").model_dump(mode="json"),
        }
    }
    assert _wrapped_json(None) is None
    assert _unwrapped_json(None) is None
    assert _unwrapped_json({"kind": "json", "value": {"ok": True}}) == {"ok": True}
    assert _unwrapped_json({"legacy": "row"}) == {"legacy": "row"}


def test_receipt_provenance_and_datetime_validation_cover_compatibility_edges() -> None:
    artifact_id = uuid4()
    assert _receipt_artifact_id(None) is None
    assert _receipt_artifact_id("not-a-record") is None
    assert _receipt_artifact_id({}) is None
    assert _receipt_artifact_id({"raw_receipt_artifact_id": artifact_id}) == artifact_id
    assert _receipt_artifact_id(_ReceiptModel(receipt_artifact_id=artifact_id)) == artifact_id
    with pytest.raises(ValueError, match="ACTION_RECEIPT_ARTIFACT_ID_INVALID"):
        _receipt_artifact_id({"receipt_artifact_id": "not-a-uuid"})

    assert _artifact_scan_provenance({}) == {}
    assert _artifact_scan_provenance({"scan_provenance": {"scanner": "clamav"}}) == {
        "scanner": "clamav"
    }
    with pytest.raises(PlatformError) as invalid_provenance:
        _artifact_scan_provenance({"scan_provenance": ["not", "an", "object"]})
    assert invalid_provenance.value.code == "ARTIFACT_SCAN_PROVENANCE_INVALID"

    default = datetime(2026, 7, 24, tzinfo=UTC)
    aware = datetime(2026, 7, 24, 9, 30, tzinfo=UTC)
    assert _parse_datetime(aware, default=default) is aware
    assert _parse_datetime("2026-07-24T09:30:00+00:00", default=default) == aware
    assert _parse_datetime("2026-07-24T09:30:00", default=default).tzinfo is UTC
    assert _parse_datetime(object(), default=default) is default
    assert _action_aad("tenant-a", artifact_id) == f"tenant-a:{artifact_id}".encode()


def test_run_database_projection_round_trips_runtime_and_legacy_rows() -> None:
    run = _run()
    contract = cast(TaskContract, run.contract)
    insert_values = PostgresRunRepository._insert_values(run, contract)
    assert insert_values["use_case"] == "document-review"
    assert insert_values["cancel_requested_at"] == run.updated_at
    assert insert_values["deadline_at"] == run.created_at + timedelta(seconds=600)

    database_run = AgentRun(**insert_values, version=run.version)
    runtime = RunRuntimeSnapshot(
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        **PostgresRunRepository._runtime_values(run),
        created_at=run.created_at,
    )
    projected = PostgresRunRepository._run_record(database_run, runtime)
    assert projected.plan == run.plan
    assert projected.outputs == run.outputs
    assert projected.result == run.result
    assert projected.progress == 0.75
    assert projected.cancellation_requested is True
    assert projected.pause_requested is True

    legacy = PostgresRunRepository._run_record(database_run, None)
    assert legacy.plan is None
    assert legacy.outputs == {}
    assert legacy.result is None
    assert legacy.progress == 0
    assert legacy.pause_requested is False

    contract_without_use_case = contract.model_copy(update={"constraints": {}})
    assert (
        PostgresRunRepository._update_values(run, contract_without_use_case)["use_case"]
        == "agent.run"
    )
    assert PostgresRunRepository._contract(contract) is contract
    assert PostgresRunRepository._contract(contract.model_dump(mode="json")) == contract


def test_run_event_projection_preserves_audit_identity() -> None:
    now = datetime.now(UTC)
    action_id = uuid4()
    row = RunEvent(
        event_id=42,
        run_id=uuid4(),
        tenant_id="tenant-a",
        sequence_no=3,
        event_type="action.prepared",
        schema_version="1.0",
        actor_type="runtime",
        actor_id="model-1",
        task_id="analyze",
        action_id=action_id,
        correlation_id="correlation-1",
        payload={"action_id": str(action_id)},
        payload_hash="c" * 64,
        created_at=now,
    )
    record = PostgresRunRepository._event_record(row)
    assert record.event_id == "42"
    assert record.actor_type == "runtime"
    assert record.action_id == action_id
    assert record.payload_hash == "c" * 64


@pytest.mark.asyncio
async def test_trajectory_transaction_delegates_event_and_versioned_save() -> None:
    run = _run()
    event = EventRecord(
        event_id="1",
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        sequence_no=1,
        event_type="run.created",
        payload={},
        correlation_id="correlation-1",
    )
    append_event = AsyncMock(return_value=event)
    save_run = AsyncMock(return_value=run)
    repository = cast(
        PostgresRunRepository,
        SimpleNamespace(
            _append_event_in_session=append_event,
            _save_in_session=save_run,
        ),
    )
    session = cast(Any, _FakeSession())
    transaction = _PostgresRunTrajectoryTransaction(repository, session, run, (event,))

    appended = await transaction.append_event(
        AuditEvent(
            event_type="trajectory.checked",
            payload={"decision": "continue"},
            correlation_id="correlation-2",
            actor_type="guard",
            actor_id="trajectory-guard",
            task_id="analyze",
        )
    )
    saved = await transaction.save_run(3)

    assert appended is event
    assert transaction.events == (event, event)
    assert saved is run
    append_event.assert_awaited_once()
    save_run.assert_awaited_once_with(session, run, 3)


@pytest.mark.asyncio
async def test_run_repository_public_transactions_commit_and_preserve_creation_semantics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _run()
    event = EventRecord(
        event_id="1",
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        sequence_no=1,
        event_type="run.created",
        payload={},
        correlation_id="correlation-1",
    )
    sessions = [_FakeSession() for _ in range(8)]
    _patch_tenant_sessions(monkeypatch, *sessions)
    repository = PostgresRunRepository(cast(Any, object()))

    create = AsyncMock(return_value=(run, True))
    append = AsyncMock(return_value=event)
    get = AsyncMock(return_value=run)
    save = AsyncMock(return_value=run)
    monkeypatch.setattr(repository, "_create_once_in_session", create)
    monkeypatch.setattr(repository, "_append_event_in_session", append)
    monkeypatch.setattr(repository, "_get_in_session", get)
    monkeypatch.setattr(repository, "_save_in_session", save)

    assert await repository.create_once(run) == (run, True)
    assert await repository.create_once_with_event(run, "run.created", {}, "correlation-1") == (
        run,
        True,
        event,
    )
    create.return_value = (run, False)
    assert await repository.create_once_with_event(run, "run.created", {}, "correlation-2") == (
        run,
        False,
        None,
    )
    assert await repository.get(run.run_id, run.tenant_id) is run
    assert await repository.save(run, 3) is run
    assert await repository.save_with_event(
        run, 3, "run.updated", {"progress": 0.75}, "correlation-3"
    ) == (run, event)
    assert await repository.append_event(run, "run.updated", {}, "correlation-4") is event

    assert [session.commit_count for session in sessions[:7]] == [1, 1, 1, 0, 1, 1, 1]


@pytest.mark.asyncio
async def test_run_repository_internal_create_and_lock_conflicts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _run()
    repository = PostgresRunRepository(cast(Any, object()))
    stored = AsyncMock(return_value=run)
    monkeypatch.setattr(repository, "_get_in_session", stored)

    created_session = _FakeSession(scalar_results=[run.run_id])
    created, was_created = await repository._create_once_in_session(
        cast(Any, created_session),
        run,
        cast(TaskContract, run.contract),
    )
    assert created is run
    assert was_created is True
    assert any(isinstance(item, RunRuntimeSnapshot) for item in created_session.added)

    matching = cast(
        AgentRun,
        SimpleNamespace(
            run_id=run.run_id,
            request_hash=run.request_hash,
        ),
    )
    duplicate_session = _FakeSession(scalar_results=[None, matching])
    duplicate, was_created = await repository._create_once_in_session(
        cast(Any, duplicate_session),
        run,
        cast(TaskContract, run.contract),
    )
    assert duplicate is run
    assert was_created is False

    with pytest.raises(Conflict) as missing_after_conflict:
        await repository._create_once_in_session(
            cast(Any, _FakeSession(scalar_results=[None, None])),
            run,
            cast(TaskContract, run.contract),
        )
    assert missing_after_conflict.value.code == "RUN_CREATE_CONFLICT"

    reused = SimpleNamespace(run_id=run.run_id, request_hash="different")
    with pytest.raises(Conflict) as reused_key:
        await repository._create_once_in_session(
            cast(Any, _FakeSession(scalar_results=[None, reused])),
            run,
            cast(TaskContract, run.contract),
        )
    assert reused_key.value.code == "IDEMPOTENCY_KEY_REUSED"

    assert (
        await repository._require_run(
            cast(Any, _FakeSession(scalar_results=[matching])),
            run.run_id,
            run.tenant_id,
            lock=True,
        )
        is matching
    )
    with pytest.raises(NotFound):
        await repository._require_run(
            cast(Any, _FakeSession(scalar_results=[None])),
            run.run_id,
            run.tenant_id,
        )


@pytest.mark.asyncio
async def test_run_repository_get_save_and_append_event_failure_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _run()
    repository = PostgresRunRepository(cast(Any, object()))
    with pytest.raises(NotFound):
        await repository._get_in_session(
            cast(Any, _FakeSession(execute_results=[_Result(None)])),
            run.run_id,
            run.tenant_id,
        )

    database_run = AgentRun(
        **PostgresRunRepository._insert_values(run, cast(TaskContract, run.contract)),
        version=run.version,
    )
    loaded = await repository._get_in_session(
        cast(Any, _FakeSession(execute_results=[_Result((database_run, None))])),
        run.run_id,
        run.tenant_id,
    )
    assert loaded.run_id == run.run_id

    get_after_save = AsyncMock(return_value=run)
    monkeypatch.setattr(repository, "_get_in_session", get_after_save)
    successful = _FakeSession(
        scalar_results=[4],
        execute_results=[_Result(None)],
    )
    assert await repository._save_in_session(cast(Any, successful), run, 3) is run
    assert successful.flush_count == 1

    with pytest.raises(NotFound):
        await repository._save_in_session(
            cast(Any, _FakeSession(scalar_results=[None, None])),
            run,
            3,
        )
    with pytest.raises(Conflict) as stale:
        await repository._save_in_session(
            cast(
                Any,
                _FakeSession(
                    scalar_results=[None, SimpleNamespace(version=9)],
                ),
            ),
            run,
            3,
        )
    assert stale.value.code == "OPTIMISTIC_LOCK_CONFLICT"

    require = AsyncMock(return_value=database_run)
    monkeypatch.setattr(repository, "_require_run", require)
    event_session = _FakeSession(execute_results=[_Result(5)])
    event = await repository._append_event_in_session(
        cast(Any, event_session),
        run,
        "run.updated",
        {"progress": Decimal("0.75")},
        "correlation-5",
        actor_type="runtime",
        actor_id=None,
        task_id="analyze",
    )
    assert event.sequence_no == 5
    assert event.actor_id == run.principal_id
    assert len(event_session.added) == 2


def test_action_projection_encrypts_payload_and_round_trips_approvals() -> None:
    run = _run()
    action = _action(run)
    receipt_id = uuid4()
    action.receipt = {
        "raw_receipt_artifact_id": str(receipt_id),
        "provider_request_id": "provider-1",
    }
    action.verification = {"passed": True}
    action.status = ActionStatus.COMMITTED
    cipher = AesGcmActionPayloadCipher(b"a" * 32)
    repository = PostgresActionRepository(cast(Any, object()), cipher)

    values = repository._action_values(action)
    assert values["receipt_artifact_id"] == receipt_id
    assert values["status"] is DatabaseActionStatus.COMMITTED
    decrypted = cipher.decrypt(
        values["payload_encrypted"],
        associated_data=_action_aad(action.tenant_id, action.action_id),
    )
    assert json.loads(decrypted) == action.canonical_payload
    assert values["receipt_json"] == {"kind": "json", "value": action.receipt}

    approval = Approval(
        approval_id=uuid4(),
        action_id=action.action_id,
        tenant_id=action.tenant_id,
        actor_id="approver-1",
        actor_roles=["approver"],
        auth_strength="mfa",
        decision=ApprovalDecision.APPROVED,
        payload_hash=action.payload_hash,
        comment="approved",
        policy_version=action.policy_version,
        created_at=action.updated_at,
    )
    projected = repository._approval_record(approval)
    assert projected["decision"] == "approved"
    assert projected["actor_roles"] == ["approver"]
    assert projected["created_at"] == action.updated_at.isoformat()


@pytest.mark.asyncio
async def test_action_row_projection_rejects_non_object_payload() -> None:
    action = _action()
    cipher = AesGcmActionPayloadCipher(b"a" * 32)
    repository = PostgresActionRepository(cast(Any, object()), cipher)
    values = repository._action_values(action)
    row = PreparedAction(**values)

    approval = Approval(
        approval_id=uuid4(),
        action_id=action.action_id,
        tenant_id=action.tenant_id,
        actor_id="approver-1",
        actor_roles=["approver"],
        auth_strength="mfa",
        decision=ApprovalDecision.APPROVED,
        payload_hash=action.payload_hash,
        comment=None,
        policy_version=action.policy_version,
        created_at=action.updated_at,
    )
    projected = await repository._record_from_row(
        cast(Any, _FakeSession(scalars_results=[[approval]])),
        row,
    )
    assert projected.canonical_payload == action.canonical_payload
    assert projected.approvals[0]["actor_id"] == "approver-1"

    row.payload_encrypted = cipher.encrypt(
        b'["not-an-object"]',
        associated_data=_action_aad(action.tenant_id, action.action_id),
    )
    with pytest.raises(PlatformError) as invalid:
        await repository._record_from_row(
            cast(Any, _FakeSession(scalars_results=[[]])),
            row,
        )
    assert invalid.value.code == "ACTION_PAYLOAD_INVALID"


@pytest.mark.asyncio
async def test_action_approval_append_validates_shape_and_run_visibility() -> None:
    action = _action()
    action.approvals = [
        {
            "actor_id": "approver-1",
            "actor_roles": ["approver", "security"],
            "auth_strength": "mfa",
            "decision": "approved",
            "comment": "looks good",
            "created_at": "2026-07-24T10:00:00",
        }
    ]
    repository = PostgresActionRepository(
        cast(Any, object()),
        AesGcmActionPayloadCipher(b"a" * 32),
    )
    session = _FakeSession()
    await repository._replace_approvals(cast(Any, session), action)
    assert session.flush_count == 1
    assert len(session.execute_results) == 0

    action.approvals = ["invalid"]
    with pytest.raises(ValueError, match="ACTION_APPROVAL_RECORD_MUST_BE_A_MAPPING"):
        await repository._replace_approvals(cast(Any, _FakeSession()), action)

    await repository._require_run(
        cast(Any, _FakeSession(scalar_results=[action.run_id])),
        action.run_id,
        action.tenant_id,
    )
    with pytest.raises(NotFound):
        await repository._require_run(
            cast(Any, _FakeSession(scalar_results=[None])),
            action.run_id,
            action.tenant_id,
        )


@pytest.mark.asyncio
async def test_action_create_rejects_mismatched_audit_inputs_before_database_access() -> None:
    action = _action()
    repository = PostgresActionRepository(
        cast(Any, object()),
        AesGcmActionPayloadCipher(b"a" * 32),
    )
    with pytest.raises(ValueError, match="AUDIT_EVENT_ACTION_MISMATCH"):
        await repository.create_once_with_event(
            action,
            AuditEvent(
                event_type="action.prepared",
                payload={},
                correlation_id="correlation-1",
                action_id=uuid4(),
            ),
        )

    wrong_run = _run()
    with pytest.raises(ValueError, match="TOOL_INVOCATION_RUN_MISMATCH"):
        await repository.create_once_with_event(
            action,
            AuditEvent(
                event_type="action.prepared",
                payload={},
                correlation_id="correlation-1",
            ),
            _invocation(wrong_run),
        )


@pytest.mark.asyncio
async def test_action_lock_context_persists_recovery_state_on_success_and_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action = _action()
    row = SimpleNamespace(version=4)
    sessions = [
        _FakeSession(scalar_results=[row]),
        _FakeSession(scalar_results=[row]),
    ]
    _patch_tenant_sessions(monkeypatch, *sessions)
    repository = PostgresActionRepository(
        cast(Any, object()),
        AesGcmActionPayloadCipher(b"a" * 32),
    )
    record = AsyncMock(return_value=action)
    persist = AsyncMock()
    monkeypatch.setattr(repository, "_record_from_row", record)
    monkeypatch.setattr(repository, "_persist_locked", persist)

    async with repository.get_for_update(action.action_id, action.tenant_id) as working:
        working.status = ActionStatus.APPROVED
    assert sessions[0].commit_count == 1

    with pytest.raises(RuntimeError, match="provider timeout"):
        async with repository.get_for_update(action.action_id, action.tenant_id) as working:
            working.status = ActionStatus.UNKNOWN
            raise RuntimeError("provider timeout")
    assert sessions[1].commit_count == 1
    assert persist.await_count == 2


@pytest.mark.asyncio
async def test_action_audit_transaction_persists_changed_state_and_audit_facts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _run()
    action = _action(run)
    baseline = _action(run)
    baseline.action_id = action.action_id
    baseline.canonical_payload = dict(action.canonical_payload)
    baseline.payload_hash = action.payload_hash
    baseline.idempotency_key = action.idempotency_key
    baseline.created_at = action.created_at
    baseline.updated_at = action.updated_at
    action.status = ActionStatus.COMMITTED
    transaction = ActionAuditTransaction(action=action)
    transaction.append_tool_invocation(_invocation(run))
    transaction.append_event(
        AuditEvent(
            event_type="action.committed",
            payload={"action_id": str(action.action_id)},
            correlation_id="correlation-commit",
            action_id=action.action_id,
        )
    )
    repository = PostgresActionRepository(
        cast(Any, object()),
        AesGcmActionPayloadCipher(b"a" * 32),
    )
    persist = AsyncMock()
    loaded_run = AsyncMock(return_value=run)
    appended = AsyncMock()
    invocation_append = AsyncMock()
    monkeypatch.setattr(repository, "_persist_locked", persist)
    monkeypatch.setattr(repository._runs, "_get_in_session", loaded_run)
    monkeypatch.setattr(repository._runs, "_append_event_in_session", appended)
    monkeypatch.setattr(production_store, "append_tool_invocation", invocation_append)

    await repository._persist_audit_transaction(
        cast(Any, _FakeSession()),
        transaction,
        baseline,
        1,
    )
    persist.assert_awaited_once()
    invocation_append.assert_awaited_once()
    appended.assert_awaited_once()

    no_change = ActionAuditTransaction(action=action)
    await repository._persist_audit_transaction(
        cast(Any, _FakeSession()),
        no_change,
        action,
        1,
    )
    assert persist.await_count == 1


@pytest.mark.asyncio
async def test_action_optimistic_lock_reports_missing_and_stale_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action = _action()
    repository = PostgresActionRepository(
        cast(Any, object()),
        AesGcmActionPayloadCipher(b"a" * 32),
    )
    _patch_tenant_sessions(
        monkeypatch,
        _FakeSession(scalar_results=[None, None]),
        _FakeSession(scalar_results=[None, SimpleNamespace(version=8)]),
    )
    with pytest.raises(NotFound):
        await repository.save(action, 1)
    with pytest.raises(Conflict) as stale:
        await repository.save(action, 1)
    assert stale.value.code == "OPTIMISTIC_LOCK_CONFLICT"

    with pytest.raises(Conflict) as locked:
        await repository._persist_locked(
            cast(Any, _FakeSession(scalar_results=[None])),
            action,
            1,
        )
    assert locked.value.code == "OPTIMISTIC_LOCK_CONFLICT"


@pytest.mark.asyncio
async def test_artifact_put_enforces_hash_run_visibility_and_compensates_new_objects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content_store = _FakeContentStore()
    store = PostgresArtifactStore(cast(Any, object()), content_store)
    invalid = _artifact()
    invalid.sha256 = "0" * 64
    with pytest.raises(PlatformError) as hash_error:
        await store.put(invalid)
    assert hash_error.value.code == "ARTIFACT_HASH_MISMATCH"

    run_id = uuid4()
    missing_run_artifact = _artifact(run_id=run_id)
    _patch_tenant_sessions(
        monkeypatch,
        _FakeSession(scalar_results=[None]),
    )
    with pytest.raises(NotFound):
        await store.put(missing_run_artifact)

    artifact = _artifact()
    _patch_tenant_sessions(
        monkeypatch,
        _FakeSession(scalar_results=[None]),
        _FakeSession(scalar_results=[artifact.artifact_id]),
    )
    assert await store.put(artifact) is artifact
    assert content_store.put_calls[-1] is artifact

    conflicting = _artifact()
    _patch_tenant_sessions(
        monkeypatch,
        _FakeSession(scalar_results=[None]),
        _FakeSession(scalar_results=[None]),
    )
    with pytest.raises(Conflict) as conflict:
        await store.put(conflicting)
    assert conflict.value.code == "ARTIFACT_ID_CONFLICT"
    assert content_store.delete_calls[-1] == (
        conflicting.artifact_id,
        conflicting.tenant_id,
    )


@pytest.mark.asyncio
async def test_artifact_existing_identity_is_idempotent_without_object_rewrite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content_store = _FakeContentStore()
    store = PostgresArtifactStore(cast(Any, object()), content_store)
    artifact = _artifact()
    _patch_tenant_sessions(
        monkeypatch,
        _FakeSession(scalar_results=[_artifact_row(artifact)]),
    )

    restored = await store.put(artifact)

    assert restored.artifact_id == artifact.artifact_id
    assert restored.sha256 == artifact.sha256
    assert content_store.put_calls == []
    assert content_store.delete_calls == []


@pytest.mark.asyncio
async def test_artifact_existing_id_rejects_new_content_before_object_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content_store = _FakeContentStore()
    store = PostgresArtifactStore(cast(Any, object()), content_store)
    original = _artifact()
    changed = _artifact()
    changed.artifact_id = original.artifact_id
    changed.content = b"different immutable content"
    changed.size_bytes = len(changed.content)
    changed.sha256 = hashlib.sha256(changed.content).hexdigest()
    _patch_tenant_sessions(
        monkeypatch,
        _FakeSession(scalar_results=[_artifact_row(original)]),
    )

    with pytest.raises(Conflict) as conflict:
        await store.put(changed)

    assert conflict.value.code == "ARTIFACT_IMMUTABLE_CONFLICT"
    assert {"sha256", "size_bytes"}.issubset(
        set(conflict.value.context["differing_fields"])
    )
    assert content_store.put_calls == []
    assert content_store.delete_calls == []


@pytest.mark.asyncio
async def test_artifact_get_materializes_metadata_and_verifies_object_integrity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content_store = _FakeContentStore()
    store = PostgresArtifactStore(cast(Any, object()), content_store)
    artifact = _artifact(expires=True)
    metadata = Artifact(**store._metadata_values(artifact))
    content_store.get_result = artifact
    _patch_tenant_sessions(monkeypatch, _FakeSession(scalar_results=[metadata]))

    stored = await store.get(artifact.artifact_id, artifact.tenant_id)
    assert stored.content == artifact.content
    assert stored.scan_status == "malware_clean"
    assert stored.scan_provenance["scanner"] == "clamav"

    _patch_tenant_sessions(monkeypatch, _FakeSession(scalar_results=[None]))
    with pytest.raises(NotFound):
        await store.get(uuid4(), artifact.tenant_id)

    corrupted = _artifact()
    corrupted.artifact_id = artifact.artifact_id
    corrupted.tenant_id = artifact.tenant_id
    corrupted.content = b"tampered"
    content_store.get_result = corrupted
    _patch_tenant_sessions(monkeypatch, _FakeSession(scalar_results=[metadata]))
    with pytest.raises(PlatformError) as integrity:
        await store.get(artifact.artifact_id, artifact.tenant_id)
    assert integrity.value.code == "ARTIFACT_HASH_MISMATCH"


@pytest.mark.asyncio
async def test_artifact_download_is_bound_to_audited_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content_store = _FakeContentStore()
    store = PostgresArtifactStore(cast(Any, object()), content_store)
    artifact = _artifact()
    metadata = Artifact(**store._metadata_values(artifact))
    download = ArtifactDownload(
        artifact_id=artifact.artifact_id,
        url="https://objects.example.test/signed",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    content_store.download_result = download

    for principal_id, tenant_id, purpose in (
        ("", artifact.tenant_id, "download"),
        ("user-1", "tenant-b", "download"),
        ("user-1", artifact.tenant_id, " "),
    ):
        with pytest.raises(ValueError, match="ARTIFACT_DOWNLOAD_AUDIT_CONTEXT_INVALID"):
            await store.create_download(
                artifact,
                principal_id=principal_id,
                tenant_id=tenant_id,
                purpose=purpose,
                expires_in_seconds=300,
            )

    _patch_tenant_sessions(monkeypatch, _FakeSession(scalar_results=[None]))
    with pytest.raises(NotFound):
        await store.create_download(
            artifact,
            principal_id="user-1",
            tenant_id=artifact.tenant_id,
            purpose="download",
            expires_in_seconds=300,
        )

    session = _FakeSession(scalar_results=[metadata])
    _patch_tenant_sessions(monkeypatch, session)
    issued = await store.create_download(
        artifact,
        principal_id="user-1",
        tenant_id=artifact.tenant_id,
        purpose="download",
        expires_in_seconds=300,
    )
    assert issued is download
    assert session.commit_count == 1
    assert len(session.added) == 1


@pytest.mark.asyncio
async def test_artifact_delete_commits_pending_before_object_then_finalizes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content_store = _FakeContentStore()
    store = PostgresArtifactStore(cast(Any, object()), content_store)
    artifact_id = uuid4()
    missing_session = _FakeSession(scalar_results=[None])
    pending_session = _FakeSession(scalar_results=[artifact_id])
    finalized_session = _FakeSession(scalar_results=[artifact_id])
    observed_boundaries: list[str] = []

    def observe_object_delete() -> None:
        assert pending_session.commit_count == 1
        assert finalized_session.commit_count == 0
        observed_boundaries.append("pending_committed_before_object_delete")

    content_store.delete_observer = observe_object_delete
    _patch_tenant_sessions(
        monkeypatch,
        missing_session,
        pending_session,
        finalized_session,
    )
    with pytest.raises(NotFound):
        await store.delete(artifact_id, "tenant-a")

    await store.delete(artifact_id, "tenant-a")
    assert content_store.delete_calls == [(artifact_id, "tenant-a")]
    assert missing_session.commit_count == 0
    assert pending_session.commit_count == 1
    assert finalized_session.commit_count == 1
    assert observed_boundaries == ["pending_committed_before_object_delete"]

    expiring = _artifact(expires=True)
    expiring.retention_policy = "classification:internal:90d"
    expiring.encryption_key_ref = (
        "arn:aws:kms:ap-southeast-1:111122223333:key/general"
    )
    expiring_values = store._metadata_values(expiring)
    assert expiring_values["retention_policy"] == "classification:internal:90d"
    assert expiring_values["encryption_key_ref"].endswith("/general")
    assert expiring_values["size_bytes"] == len(expiring.content)
    assert expiring_values["source_json"]["scan_status"] == "malware_clean"
    assert store._metadata_values(_artifact())["retention_policy"] == "default"


@pytest.mark.asyncio
async def test_artifact_delete_failure_is_durably_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content_store = _FakeContentStore()
    content_store.delete_errors.append(RuntimeError("object store unavailable"))
    store = PostgresArtifactStore(cast(Any, object()), content_store)
    artifact_id = uuid4()
    first_pending = _FakeSession(scalar_results=[artifact_id])
    error_persisted = _FakeSession()
    retry_pending = _FakeSession(scalar_results=[artifact_id])
    retry_finalized = _FakeSession(scalar_results=[artifact_id])
    _patch_tenant_sessions(
        monkeypatch,
        first_pending,
        error_persisted,
        retry_pending,
        retry_finalized,
    )

    with pytest.raises(PlatformError) as pending:
        await store.delete(artifact_id, "tenant-a")

    assert pending.value.code == "ARTIFACT_DELETE_PENDING"
    assert pending.value.retryable is True
    assert pending.value.context["storage_error_code"] == "RUNTIMEERROR"
    assert first_pending.commit_count == 1
    assert error_persisted.commit_count == 1
    assert len(error_persisted.executed_statements) == 1
    error_values = error_persisted.executed_statements[0].compile().params.values()
    assert "RUNTIMEERROR" in error_values
    assert content_store.delete_calls == [(artifact_id, "tenant-a")]

    await store.delete(artifact_id, "tenant-a")

    assert retry_pending.commit_count == 1
    assert retry_finalized.commit_count == 1
    assert content_store.delete_calls == [
        (artifact_id, "tenant-a"),
        (artifact_id, "tenant-a"),
    ]


@pytest.mark.asyncio
async def test_capability_store_applies_tenant_override_and_enable_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = PostgresCapabilityStore(cast(Any, object()))
    global_row = CapabilityRecordRow(
        tenant_id="*",
        capability_name="knowledge.search",
        version="1.0.0",
        effect="read",
        risk="low",
        enabled=True,
        disabled_reason=None,
        policy_version="bundle-1",
    )
    tenant_row = CapabilityRecordRow(
        tenant_id="tenant-a",
        capability_name="knowledge.search",
        version="1.1.0",
        effect="read",
        risk="medium",
        enabled=False,
        disabled_reason="maintenance",
        policy_version="bundle-2",
    )
    other_global = CapabilityRecordRow(
        tenant_id="*",
        capability_name="documents.read",
        version="2.0.0",
        effect="read",
        risk="low",
        enabled=True,
        disabled_reason=None,
        policy_version="bundle-1",
    )
    registered = _FakeSession()
    listed = _FakeSession(scalars_results=[[global_row, tenant_row, other_global]])
    _patch_tenant_sessions(monkeypatch, registered, listed)

    record = CapabilityRecord(
        name="knowledge.search",
        version="1.1.0",
        effect="read",
        risk="medium",
        enabled=False,
        disabled_reason="maintenance",
        policy_version="bundle-2",
    )
    await store.register("tenant-a", record)
    visible = await store.list("tenant-a")
    assert registered.commit_count == 1
    assert [item.name for item in visible] == ["documents.read", "knowledge.search"]
    assert visible[1].version == "1.1.0"
    assert visible[1].enabled is False
    assert PostgresCapabilityStore._values(record)["disabled_reason"] == "maintenance"


@pytest.mark.asyncio
async def test_capability_enable_uses_global_fallback_and_rejects_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = PostgresCapabilityStore(cast(Any, object()))
    global_row = CapabilityRecordRow(
        tenant_id="*",
        capability_name="knowledge.search",
        version="1.0.0",
        effect="read",
        risk="low",
        enabled=True,
        disabled_reason=None,
        policy_version="bundle-1",
    )
    disabled_row = CapabilityRecordRow(
        tenant_id="tenant-a",
        capability_name="knowledge.search",
        version="1.0.0",
        effect="read",
        risk="low",
        enabled=False,
        disabled_reason="incident",
        policy_version="bundle-1",
    )
    _patch_tenant_sessions(
        monkeypatch,
        _FakeSession(scalars_results=[[]]),
        _FakeSession(
            scalars_results=[[global_row]],
            execute_results=[_Result(disabled_row)],
        ),
    )
    with pytest.raises(NotFound):
        await store.set_enabled("tenant-a", "unknown", False, "incident")
    disabled = await store.set_enabled(
        "tenant-a",
        "knowledge.search",
        False,
        "incident",
    )
    assert disabled.enabled is False
    assert disabled.disabled_reason == "incident"


def test_platform_store_composes_all_production_adapters() -> None:
    platform = PostgresPlatformStore(
        cast(Any, object()),
        action_payload_cipher=AesGcmActionPayloadCipher(b"a" * 32),
        artifact_content_store=_FakeContentStore(),
    )
    assert isinstance(platform.runs, PostgresRunRepository)
    assert isinstance(platform.actions, PostgresActionRepository)
    assert isinstance(platform.artifacts, PostgresArtifactStore)
    assert isinstance(platform.capabilities, PostgresCapabilityStore)
