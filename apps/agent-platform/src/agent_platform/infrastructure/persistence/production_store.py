"""Port-compatible PostgreSQL adapters for the application service layer.

Every public operation opens a transaction-scoped tenant session. Snapshot
updates, Run events, and their outbox records can be committed atomically via
``save_with_event`` so application services can feature-detect the stronger
production path while retaining the in-memory fallback.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import secrets
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Protocol, cast
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel
from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

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
from agent_platform.domain.enums import (
    ActionStatus as DomainActionStatus,
)
from agent_platform.domain.enums import (
    RiskLevel as DomainRiskLevel,
)
from agent_platform.domain.enums import (
    RunStatus as DomainRunStatus,
)
from agent_platform.domain.hashing import canonical_json, payload_hash
from agent_platform.domain.models import (
    ExecutionPlan,
    FinalResponse,
    TaskContract,
    VerificationReport,
    WorkerOutput,
)
from agent_platform.infrastructure.persistence.artifact_models import (
    ArtifactDownloadAudit,
)
from agent_platform.infrastructure.persistence.audit import (
    PostgresAuditRepository,
    append_tool_invocation,
)
from agent_platform.infrastructure.persistence.models import (
    ActionStatus as DatabaseActionStatus,
)
from agent_platform.infrastructure.persistence.models import (
    AgentRun,
    Approval,
    Artifact,
    OutboxEvent,
    PreparedAction,
    RunEvent,
)
from agent_platform.infrastructure.persistence.models import (
    ApprovalDecision as DatabaseApprovalDecision,
)
from agent_platform.infrastructure.persistence.models import (
    RiskLevel as DatabaseRiskLevel,
)
from agent_platform.infrastructure.persistence.models import (
    RunStatus as DatabaseRunStatus,
)
from agent_platform.infrastructure.persistence.runtime_models import (
    CapabilityRecordRow,
    RunRuntimeSnapshot,
)
from agent_platform.infrastructure.persistence.session import (
    AsyncSessionFactory,
    tenant_session,
)


class ActionPayloadCipher(Protocol):
    """Encrypt immutable action payloads before they enter PostgreSQL."""

    def encrypt(self, plaintext: bytes, *, associated_data: bytes) -> bytes: ...
    def decrypt(self, ciphertext: bytes, *, associated_data: bytes) -> bytes: ...


class AesGcmActionPayloadCipher:
    """Versioned AES-256-GCM envelope for prepared-action payloads."""

    _PREFIX = b"agp1"
    _NONCE_BYTES = 12

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("ACTION_PAYLOAD_KEY_MUST_BE_32_BYTES")
        self._cipher = AESGCM(key)

    def encrypt(self, plaintext: bytes, *, associated_data: bytes) -> bytes:
        nonce = secrets.token_bytes(self._NONCE_BYTES)
        return self._PREFIX + nonce + self._cipher.encrypt(nonce, plaintext, associated_data)

    def decrypt(self, ciphertext: bytes, *, associated_data: bytes) -> bytes:
        boundary = len(self._PREFIX) + self._NONCE_BYTES
        if len(ciphertext) <= boundary or not ciphertext.startswith(self._PREFIX):
            raise ValueError("ACTION_PAYLOAD_CIPHERTEXT_INVALID")
        nonce = ciphertext[len(self._PREFIX) : boundary]
        return self._cipher.decrypt(nonce, ciphertext[boundary:], associated_data)


class ArtifactContentStore(Protocol):
    """Object-store half of the composed ArtifactStore adapter."""

    async def put(self, artifact: ArtifactRecord) -> ArtifactRecord: ...
    async def put_file(self, artifact: ArtifactRecord, path: Path) -> ArtifactRecord: ...
    async def get(self, artifact_id: UUID, tenant_id: str) -> ArtifactRecord: ...
    async def delete(self, artifact_id: UUID, tenant_id: str) -> None: ...
    def uri_for(self, artifact: ArtifactRecord) -> str: ...
    async def create_download(
        self,
        artifact: ArtifactRecord,
        *,
        principal_id: str,
        tenant_id: str,
        purpose: str,
        expires_in_seconds: int,
    ) -> ArtifactDownload: ...


def _json_value(value: Any) -> Any:
    """Convert supported domain values to deterministic JSON without pickle."""
    return json.loads(canonical_json(value))


def _artifact_scan_provenance(source: Mapping[str, Any]) -> dict[str, Any]:
    raw = source.get("scan_provenance")
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        raise PlatformError(
            "ARTIFACT_SCAN_PROVENANCE_INVALID",
            "Stored Artifact scan provenance is invalid",
            http_status=503,
        )
    materialized = _json_value(raw)
    if not isinstance(materialized, dict):
        raise PlatformError(
            "ARTIFACT_SCAN_PROVENANCE_INVALID",
            "Stored Artifact scan provenance is invalid",
            http_status=503,
        )
    return materialized


def _typed_dump(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    kinds: tuple[tuple[type[BaseModel], str], ...] = (
        (ExecutionPlan, "execution_plan"),
        (WorkerOutput, "worker_output"),
        (FinalResponse, "final_response"),
        (VerificationReport, "verification_report"),
    )
    for model_type, kind in kinds:
        if isinstance(value, model_type):
            return {"kind": kind, "value": _json_value(value)}
    return {"kind": "json", "value": _json_value(value)}


def _typed_load(envelope: Mapping[str, Any] | None) -> Any:
    if envelope is None:
        return None
    kind = envelope.get("kind")
    value = envelope.get("value")
    if kind == "execution_plan":
        return ExecutionPlan.model_validate(value)
    if kind == "worker_output":
        return WorkerOutput.model_validate(value)
    if kind == "final_response":
        return FinalResponse.model_validate(value)
    if kind == "verification_report":
        return VerificationReport.model_validate(value)
    # Compatibility with future JSON-only values and pre-envelope rows.
    if kind == "json":
        return value
    return dict(envelope)


def _dump_outputs(outputs: Mapping[str, Any]) -> dict[str, Any]:
    return {key: _typed_dump(value) for key, value in outputs.items()}


def _load_outputs(outputs: Mapping[str, Any]) -> dict[str, Any]:
    loaded: dict[str, Any] = {}
    for key, value in outputs.items():
        loaded[str(key)] = (
            _typed_load(cast(Mapping[str, Any], value)) if isinstance(value, Mapping) else value
        )
    return loaded


def _wrapped_json(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    return {"kind": "json", "value": _json_value(value)}


def _unwrapped_json(value: Mapping[str, Any] | None) -> Any:
    if value is None:
        return None
    if value.get("kind") == "json" and "value" in value:
        return value["value"]
    return dict(value)


def _receipt_artifact_id(receipt: Any) -> UUID | None:
    if isinstance(receipt, BaseModel):
        receipt = receipt.model_dump(mode="python")
    if not isinstance(receipt, Mapping):
        return None
    value = receipt.get("raw_receipt_artifact_id") or receipt.get("receipt_artifact_id")
    if value is None:
        return None
    try:
        return UUID(str(value))
    except ValueError:
        raise ValueError("ACTION_RECEIPT_ARTIFACT_ID_INVALID") from None


def _action_aad(tenant_id: str, action_id: UUID) -> bytes:
    return f"{tenant_id}:{action_id}".encode()


def _parse_datetime(value: Any, *, default: datetime) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
    return default


class _PostgresRunTrajectoryTransaction:
    """Tenant transaction holding the authoritative Run row lock."""

    def __init__(
        self,
        repository: PostgresRunRepository,
        session: AsyncSession,
        run: RunRecord,
        events: tuple[EventRecord, ...],
    ) -> None:
        self._repository = repository
        self._session = session
        self.run = run
        self._events = list(events)

    @property
    def events(self) -> tuple[EventRecord, ...]:
        return tuple(self._events)

    async def append_event(self, event: AuditEvent) -> EventRecord:
        stored = await self._repository._append_event_in_session(
            self._session,
            self.run,
            event.event_type,
            event.payload,
            event.correlation_id,
            actor_type=event.actor_type,
            actor_id=event.actor_id,
            task_id=event.task_id,
            action_id=event.action_id,
        )
        self._events.append(stored)
        return stored

    async def save_run(self, expected_version: int) -> RunRecord:
        self.run = await self._repository._save_in_session(
            self._session,
            self.run,
            expected_version,
        )
        return self.run


class PostgresRunRepository:
    # Run creation commits before the external Temporal start call. Retrying a
    # duplicate start is therefore required to heal a prior network failure.
    retry_workflow_start_on_duplicate = True

    def __init__(self, factory: AsyncSessionFactory) -> None:
        self._factory = factory

    async def create_once(self, run: RunRecord) -> tuple[RunRecord, bool]:
        contract = self._contract(run.contract)
        async with tenant_session(self._factory, run.tenant_id) as session:
            stored, created = await self._create_once_in_session(session, run, contract)
            await session.commit()
            return stored, created

    async def create_once_with_event(
        self,
        run: RunRecord,
        event_type: str,
        payload: Mapping[str, Any],
        correlation_id: str,
    ) -> tuple[RunRecord, bool, EventRecord | None]:
        """Atomically create the Run snapshot, first event, and outbox row."""
        contract = self._contract(run.contract)
        async with tenant_session(self._factory, run.tenant_id) as session:
            stored, created = await self._create_once_in_session(session, run, contract)
            event = (
                await self._append_event_in_session(
                    session,
                    stored,
                    event_type,
                    payload,
                    correlation_id,
                )
                if created
                else None
            )
            await session.commit()
            return stored, created, event

    async def get(self, run_id: UUID, tenant_id: str) -> RunRecord:
        async with tenant_session(self._factory, tenant_id) as session:
            return await self._get_in_session(session, run_id, tenant_id)

    async def resolve_contract(self, run_id: UUID, tenant_id: str) -> TaskContract:
        """Resolve the authoritative per-Run limits for Temporal start commands."""
        run = await self.get(run_id, tenant_id)
        return self._contract(run.contract)

    async def save(self, run: RunRecord, expected_version: int) -> RunRecord:
        async with tenant_session(self._factory, run.tenant_id) as session:
            stored = await self._save_in_session(session, run, expected_version)
            await session.commit()
            return stored

    async def save_with_event(
        self,
        run: RunRecord,
        expected_version: int,
        event_type: str,
        payload: Mapping[str, Any],
        correlation_id: str,
    ) -> tuple[RunRecord, EventRecord]:
        """Atomically persist the Run snapshot, event, and outbox record."""
        async with tenant_session(self._factory, run.tenant_id) as session:
            stored = await self._save_in_session(session, run, expected_version)
            event = await self._append_event_in_session(
                session,
                stored,
                event_type,
                payload,
                correlation_id,
            )
            await session.commit()
            return stored, event

    async def append_event(
        self,
        run: RunRecord,
        event_type: str,
        payload: Mapping[str, Any],
        correlation_id: str,
    ) -> EventRecord:
        async with tenant_session(self._factory, run.tenant_id) as session:
            event = await self._append_event_in_session(
                session,
                run,
                event_type,
                payload,
                correlation_id,
            )
            await session.commit()
            return event

    async def events_after(
        self, run_id: UUID, tenant_id: str, sequence_no: int
    ) -> Sequence[EventRecord]:
        async with tenant_session(self._factory, tenant_id) as session:
            await self._require_run(session, run_id, tenant_id)
            rows = (
                await session.scalars(
                    select(RunEvent)
                    .where(
                        RunEvent.run_id == run_id,
                        RunEvent.tenant_id == tenant_id,
                        RunEvent.sequence_no > sequence_no,
                    )
                    .order_by(RunEvent.sequence_no)
                )
            ).all()
            return tuple(self._event_record(row) for row in rows)

    @asynccontextmanager
    async def trajectory_transaction(
        self, run_id: UUID, tenant_id: str
    ) -> AsyncIterator[_PostgresRunTrajectoryTransaction]:
        """Serialize whole-run trajectory evaluation on the authoritative Run row."""
        async with tenant_session(self._factory, tenant_id) as session:
            await self._require_run(session, run_id, tenant_id, lock=True)
            run = await self._get_in_session(session, run_id, tenant_id)
            rows = (
                await session.scalars(
                    select(RunEvent)
                    .where(
                        RunEvent.run_id == run_id,
                        RunEvent.tenant_id == tenant_id,
                    )
                    .order_by(RunEvent.sequence_no)
                )
            ).all()
            transaction = _PostgresRunTrajectoryTransaction(
                self,
                session,
                run,
                tuple(self._event_record(row) for row in rows),
            )
            yield transaction
            await session.commit()

    async def _get_in_session(
        self, session: AsyncSession, run_id: UUID, tenant_id: str
    ) -> RunRecord:
        result = await session.execute(
            select(AgentRun, RunRuntimeSnapshot)
            .outerjoin(
                RunRuntimeSnapshot,
                (RunRuntimeSnapshot.run_id == AgentRun.run_id)
                & (RunRuntimeSnapshot.tenant_id == AgentRun.tenant_id),
            )
            .where(AgentRun.run_id == run_id, AgentRun.tenant_id == tenant_id)
        )
        row = result.one_or_none()
        if row is None:
            raise NotFound("run", str(run_id))
        database_run = cast(AgentRun, row[0])
        snapshot = cast(RunRuntimeSnapshot | None, row[1])
        run = self._run_record(database_run, snapshot)
        if run.status is DomainRunStatus.PAUSED:
            run.paused_from = await self._pause_origin_from_events(
                session,
                run_id,
                tenant_id,
            )
        return run

    @staticmethod
    async def _pause_origin_from_events(
        session: AsyncSession,
        run_id: UUID,
        tenant_id: str,
    ) -> DomainRunStatus | None:
        """Rebuild the ephemeral pause origin from the immutable event stream."""
        rows = (
            await session.scalars(
                select(RunEvent)
                .where(
                    RunEvent.run_id == run_id,
                    RunEvent.tenant_id == tenant_id,
                    RunEvent.event_type.in_(("trajectory.decision", "run.status_changed")),
                )
                .order_by(RunEvent.sequence_no.desc())
            )
        ).all()
        for event in rows:
            payload = event.payload
            raw_origin: object | None = None
            if (
                event.event_type == "trajectory.decision"
                and payload.get("run_status") == DomainRunStatus.PAUSED.value
            ):
                raw_origin = payload.get("paused_from")
            elif (
                event.event_type == "run.status_changed"
                and payload.get("to") == DomainRunStatus.PAUSED.value
            ):
                raw_origin = payload.get("from")
            if not isinstance(raw_origin, str):
                continue
            try:
                origin = DomainRunStatus(raw_origin)
            except ValueError:
                continue
            if origin is not DomainRunStatus.PAUSED:
                return origin
        return None

    async def _create_once_in_session(
        self,
        session: AsyncSession,
        run: RunRecord,
        contract: TaskContract,
    ) -> tuple[RunRecord, bool]:
        statement = (
            insert(AgentRun)
            .values(**self._insert_values(run, contract))
            .on_conflict_do_nothing(index_elements=[AgentRun.tenant_id, AgentRun.idempotency_key])
            .returning(AgentRun.run_id)
        )
        inserted_id = await session.scalar(statement)
        if inserted_id is None:
            existing = await session.scalar(
                select(AgentRun).where(
                    AgentRun.tenant_id == run.tenant_id,
                    AgentRun.idempotency_key == run.idempotency_key,
                )
            )
            if existing is None:
                raise Conflict(
                    "RUN_CREATE_CONFLICT",
                    "Run identifiers conflict with an existing record",
                    run_id=str(run.run_id),
                )
            if existing.request_hash != run.request_hash:
                raise Conflict(
                    "IDEMPOTENCY_KEY_REUSED",
                    "Idempotency key was reused for a different request",
                    idempotency_key=run.idempotency_key,
                )
            return (
                await self._get_in_session(session, existing.run_id, run.tenant_id),
                False,
            )

        session.add(
            RunRuntimeSnapshot(
                run_id=run.run_id,
                tenant_id=run.tenant_id,
                **self._runtime_values(run),
            )
        )
        await session.flush()
        return await self._get_in_session(session, run.run_id, run.tenant_id), True

    async def _require_run(
        self, session: AsyncSession, run_id: UUID, tenant_id: str, *, lock: bool = False
    ) -> AgentRun:
        statement = select(AgentRun).where(
            AgentRun.run_id == run_id, AgentRun.tenant_id == tenant_id
        )
        if lock:
            statement = statement.with_for_update()
        database_run = await session.scalar(statement)
        if database_run is None:
            raise NotFound("run", str(run_id))
        return database_run

    async def _save_in_session(
        self,
        session: AsyncSession,
        run: RunRecord,
        expected_version: int,
    ) -> RunRecord:
        contract = self._contract(run.contract)
        statement = (
            update(AgentRun)
            .where(
                AgentRun.run_id == run.run_id,
                AgentRun.tenant_id == run.tenant_id,
                AgentRun.version == expected_version,
            )
            .values(
                **self._update_values(run, contract),
                version=AgentRun.version + 1,
            )
            .returning(AgentRun.version)
        )
        new_version = await session.scalar(statement)
        if new_version is None:
            current = await session.scalar(
                select(AgentRun).where(
                    AgentRun.run_id == run.run_id,
                    AgentRun.tenant_id == run.tenant_id,
                )
            )
            if current is None:
                raise NotFound("run", str(run.run_id))
            raise Conflict(
                "OPTIMISTIC_LOCK_CONFLICT",
                "Run version changed concurrently",
                run_id=str(run.run_id),
                expected_version=expected_version,
                actual_version=current.version,
            )

        runtime_statement = (
            insert(RunRuntimeSnapshot)
            .values(
                run_id=run.run_id,
                tenant_id=run.tenant_id,
                **self._runtime_values(run),
            )
            .on_conflict_do_update(
                index_elements=[RunRuntimeSnapshot.run_id],
                set_={
                    **self._runtime_values(run),
                    "tenant_id": run.tenant_id,
                    "updated_at": run.updated_at,
                },
                where=RunRuntimeSnapshot.tenant_id == run.tenant_id,
            )
        )
        await session.execute(runtime_statement)
        await session.flush()
        return await self._get_in_session(session, run.run_id, run.tenant_id)

    async def _append_event_in_session(
        self,
        session: AsyncSession,
        run: RunRecord,
        event_type: str,
        payload: Mapping[str, Any],
        correlation_id: str,
        *,
        actor_type: str = "application",
        actor_id: str | None = None,
        task_id: str | None = None,
        action_id: UUID | None = None,
    ) -> EventRecord:
        await self._require_run(session, run.run_id, run.tenant_id, lock=True)
        serialized_payload = cast(dict[str, Any], _json_value(dict(payload)))
        sequence_result = await session.execute(
            text(
                """
                INSERT INTO run_event_sequences(run_id, next_sequence_no)
                VALUES (CAST(:run_id AS uuid), 2)
                ON CONFLICT (run_id) DO UPDATE
                SET next_sequence_no = run_event_sequences.next_sequence_no + 1
                RETURNING next_sequence_no - 1
                """
            ),
            {"run_id": str(run.run_id)},
        )
        sequence_no = int(sequence_result.scalar_one())
        digest = payload_hash(serialized_payload)
        event = RunEvent(
            run_id=run.run_id,
            tenant_id=run.tenant_id,
            sequence_no=sequence_no,
            event_type=event_type,
            schema_version="1.0",
            actor_type=actor_type,
            actor_id=actor_id or run.principal_id,
            task_id=task_id,
            action_id=action_id,
            correlation_id=correlation_id,
            payload=serialized_payload,
            payload_hash=digest,
        )
        session.add(event)
        session.add(
            OutboxEvent(
                tenant_id=run.tenant_id,
                aggregate_type="run",
                aggregate_id=str(run.run_id),
                event_key=f"{correlation_id}:{sequence_no}",
                event_type=event_type,
                payload=serialized_payload,
                payload_hash=digest,
            )
        )
        await session.flush()
        return self._event_record(event)

    @staticmethod
    def _contract(value: Any) -> TaskContract:
        if isinstance(value, TaskContract):
            return value
        return TaskContract.model_validate(_json_value(value))

    @staticmethod
    def _insert_values(run: RunRecord, contract: TaskContract) -> dict[str, Any]:
        values = PostgresRunRepository._update_values(run, contract)
        values.update(
            {
                "run_id": run.run_id,
                "tenant_id": run.tenant_id,
                "idempotency_key": run.idempotency_key,
                "request_hash": run.request_hash,
                "created_at": run.created_at,
            }
        )
        return values

    @staticmethod
    def _update_values(run: RunRecord, contract: TaskContract) -> dict[str, Any]:
        use_case = contract.constraints.get("use_case", "agent.run")
        return {
            "principal_id": run.principal_id,
            "use_case": str(use_case),
            "status": DatabaseRunStatus(run.status.value),
            "risk": DatabaseRiskLevel(contract.risk.value),
            "contract_schema_version": contract.schema_version,
            "contract_json": _json_value(contract),
            "current_plan_version": run.current_plan_version,
            "workflow_id": run.workflow_id,
            "workflow_run_id": None,
            "cost_limit_usd": contract.max_cost_usd,
            "cost_actual_usd": run.cost_actual_usd,
            "token_input": run.token_input,
            "token_output": run.token_output,
            "tool_call_count": run.tool_call_count,
            "deadline_at": run.created_at + timedelta(seconds=contract.max_duration_seconds),
            "cancel_requested_at": run.updated_at if run.cancellation_requested else None,
            "failure_code": run.failure_code,
            "failure_detail_ref": None,
            "final_artifact_id": None,
            "updated_at": run.updated_at,
            "completed_at": run.completed_at,
        }

    @staticmethod
    def _runtime_values(run: RunRecord) -> dict[str, Any]:
        return {
            "plan_json": _typed_dump(run.plan),
            "outputs_json": _dump_outputs(run.outputs),
            "result_json": _typed_dump(run.result),
            "progress": Decimal(str(run.progress)),
            "pause_requested": run.pause_requested,
            "updated_at": run.updated_at,
        }

    @staticmethod
    def _run_record(database_run: AgentRun, snapshot: RunRuntimeSnapshot | None) -> RunRecord:
        contract = TaskContract.model_validate(database_run.contract_json)
        return RunRecord(
            run_id=database_run.run_id,
            tenant_id=database_run.tenant_id,
            principal_id=database_run.principal_id,
            contract=contract,
            idempotency_key=database_run.idempotency_key,
            request_hash=database_run.request_hash,
            workflow_id=database_run.workflow_id,
            status=DomainRunStatus(database_run.status.value),
            plan=_typed_load(snapshot.plan_json) if snapshot is not None else None,
            outputs=(_load_outputs(snapshot.outputs_json) if snapshot is not None else {}),
            result=_typed_load(snapshot.result_json) if snapshot is not None else None,
            failure_code=database_run.failure_code,
            progress=float(snapshot.progress) if snapshot is not None else 0.0,
            cost_actual_usd=database_run.cost_actual_usd,
            token_input=database_run.token_input,
            token_output=database_run.token_output,
            tool_call_count=database_run.tool_call_count,
            version=database_run.version,
            current_plan_version=database_run.current_plan_version,
            cancellation_requested=database_run.cancel_requested_at is not None,
            pause_requested=(snapshot.pause_requested if snapshot is not None else False),
            created_at=database_run.created_at,
            updated_at=database_run.updated_at,
            completed_at=database_run.completed_at,
        )

    @staticmethod
    def _event_record(event: RunEvent) -> EventRecord:
        return EventRecord(
            event_id=str(event.event_id),
            run_id=event.run_id,
            tenant_id=event.tenant_id,
            sequence_no=event.sequence_no,
            event_type=event.event_type,
            payload=dict(event.payload),
            correlation_id=event.correlation_id,
            created_at=event.created_at,
            schema_version=event.schema_version,
            actor_type=event.actor_type,
            actor_id=event.actor_id,
            task_id=event.task_id,
            action_id=event.action_id,
            payload_hash=event.payload_hash,
        )


class PostgresActionRepository:
    def __init__(
        self,
        factory: AsyncSessionFactory,
        cipher: ActionPayloadCipher,
        runs: PostgresRunRepository | None = None,
    ) -> None:
        self._factory = factory
        self._cipher = cipher
        self._runs = runs or PostgresRunRepository(factory)

    async def create_once(self, action: ActionRecord) -> tuple[ActionRecord, bool]:
        async with tenant_session(self._factory, action.tenant_id) as session:
            await self._require_run(session, action.run_id, action.tenant_id)
            statement = (
                insert(PreparedAction)
                .values(**self._action_values(action))
                .on_conflict_do_nothing(
                    index_elements=[
                        PreparedAction.tenant_id,
                        PreparedAction.idempotency_key,
                    ]
                )
                .returning(PreparedAction.action_id)
            )
            inserted_id = await session.scalar(statement)
            if inserted_id is None:
                existing = await session.scalar(
                    select(PreparedAction).where(
                        PreparedAction.tenant_id == action.tenant_id,
                        PreparedAction.idempotency_key == action.idempotency_key,
                    )
                )
                if existing is None:
                    raise Conflict(
                        "ACTION_CREATE_CONFLICT",
                        "Action identifiers conflict with an existing record",
                        action_id=str(action.action_id),
                    )
                if existing.payload_hash != action.payload_hash:
                    raise Conflict(
                        "ACTION_IDEMPOTENCY_CONFLICT",
                        "Action idempotency key was reused with a different payload",
                        idempotency_key=action.idempotency_key,
                    )
                stored = await self._get_in_session(session, existing.action_id, action.tenant_id)
                await session.commit()
                return stored, False
            await self._replace_approvals(session, action)
            stored = await self._get_in_session(session, action.action_id, action.tenant_id)
            await session.commit()
            return stored, True

    async def create_once_with_event(
        self,
        action: ActionRecord,
        event: AuditEvent,
        invocation: ToolInvocationRecord | None = None,
    ) -> tuple[ActionRecord, bool, EventRecord | None]:
        """Create Action, invocation, immutable event, and outbox atomically."""
        if event.action_id not in {None, action.action_id}:
            raise ValueError("AUDIT_EVENT_ACTION_MISMATCH")
        if invocation is not None and invocation.run_id != action.run_id:
            raise ValueError("TOOL_INVOCATION_RUN_MISMATCH")
        async with tenant_session(self._factory, action.tenant_id) as session:
            run = await self._runs._get_in_session(
                session,
                action.run_id,
                action.tenant_id,
            )
            statement = (
                insert(PreparedAction)
                .values(**self._action_values(action))
                .on_conflict_do_nothing(
                    index_elements=[
                        PreparedAction.tenant_id,
                        PreparedAction.idempotency_key,
                    ]
                )
                .returning(PreparedAction.action_id)
            )
            inserted_id = await session.scalar(statement)
            if inserted_id is None:
                existing = await session.scalar(
                    select(PreparedAction).where(
                        PreparedAction.tenant_id == action.tenant_id,
                        PreparedAction.idempotency_key == action.idempotency_key,
                    )
                )
                if existing is None:
                    raise Conflict(
                        "ACTION_CREATE_CONFLICT",
                        "Action identifiers conflict with an existing record",
                        action_id=str(action.action_id),
                    )
                if existing.payload_hash != action.payload_hash:
                    raise Conflict(
                        "ACTION_IDEMPOTENCY_CONFLICT",
                        "Action idempotency key was reused with a different payload",
                        idempotency_key=action.idempotency_key,
                    )
                stored = await self._get_in_session(
                    session,
                    existing.action_id,
                    action.tenant_id,
                )
                await session.commit()
                return stored, False, None
            await self._replace_approvals(session, action)
            if invocation is not None:
                await append_tool_invocation(session, invocation)
            recorded = await self._runs._append_event_in_session(
                session,
                run,
                event.event_type,
                event.payload,
                event.correlation_id,
                actor_type=event.actor_type,
                actor_id=event.actor_id,
                task_id=event.task_id,
                action_id=event.action_id or action.action_id,
            )
            stored = await self._get_in_session(session, action.action_id, action.tenant_id)
            await session.commit()
            return stored, True, recorded

    async def get(self, action_id: UUID, tenant_id: str) -> ActionRecord:
        async with tenant_session(self._factory, tenant_id) as session:
            return await self._get_in_session(session, action_id, tenant_id)

    @asynccontextmanager
    async def get_for_update(self, action_id: UUID, tenant_id: str) -> AsyncIterator[ActionRecord]:
        async with tenant_session(self._factory, tenant_id) as session:
            row = await session.scalar(
                select(PreparedAction)
                .where(
                    PreparedAction.action_id == action_id,
                    PreparedAction.tenant_id == tenant_id,
                )
                .with_for_update()
            )
            if row is None:
                raise NotFound("action", str(action_id))
            working = await self._record_from_row(session, row)
            try:
                yield working
            except Exception:
                # UNKNOWN/EXPIRED/VERIFY_FAILED are recovery checkpoints. The
                # application deliberately raises after assigning them.
                await self._persist_locked(session, working, row.version)
                await session.commit()
                raise
            else:
                await self._persist_locked(session, working, row.version)
                await session.commit()

    @asynccontextmanager
    async def transaction(
        self,
        action_id: UUID,
        tenant_id: str,
    ) -> AsyncIterator[ActionAuditTransaction]:
        """Lock and atomically persist Action state, events, outbox, and tool calls."""
        async with tenant_session(self._factory, tenant_id) as session:
            row = await session.scalar(
                select(PreparedAction)
                .where(
                    PreparedAction.action_id == action_id,
                    PreparedAction.tenant_id == tenant_id,
                )
                .with_for_update()
            )
            if row is None:
                raise NotFound("action", str(action_id))
            working = await self._record_from_row(session, row)
            baseline = copy.deepcopy(working)
            transaction = ActionAuditTransaction(action=working)
            try:
                yield transaction
            except Exception:
                await self._persist_audit_transaction(
                    session,
                    transaction,
                    baseline,
                    row.version,
                )
                await session.commit()
                raise
            else:
                await self._persist_audit_transaction(
                    session,
                    transaction,
                    baseline,
                    row.version,
                )
                await session.commit()

    async def list_for_run(self, run_id: UUID, tenant_id: str) -> Sequence[ActionRecord]:
        async with tenant_session(self._factory, tenant_id) as session:
            await self._require_run(session, run_id, tenant_id)
            rows = (
                await session.scalars(
                    select(PreparedAction)
                    .where(
                        PreparedAction.run_id == run_id,
                        PreparedAction.tenant_id == tenant_id,
                    )
                    .order_by(PreparedAction.created_at)
                )
            ).all()
            return tuple([await self._record_from_row(session, row) for row in rows])

    async def save(self, action: ActionRecord, expected_version: int) -> ActionRecord:
        async with tenant_session(self._factory, action.tenant_id) as session:
            statement = (
                update(PreparedAction)
                .where(
                    PreparedAction.action_id == action.action_id,
                    PreparedAction.tenant_id == action.tenant_id,
                    PreparedAction.version == expected_version,
                )
                .values(
                    **self._action_update_values(action),
                    version=PreparedAction.version + 1,
                )
                .returning(PreparedAction.version)
            )
            new_version = await session.scalar(statement)
            if new_version is None:
                current = await session.scalar(
                    select(PreparedAction).where(
                        PreparedAction.action_id == action.action_id,
                        PreparedAction.tenant_id == action.tenant_id,
                    )
                )
                if current is None:
                    raise NotFound("action", str(action.action_id))
                raise Conflict(
                    "OPTIMISTIC_LOCK_CONFLICT",
                    "Action version changed concurrently",
                    action_id=str(action.action_id),
                    expected_version=expected_version,
                    actual_version=current.version,
                )
            action.version = int(new_version)
            await self._replace_approvals(session, action)
            stored = await self._get_in_session(session, action.action_id, action.tenant_id)
            await session.commit()
            return stored

    async def _persist_locked(
        self,
        session: AsyncSession,
        action: ActionRecord,
        expected_version: int,
    ) -> None:
        statement = (
            update(PreparedAction)
            .where(
                PreparedAction.action_id == action.action_id,
                PreparedAction.tenant_id == action.tenant_id,
                PreparedAction.version == expected_version,
            )
            .values(
                **self._action_update_values(action),
                version=PreparedAction.version + 1,
            )
            .returning(PreparedAction.version)
        )
        new_version = await session.scalar(statement)
        if new_version is None:
            raise Conflict(
                "OPTIMISTIC_LOCK_CONFLICT",
                "Action version changed while holding the commit lock",
                action_id=str(action.action_id),
            )
        action.version = int(new_version)
        await self._replace_approvals(session, action)

    async def _persist_audit_transaction(
        self,
        session: AsyncSession,
        transaction: ActionAuditTransaction,
        baseline: ActionRecord,
        expected_version: int,
    ) -> None:
        action = transaction.action
        changed = action != baseline
        if changed:
            action.updated_at = datetime.now(UTC)
            await self._persist_locked(session, action, expected_version)
        if not transaction.events and not transaction.tool_invocations:
            return
        run = await self._runs._get_in_session(
            session,
            action.run_id,
            action.tenant_id,
        )
        for invocation in transaction.tool_invocations:
            await append_tool_invocation(session, invocation)
        for event in transaction.events:
            await self._runs._append_event_in_session(
                session,
                run,
                event.event_type,
                event.payload,
                event.correlation_id,
                actor_type=event.actor_type,
                actor_id=event.actor_id,
                task_id=event.task_id,
                action_id=event.action_id or action.action_id,
            )

    async def _get_in_session(
        self, session: AsyncSession, action_id: UUID, tenant_id: str
    ) -> ActionRecord:
        row = await session.scalar(
            select(PreparedAction).where(
                PreparedAction.action_id == action_id,
                PreparedAction.tenant_id == tenant_id,
            )
        )
        if row is None:
            raise NotFound("action", str(action_id))
        return await self._record_from_row(session, row)

    async def _record_from_row(self, session: AsyncSession, row: PreparedAction) -> ActionRecord:
        approval_rows = (
            await session.scalars(
                select(Approval)
                .where(
                    Approval.action_id == row.action_id,
                    Approval.tenant_id == row.tenant_id,
                )
                .order_by(Approval.created_at, Approval.approval_id)
            )
        ).all()
        payload_bytes = self._cipher.decrypt(
            row.payload_encrypted,
            associated_data=_action_aad(row.tenant_id, row.action_id),
        )
        canonical_payload = json.loads(payload_bytes)
        if not isinstance(canonical_payload, dict):
            raise PlatformError(
                "ACTION_PAYLOAD_INVALID",
                "Stored action payload is not an object",
                http_status=500,
            )
        return ActionRecord(
            action_id=row.action_id,
            run_id=row.run_id,
            tenant_id=row.tenant_id,
            principal_id=row.principal_id,
            action_type=row.action_type,
            tool_name=row.tool_name,
            tool_version=row.tool_version,
            canonical_payload=canonical_payload,
            payload_hash=row.payload_hash,
            preview=dict(row.preview_json),
            risk=DomainRiskLevel(row.risk.value),
            approval_policy=row.approval_policy,
            required_approvals=row.required_approvals,
            idempotency_key=row.idempotency_key,
            policy_version=row.policy_version,
            expires_at=row.expires_at,
            status=DomainActionStatus(row.status.value),
            approvals=[self._approval_record(item) for item in approval_rows],
            receipt=_unwrapped_json(row.receipt_json),
            verification=_unwrapped_json(row.verification_json),
            failure_code=row.failure_code,
            version=row.version,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    def _action_values(self, action: ActionRecord) -> dict[str, Any]:
        return {
            "action_id": action.action_id,
            "run_id": action.run_id,
            "tenant_id": action.tenant_id,
            **self._action_update_values(action),
            "idempotency_key": action.idempotency_key,
            "created_at": action.created_at,
            "version": action.version,
        }

    def _action_update_values(self, action: ActionRecord) -> dict[str, Any]:
        encoded = canonical_json(action.canonical_payload).encode()
        return {
            "principal_id": action.principal_id,
            "action_type": action.action_type,
            "tool_name": action.tool_name,
            "tool_version": action.tool_version,
            "payload_encrypted": self._cipher.encrypt(
                encoded,
                associated_data=_action_aad(action.tenant_id, action.action_id),
            ),
            "payload_hash": action.payload_hash,
            "preview_json": _json_value(action.preview),
            "risk": DatabaseRiskLevel(action.risk.value),
            "approval_policy": action.approval_policy,
            "required_approvals": action.required_approvals,
            "status": DatabaseActionStatus(action.status.value),
            "policy_version": action.policy_version,
            "receipt_json": _wrapped_json(action.receipt),
            "receipt_artifact_id": _receipt_artifact_id(action.receipt),
            "verification_json": _wrapped_json(action.verification),
            "failure_code": action.failure_code,
            "expires_at": action.expires_at,
            "updated_at": action.updated_at,
        }

    async def _replace_approvals(self, session: AsyncSession, action: ActionRecord) -> None:
        """Append approval facts; existing audit records are never rewritten."""
        for raw in action.approvals:
            if not isinstance(raw, Mapping):
                raise ValueError("ACTION_APPROVAL_RECORD_MUST_BE_A_MAPPING")
            decision = str(raw.get("decision", ""))
            await session.execute(
                insert(Approval)
                .values(
                    approval_id=UUID(str(raw.get("approval_id", uuid4()))),
                    action_id=action.action_id,
                    tenant_id=action.tenant_id,
                    actor_id=str(raw.get("actor_id", "")),
                    actor_roles=[str(value) for value in raw.get("actor_roles", ())],
                    auth_strength=str(raw.get("auth_strength", "")),
                    decision=DatabaseApprovalDecision(decision),
                    payload_hash=str(raw.get("payload_hash", action.payload_hash)),
                    comment=(str(raw["comment"]) if raw.get("comment") is not None else None),
                    policy_version=str(raw.get("policy_version", action.policy_version)),
                    created_at=_parse_datetime(raw.get("created_at"), default=action.updated_at),
                )
                .on_conflict_do_nothing(
                    index_elements=[
                        Approval.action_id,
                        Approval.actor_id,
                        Approval.payload_hash,
                    ]
                )
            )
        await session.flush()

    @staticmethod
    async def _require_run(session: AsyncSession, run_id: UUID, tenant_id: str) -> None:
        visible = await session.scalar(
            select(AgentRun.run_id).where(
                AgentRun.run_id == run_id,
                AgentRun.tenant_id == tenant_id,
            )
        )
        if visible is None:
            raise NotFound("run", str(run_id))

    @staticmethod
    def _approval_record(row: Approval) -> dict[str, Any]:
        return {
            "approval_id": str(row.approval_id),
            "actor_id": row.actor_id,
            "actor_roles": list(row.actor_roles),
            "auth_strength": row.auth_strength,
            "decision": row.decision.value,
            "comment": row.comment,
            "policy_version": row.policy_version,
            "payload_hash": row.payload_hash,
            "created_at": row.created_at.isoformat(),
        }


class PostgresArtifactStore:
    """Compose object bytes with RLS-protected PostgreSQL metadata."""

    def __init__(
        self,
        factory: AsyncSessionFactory,
        content_store: ArtifactContentStore,
    ) -> None:
        self._factory = factory
        self._content_store = content_store

    async def put(self, artifact: ArtifactRecord) -> ArtifactRecord:
        digest = hashlib.sha256(artifact.content).hexdigest()
        if len(artifact.content) != artifact.size_bytes or digest != artifact.sha256:
            raise PlatformError(
                "ARTIFACT_HASH_MISMATCH",
                "Artifact content hash does not match metadata",
            )
        existing = await self._preflight_put(artifact)
        if existing is not None:
            return existing
        await self._content_store.put(artifact)
        return await self._persist_metadata(artifact)

    async def put_file(self, artifact: ArtifactRecord, path: Path) -> ArtifactRecord:
        """Publish a staged Artifact without materializing it in API-worker memory."""
        digest, size_bytes = await asyncio.to_thread(self._file_identity, path)
        if digest != artifact.sha256 or size_bytes != artifact.size_bytes:
            raise PlatformError(
                "ARTIFACT_HASH_MISMATCH",
                "Staged Artifact identity does not match metadata",
            )
        put_file = getattr(self._content_store, "put_file", None)
        if not callable(put_file):
            raise PlatformError(
                "ARTIFACT_STREAMING_STORE_REQUIRED",
                "Configured object store does not support staged file publication",
                http_status=503,
            )
        existing = await self._preflight_put(artifact)
        if existing is not None:
            return existing
        await put_file(artifact, path)
        return await self._persist_metadata(artifact)

    async def _preflight_put(self, artifact: ArtifactRecord) -> ArtifactRecord | None:
        async with tenant_session(self._factory, artifact.tenant_id) as session:
            if artifact.run_id is not None:
                visible_run = await session.scalar(
                    select(AgentRun.run_id).where(
                        AgentRun.run_id == artifact.run_id,
                        AgentRun.tenant_id == artifact.tenant_id,
                    )
                )
                if visible_run is None:
                    raise NotFound("run", str(artifact.run_id))
            existing = await session.scalar(
                select(Artifact).where(
                    Artifact.artifact_id == artifact.artifact_id,
                    Artifact.tenant_id == artifact.tenant_id,
                )
            )
            if existing is None:
                return None
            differing_fields = self._immutable_identity_differences(existing, artifact)
            if differing_fields:
                raise Conflict(
                    "ARTIFACT_IMMUTABLE_CONFLICT",
                    "Artifact identifiers are immutable; new content requires a new Artifact",
                    artifact_id=str(artifact.artifact_id),
                    differing_fields=differing_fields,
                )
            return self._record_from_metadata(existing)

    @staticmethod
    def _immutable_identity_differences(
        existing: Artifact,
        candidate: ArtifactRecord,
    ) -> list[str]:
        expected_source = {
            "scan_status": candidate.scan_status,
            "scan_provenance": _json_value(candidate.scan_provenance),
        }
        comparisons = {
            "tenant_id": (existing.tenant_id, candidate.tenant_id),
            "run_id": (existing.run_id, candidate.run_id),
            "kind": (existing.kind, candidate.kind),
            "media_type": (existing.media_type, candidate.media_type),
            "size_bytes": (existing.size_bytes, candidate.size_bytes),
            "sha256": (existing.sha256, candidate.sha256),
            "classification": (existing.classification, candidate.classification.value),
            "created_by": (existing.created_by, candidate.created_by),
            "retention_policy": (existing.retention_policy, candidate.retention_policy),
            "encryption_key_ref": (
                existing.encryption_key_ref,
                candidate.encryption_key_ref,
            ),
            "expires_at": (existing.expires_at, candidate.expires_at),
            "legal_hold_status": (
                existing.legal_hold_status,
                candidate.legal_hold_status,
            ),
            "source_json": (existing.source_json, expected_source),
        }
        return [field for field, (actual, expected) in comparisons.items() if actual != expected]

    async def _persist_metadata(
        self,
        artifact: ArtifactRecord,
    ) -> ArtifactRecord:
        try:
            async with tenant_session(self._factory, artifact.tenant_id) as session:
                values = self._metadata_values(artifact)
                statement = (
                    insert(Artifact)
                    .values(**values)
                    .on_conflict_do_nothing(
                        index_elements=[Artifact.artifact_id],
                    )
                    .returning(Artifact.artifact_id)
                )
                stored_id = await session.scalar(statement)
                if stored_id is None:
                    raise Conflict(
                        "ARTIFACT_ID_CONFLICT",
                        "Artifact identifier belongs to another tenant",
                        artifact_id=str(artifact.artifact_id),
                    )
                await session.commit()
        except Exception:
            await self._content_store.delete(artifact.artifact_id, artifact.tenant_id)
            raise
        return artifact

    @staticmethod
    def _file_identity(path: Path) -> tuple[str, int]:
        digest = hashlib.sha256()
        size_bytes = 0
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                size_bytes += len(chunk)
        return digest.hexdigest(), size_bytes

    async def get_metadata(self, artifact_id: UUID, tenant_id: str) -> ArtifactRecord:
        async with tenant_session(self._factory, tenant_id) as session:
            metadata = await session.scalar(
                select(Artifact).where(
                    Artifact.artifact_id == artifact_id,
                    Artifact.tenant_id == tenant_id,
                    Artifact.lifecycle_status == "available",
                    Artifact.deleted_at.is_(None),
                    (Artifact.expires_at.is_(None) | (Artifact.expires_at > func.now())),
                )
            )
            if metadata is None:
                raise NotFound("artifact", str(artifact_id))
            # Materialize before leaving the short RLS transaction. Metadata and
            # presigned downloads must never fetch a 50-200 MB object into the API.
            return self._record_from_metadata(metadata)

    async def get(self, artifact_id: UUID, tenant_id: str) -> ArtifactRecord:
        stored = await self.get_metadata(artifact_id, tenant_id)
        content = await self._content_store.get(artifact_id, tenant_id)
        digest = hashlib.sha256(content.content).hexdigest()
        if len(content.content) != stored.size_bytes or digest != stored.sha256:
            raise PlatformError(
                "ARTIFACT_HASH_MISMATCH",
                "Stored Artifact failed integrity verification",
                http_status=503,
            )
        stored.content = content.content
        return stored

    @staticmethod
    def _record_from_metadata(metadata: Artifact) -> ArtifactRecord:
        return ArtifactRecord(
            artifact_id=metadata.artifact_id,
            tenant_id=metadata.tenant_id,
            run_id=metadata.run_id,
            kind=metadata.kind,
            media_type=metadata.media_type,
            content=b"",
            size_bytes=metadata.size_bytes,
            sha256=metadata.sha256,
            classification=metadata.classification,
            created_by=metadata.created_by,
            retention_policy=metadata.retention_policy,
            encryption_key_ref=metadata.encryption_key_ref,
            object_version_id=metadata.object_version_id,
            object_retain_until=metadata.object_retain_until,
            legal_hold_status=metadata.legal_hold_status,
            expires_at=metadata.expires_at,
            deleted_at=metadata.deleted_at,
            lifecycle_status=metadata.lifecycle_status,
            delete_requested_at=metadata.delete_requested_at,
            delete_attempts=metadata.delete_attempts,
            delete_last_error_code=metadata.delete_last_error_code,
            scan_status=str(metadata.source_json.get("scan_status", "not_scanned")),
            scan_provenance=_artifact_scan_provenance(metadata.source_json),
            created_at=metadata.created_at,
        )

    async def create_download(
        self,
        artifact: ArtifactRecord,
        *,
        principal_id: str,
        tenant_id: str,
        purpose: str,
        expires_in_seconds: int,
    ) -> ArtifactDownload:
        if artifact.tenant_id != tenant_id or not principal_id.strip() or not purpose.strip():
            raise ValueError("ARTIFACT_DOWNLOAD_AUDIT_CONTEXT_INVALID")
        async with tenant_session(self._factory, tenant_id) as session:
            metadata = await session.scalar(
                select(Artifact)
                .where(
                    Artifact.artifact_id == artifact.artifact_id,
                    Artifact.tenant_id == tenant_id,
                    Artifact.lifecycle_status == "available",
                    Artifact.deleted_at.is_(None),
                    (Artifact.expires_at.is_(None) | (Artifact.expires_at > func.now())),
                )
                .with_for_update()
            )
            if metadata is None:
                raise NotFound("artifact", str(artifact.artifact_id))
            verified = self._record_from_metadata(metadata)
            download = await self._content_store.create_download(
                verified,
                principal_id=principal_id,
                tenant_id=tenant_id,
                purpose=purpose,
                expires_in_seconds=expires_in_seconds,
            )
            session.add(
                ArtifactDownloadAudit(
                    artifact_id=artifact.artifact_id,
                    tenant_id=tenant_id,
                    principal_id=principal_id,
                    purpose=purpose,
                    expires_at=download.expires_at,
                )
            )
            await session.commit()
            return download

    async def delete(self, artifact_id: UUID, tenant_id: str) -> None:
        """Durably stage deletion so object-store failures remain retryable."""
        async with tenant_session(self._factory, tenant_id) as session:
            pending_id = await session.scalar(
                update(Artifact)
                .where(
                    Artifact.artifact_id == artifact_id,
                    Artifact.tenant_id == tenant_id,
                    Artifact.deleted_at.is_(None),
                    Artifact.lifecycle_status.in_(("available", "delete_pending")),
                    Artifact.legal_hold_status == "none",
                    (
                        Artifact.object_retain_until.is_(None)
                        | (Artifact.object_retain_until <= func.now())
                    ),
                )
                .values(
                    lifecycle_status="delete_pending",
                    delete_requested_at=func.coalesce(
                        Artifact.delete_requested_at,
                        func.now(),
                    ),
                    delete_attempts=Artifact.delete_attempts + 1,
                    delete_last_error_code=None,
                )
                .returning(Artifact.artifact_id)
            )
            if pending_id is None:
                governance = await session.execute(
                    select(
                        Artifact.legal_hold_status,
                        Artifact.object_retain_until,
                    ).where(
                        Artifact.artifact_id == artifact_id,
                        Artifact.tenant_id == tenant_id,
                        Artifact.deleted_at.is_(None),
                    )
                )
                row = governance.one_or_none()
                if row is not None and row.legal_hold_status == "on":
                    raise Conflict(
                        "ARTIFACT_LEGAL_HOLD_ACTIVE",
                        "Artifact deletion is blocked by an active legal hold",
                        artifact_id=str(artifact_id),
                    )
                if (
                    row is not None
                    and row.object_retain_until is not None
                    and row.object_retain_until > datetime.now(UTC)
                ):
                    raise Conflict(
                        "ARTIFACT_RETENTION_ACTIVE",
                        "Artifact deletion is blocked until its retention period ends",
                        artifact_id=str(artifact_id),
                        retain_until=row.object_retain_until.isoformat(),
                    )
                raise NotFound("artifact", str(artifact_id))
            await session.commit()

        try:
            await self._content_store.delete(artifact_id, tenant_id)
        except NotFound:
            # A prior attempt may have removed the object before its DB finalize
            # committed. S3 deletion is semantically idempotent at this boundary.
            pass
        except Exception as exc:
            error_code = (
                exc.code if isinstance(exc, PlatformError) else type(exc).__name__.upper()
            )[:128]
            async with tenant_session(self._factory, tenant_id) as session:
                await session.execute(
                    update(Artifact)
                    .where(
                        Artifact.artifact_id == artifact_id,
                        Artifact.tenant_id == tenant_id,
                        Artifact.lifecycle_status == "delete_pending",
                    )
                    .values(delete_last_error_code=error_code)
                )
                await session.commit()
            raise PlatformError(
                "ARTIFACT_DELETE_PENDING",
                "Artifact object deletion failed and remains queued for retry",
                retryable=True,
                http_status=503,
                context={
                    "artifact_id": str(artifact_id),
                    "storage_error_code": error_code,
                },
            ) from exc

        async with tenant_session(self._factory, tenant_id) as session:
            finalized_id = await session.scalar(
                update(Artifact)
                .where(
                    Artifact.artifact_id == artifact_id,
                    Artifact.tenant_id == tenant_id,
                    Artifact.lifecycle_status == "delete_pending",
                )
                .values(
                    lifecycle_status="deleted",
                    deleted_at=func.now(),
                    delete_last_error_code=None,
                )
                .returning(Artifact.artifact_id)
            )
            if finalized_id is None:
                raise PlatformError(
                    "ARTIFACT_DELETE_FINALIZE_CONFLICT",
                    "Artifact object was removed but metadata could not be finalized",
                    retryable=True,
                    http_status=503,
                    context={"artifact_id": str(artifact_id)},
                )
            await session.commit()

    def _metadata_values(self, artifact: ArtifactRecord) -> dict[str, Any]:
        return {
            "artifact_id": artifact.artifact_id,
            "run_id": artifact.run_id,
            "tenant_id": artifact.tenant_id,
            "task_id": None,
            "kind": artifact.kind,
            "uri": self._content_store.uri_for(artifact),
            "media_type": artifact.media_type,
            "size_bytes": artifact.size_bytes,
            "sha256": artifact.sha256,
            "classification": artifact.classification,
            "source_json": {
                "scan_status": artifact.scan_status,
                "scan_provenance": _json_value(artifact.scan_provenance),
            },
            "created_by": artifact.created_by,
            "retention_policy": artifact.retention_policy,
            "encryption_key_ref": artifact.encryption_key_ref,
            "object_version_id": artifact.object_version_id,
            "object_retain_until": artifact.object_retain_until,
            "legal_hold_status": artifact.legal_hold_status,
            "expires_at": artifact.expires_at,
            "created_at": artifact.created_at,
            "deleted_at": artifact.deleted_at,
            "lifecycle_status": artifact.lifecycle_status,
            "delete_requested_at": artifact.delete_requested_at,
            "delete_attempts": artifact.delete_attempts,
            "delete_last_error_code": artifact.delete_last_error_code,
        }


class PostgresCapabilityStore:
    def __init__(self, factory: AsyncSessionFactory) -> None:
        self._factory = factory

    async def register(self, tenant_id: str, record: CapabilityRecord) -> None:
        async with tenant_session(self._factory, tenant_id) as session:
            statement = (
                insert(CapabilityRecordRow)
                .values(
                    tenant_id=tenant_id,
                    capability_name=record.name,
                    **self._values(record),
                )
                .on_conflict_do_update(
                    index_elements=[
                        CapabilityRecordRow.tenant_id,
                        CapabilityRecordRow.capability_name,
                    ],
                    set_={**self._values(record), "updated_at": func.now()},
                )
            )
            await session.execute(statement)
            await session.commit()

    async def list(self, tenant_id: str) -> Sequence[CapabilityRecord]:
        async with tenant_session(self._factory, tenant_id) as session:
            rows = (
                await session.scalars(
                    select(CapabilityRecordRow)
                    .where(CapabilityRecordRow.tenant_id.in_(("*", tenant_id)))
                    .order_by(
                        CapabilityRecordRow.capability_name,
                        CapabilityRecordRow.tenant_id,
                    )
                )
            ).all()
            visible: dict[str, CapabilityRecord] = {}
            for row in rows:
                # Tenant rows overwrite the global default.
                if row.tenant_id == "*" or row.capability_name not in visible:
                    visible[row.capability_name] = self._record(row)
            for row in rows:
                if row.tenant_id == tenant_id:
                    visible[row.capability_name] = self._record(row)
            return tuple(visible[name] for name in sorted(visible))

    async def set_enabled(
        self, tenant_id: str, name: str, enabled: bool, reason: str | None
    ) -> CapabilityRecord:
        async with tenant_session(self._factory, tenant_id) as session:
            rows = (
                await session.scalars(
                    select(CapabilityRecordRow).where(
                        CapabilityRecordRow.capability_name == name,
                        CapabilityRecordRow.tenant_id.in_(("*", tenant_id)),
                    )
                )
            ).all()
            tenant_row = next((row for row in rows if row.tenant_id == tenant_id), None)
            fallback = next((row for row in rows if row.tenant_id == "*"), None)
            source = tenant_row or fallback
            if source is None:
                raise NotFound("capability", name)
            values = {
                "version": source.version,
                "effect": source.effect,
                "risk": source.risk,
                "enabled": enabled,
                "disabled_reason": None if enabled else reason,
                "policy_version": source.policy_version,
            }
            statement = (
                insert(CapabilityRecordRow)
                .values(
                    tenant_id=tenant_id,
                    capability_name=name,
                    **values,
                )
                .on_conflict_do_update(
                    index_elements=[
                        CapabilityRecordRow.tenant_id,
                        CapabilityRecordRow.capability_name,
                    ],
                    set_={**values, "updated_at": func.now()},
                )
                .returning(CapabilityRecordRow)
            )
            result = await session.execute(statement)
            row = result.scalar_one()
            await session.commit()
            return self._record(row)

    @staticmethod
    def _values(record: CapabilityRecord) -> dict[str, Any]:
        return {
            "version": record.version,
            "effect": record.effect,
            "risk": record.risk,
            "enabled": record.enabled,
            "disabled_reason": record.disabled_reason,
            "policy_version": record.policy_version,
        }

    @staticmethod
    def _record(row: CapabilityRecordRow) -> CapabilityRecord:
        return CapabilityRecord(
            name=row.capability_name,
            version=row.version,
            effect=row.effect,
            risk=row.risk,
            enabled=row.enabled,
            disabled_reason=row.disabled_reason,
            policy_version=row.policy_version,
        )


class PostgresPlatformStore:
    """Production counterpart of ``InMemoryPlatformStore``."""

    def __init__(
        self,
        factory: AsyncSessionFactory,
        *,
        action_payload_cipher: ActionPayloadCipher,
        artifact_content_store: ArtifactContentStore,
    ) -> None:
        self.runs = PostgresRunRepository(factory)
        self.actions = PostgresActionRepository(
            factory,
            action_payload_cipher,
            self.runs,
        )
        self.audit = PostgresAuditRepository(factory, self.runs)
        self.artifacts = PostgresArtifactStore(factory, artifact_content_store)
        self.capabilities = PostgresCapabilityStore(factory)
