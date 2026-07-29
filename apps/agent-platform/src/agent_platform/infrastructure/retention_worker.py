"""Retention worker for expiring Actions, Memory, idempotency, and Artifacts."""

from __future__ import annotations

import asyncio
import json
import math
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from time import monotonic
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from sqlalchemy import delete, select, text

from agent_platform.config import Settings
from agent_platform.domain.events import RunEventType, action_expired_event_payload
from agent_platform.domain.hashing import payload_hash
from agent_platform.infrastructure.persistence.models import (
    ActionStatus,
    AgentRun,
    Artifact,
    IdempotencyRecord,
    MemoryLifecycleEvent,
    MemoryRecord,
    OutboxEvent,
    PreparedAction,
    RunEvent,
)
from agent_platform.infrastructure.persistence.session import (
    AsyncSessionFactory,
    create_session_factory,
    dispose_session_factory,
)
from agent_platform.infrastructure.retention_lifecycle import (
    PostgresLifecycleRetention,
    S3ImmutableArchiveAdapter,
)

type ArtifactDelete = Callable[[Artifact], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class RetentionSweepReport:
    expired_actions: int
    deleted_idempotency_records: int
    expired_memories: int
    deleted_artifacts: int
    archived_runs: int
    purged_runs: int
    archived_event_streams: int
    held_resources: int
    lifecycle_failures: int


@dataclass(frozen=True, slots=True)
class ActionExpiryBatchResult:
    selected: int
    expired: int
    deferred_action_ids: tuple[UUID, ...] = ()


@dataclass(slots=True)
class ActionExpiryBatchProbe:
    operation_id: UUID
    selected_action_ids: tuple[UUID, ...] = ()


class ActionExpiryOutcomeUnknown(RuntimeError):
    def __init__(
        self,
        *,
        sweep_id: UUID,
        operation_id: UUID,
        batch_number: int,
        filter_mode: str,
        filter_count: int,
        candidate_action_ids: tuple[UUID, ...],
    ) -> None:
        self.sweep_id = sweep_id
        self.operation_id = operation_id
        self.batch_number = batch_number
        self.filter_mode = filter_mode
        self.filter_count = filter_count
        self.candidate_action_ids = candidate_action_ids
        super().__init__(
            "ACTION_EXPIRY_BATCH_OUTCOME_UNKNOWN:"
            f"sweep_id={sweep_id}:operation_id={operation_id}:"
            f"batch={batch_number}:filter={filter_mode}:"
            f"filter_count={filter_count}:candidate_count={len(candidate_action_ids)}"
        )


def _artifact_expired_event(artifact: Artifact) -> OutboxEvent:
    event_payload = {
        "artifact_id": str(artifact.artifact_id),
        "sha256": artifact.sha256,
        "classification": artifact.classification,
    }
    return OutboxEvent(
        tenant_id=artifact.tenant_id,
        aggregate_type="artifact",
        aggregate_id=str(artifact.artifact_id),
        event_key=f"retention:{artifact.artifact_id}",
        event_type="artifact.expired",
        payload=event_payload,
        payload_hash=payload_hash(event_payload),
    )


class S3ArtifactDeleter:
    def __init__(
        self,
        *,
        client: Any,
        bucket: str,
        environment: str,
    ) -> None:
        self._client = client
        self._bucket = bucket
        self._environment = environment

    async def __call__(self, artifact: Artifact) -> None:
        parsed = urlsplit(artifact.uri)
        key = parsed.path.lstrip("/")
        expected_prefix = f"{self._environment}/tenant/{artifact.tenant_id}/"
        if (
            parsed.scheme != "s3"
            or parsed.netloc != self._bucket
            or not key.startswith(expected_prefix)
            or ".." in key.split("/")
        ):
            raise RuntimeError("ARTIFACT_URI_OUTSIDE_TENANT_PREFIX")
        request: dict[str, Any] = {"Bucket": self._bucket, "Key": key}
        if artifact.object_version_id:
            request["VersionId"] = artifact.object_version_id
        await asyncio.to_thread(self._client.delete_object, **request)


class PostgresRetentionWorker:
    def __init__(
        self,
        *,
        session_factory: AsyncSessionFactory,
        delete_artifact: ArtifactDelete,
        lifecycle: PostgresLifecycleRetention | None = None,
        monotonic_clock: Callable[[], float] = monotonic,
    ) -> None:
        self._sessions = session_factory
        self._delete_artifact = delete_artifact
        self._lifecycle = lifecycle
        self._monotonic_clock = monotonic_clock
        self._role_verified = False

    async def run_once(
        self,
        *,
        now: datetime | None = None,
        batch_size: int = 100,
        max_action_batches: int = 20,
        action_time_budget_seconds: float = 30.0,
    ) -> RetentionSweepReport:
        if batch_size <= 0:
            raise ValueError("RETENTION_BATCH_SIZE_MUST_BE_POSITIVE")
        if max_action_batches <= 0:
            raise ValueError("RETENTION_MAX_ACTION_BATCHES_MUST_BE_POSITIVE")
        if action_time_budget_seconds <= 0:
            raise ValueError("RETENTION_ACTION_TIME_BUDGET_MUST_BE_POSITIVE")
        current = now or datetime.now(UTC)
        expired_actions = await self._drain_expired_actions(
            current,
            batch_size=batch_size,
            max_batches=max_action_batches,
            time_budget_seconds=action_time_budget_seconds,
        )
        deleted_idempotency = await self._delete_idempotency(current, batch_size)
        expired_memories = await self._expire_memories(current, batch_size)
        deleted_artifacts = await self._delete_artifacts(current, batch_size)
        lifecycle = (
            await self._lifecycle.run_once(now=current, batch_size=batch_size)
            if self._lifecycle is not None
            else None
        )
        return RetentionSweepReport(
            expired_actions=expired_actions,
            deleted_idempotency_records=deleted_idempotency,
            expired_memories=expired_memories,
            deleted_artifacts=deleted_artifacts,
            archived_runs=lifecycle.archived_runs if lifecycle else 0,
            purged_runs=lifecycle.purged_runs if lifecycle else 0,
            archived_event_streams=lifecycle.archived_event_streams if lifecycle else 0,
            held_resources=lifecycle.held_resources if lifecycle else 0,
            lifecycle_failures=lifecycle.failures if lifecycle else 0,
        )

    async def _drain_expired_actions(
        self,
        now: datetime,
        *,
        batch_size: int,
        max_batches: int,
        time_budget_seconds: float,
    ) -> int:
        deadline = self._monotonic_clock() + time_budget_seconds
        total = 0
        deferred_action_ids: set[UUID] = set()
        operations_used = 0
        scan_batches_used = 0
        underfilled_scans = 0
        sweep_id = uuid4()

        async def expire_before_deadline(
            *,
            excluded: tuple[UUID, ...] = (),
            included: tuple[UUID, ...] | None = None,
        ) -> ActionExpiryBatchResult | None:
            remaining_seconds = deadline - self._monotonic_clock()
            if remaining_seconds <= 0:
                return None
            cleanup_grace_seconds = min(1.0, remaining_seconds * 0.1)
            operation_seconds = remaining_seconds - cleanup_grace_seconds
            probe = ActionExpiryBatchProbe(operation_id=uuid4())
            overall_timeout = asyncio.timeout(remaining_seconds)
            operation_timeout = asyncio.timeout(operation_seconds)

            def unknown_outcome() -> ActionExpiryOutcomeUnknown:
                filter_mode = (
                    "included" if included is not None else "excluded" if excluded else "all"
                )
                filter_count = len(included) if included is not None else len(excluded)
                return ActionExpiryOutcomeUnknown(
                    sweep_id=sweep_id,
                    operation_id=probe.operation_id,
                    batch_number=operations_used + 1,
                    filter_mode=filter_mode,
                    filter_count=filter_count,
                    candidate_action_ids=probe.selected_action_ids,
                )

            try:
                async with overall_timeout:
                    async with operation_timeout:
                        result = await self._expire_actions(
                            now,
                            batch_size,
                            timeout_seconds=operation_seconds,
                            excluded_action_ids=excluded,
                            included_action_ids=included,
                            probe=probe,
                        )
            except TimeoutError as exc:
                if not overall_timeout.expired() and not operation_timeout.expired():
                    raise
                raise unknown_outcome() from exc
            if overall_timeout.expired() or operation_timeout.expired():
                raise unknown_outcome()
            return result

        while scan_batches_used < max_batches:
            result = await expire_before_deadline(
                excluded=tuple(deferred_action_ids),
            )
            if result is None:
                break
            scan_batches_used += 1
            operations_used += 1
            total += result.expired
            deferred_action_ids.update(result.deferred_action_ids)
            if result.selected < batch_size:
                underfilled_scans = underfilled_scans + 1 if result.selected == 0 else 1
                if underfilled_scans >= 2:
                    break
            else:
                underfilled_scans = 0
            await asyncio.sleep(0)

        if deferred_action_ids:
            pending_retry = sorted(deferred_action_ids, key=str)
            retry_batches_used = 0
            # Scan and retry budgets are separate but share the same wall-clock deadline.
            while pending_retry and retry_batches_used < max_batches:
                retry_ids = tuple(pending_retry[:batch_size])
                del pending_retry[:batch_size]
                result = await expire_before_deadline(included=retry_ids)
                if result is None:
                    break
                retry_batches_used += 1
                operations_used += 1
                total += result.expired
                await asyncio.sleep(0)
        return total

    async def _expire_actions(
        self,
        now: datetime,
        batch_size: int,
        *,
        timeout_seconds: float | None = None,
        excluded_action_ids: tuple[UUID, ...] = (),
        included_action_ids: tuple[UUID, ...] | None = None,
        probe: ActionExpiryBatchProbe | None = None,
    ) -> ActionExpiryBatchResult:
        if excluded_action_ids and included_action_ids is not None:
            raise ValueError("ACTION_EXPIRY_FILTERS_MUTUALLY_EXCLUSIVE")
        async with self._sessions() as session, session.begin():
            if timeout_seconds is not None:
                if timeout_seconds <= 0:
                    raise ValueError("RETENTION_ACTION_TIMEOUT_MUST_BE_POSITIVE")
                timeout = f"{max(math.ceil(timeout_seconds * 1000), 1)}ms"
                for setting in ("statement_timeout", "lock_timeout"):
                    await session.execute(
                        text("SELECT set_config(:setting, :timeout, true)"),
                        {"setting": setting, "timeout": timeout},
                    )
            await self._assert_retention_role(session)
            eligible_actions = select(PreparedAction).where(
                PreparedAction.expires_at <= now,
                PreparedAction.status.in_(
                    (
                        ActionStatus.PROPOSED,
                        ActionStatus.PREPARED,
                        ActionStatus.PENDING_APPROVAL,
                        ActionStatus.APPROVED,
                    )
                ),
            )
            if included_action_ids is not None:
                eligible_actions = eligible_actions.where(
                    PreparedAction.action_id.in_(included_action_ids)
                )
            elif excluded_action_ids:
                eligible_actions = eligible_actions.where(
                    PreparedAction.action_id.not_in(excluded_action_ids)
                )
            records = list(
                (
                    await session.scalars(
                        eligible_actions.order_by(
                            PreparedAction.expires_at, PreparedAction.action_id
                        )
                        .limit(batch_size)
                        .with_for_update(skip_locked=True)
                    )
                ).all()
            )
            if probe is not None:
                probe.selected_action_ids = tuple(action.action_id for action in records)
            if not records:
                return ActionExpiryBatchResult(selected=0, expired=0)
            expired = 0
            deferred: list[UUID] = []
            for action in sorted(
                records,
                key=lambda candidate: (str(candidate.run_id), str(candidate.action_id)),
            ):
                run_id = await session.scalar(
                    select(AgentRun.run_id)
                    .where(
                        AgentRun.run_id == action.run_id,
                        AgentRun.tenant_id == action.tenant_id,
                    )
                    .with_for_update(skip_locked=True)
                )
                if run_id is None:
                    exists = await session.scalar(
                        select(AgentRun.run_id).where(
                            AgentRun.run_id == action.run_id,
                            AgentRun.tenant_id == action.tenant_id,
                        )
                    )
                    if exists is None:
                        raise RuntimeError("ACTION_EXPIRY_RUN_NOT_FOUND")
                    deferred.append(action.action_id)
                    continue
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
                    {"run_id": str(action.run_id)},
                )
                sequence_no = int(sequence_result.scalar_one())
                previous_status = action.status.value
                event_payload = action_expired_event_payload(
                    run_id=action.run_id,
                    action_id=action.action_id,
                    payload_digest=action.payload_hash,
                    previous_status=previous_status,
                    scheduled_expires_at=action.expires_at,
                    expired_at=now,
                    reason="retention_fallback",
                )
                digest = payload_hash(event_payload)
                correlation_id = f"retention:action-expired:{action.action_id}"
                if probe is not None:
                    # The operation suffix is the durable readback key after a timeout.
                    correlation_id = f"{correlation_id}:operation:{probe.operation_id}"
                action.status = ActionStatus.EXPIRED
                action.failure_code = "ACTION_EXPIRED"
                action.updated_at = now
                action.version = int(action.version) + 1
                session.add(
                    RunEvent(
                        run_id=action.run_id,
                        tenant_id=action.tenant_id,
                        sequence_no=sequence_no,
                        event_type=RunEventType.ACTION_EXPIRED.value,
                        schema_version="1.0",
                        actor_type="maintenance",
                        actor_id="retention-worker",
                        task_id=None,
                        action_id=action.action_id,
                        correlation_id=correlation_id,
                        payload=event_payload,
                        payload_hash=digest,
                    )
                )
                session.add(
                    OutboxEvent(
                        tenant_id=action.tenant_id,
                        aggregate_type="run",
                        aggregate_id=str(action.run_id),
                        event_key=f"{correlation_id}:{sequence_no}",
                        event_type=RunEventType.ACTION_EXPIRED.value,
                        payload=event_payload,
                        payload_hash=digest,
                    )
                )
                expired += 1
            await session.flush()
            return ActionExpiryBatchResult(
                selected=len(records),
                expired=expired,
                deferred_action_ids=tuple(deferred),
            )

    async def _delete_idempotency(self, now: datetime, batch_size: int) -> int:
        async with self._sessions() as session, session.begin():
            await self._assert_retention_role(session)
            keys = list(
                (
                    await session.execute(
                        select(
                            IdempotencyRecord.tenant_id,
                            IdempotencyRecord.scope,
                            IdempotencyRecord.idempotency_key,
                        )
                        .where(IdempotencyRecord.expires_at <= now)
                        .order_by(IdempotencyRecord.expires_at)
                        .limit(batch_size)
                        .with_for_update(skip_locked=True)
                    )
                ).all()
            )
            for tenant_id, scope, key in keys:
                await session.execute(
                    delete(IdempotencyRecord).where(
                        IdempotencyRecord.tenant_id == tenant_id,
                        IdempotencyRecord.scope == scope,
                        IdempotencyRecord.idempotency_key == key,
                    )
                )
            return len(keys)

    async def _expire_memories(self, now: datetime, batch_size: int) -> int:
        async with self._sessions() as session, session.begin():
            await self._assert_retention_role(session)
            records = list(
                (
                    await session.scalars(
                        select(MemoryRecord)
                        .where(
                            MemoryRecord.valid_until.is_not(None),
                            MemoryRecord.valid_until <= now,
                            MemoryRecord.deleted_at.is_(None),
                        )
                        .order_by(MemoryRecord.valid_until)
                        .limit(batch_size)
                        .with_for_update(skip_locked=True)
                    )
                ).all()
            )
            for record in records:
                record.deleted_at = now
                session.add(
                    MemoryLifecycleEvent(
                        event_id=uuid4(),
                        memory_id=record.memory_id,
                        tenant_id=record.tenant_id,
                        event_type="expired",
                        actor_id="retention-worker",
                        reason="Memory reached valid_until.",
                        previous_hash=record.content_hash,
                        metadata_json={"expired_at": now.isoformat()},
                    )
                )
            return len(records)

    async def _delete_artifacts(self, now: datetime, batch_size: int) -> int:
        async with self._sessions() as session, session.begin():
            await self._assert_retention_role(session)
            records = list(
                (
                    await session.scalars(
                        select(Artifact)
                        .where(
                            Artifact.deleted_at.is_(None),
                            Artifact.legal_hold_status == "none",
                            (
                                Artifact.object_retain_until.is_(None)
                                | (Artifact.object_retain_until <= now)
                            ),
                            (Artifact.lifecycle_status == "delete_pending")
                            | (
                                (Artifact.lifecycle_status == "available")
                                & Artifact.expires_at.is_not(None)
                                & (Artifact.expires_at <= now)
                            ),
                        )
                        .order_by(
                            Artifact.delete_requested_at.asc().nulls_last(),
                            Artifact.expires_at.asc().nulls_last(),
                        )
                        .limit(batch_size)
                        .with_for_update(skip_locked=True)
                    )
                ).all()
            )
            deleted = 0
            for artifact in records:
                expired = artifact.lifecycle_status == "available"
                artifact.lifecycle_status = "delete_pending"
                artifact.delete_requested_at = artifact.delete_requested_at or now
                artifact.delete_attempts += 1
                artifact.delete_last_error_code = None
                try:
                    await self._delete_artifact(artifact)
                except Exception as exc:
                    artifact.delete_last_error_code = str(
                        getattr(exc, "code", type(exc).__name__.upper())
                    )[:128]
                    continue
                artifact.lifecycle_status = "deleted"
                artifact.deleted_at = now
                artifact.delete_last_error_code = None
                if expired:
                    session.add(_artifact_expired_event(artifact))
                deleted += 1
            return deleted

    async def _assert_retention_role(self, session: Any) -> None:
        if self._role_verified:
            return
        allowed = await session.scalar(
            text("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user")
        )
        if allowed is not True:
            raise RuntimeError("RETENTION_ROLE_MUST_BYPASS_RLS")
        self._role_verified = True


async def _run_once() -> RetentionSweepReport:
    import boto3
    from botocore.config import Config as BotoConfig  # type: ignore[import-untyped]

    settings = Settings(process_role="retention-worker")
    sessions = create_session_factory(settings.database_dsn.get_secret_value())
    client_options: dict[str, Any] = {
        "region_name": settings.artifact_region or "us-east-1",
    }
    if settings.artifact_endpoint_url:
        client_options["endpoint_url"] = settings.artifact_endpoint_url
        client_options["config"] = BotoConfig(s3={"addressing_style": "path"})
    client = boto3.client("s3", **client_options)
    archive_kms_key = (settings.artifact_kms_key or "").strip() or None
    if settings.environment in {"staging", "prod"} and archive_kms_key is None:
        client.close()
        await dispose_session_factory(sessions)
        raise RuntimeError("RETENTION_ARCHIVE_KMS_KEY_REQUIRED")
    try:
        lifecycle = PostgresLifecycleRetention(
            session_factory=sessions,
            archive=S3ImmutableArchiveAdapter(
                client=client,
                bucket=settings.artifact_bucket,
                environment=settings.environment,
                kms_key_id=archive_kms_key,
                allow_unencrypted_local=settings.artifact_allow_unencrypted_local,
            ),
        )
        worker = PostgresRetentionWorker(
            session_factory=sessions,
            delete_artifact=S3ArtifactDeleter(
                client=client,
                bucket=settings.artifact_bucket,
                environment=settings.environment,
            ),
            lifecycle=lifecycle,
        )
        return await worker.run_once()
    finally:
        client.close()
        await dispose_session_factory(sessions)


def main() -> None:
    report = asyncio.run(_run_once())
    print(
        json.dumps(
            {
                "expired_actions": report.expired_actions,
                "deleted_idempotency_records": (report.deleted_idempotency_records),
                "expired_memories": report.expired_memories,
                "deleted_artifacts": report.deleted_artifacts,
                "archived_runs": report.archived_runs,
                "purged_runs": report.purged_runs,
                "archived_event_streams": report.archived_event_streams,
                "held_resources": report.held_resources,
                "lifecycle_failures": report.lifecycle_failures,
            },
            sort_keys=True,
        )
    )
