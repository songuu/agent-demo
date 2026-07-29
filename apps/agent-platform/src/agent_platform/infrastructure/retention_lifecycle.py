"""Policy-driven retention, legal hold, and immutable archive adapters."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import re
from collections.abc import AsyncIterable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Literal, Protocol, cast
from urllib.parse import quote, urlsplit
from uuid import UUID, uuid4

from sqlalchemy import Text, case, exists, or_, select, text, update
from sqlalchemy import cast as sql_cast

from agent_platform.domain.hashing import canonical_json, payload_hash
from agent_platform.infrastructure.persistence.models import (
    AgentRun,
    Artifact,
    RunEvent,
    TaskExecution,
)
from agent_platform.infrastructure.persistence.retention_models import (
    LegalHold,
    LegalHoldEvent,
    RetentionEvidence,
    RetentionJob,
    RetentionPolicyVersion,
)
from agent_platform.infrastructure.persistence.runtime_models import RunRuntimeSnapshot
from agent_platform.infrastructure.persistence.session import (
    AsyncSessionFactory,
    tenant_session,
)

PLATFORM_POLICY_TENANT = "__platform__"
TERMINAL_RUN_STATUSES = ("completed", "failed", "cancelled")
RUN_POLICY_RESOURCE = "agent_run"
EVENT_POLICY_RESOURCE = "run_event"
_SAFE_RESOURCE_TYPE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")

type ArchiveRows = Iterable[Mapping[str, Any]] | AsyncIterable[Mapping[str, Any]]


class LifecycleAction(StrEnum):
    RETAIN = "retain"
    HOLD = "hold"
    ARCHIVE = "archive"
    PURGE = "purge"


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    policy_key: str
    version: int
    resource_type: str
    classification: str
    business_requirement: str
    audit_requirement: str
    owner_id: str
    online_retention_days: int
    archive_retention_days: int | None
    disposition: str
    immutable_archive: bool
    legal_hold_enabled: bool

    def validate(self) -> None:
        required = {
            "policy_key": self.policy_key,
            "resource_type": self.resource_type,
            "classification": self.classification,
            "business_requirement": self.business_requirement,
            "audit_requirement": self.audit_requirement,
            "owner_id": self.owner_id,
            "disposition": self.disposition,
        }
        if any(not value.strip() for value in required.values()):
            raise ValueError("RETENTION_POLICY_REQUIRED_FIELD_MISSING")
        if self.version <= 0 or self.online_retention_days <= 0:
            raise ValueError("RETENTION_POLICY_VERSION_OR_DURATION_INVALID")
        if (
            self.archive_retention_days is not None
            and self.archive_retention_days < self.online_retention_days
        ):
            raise ValueError("RETENTION_ARCHIVE_DURATION_TOO_SHORT")
        if self.resource_type == RUN_POLICY_RESOURCE and not (
            90 <= self.online_retention_days <= 365
        ):
            raise ValueError("AGENT_RUN_RETENTION_OUT_OF_RANGE")
        if self.resource_type == EVENT_POLICY_RESOURCE:
            if self.online_retention_days < 365:
                raise ValueError("RUN_EVENT_RETENTION_TOO_SHORT")
            if self.disposition != "immutable_archive" or not self.immutable_archive:
                raise ValueError("RUN_EVENT_IMMUTABLE_ARCHIVE_REQUIRED")
        if self.resource_type == "model_raw":
            if self.online_retention_days > 7 or self.disposition != "hash_only_delete":
                raise ValueError("MODEL_RAW_RETENTION_NOT_MINIMAL")
        if self.resource_type == "tool_raw" and self.disposition != "artifact_then_delete":
            raise ValueError("TOOL_RAW_MUST_ARCHIVE_BEFORE_DELETE")
        if self.resource_type == "approval_receipt":
            if self.online_retention_days < 2_555 or self.disposition != "retain":
                raise ValueError("APPROVAL_RECEIPT_MUST_BE_LONG_LIVED")


@dataclass(frozen=True, slots=True)
class LifecycleResourceState:
    completed_at: datetime
    archived: bool
    purged: bool


def decide_lifecycle_action(
    *,
    policy: RetentionPolicy,
    state: LifecycleResourceState,
    now: datetime,
    active_legal_hold: bool,
) -> LifecycleAction:
    policy.validate()
    if state.completed_at.tzinfo is None or state.completed_at.utcoffset() is None:
        raise ValueError("RETENTION_COMPLETION_TIMEZONE_REQUIRED")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("RETENTION_NOW_TIMEZONE_REQUIRED")
    if active_legal_hold:
        return LifecycleAction.HOLD
    if state.purged:
        return LifecycleAction.RETAIN
    age = now - state.completed_at
    if (
        state.archived
        and policy.disposition == "archive_then_purge"
        and policy.archive_retention_days is not None
        and age >= timedelta(days=policy.archive_retention_days)
    ):
        return LifecycleAction.PURGE
    if not state.archived and age >= timedelta(days=policy.online_retention_days):
        if policy.disposition in {"archive_then_purge", "immutable_archive"}:
            return LifecycleAction.ARCHIVE
    return LifecycleAction.RETAIN


@dataclass(frozen=True, slots=True)
class ArchiveDescriptor:
    tenant_id: str
    resource_type: str
    resource_id: str
    policy: RetentionPolicy

    def validate(self) -> None:
        self.policy.validate()
        if not self.tenant_id.strip() or not self.resource_id.strip():
            raise ValueError("RETENTION_ARCHIVE_SCOPE_REQUIRED")
        if (
            self.resource_type != self.policy.resource_type
            or not _SAFE_RESOURCE_TYPE.fullmatch(self.resource_type)
        ):
            raise ValueError("RETENTION_ARCHIVE_RESOURCE_TYPE_INVALID")
        if not self.policy.immutable_archive:
            raise ValueError("RETENTION_ARCHIVE_IMMUTABILITY_REQUIRED")


@dataclass(frozen=True, slots=True)
class ImmutableArchiveReceipt:
    tenant_id: str
    resource_type: str
    resource_id: str
    uri: str
    sha256: str
    version_id: str
    object_lock_mode: str
    retain_until: datetime
    content_length: int
    policy_key: str
    policy_version: int


class ImmutableArchiveAdapter(Protocol):
    async def archive_json_lines(
        self,
        descriptor: ArchiveDescriptor,
        rows: ArchiveRows,
    ) -> ImmutableArchiveReceipt: ...

    async def restore_and_verify(self, receipt: ImmutableArchiveReceipt) -> bytes: ...


class S3ImmutableArchiveAdapter:
    """Write content-addressed JSONL with KMS, versioning, and Object Lock evidence."""

    def __init__(
        self,
        *,
        client: Any,
        bucket: str,
        environment: str,
        kms_key_id: str | None,
        object_lock_mode: Literal["GOVERNANCE", "COMPLIANCE"] = "COMPLIANCE",
    ) -> None:
        if not bucket.strip():
            raise ValueError("RETENTION_ARCHIVE_BUCKET_REQUIRED")
        if kms_key_id is not None and not kms_key_id.strip():
            raise ValueError("RETENTION_ARCHIVE_KMS_INVALID")
        if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", environment):
            raise ValueError("RETENTION_ARCHIVE_ENVIRONMENT_INVALID")
        self._client = client
        self._bucket = bucket
        self._environment = environment
        self._kms_key_id = kms_key_id.strip() if kms_key_id is not None else None
        self._object_lock_mode = object_lock_mode

    async def archive_json_lines(
        self,
        descriptor: ArchiveDescriptor,
        rows: ArchiveRows,
    ) -> ImmutableArchiveReceipt:
        descriptor.validate()
        with TemporaryDirectory(prefix="agent-retention-") as directory:
            path = Path(directory) / "archive.jsonl"
            digest, size = await self._write_archive(path, descriptor, rows)
            key = (
                f"{self._environment}/tenant/{quote(descriptor.tenant_id, safe='')}/"
                f"retention/{descriptor.resource_type}/{digest}.jsonl"
            )
            retain_days = descriptor.policy.archive_retention_days
            if retain_days is None:
                raise ValueError("RETENTION_ARCHIVE_DURATION_REQUIRED")
            requested_retain_until = datetime.now(UTC) + timedelta(days=retain_days)
            metadata = {
                "sha256": digest,
                "policy-key": descriptor.policy.policy_key,
                "policy-version": str(descriptor.policy.version),
                "resource-type": descriptor.resource_type,
                "resource-id-sha256": hashlib.sha256(
                    descriptor.resource_id.encode("utf-8")
                ).hexdigest(),
                "tenant-id-sha256": hashlib.sha256(
                    descriptor.tenant_id.encode("utf-8")
                ).hexdigest(),
            }
            version_id = await self._put_content_addressed(
                path=path,
                key=key,
                size=size,
                digest=digest,
                metadata=metadata,
                retain_until=requested_retain_until,
            )
            head = await asyncio.to_thread(
                self._client.head_object,
                Bucket=self._bucket,
                Key=key,
            )
            actual_retain_until = self._verify_head(
                head=head,
                digest=digest,
                size=size,
                metadata=metadata,
            )
            actual_version = str(head.get("VersionId") or version_id or "").strip()
            if not actual_version:
                raise RuntimeError("RETENTION_ARCHIVE_VERSION_ID_REQUIRED")
            return ImmutableArchiveReceipt(
                tenant_id=descriptor.tenant_id,
                resource_type=descriptor.resource_type,
                resource_id=descriptor.resource_id,
                uri=f"s3://{self._bucket}/{key}",
                sha256=digest,
                version_id=actual_version,
                object_lock_mode=self._object_lock_mode,
                retain_until=actual_retain_until,
                content_length=size,
                policy_key=descriptor.policy.policy_key,
                policy_version=descriptor.policy.version,
            )

    async def restore_and_verify(self, receipt: ImmutableArchiveReceipt) -> bytes:
        parsed = urlsplit(receipt.uri)
        key = parsed.path.lstrip("/")
        expected_prefix = (
            f"{self._environment}/tenant/{quote(receipt.tenant_id, safe='')}/"
            f"retention/{receipt.resource_type}/"
        )
        if (
            parsed.scheme != "s3"
            or parsed.netloc != self._bucket
            or not key.startswith(expected_prefix)
            or not key.endswith(f"/{receipt.sha256}.jsonl")
            or ".." in key.split("/")
        ):
            raise RuntimeError("RETENTION_ARCHIVE_URI_OUTSIDE_SCOPE")
        response = await asyncio.to_thread(
            self._client.get_object,
            Bucket=self._bucket,
            Key=key,
            VersionId=receipt.version_id,
        )
        body = response.get("Body")
        if body is None or not hasattr(body, "read"):
            raise RuntimeError("RETENTION_ARCHIVE_BODY_MISSING")
        content = await asyncio.to_thread(body.read)
        close = getattr(body, "close", None)
        if callable(close):
            close()
        if not isinstance(content, bytes):
            raise RuntimeError("RETENTION_ARCHIVE_BODY_INVALID")
        if hashlib.sha256(content).hexdigest() != receipt.sha256:
            raise RuntimeError("RETENTION_ARCHIVE_HASH_MISMATCH")
        return content

    @staticmethod
    async def _write_archive(
        path: Path,
        descriptor: ArchiveDescriptor,
        rows: ArchiveRows,
    ) -> tuple[str, int]:
        digest = hashlib.sha256()
        size = 0

        def write_line(handle: Any, value: Mapping[str, Any]) -> None:
            nonlocal size
            line = canonical_json(value).encode("utf-8") + b"\n"
            handle.write(line)
            digest.update(line)
            size += len(line)

        header = {
            "schema_version": "RetentionArchive@1.0",
            "tenant_id": descriptor.tenant_id,
            "resource_type": descriptor.resource_type,
            "resource_id": descriptor.resource_id,
            "policy": {
                "policy_key": descriptor.policy.policy_key,
                "version": descriptor.policy.version,
                "classification": descriptor.policy.classification,
                "business_requirement": descriptor.policy.business_requirement,
                "audit_requirement": descriptor.policy.audit_requirement,
                "owner_id": descriptor.policy.owner_id,
                "online_retention_days": descriptor.policy.online_retention_days,
                "archive_retention_days": descriptor.policy.archive_retention_days,
                "disposition": descriptor.policy.disposition,
            },
        }
        with path.open("wb") as handle:
            write_line(handle, header)
            if isinstance(rows, AsyncIterable):
                async for row in rows:
                    write_line(handle, row)
            else:
                for row in rows:
                    write_line(handle, row)
        return digest.hexdigest(), size

    async def _put_content_addressed(
        self,
        *,
        path: Path,
        key: str,
        size: int,
        digest: str,
        metadata: dict[str, str],
        retain_until: datetime,
    ) -> str | None:
        checksum = base64.b64encode(bytes.fromhex(digest)).decode("ascii")

        encryption = (
            {
                "ServerSideEncryption": "aws:kms",
                "SSEKMSKeyId": self._kms_key_id,
                "BucketKeyEnabled": True,
            }
            if self._kms_key_id is not None
            else {"ServerSideEncryption": "AES256"}
        )

        def put() -> dict[str, Any]:
            with path.open("rb") as body:
                return cast(
                    dict[str, Any],
                    self._client.put_object(
                        Bucket=self._bucket,
                        Key=key,
                        Body=body,
                        ContentLength=size,
                        ContentType="application/x-ndjson",
                        Metadata=metadata,
                        ChecksumSHA256=checksum,
                        ObjectLockMode=self._object_lock_mode,
                        ObjectLockRetainUntilDate=retain_until,
                        IfNoneMatch="*",
                        **encryption,
                    ),
                )

        try:
            response = await asyncio.to_thread(put)
        except Exception as exc:
            if not self._precondition_failed(exc):
                raise
            return None
        return str(response.get("VersionId") or "").strip() or None

    def _verify_head(
        self,
        *,
        head: Mapping[str, Any],
        digest: str,
        size: int,
        metadata: Mapping[str, str],
    ) -> datetime:
        actual_metadata = head.get("Metadata")
        if not isinstance(actual_metadata, Mapping) or any(
            str(actual_metadata.get(key, "")) != value for key, value in metadata.items()
        ):
            raise RuntimeError("RETENTION_ARCHIVE_METADATA_MISMATCH")
        if head.get("ContentLength") != size:
            raise RuntimeError("RETENTION_ARCHIVE_SIZE_MISMATCH")
        if str(actual_metadata.get("sha256", "")) != digest:
            raise RuntimeError("RETENTION_ARCHIVE_HASH_METADATA_MISMATCH")
        if self._kms_key_id is not None:
            if (
                head.get("ServerSideEncryption") != "aws:kms"
                or head.get("SSEKMSKeyId") != self._kms_key_id
            ):
                raise RuntimeError("RETENTION_ARCHIVE_KMS_READBACK_FAILED")
        elif head.get("ServerSideEncryption") != "AES256":
            raise RuntimeError("RETENTION_ARCHIVE_ENCRYPTION_READBACK_FAILED")
        if head.get("ObjectLockMode") != self._object_lock_mode:
            raise RuntimeError("RETENTION_ARCHIVE_OBJECT_LOCK_READBACK_FAILED")
        raw_retain_until = head.get("ObjectLockRetainUntilDate")
        if not isinstance(raw_retain_until, datetime):
            raise RuntimeError("RETENTION_ARCHIVE_RETAIN_UNTIL_REQUIRED")
        retain_until = raw_retain_until.astimezone(UTC)
        if retain_until <= datetime.now(UTC):
            raise RuntimeError("RETENTION_ARCHIVE_OBJECT_LOCK_EXPIRED")
        return retain_until

    @staticmethod
    def _precondition_failed(exc: Exception) -> bool:
        response = getattr(exc, "response", None)
        if not isinstance(response, Mapping):
            return False
        error = response.get("Error")
        if not isinstance(error, Mapping):
            return False
        return str(error.get("Code", "")) in {"412", "PreconditionFailed"}


@dataclass(frozen=True, slots=True)
class LifecycleSweepReport:
    archived_runs: int = 0
    purged_runs: int = 0
    archived_event_streams: int = 0
    held_resources: int = 0
    failures: int = 0


class PostgresLifecycleRetention:
    """Archive/purge terminal Runs and immutable event streams with durable retries."""

    def __init__(
        self,
        *,
        session_factory: AsyncSessionFactory,
        archive: ImmutableArchiveAdapter,
    ) -> None:
        self._sessions = session_factory
        self._archive = archive
        self._role_verified = False

    async def run_once(
        self,
        *,
        now: datetime | None = None,
        batch_size: int = 100,
    ) -> LifecycleSweepReport:
        if batch_size <= 0:
            raise ValueError("RETENTION_BATCH_SIZE_MUST_BE_POSITIVE")
        current = now or datetime.now(UTC)
        archived_runs, held_a, failed_a = await self._archive_runs(current, batch_size)
        purged_runs, held_p, failed_p = await self._purge_runs(current, batch_size)
        archived_events, held_e, failed_e = await self._archive_events(current, batch_size)
        return LifecycleSweepReport(
            archived_runs=archived_runs,
            purged_runs=purged_runs,
            archived_event_streams=archived_events,
            held_resources=held_a + held_p + held_e,
            failures=failed_a + failed_p + failed_e,
        )

    async def _archive_runs(self, now: datetime, batch_size: int) -> tuple[int, int, int]:
        done = exists().where(
            RetentionJob.tenant_id == AgentRun.tenant_id,
            RetentionJob.resource_type == RUN_POLICY_RESOURCE,
            RetentionJob.resource_id == sql_cast(AgentRun.run_id, Text),
            RetentionJob.operation == "archive",
            RetentionJob.status == "succeeded",
        )
        async with self._sessions() as session:
            await self._assert_retention_role(session)
            rows = list(
                (
                    await session.scalars(
                        select(AgentRun)
                        .where(
                            AgentRun.status.in_(TERMINAL_RUN_STATUSES),
                            AgentRun.completed_at.is_not(None),
                            AgentRun.completed_at <= now - timedelta(days=90),
                            ~done,
                        )
                        .order_by(AgentRun.completed_at)
                        .limit(batch_size)
                    )
                ).all()
            )
        archived = held = failed = 0
        for run in rows:
            policy = await self._policy(run.tenant_id, RUN_POLICY_RESOURCE)
            completed_at = cast(datetime, run.completed_at)
            if now - completed_at < timedelta(days=policy.online_retention_days):
                continue
            hold = await self._active_hold(
                tenant_id=run.tenant_id,
                resource_type=RUN_POLICY_RESOURCE,
                resource_id=str(run.run_id),
                now=now,
            )
            if hold is not None:
                await self._mark_held(
                    tenant_id=run.tenant_id,
                    resource_type=RUN_POLICY_RESOURCE,
                    resource_id=str(run.run_id),
                    operation="archive",
                    policy=policy,
                    hold=hold,
                    now=now,
                )
                held += 1
                continue
            job = await self._claim_job(
                tenant_id=run.tenant_id,
                resource_type=RUN_POLICY_RESOURCE,
                resource_id=str(run.run_id),
                operation="archive",
                policy=policy,
                now=now,
            )
            if job is None:
                continue
            try:
                records = await self._run_archive_records(run)
                source_hash = payload_hash(records)
                receipt = await self._archive.archive_json_lines(
                    ArchiveDescriptor(
                        tenant_id=run.tenant_id,
                        resource_type=RUN_POLICY_RESOURCE,
                        resource_id=str(run.run_id),
                        policy=policy,
                    ),
                    records,
                )
                await self._complete_job(
                    job_id=job.job_id,
                    operation="archived",
                    now=now,
                    source_hash=source_hash,
                    receipt=receipt,
                )
            except Exception as exc:
                await self._fail_job(job.job_id, exc, now)
                failed += 1
            else:
                archived += 1
        return archived, held, failed

    async def _purge_runs(self, now: datetime, batch_size: int) -> tuple[int, int, int]:
        archive_done = exists().where(
            RetentionJob.tenant_id == AgentRun.tenant_id,
            RetentionJob.resource_type == RUN_POLICY_RESOURCE,
            RetentionJob.resource_id == sql_cast(AgentRun.run_id, Text),
            RetentionJob.operation == "archive",
            RetentionJob.status == "succeeded",
        )
        purge_done = exists().where(
            RetentionJob.tenant_id == AgentRun.tenant_id,
            RetentionJob.resource_type == RUN_POLICY_RESOURCE,
            RetentionJob.resource_id == sql_cast(AgentRun.run_id, Text),
            RetentionJob.operation == "purge",
            RetentionJob.status == "succeeded",
        )
        async with self._sessions() as session:
            await self._assert_retention_role(session)
            rows = list(
                (
                    await session.scalars(
                        select(AgentRun)
                        .where(
                            AgentRun.status.in_(TERMINAL_RUN_STATUSES),
                            AgentRun.completed_at.is_not(None),
                            AgentRun.completed_at <= now - timedelta(days=90),
                            archive_done,
                            ~purge_done,
                        )
                        .order_by(AgentRun.completed_at)
                        .limit(batch_size)
                    )
                ).all()
            )
        purged = held = failed = 0
        for run in rows:
            policy = await self._policy(run.tenant_id, RUN_POLICY_RESOURCE)
            if (
                policy.archive_retention_days is None
                or now - cast(datetime, run.completed_at)
                < timedelta(days=policy.archive_retention_days)
            ):
                continue
            hold = await self._active_hold(
                tenant_id=run.tenant_id,
                resource_type=RUN_POLICY_RESOURCE,
                resource_id=str(run.run_id),
                now=now,
            )
            if hold is not None:
                await self._mark_held(
                    tenant_id=run.tenant_id,
                    resource_type=RUN_POLICY_RESOURCE,
                    resource_id=str(run.run_id),
                    operation="purge",
                    policy=policy,
                    hold=hold,
                    now=now,
                )
                held += 1
                continue
            job = await self._claim_job(
                tenant_id=run.tenant_id,
                resource_type=RUN_POLICY_RESOURCE,
                resource_id=str(run.run_id),
                operation="purge",
                policy=policy,
                now=now,
            )
            if job is None:
                continue
            try:
                await self._purge_run(job.job_id, run, now)
            except Exception as exc:
                await self._fail_job(job.job_id, exc, now)
                failed += 1
            else:
                purged += 1
        return purged, held, failed

    async def _archive_events(self, now: datetime, batch_size: int) -> tuple[int, int, int]:
        done = exists().where(
            RetentionJob.tenant_id == AgentRun.tenant_id,
            RetentionJob.resource_type == EVENT_POLICY_RESOURCE,
            RetentionJob.resource_id == sql_cast(AgentRun.run_id, Text),
            RetentionJob.operation == "archive",
            RetentionJob.status == "succeeded",
        )
        async with self._sessions() as session:
            await self._assert_retention_role(session)
            rows = list(
                (
                    await session.scalars(
                        select(AgentRun)
                        .where(
                            AgentRun.status.in_(TERMINAL_RUN_STATUSES),
                            AgentRun.completed_at.is_not(None),
                            AgentRun.completed_at <= now - timedelta(days=365),
                            ~done,
                        )
                        .order_by(AgentRun.completed_at)
                        .limit(batch_size)
                    )
                ).all()
            )
        archived = held = failed = 0
        for run in rows:
            policy = await self._policy(run.tenant_id, EVENT_POLICY_RESOURCE)
            if now - cast(datetime, run.completed_at) < timedelta(
                days=policy.online_retention_days
            ):
                continue
            hold = await self._active_hold(
                tenant_id=run.tenant_id,
                resource_type=EVENT_POLICY_RESOURCE,
                resource_id=str(run.run_id),
                now=now,
                include_parent_run=True,
            )
            if hold is not None:
                await self._mark_held(
                    tenant_id=run.tenant_id,
                    resource_type=EVENT_POLICY_RESOURCE,
                    resource_id=str(run.run_id),
                    operation="archive",
                    policy=policy,
                    hold=hold,
                    now=now,
                )
                held += 1
                continue
            job = await self._claim_job(
                tenant_id=run.tenant_id,
                resource_type=EVENT_POLICY_RESOURCE,
                resource_id=str(run.run_id),
                operation="archive",
                policy=policy,
                now=now,
            )
            if job is None:
                continue
            try:
                rows_stream = self._event_rows(run.run_id, run.tenant_id)
                receipt = await self._archive.archive_json_lines(
                    ArchiveDescriptor(
                        tenant_id=run.tenant_id,
                        resource_type=EVENT_POLICY_RESOURCE,
                        resource_id=str(run.run_id),
                        policy=policy,
                    ),
                    rows_stream,
                )
                await self._complete_job(
                    job_id=job.job_id,
                    operation="archived",
                    now=now,
                    source_hash=receipt.sha256,
                    receipt=receipt,
                )
            except Exception as exc:
                await self._fail_job(job.job_id, exc, now)
                failed += 1
            else:
                archived += 1
        return archived, held, failed

    async def _policy(self, tenant_id: str, resource_type: str) -> RetentionPolicy:
        async with self._sessions() as session:
            await self._assert_retention_role(session)
            row = await session.scalar(
                select(RetentionPolicyVersion)
                .where(
                    RetentionPolicyVersion.tenant_id.in_(
                        (tenant_id, PLATFORM_POLICY_TENANT)
                    ),
                    RetentionPolicyVersion.resource_type == resource_type,
                    RetentionPolicyVersion.enabled.is_(True),
                    RetentionPolicyVersion.effective_at <= datetime.now(UTC),
                )
                .order_by(
                    case(
                        (RetentionPolicyVersion.tenant_id == tenant_id, 0),
                        else_=1,
                    ),
                    RetentionPolicyVersion.version.desc(),
                )
                .limit(1)
            )
        if row is None:
            raise RuntimeError(f"RETENTION_POLICY_NOT_FOUND:{resource_type}")
        policy = RetentionPolicy(
            policy_key=row.policy_key,
            version=row.version,
            resource_type=row.resource_type,
            classification=row.classification,
            business_requirement=row.business_requirement,
            audit_requirement=row.audit_requirement,
            owner_id=row.owner_id,
            online_retention_days=row.online_retention_days,
            archive_retention_days=row.archive_retention_days,
            disposition=row.disposition,
            immutable_archive=row.immutable_archive,
            legal_hold_enabled=row.legal_hold_enabled,
        )
        policy.validate()
        return policy

    async def _active_hold(
        self,
        *,
        tenant_id: str,
        resource_type: str,
        resource_id: str,
        now: datetime,
        include_parent_run: bool = False,
    ) -> LegalHold | None:
        resource_types = (
            (resource_type, RUN_POLICY_RESOURCE)
            if include_parent_run
            else (resource_type,)
        )
        async with self._sessions() as session:
            await self._assert_retention_role(session)
            hold = await session.scalar(
                select(LegalHold)
                .where(
                    LegalHold.tenant_id == tenant_id,
                    LegalHold.resource_type.in_(resource_types),
                    LegalHold.resource_id.in_((resource_id, "*")),
                    LegalHold.status == "active",
                    LegalHold.starts_at <= now,
                    or_(LegalHold.expires_at.is_(None), LegalHold.expires_at > now),
                )
                .order_by(LegalHold.starts_at, LegalHold.hold_id)
                .limit(1)
            )
        return hold

    async def _claim_job(
        self,
        *,
        tenant_id: str,
        resource_type: str,
        resource_id: str,
        operation: str,
        policy: RetentionPolicy,
        now: datetime,
    ) -> RetentionJob | None:
        async with self._sessions() as session, session.begin():
            await self._assert_retention_role(session)
            job = await session.scalar(
                select(RetentionJob)
                .where(
                    RetentionJob.tenant_id == tenant_id,
                    RetentionJob.resource_type == resource_type,
                    RetentionJob.resource_id == resource_id,
                    RetentionJob.operation == operation,
                    RetentionJob.policy_key == policy.policy_key,
                    RetentionJob.policy_version == policy.version,
                )
                .with_for_update()
            )
            if job is None:
                job = RetentionJob(
                    job_id=uuid4(),
                    tenant_id=tenant_id,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    operation=operation,
                    policy_key=policy.policy_key,
                    policy_version=policy.version,
                    status="in_progress",
                    attempts=1,
                    next_attempt_at=now,
                    started_at=now,
                    updated_at=now,
                )
                session.add(job)
                return job
            stale = job.started_at is not None and job.started_at <= now - timedelta(hours=1)
            if job.status == "succeeded":
                return None
            if job.status == "in_progress" and not stale:
                return None
            if job.status == "failed" and job.next_attempt_at > now:
                return None
            job.status = "in_progress"
            job.attempts += 1
            job.started_at = now
            job.completed_at = None
            job.last_error_code = None
            job.last_error_detail = None
            job.updated_at = now
            return job

    async def _mark_held(
        self,
        *,
        tenant_id: str,
        resource_type: str,
        resource_id: str,
        operation: str,
        policy: RetentionPolicy,
        hold: LegalHold,
        now: datetime,
    ) -> None:
        async with self._sessions() as session, session.begin():
            await self._assert_retention_role(session)
            job = await session.scalar(
                select(RetentionJob)
                .where(
                    RetentionJob.tenant_id == tenant_id,
                    RetentionJob.resource_type == resource_type,
                    RetentionJob.resource_id == resource_id,
                    RetentionJob.operation == operation,
                    RetentionJob.policy_key == policy.policy_key,
                    RetentionJob.policy_version == policy.version,
                )
                .with_for_update()
            )
            if job is None:
                job = RetentionJob(
                    job_id=uuid4(),
                    tenant_id=tenant_id,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    operation=operation,
                    policy_key=policy.policy_key,
                    policy_version=policy.version,
                    status="held",
                    attempts=0,
                    next_attempt_at=now,
                    updated_at=now,
                )
                session.add(job)
                await session.flush()
            elif job.status == "held":
                return
            elif job.status == "succeeded":
                return
            else:
                job.status = "held"
                job.updated_at = now
            await self._append_evidence(
                session=session,
                job=job,
                operation="legal_hold_blocked",
                now=now,
                legal_hold_id=hold.hold_id,
                details={
                    "case_reference_hash": hashlib.sha256(
                        hold.case_reference.encode("utf-8")
                    ).hexdigest(),
                    "hold_owner": hold.owner_id,
                },
            )

    async def _complete_job(
        self,
        *,
        job_id: UUID,
        operation: str,
        now: datetime,
        source_hash: str,
        receipt: ImmutableArchiveReceipt,
    ) -> None:
        async with self._sessions() as session, session.begin():
            await self._assert_retention_role(session)
            job = await session.scalar(
                select(RetentionJob)
                .where(RetentionJob.job_id == job_id)
                .with_for_update()
            )
            if job is None:
                raise RuntimeError("RETENTION_JOB_NOT_FOUND")
            if job.status == "succeeded":
                return
            if job.status != "in_progress":
                raise RuntimeError("RETENTION_JOB_NOT_IN_PROGRESS")
            job.status = "succeeded"
            job.source_payload_hash = source_hash
            job.archive_uri = receipt.uri
            job.archive_sha256 = receipt.sha256
            job.archive_version_id = receipt.version_id
            job.object_lock_mode = receipt.object_lock_mode
            job.retain_until = receipt.retain_until
            job.completed_at = now
            job.updated_at = now
            await self._append_evidence(
                session=session,
                job=job,
                operation=operation,
                now=now,
                source_payload_hash=source_hash,
                receipt=receipt,
                details={"content_length": receipt.content_length},
            )

    async def _fail_job(self, job_id: UUID, exc: Exception, now: datetime) -> None:
        async with self._sessions() as session, session.begin():
            await self._assert_retention_role(session)
            job = await session.scalar(
                select(RetentionJob)
                .where(RetentionJob.job_id == job_id)
                .with_for_update()
            )
            if job is None or job.status == "succeeded":
                return
            code = str(getattr(exc, "code", type(exc).__name__.upper()))[:128]
            detail = str(exc)[:1_000]
            backoff_minutes = min(2 ** min(max(job.attempts, 1), 10), 1_440)
            job.status = "failed"
            job.last_error_code = code
            job.last_error_detail = detail
            job.next_attempt_at = now + timedelta(minutes=backoff_minutes)
            job.completed_at = now
            job.updated_at = now
            await self._append_evidence(
                session=session,
                job=job,
                operation="failed",
                now=now,
                details={"error_code": code},
            )

    async def _purge_run(self, job_id: UUID, run: AgentRun, now: datetime) -> None:
        async with self._sessions() as session, session.begin():
            await self._assert_retention_role(session)
            job = await session.scalar(
                select(RetentionJob)
                .where(RetentionJob.job_id == job_id)
                .with_for_update()
            )
            database_run = await session.scalar(
                select(AgentRun)
                .where(
                    AgentRun.run_id == run.run_id,
                    AgentRun.tenant_id == run.tenant_id,
                )
                .with_for_update()
            )
            if job is None or database_run is None:
                raise RuntimeError("RETENTION_PURGE_TARGET_NOT_FOUND")
            if job.status != "in_progress":
                raise RuntimeError("RETENTION_JOB_NOT_IN_PROGRESS")
            archive_job = await session.scalar(
                select(RetentionJob).where(
                    RetentionJob.tenant_id == run.tenant_id,
                    RetentionJob.resource_type == RUN_POLICY_RESOURCE,
                    RetentionJob.resource_id == str(run.run_id),
                    RetentionJob.operation == "archive",
                    RetentionJob.status == "succeeded",
                )
            )
            if archive_job is None or not archive_job.archive_sha256:
                raise RuntimeError("RETENTION_ARCHIVE_REQUIRED_BEFORE_PURGE")
            source_hash = payload_hash(self._orm_payload(database_run))
            principal_hash = hashlib.sha256(
                database_run.principal_id.encode("utf-8")
            ).hexdigest()
            database_run.principal_id = f"sha256:{principal_hash}"
            database_run.contract_schema_version = "RetentionPurged@1.0"
            database_run.contract_json = {
                "archived_snapshot_sha256": archive_job.archive_sha256,
                "request_hash": database_run.request_hash,
                "retention_status": "purged",
            }
            database_run.workflow_run_id = None
            database_run.updated_at = now
            await session.execute(
                update(RunRuntimeSnapshot)
                .where(
                    RunRuntimeSnapshot.run_id == run.run_id,
                    RunRuntimeSnapshot.tenant_id == run.tenant_id,
                )
                .values(
                    plan_json=None,
                    outputs_json={},
                    result_json=None,
                    updated_at=now,
                )
            )
            await session.execute(
                update(TaskExecution)
                .where(
                    TaskExecution.run_id == run.run_id,
                    TaskExecution.tenant_id == run.tenant_id,
                )
                .values(
                    model_settings=None,
                    input_refs=[],
                    output_json=None,
                )
            )
            job.status = "succeeded"
            job.source_payload_hash = source_hash
            job.completed_at = now
            job.updated_at = now
            await self._append_evidence(
                session=session,
                job=job,
                operation="purged",
                now=now,
                source_payload_hash=source_hash,
                details={
                    "archive_sha256": archive_job.archive_sha256,
                    "preserved_statistics": [
                        "status",
                        "risk",
                        "use_case",
                        "cost_actual_usd",
                        "token_input",
                        "token_output",
                        "tool_call_count",
                    ],
                },
            )

    async def _append_evidence(
        self,
        *,
        session: Any,
        job: RetentionJob,
        operation: str,
        now: datetime,
        legal_hold_id: UUID | None = None,
        source_payload_hash: str | None = None,
        receipt: ImmutableArchiveReceipt | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        previous = await session.scalar(
            select(RetentionEvidence)
            .where(RetentionEvidence.job_id == job.job_id)
            .order_by(RetentionEvidence.sequence_no.desc())
            .limit(1)
        )
        sequence = 1 if previous is None else previous.sequence_no + 1
        previous_hash = None if previous is None else previous.evidence_hash
        evidence_payload = {
            "job_id": str(job.job_id),
            "tenant_id": job.tenant_id,
            "sequence_no": sequence,
            "operation": operation,
            "resource_type": job.resource_type,
            "resource_id": job.resource_id,
            "policy_key": job.policy_key,
            "policy_version": job.policy_version,
            "legal_hold_id": str(legal_hold_id) if legal_hold_id else None,
            "source_payload_hash": source_payload_hash,
            "archive_uri": receipt.uri if receipt else None,
            "archive_sha256": receipt.sha256 if receipt else None,
            "archive_version_id": receipt.version_id if receipt else None,
            "object_lock_mode": receipt.object_lock_mode if receipt else None,
            "retain_until": receipt.retain_until if receipt else None,
            "previous_hash": previous_hash,
            "details": details or {},
            "created_at": now,
        }
        session.add(
            RetentionEvidence(
                evidence_id=uuid4(),
                job_id=job.job_id,
                tenant_id=job.tenant_id,
                sequence_no=sequence,
                operation=operation,
                resource_type=job.resource_type,
                resource_id=job.resource_id,
                policy_key=job.policy_key,
                policy_version=job.policy_version,
                legal_hold_id=legal_hold_id,
                source_payload_hash=source_payload_hash,
                archive_uri=receipt.uri if receipt else None,
                archive_sha256=receipt.sha256 if receipt else None,
                archive_version_id=receipt.version_id if receipt else None,
                object_lock_mode=receipt.object_lock_mode if receipt else None,
                retain_until=receipt.retain_until if receipt else None,
                previous_hash=previous_hash,
                evidence_hash=payload_hash(evidence_payload),
                details=details or {},
                created_at=now,
            )
        )

    async def _run_archive_records(self, run: AgentRun) -> list[dict[str, Any]]:
        async with self._sessions() as session:
            await self._assert_retention_role(session)
            snapshot = await session.scalar(
                select(RunRuntimeSnapshot).where(
                    RunRuntimeSnapshot.run_id == run.run_id,
                    RunRuntimeSnapshot.tenant_id == run.tenant_id,
                )
            )
            executions = list(
                (
                    await session.scalars(
                        select(TaskExecution)
                        .where(
                            TaskExecution.run_id == run.run_id,
                            TaskExecution.tenant_id == run.tenant_id,
                        )
                        .order_by(
                            TaskExecution.plan_version,
                            TaskExecution.task_id,
                            TaskExecution.attempt,
                        )
                    )
                ).all()
            )
        records = [{"record_type": "agent_run", "data": self._orm_payload(run)}]
        if snapshot is not None:
            records.append(
                {
                    "record_type": "run_runtime_snapshot",
                    "data": self._orm_payload(snapshot),
                }
            )
        records.extend(
            {
                "record_type": "task_execution",
                "data": self._orm_payload(execution),
            }
            for execution in executions
        )
        return records

    async def _event_rows(
        self,
        run_id: UUID,
        tenant_id: str,
    ) -> AsyncIterable[Mapping[str, Any]]:
        async with self._sessions() as session:
            await self._assert_retention_role(session)
            result = await session.stream_scalars(
                select(RunEvent)
                .where(
                    RunEvent.run_id == run_id,
                    RunEvent.tenant_id == tenant_id,
                )
                .order_by(RunEvent.sequence_no)
            )
            async for event in result:
                yield {
                    "record_type": "run_event",
                    "data": self._orm_payload(event),
                }

    @staticmethod
    def _orm_payload(row: Any) -> dict[str, Any]:
        return {
            column.name: getattr(row, column.name)
            for column in row.__table__.columns
        }

    async def _assert_retention_role(self, session: Any) -> None:
        if self._role_verified:
            return
        allowed = await session.scalar(
            text("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user")
        )
        if allowed is not True:
            raise RuntimeError("RETENTION_ROLE_MUST_BYPASS_RLS")
        self._role_verified = True


@dataclass(frozen=True, slots=True)
class ApplyLegalHold:
    tenant_id: str
    resource_type: str
    resource_id: str
    reason: str
    case_reference: str
    owner_id: str
    policy_key: str
    policy_version: int
    starts_at: datetime
    expires_at: datetime | None = None


class PostgresLegalHoldService:
    """Apply/release holds while writing a hash-chained immutable event."""

    def __init__(self, session_factory: AsyncSessionFactory) -> None:
        self._sessions = session_factory

    async def apply(self, command: ApplyLegalHold, *, actor_id: str) -> UUID:
        values = (
            command.tenant_id,
            command.resource_type,
            command.resource_id,
            command.reason,
            command.case_reference,
            command.owner_id,
            command.policy_key,
            actor_id,
        )
        if any(not value.strip() for value in values) or command.policy_version <= 0:
            raise ValueError("LEGAL_HOLD_REQUIRED_FIELD_MISSING")
        if command.starts_at.tzinfo is None or command.starts_at.utcoffset() is None:
            raise ValueError("LEGAL_HOLD_START_TIMEZONE_REQUIRED")
        if command.expires_at is not None and (
            command.expires_at.tzinfo is None
            or command.expires_at.utcoffset() is None
            or command.expires_at <= command.starts_at
        ):
            raise ValueError("LEGAL_HOLD_EXPIRY_INVALID")
        hold_id = uuid4()
        details = {
            "resource_type": command.resource_type,
            "resource_id": command.resource_id,
            "case_reference_hash": hashlib.sha256(
                command.case_reference.encode("utf-8")
            ).hexdigest(),
            "owner_id": command.owner_id,
            "policy_key": command.policy_key,
            "policy_version": command.policy_version,
            "starts_at": command.starts_at.isoformat(),
            "expires_at": (
                command.expires_at.isoformat()
                if command.expires_at is not None
                else None
            ),
        }
        artifact_id = self._artifact_id(
            command.resource_type,
            command.resource_id,
            expires_at=command.expires_at,
        )
        event_hash = payload_hash(
            {
                "hold_id": str(hold_id),
                "tenant_id": command.tenant_id,
                "sequence_no": 1,
                "event_type": "applied",
                "actor_id": actor_id,
                "reason": command.reason,
                "previous_hash": None,
                "details": details,
            }
        )
        async with tenant_session(self._sessions, command.tenant_id) as session:
            session.add(
                LegalHold(
                    hold_id=hold_id,
                    tenant_id=command.tenant_id,
                    resource_type=command.resource_type,
                    resource_id=command.resource_id,
                    reason=command.reason,
                    case_reference=command.case_reference,
                    owner_id=command.owner_id,
                    policy_key=command.policy_key,
                    policy_version=command.policy_version,
                    status="active",
                    starts_at=command.starts_at,
                    expires_at=command.expires_at,
                    version=0,
                )
            )
            session.add(
                LegalHoldEvent(
                    event_id=uuid4(),
                    hold_id=hold_id,
                    tenant_id=command.tenant_id,
                    sequence_no=1,
                    event_type="applied",
                    actor_id=actor_id,
                    reason=command.reason,
                    previous_hash=None,
                    event_hash=event_hash,
                    details=details,
                )
            )
            if artifact_id is not None:
                updated_artifact = await session.scalar(
                    update(Artifact)
                    .where(
                        Artifact.artifact_id == artifact_id,
                        Artifact.tenant_id == command.tenant_id,
                        Artifact.deleted_at.is_(None),
                    )
                    .values(legal_hold_status="on")
                    .returning(Artifact.artifact_id)
                )
                if updated_artifact is None:
                    raise RuntimeError("LEGAL_HOLD_ARTIFACT_NOT_FOUND")
            await session.commit()
        return hold_id

    async def release(
        self,
        *,
        tenant_id: str,
        hold_id: UUID,
        actor_id: str,
        reason: str,
        now: datetime | None = None,
    ) -> None:
        if not tenant_id.strip() or not actor_id.strip() or not reason.strip():
            raise ValueError("LEGAL_HOLD_RELEASE_CONTEXT_REQUIRED")
        released_at = now or datetime.now(UTC)
        if released_at.tzinfo is None or released_at.utcoffset() is None:
            raise ValueError("LEGAL_HOLD_RELEASE_TIMEZONE_REQUIRED")
        async with tenant_session(self._sessions, tenant_id) as session:
            hold = await session.scalar(
                select(LegalHold)
                .where(
                    LegalHold.hold_id == hold_id,
                    LegalHold.tenant_id == tenant_id,
                )
                .with_for_update()
            )
            if hold is None:
                raise RuntimeError("LEGAL_HOLD_NOT_FOUND")
            if hold.status != "active":
                raise RuntimeError("LEGAL_HOLD_NOT_ACTIVE")
            previous = await session.scalar(
                select(LegalHoldEvent)
                .where(LegalHoldEvent.hold_id == hold_id)
                .order_by(LegalHoldEvent.sequence_no.desc())
                .limit(1)
            )
            if previous is None:
                raise RuntimeError("LEGAL_HOLD_EVENT_CHAIN_MISSING")
            details = {
                "released_at": released_at.isoformat(),
                "previous_status": hold.status,
            }
            event_hash = payload_hash(
                {
                    "hold_id": str(hold_id),
                    "tenant_id": tenant_id,
                    "sequence_no": previous.sequence_no + 1,
                    "event_type": "released",
                    "actor_id": actor_id,
                    "reason": reason,
                    "previous_hash": previous.event_hash,
                    "details": details,
                }
            )
            hold.status = "released"
            hold.released_at = released_at
            hold.released_by = actor_id
            hold.release_reason = reason
            hold.version += 1
            hold.updated_at = released_at
            session.add(
                LegalHoldEvent(
                    event_id=uuid4(),
                    hold_id=hold_id,
                    tenant_id=tenant_id,
                    sequence_no=previous.sequence_no + 1,
                    event_type="released",
                    actor_id=actor_id,
                    reason=reason,
                    previous_hash=previous.event_hash,
                    event_hash=event_hash,
                    details=details,
                    created_at=released_at,
                )
            )
            if hold.resource_type == "artifact":
                artifact_id = self._artifact_id(
                    hold.resource_type,
                    hold.resource_id,
                    expires_at=None,
                )
                other_active = await session.scalar(
                    select(
                        exists().where(
                            LegalHold.tenant_id == tenant_id,
                            LegalHold.resource_type == "artifact",
                            LegalHold.resource_id == hold.resource_id,
                            LegalHold.status == "active",
                            LegalHold.hold_id != hold_id,
                        )
                    )
                )
                if other_active is not True:
                    await session.execute(
                        update(Artifact)
                        .where(
                            Artifact.artifact_id == artifact_id,
                            Artifact.tenant_id == tenant_id,
                            Artifact.deleted_at.is_(None),
                        )
                        .values(legal_hold_status="none")
                    )
            await session.commit()

    @staticmethod
    def _artifact_id(
        resource_type: str,
        resource_id: str,
        *,
        expires_at: datetime | None,
    ) -> UUID | None:
        if resource_type != "artifact":
            return None
        if expires_at is not None:
            raise ValueError("ARTIFACT_LEGAL_HOLD_EXPLICIT_RELEASE_REQUIRED")
        try:
            return UUID(resource_id)
        except ValueError as exc:
            raise ValueError("ARTIFACT_LEGAL_HOLD_RESOURCE_ID_INVALID") from exc



