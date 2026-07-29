from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.dialects import postgresql

from agent_platform.infrastructure.persistence.models import AgentRun
from agent_platform.infrastructure.retention_lifecycle import (
    ArchiveDescriptor,
    LifecycleAction,
    LifecycleResourceState,
    PostgresLifecycleRetention,
    RetentionPolicy,
    S3ImmutableArchiveAdapter,
    decide_lifecycle_action,
)


def _policy(
    *,
    resource_type: str = "agent_run",
    online_days: int = 180,
    archive_days: int | None = 365,
    disposition: str = "archive_then_purge",
    immutable_archive: bool = True,
) -> RetentionPolicy:
    return RetentionPolicy(
        policy_key=f"{resource_type}-default",
        version=1,
        resource_type=resource_type,
        classification="any",
        business_requirement="Business reconstruction and support.",
        audit_requirement="Retain the minimum evidence required for audit.",
        owner_id="platform-data-governance",
        online_retention_days=online_days,
        archive_retention_days=archive_days,
        disposition=disposition,
        immutable_archive=immutable_archive,
        legal_hold_enabled=True,
    )


@pytest.mark.parametrize(
    ("policy", "error"),
    [
        (_policy(online_days=89), "AGENT_RUN_RETENTION_OUT_OF_RANGE"),
        (
            _policy(
                resource_type="run_event",
                online_days=364,
                archive_days=2_555,
                disposition="immutable_archive",
            ),
            "RUN_EVENT_RETENTION_TOO_SHORT",
        ),
        (
            _policy(
                resource_type="model_raw",
                online_days=8,
                archive_days=None,
                disposition="hash_only_delete",
                immutable_archive=False,
            ),
            "MODEL_RAW_RETENTION_NOT_MINIMAL",
        ),
        (
            _policy(
                resource_type="tool_raw",
                online_days=7,
                archive_days=90,
                disposition="hash_only_delete",
                immutable_archive=False,
            ),
            "TOOL_RAW_MUST_ARCHIVE_BEFORE_DELETE",
        ),
        (
            _policy(
                resource_type="approval_receipt",
                online_days=2_555,
                archive_days=3_650,
                disposition="archive_then_purge",
            ),
            "APPROVAL_RECEIPT_MUST_BE_LONG_LIVED",
        ),
        (_policy(disposition="unknown"), "RETENTION_POLICY_DISPOSITION_INVALID"),
        (
            _policy(immutable_archive=False),
            "RETENTION_POLICY_IMMUTABLE_ARCHIVE_REQUIRED",
        ),
        (
            _policy(archive_days=None),
            "RETENTION_POLICY_ARCHIVE_DURATION_REQUIRED",
        ),
    ],
)
def test_policy_enforces_architecture_retention_baselines(
    policy: RetentionPolicy,
    error: str,
) -> None:
    with pytest.raises(ValueError, match=error):
        policy.validate()


def test_lifecycle_decision_never_bypasses_legal_hold() -> None:
    now = datetime(2026, 7, 27, 10, 0, tzinfo=UTC)
    state = LifecycleResourceState(
        completed_at=now - timedelta(days=500),
        archived=True,
        purged=False,
    )

    assert (
        decide_lifecycle_action(
            policy=_policy(),
            state=state,
            now=now,
            active_legal_hold=True,
        )
        is LifecycleAction.HOLD
    )
    assert (
        decide_lifecycle_action(
            policy=_policy(),
            state=state,
            now=now,
            active_legal_hold=False,
        )
        is LifecycleAction.PURGE
    )


@pytest.mark.asyncio
async def test_purge_rechecks_legal_hold_inside_mutation_transaction() -> None:
    run_id = uuid4()
    now = datetime.now(UTC)
    job = SimpleNamespace(
        job_id=uuid4(),
        tenant_id="tenant-a",
        resource_type="agent_run",
        resource_id=str(run_id),
        policy_key="agent-run-default",
        policy_version=1,
        status="in_progress",
        updated_at=now,
    )
    run = SimpleNamespace(
        run_id=run_id,
        tenant_id="tenant-a",
        principal_id="principal-sensitive",
    )
    hold = SimpleNamespace(
        hold_id=uuid4(),
        case_reference="case-1",
        owner_id="legal",
    )
    session = _PurgeSession([True, job, run, hold, None])
    lifecycle = PostgresLifecycleRetention(
        session_factory=_PurgeSessionFactory(session),
        archive=object(),
    )

    purged = await lifecycle._purge_run(job.job_id, run, now)

    assert purged is False
    assert job.status == "held"
    assert run.principal_id == "principal-sensitive"
    assert session.added[0].operation == "legal_hold_blocked"
    assert any("pg_advisory_xact_lock" in str(statement) for statement in session.executed)


def test_candidate_deadline_uses_effective_policy_before_limit() -> None:
    deadline = PostgresLifecycleRetention._retention_deadline_reached(
        now=datetime(2026, 7, 29, tzinfo=UTC),
        resource_type="agent_run",
        retention_field="online_retention_days",
    )
    statement = select(AgentRun.run_id).where(deadline).limit(10)

    sql = str(
        statement.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )

    assert "retention_policy_versions" in sql
    assert "online_retention_days" in sql
    assert "__platform__" in sql
    assert "agent_run" in sql
    assert "EXTRACT(epoch FROM" in sql
    assert sql.index("online_retention_days") < sql.index("LIMIT")


@pytest.mark.asyncio
async def test_s3_archive_is_content_addressed_kms_encrypted_and_object_locked() -> None:
    client = _S3Client()
    adapter = S3ImmutableArchiveAdapter(
        client=client,
        bucket="agent-platform-prod",
        environment="prod",
        kms_key_id="kms-retention",
        object_lock_mode="COMPLIANCE",
    )
    descriptor = ArchiveDescriptor(
        tenant_id="tenant-a",
        resource_type="run_event",
        resource_id="run-1",
        policy=_policy(
            resource_type="run_event",
            online_days=365,
            archive_days=2_555,
            disposition="immutable_archive",
        ),
        retention_anchor=datetime.now(UTC),
    )
    records = [
        {"sequence_no": 1, "payload_hash": "a" * 64},
        {"sequence_no": 2, "payload_hash": "b" * 64},
    ]

    receipt = await adapter.archive_json_lines(descriptor, records)

    assert receipt.uri.startswith(
        "s3://agent-platform-prod/prod/tenant/tenant-a/retention/run_event/"
    )
    assert receipt.uri.endswith(f"/{receipt.sha256}.jsonl")
    assert receipt.version_id == "version-1"
    assert receipt.object_lock_mode == "COMPLIANCE"
    assert receipt.retain_until > datetime.now(UTC) + timedelta(days=2_554)
    assert receipt.content_length == len(client.objects[receipt.uri.rsplit("/", 1)[-1]])
    assert client.puts[0]["ServerSideEncryption"] == "aws:kms"
    assert client.puts[0]["SSEKMSKeyId"] == "kms-retention"
    assert client.puts[0]["BucketKeyEnabled"] is True
    assert client.puts[0]["ObjectLockMode"] == "COMPLIANCE"
    assert client.puts[0]["IfNoneMatch"] == "*"
    assert client.puts[0]["Metadata"]["sha256"] == receipt.sha256
    assert client.heads[0]["VersionId"] == "version-1"
    assert (
        await adapter.restore_and_verify(receipt) == client.objects[receipt.uri.rsplit("/", 1)[-1]]
    )


@pytest.mark.asyncio
async def test_dev_minio_archive_can_explicitly_disable_unsupported_encryption() -> None:
    client = _S3Client()
    adapter = S3ImmutableArchiveAdapter(
        client=client,
        bucket="agent-platform-local",
        environment="dev",
        kms_key_id=None,
        allow_unencrypted_local=True,
    )
    descriptor = ArchiveDescriptor(
        tenant_id="tenant-a",
        resource_type="agent_run",
        resource_id="run-local",
        policy=_policy(),
        retention_anchor=datetime.now(UTC),
    )

    await adapter.archive_json_lines(descriptor, [{"run_id": "run-local"}])

    assert "ServerSideEncryption" not in client.puts[0]
    assert "SSEKMSKeyId" not in client.puts[0]


def test_unencrypted_archive_is_rejected_outside_local_development() -> None:
    with pytest.raises(ValueError, match="ARTIFACT_UNENCRYPTED_LOCAL_FORBIDDEN"):
        S3ImmutableArchiveAdapter(
            client=_S3Client(),
            bucket="agent-platform-prod",
            environment="prod",
            kms_key_id=None,
            allow_unencrypted_local=True,
        )


@pytest.mark.asyncio
async def test_s3_archive_retry_verifies_existing_content_addressed_version() -> None:
    client = _S3Client()
    adapter = S3ImmutableArchiveAdapter(
        client=client,
        bucket="agent-platform-prod",
        environment="prod",
        kms_key_id="kms-retention",
    )
    descriptor = ArchiveDescriptor(
        tenant_id="tenant-a",
        resource_type="agent_run",
        resource_id="run-1",
        policy=_policy(),
        retention_anchor=datetime.now(UTC),
    )

    first = await adapter.archive_json_lines(descriptor, [{"run_id": "run-1"}])
    second = await adapter.archive_json_lines(descriptor, [{"run_id": "run-1"}])

    assert second.uri == first.uri
    assert second.sha256 == first.sha256
    assert second.version_id == first.version_id
    assert len(client.puts) == 2
    assert (
        client.puts[1]["ObjectLockRetainUntilDate"] == client.puts[0]["ObjectLockRetainUntilDate"]
    )


@pytest.mark.asyncio
async def test_s3_archive_rejects_object_lock_shorter_than_policy() -> None:
    client = _S3Client()
    client.retain_until_override = datetime.now(UTC) + timedelta(days=1)
    adapter = S3ImmutableArchiveAdapter(
        client=client,
        bucket="agent-platform-prod",
        environment="prod",
        kms_key_id="kms-retention",
    )
    descriptor = ArchiveDescriptor(
        tenant_id="tenant-a",
        resource_type="agent_run",
        resource_id="run-1",
        policy=_policy(),
        retention_anchor=datetime.now(UTC),
    )

    with pytest.raises(
        RuntimeError,
        match="RETENTION_ARCHIVE_OBJECT_LOCK_DURATION_TOO_SHORT",
    ):
        await adapter.archive_json_lines(descriptor, [{"run_id": "run-1"}])


@pytest.mark.asyncio
async def test_restore_rejects_archive_content_hash_mismatch() -> None:
    client = _S3Client()
    adapter = S3ImmutableArchiveAdapter(
        client=client,
        bucket="agent-platform-prod",
        environment="prod",
        kms_key_id="kms-retention",
    )
    descriptor = ArchiveDescriptor(
        tenant_id="tenant-a",
        resource_type="agent_run",
        resource_id="run-1",
        policy=_policy(),
        retention_anchor=datetime.now(UTC),
    )
    receipt = await adapter.archive_json_lines(descriptor, [{"run_id": "run-1"}])
    key = receipt.uri.rsplit("/", 1)[-1]
    client.objects[key] = b"tampered"

    with pytest.raises(RuntimeError, match="RETENTION_ARCHIVE_HASH_MISMATCH"):
        await adapter.restore_and_verify(receipt)


class _PreconditionFailed(RuntimeError):
    def __init__(self) -> None:
        super().__init__("precondition failed")
        self.response = {"Error": {"Code": "PreconditionFailed"}}


class _Transaction:
    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *_args: Any) -> None:
        return None


class _PurgeSession:
    def __init__(self, scalars: list[Any]) -> None:
        self._scalars = iter(scalars)
        self.added: list[Any] = []
        self.executed: list[Any] = []

    async def __aenter__(self) -> _PurgeSession:
        return self

    async def __aexit__(self, *_args: Any) -> None:
        return None

    def begin(self) -> _Transaction:
        return _Transaction()

    async def scalar(self, _statement: Any) -> Any:
        return next(self._scalars)

    async def execute(self, statement: Any, _parameters: Any = None) -> None:
        self.executed.append(statement)

    def add(self, value: Any) -> None:
        self.added.append(value)


class _PurgeSessionFactory:
    def __init__(self, session: _PurgeSession) -> None:
        self._session = session

    def __call__(self) -> _PurgeSession:
        return self._session


class _Body:
    def __init__(self, value: bytes) -> None:
        self._value = value

    def read(self) -> bytes:
        return self._value


class _S3Client:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.metadata: dict[str, dict[str, Any]] = {}
        self.puts: list[dict[str, Any]] = []
        self.heads: list[dict[str, Any]] = []
        self.retain_until_override: datetime | None = None

    def put_object(self, **kwargs: Any) -> dict[str, str]:
        body = kwargs["Body"]
        content = body.read() if hasattr(body, "read") else bytes(body)
        key = str(kwargs["Key"])
        short_key = key.rsplit("/", 1)[-1]
        self.puts.append({key: value for key, value in kwargs.items() if key != "Body"})
        if short_key in self.objects:
            raise _PreconditionFailed()
        assert hashlib.sha256(content).hexdigest() == kwargs["Metadata"]["sha256"]
        self.objects[short_key] = content
        self.metadata[short_key] = {
            "ContentLength": len(content),
            "Metadata": kwargs["Metadata"],
            "ObjectLockMode": kwargs["ObjectLockMode"],
            "ObjectLockRetainUntilDate": (
                self.retain_until_override or kwargs["ObjectLockRetainUntilDate"]
            ),
            "VersionId": "version-1",
        }
        for key in ("ServerSideEncryption", "SSEKMSKeyId"):
            if key in kwargs:
                self.metadata[short_key][key] = kwargs[key]
        return {"VersionId": "version-1"}

    def head_object(self, **kwargs: Any) -> dict[str, Any]:
        self.heads.append(kwargs)
        return self.metadata[str(kwargs["Key"]).rsplit("/", 1)[-1]]

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        key = str(kwargs["Key"]).rsplit("/", 1)[-1]
        return {"Body": _Body(self.objects[key])}
