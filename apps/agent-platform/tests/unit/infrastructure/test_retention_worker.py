from __future__ import annotations

from collections import deque
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from agent_platform.domain.hashing import payload_hash
from agent_platform.infrastructure.persistence.models import Artifact
from agent_platform.infrastructure.retention_worker import (
    PostgresRetentionWorker,
    S3ArtifactDeleter,
    _artifact_expired_event,
)


@pytest.mark.asyncio
async def test_s3_retention_delete_is_bound_to_environment_and_tenant() -> None:
    client = _S3Client()
    deleter = S3ArtifactDeleter(
        client=client,
        bucket="agent-platform-prod",
        environment="prod",
    )
    artifact = _artifact(
        uri=(f"s3://agent-platform-prod/prod/tenant/tenant-a/run/unbound/artifacts/{uuid4()}")
    )

    await deleter(artifact)

    assert client.calls == [
        {
            "Bucket": "agent-platform-prod",
            "Key": artifact.uri.removeprefix("s3://agent-platform-prod/"),
            "VersionId": "version-retained",
        }
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "uri",
    [
        "s3://other-bucket/prod/tenant/tenant-a/artifacts/id",
        "s3://agent-platform-prod/staging/tenant/tenant-a/artifacts/id",
        "s3://agent-platform-prod/prod/tenant/tenant-b/artifacts/id",
        "s3://agent-platform-prod/prod/tenant/tenant-a/../tenant-b/id",
        "https://agent-platform-prod/prod/tenant/tenant-a/id",
    ],
)
async def test_s3_retention_rejects_out_of_scope_uri(uri: str) -> None:
    deleter = S3ArtifactDeleter(
        client=_S3Client(),
        bucket="agent-platform-prod",
        environment="prod",
    )

    with pytest.raises(RuntimeError, match="ARTIFACT_URI_OUTSIDE_TENANT_PREFIX"):
        await deleter(_artifact(uri=uri))


def test_artifact_expiry_outbox_hash_covers_the_canonical_event_payload() -> None:
    artifact = _artifact(
        uri=(f"s3://agent-platform-prod/prod/tenant/tenant-a/run/unbound/artifacts/{uuid4()}")
    )

    event = _artifact_expired_event(artifact)

    assert event.payload_hash == payload_hash(event.payload)
    assert event.payload_hash != artifact.sha256


@pytest.mark.asyncio
async def test_delete_pending_artifact_survives_failure_and_retries_next_sweep() -> None:
    artifact = _artifact(
        uri=(f"s3://agent-platform-prod/prod/tenant/tenant-a/run/unbound/artifacts/{uuid4()}")
    )
    requested_at = datetime.now(UTC)
    artifact.lifecycle_status = "delete_pending"
    artifact.delete_requested_at = requested_at
    artifact.delete_attempts = 1
    artifact.delete_last_error_code = "PREVIOUS_FAILURE"
    artifact.deleted_at = None
    artifact.expires_at = None
    first_session = _RetentionSession([artifact], role_allowed=True)
    retry_session = _RetentionSession([artifact])
    delete_calls: list[Artifact] = []

    async def delete(candidate: Artifact) -> None:
        delete_calls.append(candidate)
        if len(delete_calls) == 1:
            raise RuntimeError("object store unavailable")

    worker = PostgresRetentionWorker(
        session_factory=_RetentionSessionFactory(first_session, retry_session),
        delete_artifact=delete,
    )

    first_deleted = await worker._delete_artifacts(datetime.now(UTC), batch_size=10)

    assert first_deleted == 0
    assert artifact.lifecycle_status == "delete_pending"
    assert artifact.deleted_at is None
    assert artifact.delete_requested_at == requested_at
    assert artifact.delete_attempts == 2
    assert artifact.delete_last_error_code == "RUNTIMEERROR"

    retry_now = datetime.now(UTC)
    retry_deleted = await worker._delete_artifacts(retry_now, batch_size=10)

    assert retry_deleted == 1
    assert len(delete_calls) == 2
    assert artifact.lifecycle_status == "deleted"
    assert artifact.deleted_at == retry_now
    assert artifact.delete_requested_at == requested_at
    assert artifact.delete_attempts == 3
    assert artifact.delete_last_error_code is None
    assert first_session.role_checks == 1
    assert retry_session.role_checks == 0
    assert first_session.added == []
    assert retry_session.added == []


def _artifact(*, uri: str) -> Artifact:
    return Artifact(
        artifact_id=uuid4(),
        run_id=None,
        tenant_id="tenant-a",
        task_id=None,
        kind="report",
        uri=uri,
        media_type="application/json",
        size_bytes=2,
        sha256="0" * 64,
        classification="internal",
        source_json={},
        created_by="test",
        retention_policy="expire",
        object_version_id="version-retained",
    )


class _S3Client:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def delete_object(self, **kwargs: Any) -> None:
        self.calls.append(kwargs)


class _ScalarRows:
    def __init__(self, rows: list[Artifact]) -> None:
        self._rows = rows

    def all(self) -> list[Artifact]:
        return self._rows


class _AsyncContext:
    def __init__(self, value: Any = None) -> None:
        self._value = value

    async def __aenter__(self) -> Any:
        return self._value

    async def __aexit__(self, *_args: Any) -> None:
        return None


class _RetentionSession:
    def __init__(self, artifacts: list[Artifact], *, role_allowed: bool = False) -> None:
        self._artifacts = artifacts
        self._role_allowed = role_allowed
        self.role_checks = 0
        self.added: list[Any] = []

    def begin(self) -> _AsyncContext:
        return _AsyncContext()

    async def scalar(self, _statement: Any) -> bool:
        self.role_checks += 1
        return self._role_allowed

    async def scalars(self, _statement: Any) -> _ScalarRows:
        return _ScalarRows(self._artifacts)

    def add(self, value: Any) -> None:
        self.added.append(value)


class _RetentionSessionFactory:
    def __init__(self, *sessions: _RetentionSession) -> None:
        self._sessions = deque(sessions)

    def __call__(self) -> _AsyncContext:
        if not self._sessions:
            raise AssertionError("unexpected retention session")
        return _AsyncContext(self._sessions.popleft())
