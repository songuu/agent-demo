from __future__ import annotations

import asyncio
import hashlib
import math
import os
from collections import Counter
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import boto3
import pytest
import pytest_asyncio
from botocore.config import Config  # type: ignore[import-untyped]
from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from sqlalchemy import delete, select

from agent_platform.application.errors import PlatformError
from agent_platform.application.records import ArtifactDownload, ArtifactRecord
from agent_platform.infrastructure.artifacts.addressable_s3_store import (
    AddressableS3ArtifactStore,
)
from agent_platform.infrastructure.persistence.models import Artifact
from agent_platform.infrastructure.persistence.production_store import (
    PostgresArtifactStore,
)
from agent_platform.infrastructure.persistence.session import (
    AsyncSessionFactory,
    create_session_factory,
    dispose_session_factory,
    tenant_session,
)

pytestmark = pytest.mark.integration

MIB = 1024 * 1024
LARGE_ARTIFACT_BYTES = 50 * MIB
MULTIPART_PART_BYTES = 8 * MIB
STORAGE_ENVIRONMENT = "integration"


@dataclass(frozen=True, slots=True)
class RequiredServices:
    database_url: str
    minio_url: str
    access_key: str
    secret_key: str
    bucket: str


@dataclass(slots=True)
class ServiceBackedArtifactEnvironment:
    config: RequiredServices
    s3: Any
    recording_s3: RecordingS3Client
    session_factory: AsyncSessionFactory
    content_store: AddressableS3ArtifactStore


@dataclass(frozen=True, slots=True)
class LifecycleState:
    status: str
    delete_attempts: int
    delete_last_error_code: str | None
    delete_requested_at: datetime | None
    deleted_at: datetime | None


class RecordingS3Client:
    """Record calls and bridge the local MinIO image's missing SSE backend.

    Production must keep the store's fail-closed AES256/KMS policy. The
    repository's local-only MinIO service has no KMS configured and rejects
    even SSE-S3 requests. This test adapter records every requested encryption
    mode before removing only that unsupported local transport header.
    """

    def __init__(self, delegate: Any) -> None:
        self._delegate = delegate
        self.calls: Counter[str] = Counter()
        self.requested_server_side_encryption: list[str] = []

    def __getattr__(self, name: str) -> Any:
        target = getattr(self._delegate, name)
        if not callable(target):
            return target

        def invoke(*args: Any, **kwargs: Any) -> Any:
            self.calls[name] += 1
            encryption = kwargs.get("ServerSideEncryption")
            if encryption == "AES256":
                self.requested_server_side_encryption.append(encryption)
                kwargs = {
                    key: value for key, value in kwargs.items() if key != "ServerSideEncryption"
                }
            return target(*args, **kwargs)

        return invoke


class FailFirstDeleteStore:
    """Inject exactly one provider failure while delegating every real S3 operation."""

    def __init__(self, delegate: AddressableS3ArtifactStore) -> None:
        self._delegate = delegate
        self.delete_calls = 0

    async def put(self, artifact: ArtifactRecord) -> ArtifactRecord:
        return await self._delegate.put(artifact)

    async def put_file(self, artifact: ArtifactRecord, path: Path) -> ArtifactRecord:
        return await self._delegate.put_file(artifact, path)

    async def get(self, artifact_id: UUID, tenant_id: str) -> ArtifactRecord:
        return await self._delegate.get(artifact_id, tenant_id)

    async def delete(self, artifact_id: UUID, tenant_id: str) -> None:
        self.delete_calls += 1
        if self.delete_calls == 1:
            raise PlatformError(
                "S3_DELETE_TEMPORARY",
                "Injected transient S3 delete failure",
                retryable=True,
                http_status=503,
            )
        await self._delegate.delete(artifact_id, tenant_id)

    def uri_for(self, artifact: ArtifactRecord) -> str:
        return self._delegate.uri_for(artifact)

    async def create_download(
        self,
        artifact: ArtifactRecord,
        *,
        principal_id: str,
        tenant_id: str,
        purpose: str,
        expires_in_seconds: int,
    ) -> ArtifactDownload:
        return await self._delegate.create_download(
            artifact,
            principal_id=principal_id,
            tenant_id=tenant_id,
            purpose=purpose,
            expires_in_seconds=expires_in_seconds,
        )


def _required_services() -> RequiredServices:
    names = {
        "database_url": "AGENT_TEST_DATABASE_URL",
        "minio_url": "AGENT_TEST_MINIO_URL",
        "access_key": "AGENT_TEST_MINIO_ACCESS_KEY",
        "secret_key": "AGENT_TEST_MINIO_SECRET_KEY",
        "bucket": "AGENT_TEST_MINIO_BUCKET",
    }
    values = {field: os.getenv(variable, "").strip() for field, variable in names.items()}
    missing = [names[field] for field, value in values.items() if not value]
    if missing:
        pytest.skip(f"required Artifact integration services are not configured: {missing}")
    return RequiredServices(**values)


def _s3_client(config: RequiredServices) -> Any:
    return boto3.client(
        "s3",
        endpoint_url=config.minio_url,
        aws_access_key_id=config.access_key,
        aws_secret_access_key=config.secret_key,
        region_name="us-east-1",
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            retries={"max_attempts": 2, "mode": "standard"},
        ),
    )


@pytest_asyncio.fixture
async def artifact_environment() -> AsyncIterator[ServiceBackedArtifactEnvironment]:
    config = _required_services()
    s3 = _s3_client(config)
    await asyncio.to_thread(s3.head_bucket, Bucket=config.bucket)
    recording_s3 = RecordingS3Client(s3)
    content_store = AddressableS3ArtifactStore(
        client=recording_s3,
        bucket=config.bucket,
        kms_key_id=None,
        environment=STORAGE_ENVIRONMENT,
        multipart_part_size_bytes=MULTIPART_PART_BYTES,
    )
    session_factory = create_session_factory(config.database_url)
    environment = ServiceBackedArtifactEnvironment(
        config=config,
        s3=s3,
        recording_s3=recording_s3,
        session_factory=session_factory,
        content_store=content_store,
    )
    try:
        yield environment
    finally:
        await dispose_session_factory(session_factory)
        await asyncio.to_thread(s3.close)


def _artifact_key(artifact: ArtifactRecord) -> str:
    return (
        f"{STORAGE_ENVIRONMENT}/tenant/{artifact.tenant_id}/"
        f"run/unbound/artifacts/{artifact.artifact_id}"
    )


def _malware_provenance(*, sha256: str, size_bytes: int) -> dict[str, Any]:
    return {
        "malware": {
            "request_id": f"integration-scan-{uuid4()}",
            "sha256": sha256,
            "size_bytes": size_bytes,
            "verdict": "clean",
            "engine": "integration-controlled-av",
            "engine_version": "2026.07.27",
            "scanned_at": datetime.now(UTC).isoformat(),
            "evidence_id": f"integration-evidence-{uuid4()}",
        }
    }


def _record(
    *,
    tenant_id: str,
    content: bytes,
    size_bytes: int,
    sha256: str,
) -> ArtifactRecord:
    return ArtifactRecord(
        artifact_id=uuid4(),
        tenant_id=tenant_id,
        run_id=None,
        kind="service-backed-integration",
        media_type="application/octet-stream",
        content=content,
        size_bytes=size_bytes,
        sha256=sha256,
        classification="internal",
        created_by="artifact-integration-test",
        scan_status="malware_clean",
        scan_provenance=_malware_provenance(
            sha256=sha256,
            size_bytes=size_bytes,
        ),
    )


def _write_large_file(path: Path) -> str:
    digest = hashlib.sha256()
    chunk = bytes(range(256)) * 4096
    with path.open("wb") as handle:
        for _ in range(LARGE_ARTIFACT_BYTES // len(chunk)):
            handle.write(chunk)
            digest.update(chunk)
    assert path.stat().st_size == LARGE_ARTIFACT_BYTES
    return digest.hexdigest()


async def _delete_artifact_metadata(
    factory: AsyncSessionFactory,
    *,
    artifact_id: UUID,
    tenant_id: str,
) -> None:
    async with tenant_session(factory, tenant_id) as session:
        await session.execute(
            delete(Artifact).where(
                Artifact.artifact_id == artifact_id,
                Artifact.tenant_id == tenant_id,
            )
        )
        await session.commit()


async def _lifecycle_state(
    factory: AsyncSessionFactory,
    *,
    artifact_id: UUID,
    tenant_id: str,
) -> LifecycleState:
    async with tenant_session(factory, tenant_id) as session:
        row = (
            await session.execute(
                select(
                    Artifact.lifecycle_status,
                    Artifact.delete_attempts,
                    Artifact.delete_last_error_code,
                    Artifact.delete_requested_at,
                    Artifact.deleted_at,
                ).where(
                    Artifact.artifact_id == artifact_id,
                    Artifact.tenant_id == tenant_id,
                )
            )
        ).one()
        return LifecycleState(
            status=row.lifecycle_status,
            delete_attempts=row.delete_attempts,
            delete_last_error_code=row.delete_last_error_code,
            delete_requested_at=row.delete_requested_at,
            deleted_at=row.deleted_at,
        )


def _assert_object_missing(s3: Any, *, bucket: str, key: str) -> None:
    with pytest.raises(ClientError) as exc_info:
        s3.head_object(Bucket=bucket, Key=key)
    error = exc_info.value.response.get("Error", {})
    assert error.get("Code") in {"404", "NoSuchKey", "NotFound"}


@pytest.mark.asyncio
async def test_fifty_mib_file_uses_multipart_and_persists_exact_metadata(
    artifact_environment: ServiceBackedArtifactEnvironment,
    tmp_path: Path,
) -> None:
    path = tmp_path / "fifty-mib-artifact.bin"
    digest = await asyncio.to_thread(_write_large_file, path)
    tenant_id = f"tenant-stream-{uuid4()}"
    artifact = _record(
        tenant_id=tenant_id,
        content=b"",
        size_bytes=LARGE_ARTIFACT_BYTES,
        sha256=digest,
    )
    key = _artifact_key(artifact)
    store = PostgresArtifactStore(
        artifact_environment.session_factory,
        artifact_environment.content_store,
    )

    try:
        stored = await store.put_file(artifact, path)
        metadata = await store.get_metadata(artifact.artifact_id, tenant_id)
        head = await asyncio.to_thread(
            artifact_environment.s3.head_object,
            Bucket=artifact_environment.config.bucket,
            Key=key,
        )
        pending = await asyncio.to_thread(
            artifact_environment.s3.list_objects_v2,
            Bucket=artifact_environment.config.bucket,
            Prefix=f"{key.rsplit('/', 1)[0]}/.pending/",
        )

        assert stored.artifact_id == artifact.artifact_id
        assert stored.content == b""
        assert metadata.content == b""
        assert metadata.size_bytes == LARGE_ARTIFACT_BYTES
        assert metadata.sha256 == digest
        assert metadata.lifecycle_status == "available"
        assert head["ContentLength"] == LARGE_ARTIFACT_BYTES
        assert head["Metadata"]["sha256"] == digest
        assert head["Metadata"]["scan-status"] == "malware_clean"
        assert artifact_environment.recording_s3.requested_server_side_encryption == [
            "AES256",
            "AES256",
        ]
        assert pending.get("KeyCount", 0) == 0
        assert artifact_environment.recording_s3.calls["put_object"] == 0
        assert artifact_environment.recording_s3.calls["create_multipart_upload"] == 1
        assert artifact_environment.recording_s3.calls["upload_part"] == math.ceil(
            LARGE_ARTIFACT_BYTES / MULTIPART_PART_BYTES
        )
        assert artifact_environment.recording_s3.calls["complete_multipart_upload"] == 1
        assert artifact_environment.recording_s3.calls["copy_object"] == 1
    finally:
        await asyncio.to_thread(
            artifact_environment.s3.delete_object,
            Bucket=artifact_environment.config.bucket,
            Key=key,
        )
        await _delete_artifact_metadata(
            artifact_environment.session_factory,
            artifact_id=artifact.artifact_id,
            tenant_id=tenant_id,
        )


@pytest.mark.asyncio
async def test_delete_failure_is_durable_and_second_attempt_removes_real_minio_object(
    artifact_environment: ServiceBackedArtifactEnvironment,
) -> None:
    content = b"delete-recovery-service-backed-artifact"
    digest = hashlib.sha256(content).hexdigest()
    tenant_id = f"tenant-delete-{uuid4()}"
    artifact = _record(
        tenant_id=tenant_id,
        content=content,
        size_bytes=len(content),
        sha256=digest,
    )
    key = _artifact_key(artifact)
    failing_content_store = FailFirstDeleteStore(artifact_environment.content_store)
    store = PostgresArtifactStore(
        artifact_environment.session_factory,
        failing_content_store,
    )

    try:
        await store.put(artifact)
        await asyncio.to_thread(
            artifact_environment.s3.head_object,
            Bucket=artifact_environment.config.bucket,
            Key=key,
        )

        with pytest.raises(PlatformError) as exc_info:
            await store.delete(artifact.artifact_id, tenant_id)
        assert exc_info.value.code == "ARTIFACT_DELETE_PENDING"
        assert exc_info.value.retryable is True
        assert exc_info.value.context["storage_error_code"] == "S3_DELETE_TEMPORARY"

        pending = await _lifecycle_state(
            artifact_environment.session_factory,
            artifact_id=artifact.artifact_id,
            tenant_id=tenant_id,
        )
        assert pending.status == "delete_pending"
        assert pending.delete_attempts == 1
        assert pending.delete_last_error_code == "S3_DELETE_TEMPORARY"
        assert pending.delete_requested_at is not None
        assert pending.deleted_at is None
        await asyncio.to_thread(
            artifact_environment.s3.head_object,
            Bucket=artifact_environment.config.bucket,
            Key=key,
        )

        await store.delete(artifact.artifact_id, tenant_id)
        deleted = await _lifecycle_state(
            artifact_environment.session_factory,
            artifact_id=artifact.artifact_id,
            tenant_id=tenant_id,
        )
        assert deleted.status == "deleted"
        assert deleted.delete_attempts == 2
        assert deleted.delete_last_error_code is None
        assert deleted.delete_requested_at == pending.delete_requested_at
        assert deleted.deleted_at is not None
        assert failing_content_store.delete_calls == 2
        await asyncio.to_thread(
            _assert_object_missing,
            artifact_environment.s3,
            bucket=artifact_environment.config.bucket,
            key=key,
        )
    finally:
        await asyncio.to_thread(
            artifact_environment.s3.delete_object,
            Bucket=artifact_environment.config.bucket,
            Key=key,
        )
        await _delete_artifact_metadata(
            artifact_environment.session_factory,
            artifact_id=artifact.artifact_id,
            tenant_id=tenant_id,
        )


@pytest.mark.asyncio
async def test_minio_accepts_versioning_and_lifecycle_configuration(
    artifact_environment: ServiceBackedArtifactEnvironment,
) -> None:
    base = artifact_environment.config.bucket[:40].rstrip("-")
    bucket = f"{base}-it-{uuid4().hex[:12]}"
    lifecycle = {
        "Rules": [
            {
                "ID": "artifact-retention-contract",
                "Status": "Enabled",
                "Filter": {"Prefix": f"{STORAGE_ENVIRONMENT}/"},
                "Expiration": {"Days": 7},
                "NoncurrentVersionExpiration": {"NoncurrentDays": 7},
                "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1},
            }
        ]
    }

    await asyncio.to_thread(artifact_environment.s3.create_bucket, Bucket=bucket)
    try:
        await asyncio.to_thread(
            artifact_environment.s3.put_bucket_versioning,
            Bucket=bucket,
            VersioningConfiguration={"Status": "Enabled"},
        )
        await asyncio.to_thread(
            artifact_environment.s3.put_bucket_lifecycle_configuration,
            Bucket=bucket,
            LifecycleConfiguration=lifecycle,
        )
        versioning = await asyncio.to_thread(
            artifact_environment.s3.get_bucket_versioning,
            Bucket=bucket,
        )
        configured = await asyncio.to_thread(
            artifact_environment.s3.get_bucket_lifecycle_configuration,
            Bucket=bucket,
        )

        assert versioning["Status"] == "Enabled"
        rule = next(
            rule for rule in configured["Rules"] if rule["ID"] == "artifact-retention-contract"
        )
        assert rule["Status"] == "Enabled"
        assert rule["Expiration"]["Days"] == 7
        assert rule["NoncurrentVersionExpiration"]["NoncurrentDays"] == 7
        abort_rule = rule.get("AbortIncompleteMultipartUpload")
        if abort_rule is not None:
            assert abort_rule["DaysAfterInitiation"] == 1
    finally:
        try:
            await asyncio.to_thread(
                artifact_environment.s3.delete_bucket_lifecycle,
                Bucket=bucket,
            )
        finally:
            await asyncio.to_thread(artifact_environment.s3.delete_bucket, Bucket=bucket)
