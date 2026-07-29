from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
import pytest
from pydantic import SecretStr

from agent_platform.api.app import create_app
from agent_platform.application.records import ArtifactDownload, ArtifactRecord
from agent_platform.config import Settings
from agent_platform.container import build_container
from agent_platform.infrastructure.artifacts.malware import MalwareScanEvidence


def _settings() -> Settings:
    return Settings(
        environment="test",
        database_dsn=SecretStr("postgresql+asyncpg://test:test@localhost/test"),
        temporal_namespace="test",
        artifact_bucket="test",
        opa_url="http://opa.test",
        auth_disabled=True,
        workflow_backend="inline",
        persistence_backend="memory",
        artifact_backend="memory",
        policy_backend="builtin",
        max_request_bytes=1_024,
        artifact_max_upload_bytes=3 * 1024 * 1024,
        artifact_max_in_memory_bytes=1024 * 1024,
        artifact_presign_enabled=True,
        artifact_presign_ttl_seconds=60,
    )


def _headers() -> dict[str, str]:
    return {
        "Content-Type": "application/octet-stream",
        "X-Agent-Tenant": "tenant-a",
        "X-Agent-User": "artifact-user",
        "X-Agent-Roles": "analyst",
        "X-Agent-Scopes": "artifact:read,artifact:write",
        "X-Agent-Auth-Strength": "mfa",
        "X-Correlation-ID": "artifact-streaming-route",
    }


class _CleanFileMalwareScanner:
    def __init__(self) -> None:
        self.scanned_paths: list[Path] = []
        self.path_existed_during_scan = False

    async def scan(self, content: bytes, *, media_type: str) -> MalwareScanEvidence:
        del content, media_type
        raise AssertionError("large Artifact must use the file-scanning boundary")

    async def scan_file(
        self,
        path: Path,
        *,
        media_type: str,
        sha256: str,
        size_bytes: int,
    ) -> MalwareScanEvidence:
        del media_type
        self.scanned_paths.append(path)
        self.path_existed_during_scan = await asyncio.to_thread(path.is_file)
        return MalwareScanEvidence(
            request_id="streaming-scan-request",
            sha256=sha256,
            size_bytes=size_bytes,
            verdict="clean",
            engine="controlled-av",
            engine_version="2026.07.27",
            scanned_at=datetime.now(UTC),
            evidence_id="streaming-scan-evidence",
        )

    async def healthcheck(self) -> str:
        return "ok"

    async def aclose(self) -> None:
        return None


class _FileAndMetadataArtifactStore:
    def __init__(self) -> None:
        self.stored: ArtifactRecord | None = None
        self.object_content: bytes | None = None
        self.staged_path: Path | None = None
        self.path_existed_during_put = False
        self.put_calls = 0
        self.put_file_calls = 0
        self.get_calls = 0
        self.get_metadata_calls = 0
        self.download_calls: list[dict[str, Any]] = []

    async def put(self, artifact: ArtifactRecord) -> ArtifactRecord:
        del artifact
        self.put_calls += 1
        raise AssertionError("S3 route must not use the in-memory put boundary")

    async def put_file(self, artifact: ArtifactRecord, path: Path) -> ArtifactRecord:
        self.put_file_calls += 1
        self.staged_path = path
        self.path_existed_during_put = await asyncio.to_thread(path.is_file)
        self.object_content = await asyncio.to_thread(path.read_bytes)
        artifact.object_version_id = "version-streamed"
        artifact.object_retain_until = datetime.now(UTC) + timedelta(days=90)
        self.stored = artifact
        return artifact

    async def get(self, artifact_id: UUID, tenant_id: str) -> ArtifactRecord:
        self.get_calls += 1
        assert self.stored is not None
        assert self.object_content is not None
        assert self.stored.artifact_id == artifact_id
        assert self.stored.tenant_id == tenant_id
        return ArtifactRecord(
            artifact_id=self.stored.artifact_id,
            tenant_id=self.stored.tenant_id,
            run_id=self.stored.run_id,
            kind=self.stored.kind,
            media_type=self.stored.media_type,
            content=self.object_content,
            sha256=self.stored.sha256,
            classification=self.stored.classification,
            created_by=self.stored.created_by,
            retention_policy=self.stored.retention_policy,
            object_version_id=self.stored.object_version_id,
            object_retain_until=self.stored.object_retain_until,
            legal_hold_status=self.stored.legal_hold_status,
            scan_status=self.stored.scan_status,
            scan_provenance=self.stored.scan_provenance,
            created_at=self.stored.created_at,
        )

    async def get_metadata(self, artifact_id: UUID, tenant_id: str) -> ArtifactRecord:
        self.get_metadata_calls += 1
        assert self.stored is not None
        assert self.stored.artifact_id == artifact_id
        assert self.stored.tenant_id == tenant_id
        return self.stored

    async def delete(self, artifact_id: UUID, tenant_id: str) -> None:
        del artifact_id, tenant_id

    async def create_download(
        self,
        artifact: ArtifactRecord,
        *,
        principal_id: str,
        tenant_id: str,
        purpose: str,
        expires_in_seconds: int,
    ) -> ArtifactDownload:
        self.download_calls.append(
            {
                "artifact_id": artifact.artifact_id,
                "principal_id": principal_id,
                "tenant_id": tenant_id,
                "purpose": purpose,
                "expires_in_seconds": expires_in_seconds,
            }
        )
        return ArtifactDownload(
            artifact_id=artifact.artifact_id,
            url=f"https://objects.example.test/{artifact.artifact_id}?signed=1",
            expires_at=datetime.now(UTC) + timedelta(seconds=expires_in_seconds),
        )


@pytest.mark.asyncio
async def test_s3_routes_stream_upload_and_keep_metadata_reads_content_free() -> None:
    runtime_settings = _settings()
    container = await build_container(runtime_settings)
    store = _FileAndMetadataArtifactStore()
    malware_scanner = _CleanFileMalwareScanner()
    container.store.artifacts = store
    container.artifact_malware_scanner = malware_scanner
    # The container is deliberately built with local adapters, then this route-level
    # test switches only the Artifact boundary to exercise the production S3 branch.
    runtime_settings.artifact_backend = "s3"
    app = create_app(runtime_settings, container=container)
    payload = b"\x80" * (2 * 1024 * 1024)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        created = await client.post(
            "/v1/artifacts?classification=internal",
            content=payload,
            headers=_headers(),
        )

        assert created.status_code == 201
        artifact_id = UUID(created.json()["artifact_id"])
        metadata = await client.get(
            f"/v1/artifacts/{artifact_id}",
            headers=_headers(),
        )
        presigned = await client.get(
            f"/v1/artifacts/{artifact_id}?download=true&purpose=incident-review",
            headers=_headers(),
        )

    assert store.put_calls == 0
    assert store.put_file_calls == 1
    assert store.stored is not None
    assert store.stored.content == b""
    assert store.stored.size_bytes == len(payload)
    assert store.stored.sha256 == hashlib.sha256(payload).hexdigest()
    assert store.stored.scan_provenance["transport"] == {
        "mode": "request-stream-to-file",
        "request_size_bytes": len(payload),
        "request_sha256": hashlib.sha256(payload).hexdigest(),
        "chunk_count": 1,
        "max_request_chunk_bytes": len(payload),
    }
    assert store.path_existed_during_put is True
    assert malware_scanner.path_existed_during_scan is True
    assert store.staged_path is not None
    assert not store.staged_path.exists()

    assert metadata.status_code == 200
    assert metadata.json()["size_bytes"] == len(payload)
    assert metadata.json()["object_version_id"] == "version-streamed"
    assert metadata.json()["object_retain_until"] is not None
    assert metadata.json()["legal_hold_status"] == "none"
    assert presigned.status_code == 200
    assert presigned.json()["url"].startswith("https://objects.example.test/")
    assert store.get_metadata_calls == 2
    assert store.get_calls == 0
    assert store.download_calls == [
        {
            "artifact_id": artifact_id,
            "principal_id": "artifact-user",
            "tenant_id": "tenant-a",
            "purpose": "incident-review",
            "expires_in_seconds": 60,
        }
    ]
    await container.aclose()


@pytest.mark.asyncio
async def test_digest_addressed_content_route_is_stable_and_hash_bound() -> None:
    runtime_settings = _settings()
    container = await build_container(runtime_settings)
    store = _FileAndMetadataArtifactStore()
    container.store.artifacts = store
    container.artifact_malware_scanner = _CleanFileMalwareScanner()
    runtime_settings.artifact_backend = "s3"
    app = create_app(runtime_settings, container=container)
    payload = b"stable release evidence bytes"
    digest = hashlib.sha256(payload).hexdigest()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        created = await client.post(
            "/v1/artifacts?classification=internal",
            content=payload,
            headers=_headers(),
        )
        artifact_id = UUID(created.json()["artifact_id"])
        content = await client.get(
            f"/v1/artifacts/{artifact_id}/content/sha256:{digest}",
            headers=_headers(),
        )
        mismatch = await client.get(
            f"/v1/artifacts/{artifact_id}/content/sha256:{'0' * 64}",
            headers=_headers(),
        )

    assert content.status_code == 307
    assert content.headers["location"].startswith("https://objects.example.test/")
    assert content.headers["etag"] == f'"sha256:{digest}"'
    assert content.headers["content-location"].endswith(f"sha256:{digest}")
    assert content.headers["cache-control"] == "no-store"
    assert mismatch.status_code == 404
    assert store.get_calls == 0
    assert store.download_calls[-1]["purpose"] == "content-addressed-read"
    await container.aclose()
