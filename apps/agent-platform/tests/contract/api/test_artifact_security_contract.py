from __future__ import annotations

import hashlib
import io
import zipfile
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio
from pydantic import SecretStr

from agent_platform.api.app import create_app
from agent_platform.application.records import ArtifactDownload, ArtifactRecord, RunRecord
from agent_platform.config import Settings
from agent_platform.container import build_container
from agent_platform.infrastructure.artifacts.scanner import ArtifactScanner
from agent_platform.infrastructure.memory_store import InMemoryArtifactStore


def settings() -> Settings:
    return Settings(
        environment="test",
        database_dsn=SecretStr("postgresql+asyncpg://test:test@localhost/test"),
        temporal_address="localhost:7233",
        temporal_namespace="test",
        openai_api_key=SecretStr(""),
        artifact_bucket="test",
        opa_url="http://opa.test",
        auth_disabled=True,
        workflow_backend="inline",
        persistence_backend="memory",
        artifact_backend="memory",
        policy_backend="builtin",
        max_request_bytes=1_024,
        artifact_presign_ttl_seconds=60,
        artifact_presign_enabled=True,
    )


def headers(
    *,
    tenant: str = "tenant-a",
    scopes: str = "runs:read,artifact:read,artifact:write",
    correlation_id: str = "artifact-contract-1",
) -> dict[str, str]:
    return {
        "Content-Type": "application/octet-stream",
        "X-Agent-Tenant": tenant,
        "X-Agent-User": "artifact-user",
        "X-Agent-Roles": "analyst",
        "X-Agent-Scopes": scopes,
        "X-Agent-Auth-Strength": "mfa",
        "X-Correlation-ID": correlation_id,
    }


@pytest_asyncio.fixture
async def api() -> AsyncIterator[tuple[httpx.AsyncClient, Any]]:
    runtime_settings = settings()
    container = await build_container(runtime_settings)
    container.artifact_scanner = ArtifactScanner(max_upload_bytes=256)
    app = create_app(runtime_settings, container=container)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        yield client, container
    await container.aclose()


async def chunked_body(*chunks: bytes) -> AsyncIterator[bytes]:
    for chunk in chunks:
        yield chunk


def malicious_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("../escape.txt", b"x")
    return buffer.getvalue()


async def upload(
    client: httpx.AsyncClient,
    *,
    content: bytes = b"source-backed artifact",
    query: str = "classification=internal",
    request_headers: dict[str, str] | None = None,
) -> httpx.Response:
    return await client.post(
        f"/v1/artifacts?{query}",
        content=content,
        headers=request_headers or headers(),
    )


@pytest.mark.asyncio
async def test_chunked_upload_enforces_cumulative_limit_without_content_length(
    api: tuple[httpx.AsyncClient, Any],
) -> None:
    client, container = api
    response = await client.post(
        "/v1/artifacts?classification=internal",
        content=chunked_body(b"a" * 200, b"b" * 57),
        headers=headers(),
    )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "ARTIFACT_SIZE_LIMIT_EXCEEDED"
    assert container.store.artifacts._artifacts == {}


@pytest.mark.asyncio
async def test_upload_maps_scanner_failures_and_mime_mismatch_to_stable_errors(
    api: tuple[httpx.AsyncClient, Any],
) -> None:
    client, _ = api
    executable = await upload(client, content=b"MZ" + b"\x00" * 10)
    traversal = await upload(client, content=malicious_zip())
    mismatch = await client.post(
        "/v1/artifacts?classification=internal",
        content=b"%PDF-1.7\nreport",
        headers={**headers(), "Content-Type": "application/json"},
    )

    assert executable.status_code == 422
    assert executable.json()["error"]["code"] == "EXECUTABLE_CONTENT_DENIED"
    assert traversal.status_code == 422
    assert traversal.json()["error"]["code"] == "ARCHIVE_PATH_TRAVERSAL"
    assert mismatch.status_code == 415
    assert mismatch.json()["error"]["code"] == "ARTIFACT_MEDIA_TYPE_MISMATCH"


@pytest.mark.asyncio
async def test_upload_classification_must_be_in_authenticated_data_scope(
    api: tuple[httpx.AsyncClient, Any],
) -> None:
    client, _ = api
    response = await upload(client, query="classification=confidential")

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "ARTIFACT_CLASSIFICATION_FORBIDDEN"


@pytest.mark.asyncio
async def test_get_hides_cross_tenant_expired_and_out_of_scope_artifacts(
    api: tuple[httpx.AsyncClient, Any],
) -> None:
    client, container = api
    created = await upload(client)
    artifact_id = created.json()["artifact_id"]

    cross_tenant = await client.get(
        f"/v1/artifacts/{artifact_id}",
        headers=headers(tenant="tenant-b"),
    )
    assert cross_tenant.status_code == 404
    assert cross_tenant.json()["error"]["code"] == "NOT_FOUND"

    content = b"expired"
    expired = ArtifactRecord(
        artifact_id=uuid4(),
        tenant_id="tenant-a",
        run_id=None,
        kind="document",
        media_type="text/plain",
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        classification="internal",
        created_by="artifact-user",
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    await container.store.artifacts.put(expired)
    expired_response = await client.get(
        f"/v1/artifacts/{expired.artifact_id}",
        headers=headers(),
    )
    assert expired_response.status_code == 404
    assert expired_response.json()["error"]["code"] == "NOT_FOUND"

    secret = ArtifactRecord(
        artifact_id=uuid4(),
        tenant_id="tenant-a",
        run_id=None,
        kind="document",
        media_type="text/plain",
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        classification="secret",
        created_by="artifact-user",
    )
    await container.store.artifacts.put(secret)
    secret_response = await client.get(
        f"/v1/artifacts/{secret.artifact_id}",
        headers=headers(),
    )
    assert secret_response.status_code == 404
    assert secret_response.json()["error"]["code"] == "NOT_FOUND"


@pytest.mark.asyncio
async def test_download_requires_purpose_read_scope_and_writes_access_audit(
    api: tuple[httpx.AsyncClient, Any],
) -> None:
    client, container = api
    run = RunRecord(
        run_id=uuid4(),
        tenant_id="tenant-a",
        principal_id="artifact-user",
        contract={},
        idempotency_key="artifact-audit-run",
        request_hash="request-hash",
        workflow_id="inline",
    )
    await container.store.runs.create_once(run)
    created = await upload(client, query=f"classification=internal&run_id={run.run_id}")
    artifact_id = created.json()["artifact_id"]

    no_purpose = await client.get(
        f"/v1/artifacts/{artifact_id}?download=true",
        headers=headers(),
    )
    assert no_purpose.status_code == 400
    assert no_purpose.json()["error"]["code"] == "ARTIFACT_DOWNLOAD_PURPOSE_REQUIRED"

    no_read_scope = await client.get(
        f"/v1/artifacts/{artifact_id}?download=true&purpose=incident-review",
        headers=headers(scopes="artifact:write"),
    )
    assert no_read_scope.status_code == 403
    assert no_read_scope.json()["error"]["code"] == "ARTIFACT_READ_SCOPE_REQUIRED"

    downloaded = await client.get(
        f"/v1/artifacts/{artifact_id}?download=true&purpose=incident-review",
        headers=headers(correlation_id="artifact-access-1"),
    )
    assert downloaded.status_code == 200
    assert downloaded.content == b"source-backed artifact"
    events = await container.store.runs.events_after(run.run_id, "tenant-a", 0)
    accessed = [event for event in events if event.event_type == "artifact.accessed"]
    assert len(accessed) == 1
    assert accessed[0].correlation_id == "artifact-access-1"
    assert accessed[0].payload == {
        "artifact_id": artifact_id,
        "classification": "internal",
        "principal_id": "artifact-user",
        "purpose": "incident-review",
        "sha256": created.json()["sha256"],
        "transport": "direct",
    }


class PresigningArtifactStore(InMemoryArtifactStore):
    def __init__(self) -> None:
        super().__init__()
        self.download_calls: list[dict[str, object]] = []

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
async def test_download_uses_backward_compatible_presign_protocol_when_available(
    api: tuple[httpx.AsyncClient, Any],
) -> None:
    client, container = api
    store = PresigningArtifactStore()
    container.store.artifacts = store
    created = await upload(client)
    artifact_id = created.json()["artifact_id"]

    response = await client.get(
        f"/v1/artifacts/{artifact_id}?download=true&purpose=user-export",
        headers=headers(),
    )

    assert response.status_code == 200
    assert response.json()["artifact_id"] == artifact_id
    assert response.json()["url"].startswith("https://objects.example.test/")
    assert store.download_calls == [
        {
            "artifact_id": UUID(artifact_id),
            "principal_id": "artifact-user",
            "tenant_id": "tenant-a",
            "purpose": "user-export",
            "expires_in_seconds": 60,
        }
    ]


@pytest.mark.asyncio
async def test_delete_is_idempotent_and_audited_once(
    api: tuple[httpx.AsyncClient, Any],
) -> None:
    client, container = api
    run = RunRecord(
        run_id=uuid4(),
        tenant_id="tenant-a",
        principal_id="artifact-user",
        contract={},
        idempotency_key="artifact-delete-run",
        request_hash="request-hash",
        workflow_id="inline",
    )
    await container.store.runs.create_once(run)
    created = await upload(client, query=f"classification=internal&run_id={run.run_id}")
    artifact_id = created.json()["artifact_id"]

    first = await client.delete(
        f"/v1/artifacts/{artifact_id}",
        headers=headers(correlation_id="artifact-delete-1"),
    )
    second = await client.delete(
        f"/v1/artifacts/{artifact_id}",
        headers=headers(correlation_id="artifact-delete-2"),
    )

    assert first.status_code == 204
    assert second.status_code == 204
    events = await container.store.runs.events_after(run.run_id, "tenant-a", 0)
    deleted = [event for event in events if event.event_type == "artifact.deleted"]
    assert len(deleted) == 1
    assert deleted[0].correlation_id == "artifact-delete-1"
    assert deleted[0].payload["artifact_id"] == artifact_id
