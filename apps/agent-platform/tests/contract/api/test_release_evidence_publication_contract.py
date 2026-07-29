from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from pydantic import SecretStr
from tests.unit.api.test_release_evidence_artifact_contract import (
    BINDING,
    GIT_SHA,
    IMAGE_DIGEST,
    RELEASE_ID,
    _identity,
)

from agent_platform.api.app import create_app
from agent_platform.api.dependencies import current_identity
from agent_platform.config import Settings
from agent_platform.container import build_container


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
        artifact_retention_restricted_days=90,
    )


def _headers() -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "X-Evidence-Release-ID": RELEASE_ID,
        "X-Evidence-Git-SHA": GIT_SHA,
        "X-Evidence-Image-Digest": IMAGE_DIGEST,
    }


@pytest.mark.asyncio
async def test_release_evidence_upload_persists_identity_and_365_day_expiry() -> None:
    settings = _settings()
    container = await build_container(settings)
    app = create_app(settings, container=container)
    app.dependency_overrides[current_identity] = _identity
    started_at = datetime.now(UTC)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/v1/artifacts?kind=release-evidence-component&classification=restricted",
            content=b'{"schema_version":"1.0"}',
            headers=_headers(),
        )

    assert response.status_code == 201, response.text
    metadata: dict[str, Any] = response.json()
    assert metadata["classification"] == "restricted"
    assert metadata["scan_provenance"]["release_binding"] == BINDING
    assert metadata["retention_policy"] == "release-evidence@1:immutable:365d"
    assert datetime.fromisoformat(metadata["expires_at"]) >= (started_at + timedelta(days=365))
    await container.aclose()


@pytest.mark.asyncio
async def test_release_evidence_upload_rejects_missing_identity_headers() -> None:
    settings = _settings()
    container = await build_container(settings)
    app = create_app(settings, container=container)
    app.dependency_overrides[current_identity] = _identity

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/v1/artifacts?kind=release-evidence&classification=restricted",
            content=b'{"schema_version":"1.0"}',
            headers={"Content-Type": "application/json"},
        )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "RELEASE_EVIDENCE_IDENTITY_INVALID"
    await container.aclose()
