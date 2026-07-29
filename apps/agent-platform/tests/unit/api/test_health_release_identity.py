from __future__ import annotations

import httpx
import pytest
from pydantic import SecretStr

from agent_platform.api.app import create_app
from agent_platform.config import Settings
from agent_platform.container import build_container

GIT_SHA = "a" * 40
IMAGE_DIGEST = "sha256:" + "b" * 64


@pytest.mark.asyncio
async def test_health_exposes_exact_release_sha_and_image_digest() -> None:
    settings = Settings(
        environment="test",
        database_dsn=SecretStr("postgresql+asyncpg://test:test@localhost/test"),
        openai_api_key=SecretStr(""),
        auth_disabled=True,
        workflow_backend="inline",
        persistence_backend="memory",
        artifact_backend="memory",
        policy_backend="builtin",
        release_git_sha=GIT_SHA,
        release_image_digest=IMAGE_DIGEST,
    )
    container = await build_container(settings)
    app = create_app(settings, container=container)
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            health = await client.get("/health")
    finally:
        await container.aclose()

    assert health.status_code == 200
    assert health.json()["release_git_sha"] == GIT_SHA
    assert health.json()["release_image_digest"] == IMAGE_DIGEST


@pytest.mark.asyncio
async def test_metrics_scrape_refreshes_operational_database_snapshot() -> None:
    settings = Settings(
        environment="test",
        database_dsn=SecretStr("postgresql+asyncpg://test:test@localhost/test"),
        openai_api_key=SecretStr(""),
        auth_disabled=True,
        workflow_backend="inline",
        persistence_backend="memory",
        artifact_backend="memory",
        policy_backend="builtin",
    )
    container = await build_container(settings)

    class Sampler:
        def __init__(self) -> None:
            self.calls = 0

        async def collect(self) -> bool:
            self.calls += 1
            return True

    sampler = Sampler()
    container.operational_metrics = sampler
    app = create_app(settings, container=container)
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.get("/metrics")
    finally:
        await container.aclose()

    assert response.status_code == 200
    assert sampler.calls == 1
