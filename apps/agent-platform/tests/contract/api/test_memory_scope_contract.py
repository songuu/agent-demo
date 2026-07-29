from __future__ import annotations

import httpx
import pytest
from pydantic import SecretStr

from agent_platform.api.app import create_app
from agent_platform.config import Settings
from agent_platform.container import build_container


def headers() -> dict[str, str]:
    return {
        "X-Agent-Tenant": "tenant-a",
        "X-Agent-User": "memory-user",
        "X-Agent-Roles": "analyst",
        "X-Agent-Scopes": "memory:read,memory:write,knowledge:read",
        "X-Agent-Auth-Strength": "mfa",
    }


def body() -> dict[str, object]:
    return {
        "subject_type": "user",
        "subject_id": "memory-user",
        "memory_type": "preference",
        "content": "Use source-backed Chinese.",
        "classification": "internal",
        "write_policy": "explicit-user-approval",
        "confirm_write": True,
        "purpose": "market-research",
        "data_scope": {
            "tenant_id": "tenant-a",
            "resource_types": ["knowledge"],
            "resource_ids": ["doc-1"],
            "classifications": ["internal"],
        },
    }


@pytest.mark.asyncio
async def test_memory_api_binds_subject_scope_purpose_and_classification() -> None:
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
    app = create_app(settings, container=container)
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://test",
        ) as client:
            created = await client.post("/v1/memories", json=body(), headers=headers())
            assert created.status_code == 201, created.text
            payload = created.json()
            assert payload["purpose"] == "market-research"
            assert payload["version"] == 1
            assert payload["data_scope"]["resource_ids"] == ["doc-1"]

            matching = await client.get(
                "/v1/memories?purpose=market-research",
                headers=headers(),
            )
            other_purpose = await client.get(
                "/v1/memories?purpose=incident-review",
                headers=headers(),
            )
            assert [item["memory_id"] for item in matching.json()] == [payload["memory_id"]]
            assert other_purpose.json() == []

            wrong_subject = body()
            wrong_subject["subject_id"] = "another-user"
            denied = await client.post(
                "/v1/memories",
                json=wrong_subject,
                headers=headers(),
            )
            assert denied.status_code == 403
            assert denied.json()["error"]["code"] == "MEMORY_SUBJECT_PRINCIPAL_MISMATCH"

            disallowed_classification = body()
            disallowed_classification["classification"] = "confidential"
            denied = await client.post(
                "/v1/memories",
                json=disallowed_classification,
                headers=headers(),
            )
            assert denied.status_code == 403
            assert denied.json()["error"]["code"] == "MEMORY_DATA_SCOPE_FORBIDDEN"
    finally:
        await container.aclose()
