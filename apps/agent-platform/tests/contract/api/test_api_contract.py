from __future__ import annotations

import asyncio

import httpx
import pytest
import pytest_asyncio
from pydantic import SecretStr

from agent_platform.api.app import create_app
from agent_platform.config import Settings
from agent_platform.container import build_container


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
    )


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def client() -> httpx.AsyncClient:
    runtime_settings = settings()
    container = await build_container(runtime_settings)
    app = create_app(runtime_settings, container=container)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as value:
        yield value
    await container.aclose()


def run_body(*, with_action: bool = False) -> dict[str, object]:
    capabilities = ["knowledge.search", "artifact.create"]
    if with_action:
        capabilities.append("email.prepare")
    return {
        "goal": "Compare SG and JP with source-backed conclusions",
        "success_criteria": [
            {
                "id": "sc-1",
                "description": "Every key claim cites evidence",
                "severity": "must",
                "verification": "evidence",
            }
        ],
        "allowed_capabilities": capabilities,
        "constraints": {
            "markets": ["SG", "JP"],
            "recipients": ["leader@example.test"],
        },
        "budget": {
            "max_cost_usd": "5.00",
            "max_duration_seconds": 120,
            "max_tool_calls": 10,
        },
        "external_write_policy": "approval" if with_action else "deny",
        "requested_output": {"format": "market_report@1.0"},
    }


async def wait_status(
    client: httpx.AsyncClient,
    run_id: str,
    expected: set[str],
    *,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    for _ in range(200):
        response = await client.get(f"/v1/runs/{run_id}", headers=headers)
        if response.status_code == 200 and response.json()["status"] in expected:
            return response
        await asyncio.sleep(0.01)
    pytest.fail(f"run {run_id} did not reach {expected}")


@pytest.mark.asyncio(loop_scope="module")
async def test_run_202_idempotency_snapshot_etag_sse_and_tenant_boundary(
    client: httpx.AsyncClient,
) -> None:
    headers = {
        "Idempotency-Key": "api-read-only-1",
        "X-Correlation-ID": "correlation-read-1",
    }
    response = await client.post("/v1/runs", json=run_body(), headers=headers)
    assert response.status_code == 202, response.text
    assert response.headers["location"].startswith("/v1/runs/")
    assert response.headers["x-correlation-id"] == "correlation-read-1"
    accepted = response.json()

    duplicate = await client.post("/v1/runs", json=run_body(), headers=headers)
    assert duplicate.status_code == 202
    assert duplicate.json()["run_id"] == accepted["run_id"]

    snapshot = await wait_status(client, accepted["run_id"], {"completed"})
    body = snapshot.json()
    assert body["result"]["claims"]
    assert body["result"]["evidence"]
    etag = snapshot.headers["etag"]
    not_modified = await client.get(
        f"/v1/runs/{accepted['run_id']}", headers={"If-None-Match": etag}
    )
    assert not_modified.status_code == 304

    events = await client.get(f"/v1/runs/{accepted['run_id']}/events")
    assert events.status_code == 200
    assert "event: run.completed" in events.text
    first_id = next(
        line.removeprefix("id: ") for line in events.text.splitlines() if line.startswith("id: ")
    )
    resumed = await client.get(
        f"/v1/runs/{accepted['run_id']}/events",
        headers={"Last-Event-ID": first_id},
    )
    assert resumed.text.count("id: ") < events.text.count("id: ")

    hidden = await client.get(
        f"/v1/runs/{accepted['run_id']}",
        headers={"X-Agent-Tenant": "tenant-b"},
    )
    assert hidden.status_code == 404
    assert hidden.json()["error"]["code"] == "NOT_FOUND"


@pytest.mark.asyncio(loop_scope="module")
async def test_action_approval_endpoint_commits_only_after_step_up(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post(
        "/v1/runs",
        json=run_body(with_action=True),
        headers={
            "Idempotency-Key": "api-action-1",
            "X-Agent-User": "requester",
        },
    )
    assert response.status_code == 202, response.text
    run_id = response.json()["run_id"]
    await wait_status(client, run_id, {"waiting_approval"})
    actions = await client.get(f"/v1/runs/{run_id}/actions")
    action = actions.json()[0]

    weak = await client.post(
        f"/v1/actions/{action['action_id']}:approve",
        json={"payload_hash": action["payload_hash"], "comment": "weak"},
        headers={
            "X-Agent-User": "approver",
            "X-Agent-Roles": "approver",
            "X-Agent-Auth-Strength": "password",
        },
    )
    assert weak.status_code == 403
    assert weak.json()["error"]["code"] == "STEP_UP_AUTH_REQUIRED"

    approved = await client.post(
        f"/v1/actions/{action['action_id']}:approve",
        json={"payload_hash": action["payload_hash"], "comment": "approved"},
        headers={
            "X-Agent-User": "approver",
            "X-Agent-Roles": "approver",
            "X-Agent-Auth-Strength": "phishing_resistant",
        },
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"
    final = await wait_status(client, run_id, {"completed", "failed"})
    assert final.json()["status"] == "completed", final.text
    committed = await client.get(f"/v1/runs/{run_id}/actions")
    assert committed.json()[0]["status"] == "committed"
    assert committed.json()[0]["verification"]["passed"] is True


@pytest.mark.asyncio(loop_scope="module")
async def test_artifact_lifecycle_capability_kill_switch_and_openapi(
    client: httpx.AsyncClient,
) -> None:
    uploaded = await client.post(
        "/v1/artifacts?kind=document&classification=internal",
        content=b"source-backed artifact",
        headers={"Content-Type": "application/octet-stream"},
    )
    assert uploaded.status_code == 201, uploaded.text
    artifact = uploaded.json()
    metadata = await client.get(f"/v1/artifacts/{artifact['artifact_id']}")
    assert metadata.json()["sha256"] == artifact["sha256"]
    missing_purpose = await client.get(f"/v1/artifacts/{artifact['artifact_id']}?download=true")
    assert missing_purpose.status_code == 400
    assert missing_purpose.json()["error"]["code"] == "ARTIFACT_DOWNLOAD_PURPOSE_REQUIRED"
    downloaded = await client.get(
        f"/v1/artifacts/{artifact['artifact_id']}?download=true&purpose=contract-test"
    )
    assert downloaded.content == b"source-backed artifact"
    deleted = await client.delete(f"/v1/artifacts/{artifact['artifact_id']}")
    assert deleted.status_code == 204
    missing = await client.get(f"/v1/artifacts/{artifact['artifact_id']}")
    assert missing.status_code == 404

    capabilities = await client.get("/v1/capabilities")
    names = {item["name"] for item in capabilities.json()}
    assert {"knowledge.search", "artifact.create", "email.prepare"} <= names
    disabled = await client.post(
        "/v1/admin/capabilities/email.prepare:disable",
        json={"reason": "incident response", "scope": "capability"},
    )
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False
    after = await client.get("/v1/capabilities")
    assert "email.prepare" not in {item["name"] for item in after.json()}

    openapi = (await client.get("/openapi.json")).json()
    required_paths = {
        "/v1/runs",
        "/v1/runs/{run_id}",
        "/v1/runs/{run_id}/events",
        "/v1/runs/{run_id}:cancel",
        "/v1/runs/{run_id}:resume",
        "/v1/runs/{run_id}/actions",
        "/v1/actions/{action_id}:approve",
        "/v1/actions/{action_id}:reject",
        "/v1/artifacts/{artifact_id}",
        "/v1/capabilities",
        "/v1/admin/capabilities/{name}:disable",
    }
    assert required_paths <= set(openapi["paths"])


@pytest.mark.asyncio(loop_scope="module")
async def test_validation_errors_use_stable_schema(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post(
        "/v1/runs",
        json={"goal": ""},
        headers={"Idempotency-Key": "invalid-request-1"},
    )
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "SCHEMA_VALIDATION_FAILED"
    assert error["retryable"] is False
    assert error["correlation_id"]
