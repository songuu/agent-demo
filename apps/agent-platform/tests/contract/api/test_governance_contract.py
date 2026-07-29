from __future__ import annotations

import asyncio

import httpx
import pytest
import pytest_asyncio
from pydantic import SecretStr

from agent_platform.api.app import create_app
from agent_platform.config import Settings
from agent_platform.container import build_container


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def client() -> httpx.AsyncClient:
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
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as value:
        yield value
    await container.aclose()


def identity_headers(*, tenant: str = "tenant-a") -> dict[str, str]:
    return {
        "X-Agent-Tenant": tenant,
        "X-Agent-User": "governance-user",
        "X-Agent-Roles": "analyst",
        "X-Agent-Scopes": (
            "memory:read,memory:write,audit:read,admin:webhooks,"
            "admin:kill-switch,runs:create,runs:read,knowledge:read,artifact:write"
        ),
        "X-Agent-Auth-Strength": "mfa",
    }


@pytest.mark.asyncio(loop_scope="module")
async def test_memory_is_visible_correctable_deletable_and_tenant_scoped(
    client: httpx.AsyncClient,
) -> None:
    body = {
        "subject_type": "user",
        "subject_id": "governance-user",
        "memory_type": "preference",
        "content": "Use concise Chinese.",
        "classification": "internal",
        "write_policy": "explicit-user-approval",
        "confirm_write": True,
        "source_refs": ["user-request-1"],
    }
    created = await client.post("/v1/memories", json=body, headers=identity_headers())
    assert created.status_code == 201, created.text
    memory_id = created.json()["memory_id"]

    cross_tenant = await client.get("/v1/memories", headers=identity_headers(tenant="tenant-b"))
    assert cross_tenant.status_code == 200
    assert cross_tenant.json() == []

    corrected = await client.post(
        f"/v1/memories/{memory_id}:correct",
        json={
            "content": "Use direct, evidence-backed Chinese.",
            "reason": "User clarified the preference.",
        },
        headers=identity_headers(),
    )
    assert corrected.status_code == 200, corrected.text
    corrected_id = corrected.json()["memory_id"]
    assert corrected_id != memory_id
    assert corrected.json()["content"] == "Use direct, evidence-backed Chinese."

    deleted = await client.post(
        f"/v1/memories/{corrected_id}:delete",
        json={"reason": "User requested erasure."},
        headers=identity_headers(),
    )
    assert deleted.status_code == 204, deleted.text
    visible = await client.get("/v1/memories", headers=identity_headers())
    assert visible.json() == []


@pytest.mark.asyncio(loop_scope="module")
async def test_webhook_secret_is_returned_only_on_create_and_rotation(
    client: httpx.AsyncClient,
) -> None:
    created = await client.post(
        "/v1/admin/webhooks",
        json={
            "endpoint_name": "operations",
            "url": "https://hooks.example.test/agent",
            "event_types": ["run.completed", "action.committed"],
        },
        headers=identity_headers(),
    )
    assert created.status_code == 201, created.text
    endpoint = created.json()
    assert endpoint["signing_secret"]

    listed = await client.get("/v1/admin/webhooks", headers=identity_headers())
    assert listed.status_code == 200
    assert listed.json()[0]["signing_secret"] is None

    rotated = await client.post(
        f"/v1/admin/webhooks/{endpoint['endpoint_id']}:rotate-secret",
        headers=identity_headers(),
    )
    assert rotated.status_code == 200, rotated.text
    assert rotated.json()["secret_version"] == 2
    assert rotated.json()["signing_secret"] != endpoint["signing_secret"]


@pytest.mark.asyncio(loop_scope="module")
async def test_global_kill_switch_blocks_new_runs_but_keeps_audit_queries(
    client: httpx.AsyncClient,
) -> None:
    activated = await client.post(
        "/v1/admin/kill-switches",
        json={
            "scope": "global",
            "scope_id": "*",
            "mode": "all",
            "reason": "SEC-010 contract exercise",
            "incident_id": "TEST-SEC-010",
        },
        headers=identity_headers(),
    )
    assert activated.status_code == 201, activated.text
    switch_id = activated.json()["switch_id"]

    blocked = await client.post(
        "/v1/runs",
        json={
            "goal": "This run must be blocked.",
            "success_criteria": [
                {
                    "id": "sc-1",
                    "description": "No execution starts.",
                    "severity": "must",
                    "verification": "schema",
                }
            ],
            "allowed_capabilities": ["knowledge.search"],
            "constraints": {},
            "budget": {
                "max_cost_usd": "1.00",
                "max_duration_seconds": 30,
                "max_tool_calls": 1,
            },
            "external_write_policy": "deny",
            "requested_output": {"format": "test@1.0"},
        },
        headers={**identity_headers(), "Idempotency-Key": "kill-switch-run-1"},
    )
    assert blocked.status_code == 503, blocked.text
    assert blocked.json()["error"]["code"] == "GLOBAL_KILL_SWITCH_ACTIVE"

    listed = await client.get("/v1/admin/kill-switches", headers=identity_headers())
    assert listed.status_code == 200
    assert listed.json()[0]["switch_id"] == switch_id

    deactivated = await client.post(
        f"/v1/admin/kill-switches/{switch_id}:deactivate",
        json={"reason": "Contract exercise complete."},
        headers=identity_headers(),
    )
    assert deactivated.status_code == 200
    assert deactivated.json()["deactivated_at"] is not None


@pytest.mark.asyncio(loop_scope="module")
async def test_run_audit_export_contains_ordered_correlation_evidence(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post(
        "/v1/runs",
        json={
            "goal": "Create auditable evidence.",
            "success_criteria": [
                {
                    "id": "sc-1",
                    "description": "Return a verified answer.",
                    "severity": "must",
                    "verification": "schema",
                }
            ],
            "allowed_capabilities": ["knowledge.search"],
            "constraints": {},
            "budget": {
                "max_cost_usd": "1.00",
                "max_duration_seconds": 120,
                "max_tool_calls": 2,
            },
            "external_write_policy": "deny",
            "requested_output": {"format": "audit_test@1.0"},
        },
        headers={
            **identity_headers(),
            "Idempotency-Key": "audit-export-run-1",
            "X-Correlation-ID": "audit-correlation-1",
        },
    )
    assert response.status_code == 202, response.text
    run_id = response.json()["run_id"]
    for _ in range(100):
        snapshot = await client.get(f"/v1/runs/{run_id}", headers=identity_headers())
        if snapshot.json().get("status") in {"completed", "failed"}:
            break
        await asyncio.sleep(0.01)

    exported = await client.get(f"/v1/audit/runs/{run_id}", headers=identity_headers())
    assert exported.status_code == 200, exported.text
    audit = exported.json()
    assert audit["contract"]["goal"] == "Create auditable evidence."
    assert audit["plans"], exported.text
    assert audit["plans"][0]["plan_hash"]
    assert audit["plans"][0]["planner_model"] == "deterministic-reference-runtime"
    assert audit["plans"][0]["prompt_id"] == "not-applicable"
    assert audit["task_executions"]
    assert all(item["status"] == "succeeded" for item in audit["task_executions"])
    assert all(
        item["model_name"] == "deterministic-reference-runtime"
        for item in audit["task_executions"]
    )
    assert all(item["prompt_id"] == "not-applicable" for item in audit["task_executions"])
    assert audit["tool_invocations"]
    assert all(item["effect"] == "read" for item in audit["tool_invocations"])
    assert all(item["policy_decision_id"] for item in audit["tool_invocations"])
    events = audit["events"]
    assert events
    assert [item["sequence_no"] for item in events] == list(range(1, len(events) + 1))
    assert all(item["correlation_id"] for item in events)
    assert all(item["payload_hash"] for item in events)
    assert {
        "plan.created",
        "task.started",
        "task.completed",
        "tool.completed",
    } <= {item["event_type"] for item in events}
    assert all(
        item["task_id"]
        for item in events
        if item["event_type"] in {"task.started", "task.completed", "tool.completed"}
    )
