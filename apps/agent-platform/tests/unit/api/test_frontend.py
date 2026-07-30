from __future__ import annotations

import httpx
import pytest
from pydantic import SecretStr

from agent_platform.api.app import create_app
from agent_platform.config import Settings
from agent_platform.container import build_container


def _settings() -> Settings:
    return Settings(
        environment="test",
        database_dsn=SecretStr("postgresql+asyncpg://test:test@localhost/test"),
        openai_api_key=SecretStr(""),
        auth_disabled=True,
        workflow_backend="inline",
        persistence_backend="memory",
        artifact_backend="memory",
        policy_backend="builtin",
    )


@pytest.mark.asyncio
async def test_frontend_root_and_assets_are_renderable_and_fail_closed() -> None:
    settings = _settings()
    container = await build_container(settings)
    app = create_app(settings, container=container)
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            page = await client.get("/")
            stylesheet = await client.get("/assets/app.css")
            script = await client.get("/assets/app.js")
    finally:
        await container.aclose()

    assert page.status_code == 200
    assert page.headers["content-type"].startswith("text/html")
    assert page.headers["cache-control"] == "no-store"
    assert page.headers["x-content-type-options"] == "nosniff"
    assert page.headers["x-frame-options"] == "DENY"
    assert page.headers["referrer-policy"] == "no-referrer"
    assert page.headers["cross-origin-opener-policy"] == "same-origin"
    assert page.headers["cross-origin-resource-policy"] == "same-origin"
    assert page.headers["permissions-policy"] == "camera=(), geolocation=(), microphone=()"
    content_security_policy = page.headers["content-security-policy"]
    assert "default-src 'none'" in content_security_policy
    assert "script-src 'self'" in content_security_policy
    assert "style-src 'self'" in content_security_policy
    assert "connect-src 'self'" in content_security_policy
    assert 'lang="zh-CN"' in page.text
    assert 'data-agent-platform-shell="v1"' in page.text
    assert 'data-agent-platform-console="v1"' in page.text
    assert "GPT-5.6 Agent Platform" in page.text
    assert "受约束单节点开发环境" in page.text
    assert 'id="console-token"' in page.text
    assert 'type="password"' in page.text
    assert 'id="run-create-form"' in page.text
    assert 'id="artifact-upload-form"' in page.text
    assert 'id="memory-create-form"' in page.text
    assert 'id="kill-switch-form"' in page.text
    assert 'id="webhook-form"' in page.text
    assert 'href="assets/app.css"' in page.text
    assert 'src="assets/app.js"' in page.text

    assert stylesheet.status_code == 200
    assert stylesheet.headers["content-type"].startswith("text/css")
    assert "--color-bg:" in stylesheet.text
    assert "@media" in stylesheet.text

    assert script.status_code == 200
    assert script.headers["content-type"].startswith("application/javascript")
    assert 'new URL("health", window.location.href)' in script.text
    assert 'new URL("ready", window.location.href)' in script.text
    assert 'scannerStatus === "error:policy-fail-closed:structural-only"' in script.text
    assert 'name !== "artifact_malware_scanner" && dependencyStatus !== "ok"' in script.text
    assert "unexpectedFailures.length === 0" in script.text
    assert 'new URL("v1/runs", window.location.href)' in script.text
    assert 'new Set(["completed", "failed", "cancelled"])' in script.text
    assert 'new URL("v1/capabilities", window.location.href)' in script.text
    assert 'new URL("v1/artifacts", window.location.href)' in script.text
    assert 'new URL("v1/memories", window.location.href)' in script.text
    assert 'new URL("v1/admin/kill-switches", window.location.href)' in script.text
    assert 'new URL("v1/admin/webhooks", window.location.href)' in script.text
    assert "Authorization" in script.text
    assert "Idempotency-Key" in script.text
    assert "X-Correlation-ID" in script.text
    assert "window.setInterval(refresh, 60_000)" in script.text
    assert ".textContent" in script.text
    assert ".innerHTML" not in script.text
    assert "localStorage" not in script.text
    assert "sessionStorage" not in script.text


@pytest.mark.asyncio
async def test_console_token_connects_the_public_frontend_to_real_run_apis() -> None:
    token = "single-node-console-test-token-000000000000"
    settings = Settings(
        environment="test",
        database_dsn=SecretStr("postgresql+asyncpg://test:test@localhost/test"),
        openai_api_key=SecretStr(""),
        auth_disabled=True,
        development_console_token=SecretStr(token),
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
            anonymous = await client.get(
                "/v1/capabilities",
                headers={"X-Agent-Roles": "admin"},
            )
            headers = {
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": "functional-console-run-1",
                "X-Correlation-ID": "functional-console-correlation-1",
            }
            capabilities = await client.get("/v1/capabilities", headers=headers)
            accepted = await client.post(
                "/v1/runs",
                headers=headers,
                json={
                    "goal": "Verify the governed console reaches the run workflow",
                    "success_criteria": [
                        {
                            "id": "console_api",
                            "description": "The run is accepted and can be read back",
                            "severity": "must",
                            "verification": "evidence",
                        }
                    ],
                    "allowed_capabilities": ["knowledge.search"],
                    "constraints": {"use_case": "governed-console"},
                    "budget": {
                        "max_cost_usd": "1.00",
                        "max_duration_seconds": 120,
                        "max_tool_calls": 10,
                    },
                    "external_write_policy": "deny",
                    "requested_output": {"format": "application/json"},
                },
            )
            snapshot = await client.get(
                f"/v1/runs/{accepted.json()['run_id']}",
                headers={"Authorization": f"Bearer {token}"},
            )
    finally:
        await container.aclose()

    assert anonymous.status_code == 401
    assert capabilities.status_code == 200
    assert accepted.status_code == 202, accepted.text
    assert accepted.headers["x-correlation-id"] == "functional-console-correlation-1"
    assert snapshot.status_code == 200, snapshot.text
    assert snapshot.json()["run_id"] == accepted.json()["run_id"]
