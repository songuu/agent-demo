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
    assert "GPT-5.6 Agent Platform" in page.text
    assert "受约束单节点开发环境" in page.text
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
    assert "window.setInterval(refresh, 60_000)" in script.text
    assert ".textContent" in script.text
    assert ".innerHTML" not in script.text
    assert "/v1/" not in script.text
