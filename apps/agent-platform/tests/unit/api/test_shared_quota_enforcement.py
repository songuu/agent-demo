from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from starlette.requests import Request

from agent_platform.api.dependencies import (
    RequestIdentity,
    _consume_authenticated_quota,
)
from agent_platform.api.middleware import SecurityEnvelopeMiddleware
from agent_platform.application.errors import PlatformError
from agent_platform.domain.enums import DataClassification
from agent_platform.domain.models import DataScope, Principal
from agent_platform.infrastructure.quota import QuotaDecision, QuotaDimension


class FakeQuotaLimiter:
    def __init__(self, decision: QuotaDecision | Exception) -> None:
        self.decision = decision
        self.calls: list[tuple[QuotaDimension, ...]] = []

    async def consume(
        self,
        dimensions: tuple[QuotaDimension, ...],
    ) -> QuotaDecision:
        self.calls.append(dimensions)
        if isinstance(self.decision, Exception):
            raise self.decision
        return self.decision


def _settings() -> SimpleNamespace:
    return SimpleNamespace(
        environment="prod",
        quota_backend="redis",
        pre_auth_ip_requests_per_minute=10,
        user_requests_per_minute=20,
        tenant_requests_per_minute=30,
        use_case_requests_per_minute=40,
        ip_requests_per_minute=50,
    )


@pytest.mark.asyncio
async def test_pre_auth_redis_quota_returns_429_with_retry_after() -> None:
    limiter = FakeQuotaLimiter(QuotaDecision(False, 17, "pre_auth_ip"))
    app = FastAPI()
    app.state.container = SimpleNamespace(settings=_settings(), quota_limiter=limiter)
    app.add_middleware(SecurityEnvelopeMiddleware, max_request_bytes=1_024)

    @app.get("/probe")
    async def probe() -> dict[str, bool]:
        return {"ok": True}

    transport = httpx.ASGITransport(
        app=app,
        client=("203.0.113.10", 40_000),
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/probe")

    assert response.status_code == 429
    assert response.headers["retry-after"] == "17"
    assert response.json()["error"]["details"]["dimension"] == "pre_auth_ip"
    assert limiter.calls[0][0].value == "203.0.113.10"


@pytest.mark.asyncio
async def test_authenticated_quota_uses_trusted_principal_body_use_case_and_ip() -> None:
    limiter = FakeQuotaLimiter(QuotaDecision(False, 23, "tenant"))
    app = FastAPI()
    app.state.container = SimpleNamespace(settings=_settings(), quota_limiter=limiter)
    scope: dict[str, Any] = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/v1/runs",
        "raw_path": b"/v1/runs",
        "query_string": b"",
        "headers": [],
        "client": ("203.0.113.10", 40_000),
        "server": ("testserver", 443),
        "app": app,
        "state": {"source_host": "203.0.113.10"},
    }
    request = Request(scope)
    request._body = json.dumps({"constraints": {"use_case": "document-review"}}).encode()
    identity = RequestIdentity(
        principal=Principal(
            user_id="user-7",
            tenant_id="tenant-a",
            roles=frozenset({"member"}),
            scopes=frozenset({"knowledge:read"}),
            auth_strength="mfa",
        ),
        data_scope=DataScope(
            tenant_id="tenant-a",
            resource_types=frozenset({"knowledge"}),
            classifications=frozenset({DataClassification.INTERNAL}),
        ),
    )

    with pytest.raises(PlatformError, match="RATE_LIMITED") as caught:
        await _consume_authenticated_quota(request, identity)

    dimensions = {item.name: item for item in limiter.calls[0]}
    assert set(dimensions) == {"user", "tenant", "use_case", "ip"}
    assert dimensions["user"].value == "tenant-a\0user-7"
    assert dimensions["tenant"].value == "tenant-a"
    assert dimensions["use_case"].value == "document-review"
    assert dimensions["ip"].value == "203.0.113.10"
    assert caught.value.context == {
        "dimension": "tenant",
        "retry_after_seconds": 23,
    }


@pytest.mark.asyncio
async def test_production_request_fails_closed_when_quota_limiter_is_missing() -> None:
    app = FastAPI()
    app.state.container = SimpleNamespace(settings=_settings(), quota_limiter=None)
    request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "https",
            "path": "/v1/runs",
            "raw_path": b"/v1/runs",
            "query_string": b"",
            "headers": [],
            "client": ("203.0.113.10", 40_000),
            "server": ("testserver", 443),
            "app": app,
            "state": {"source_host": "203.0.113.10"},
        }
    )
    identity = RequestIdentity(
        principal=Principal(
            user_id="user-7",
            tenant_id="tenant-a",
            auth_strength="mfa",
        ),
        data_scope=DataScope(
            tenant_id="tenant-a",
            resource_types=frozenset({"knowledge"}),
        ),
    )

    with pytest.raises(PlatformError, match="QUOTA_BACKEND_UNAVAILABLE"):
        await _consume_authenticated_quota(request, identity)
