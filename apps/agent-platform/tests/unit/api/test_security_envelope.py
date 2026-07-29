from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI, Request

from agent_platform.api.middleware import SecurityEnvelopeMiddleware


def _app(
    *,
    max_request_bytes: int = 64,
    requests_per_minute: int = 120,
    trusted_proxy_cidrs: tuple[str, ...] = (),
) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        SecurityEnvelopeMiddleware,
        max_request_bytes=max_request_bytes,
        requests_per_minute=requests_per_minute,
        trusted_proxy_cidrs=trusted_proxy_cidrs,
    )

    @app.get("/probe")
    async def probe() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/echo")
    async def echo(request: Request) -> dict[str, int]:
        return {"size": len(await request.body())}

    return app


@pytest.mark.asyncio
async def test_untrusted_tenant_header_cannot_reset_pre_auth_rate_limit() -> None:
    transport = httpx.ASGITransport(
        app=_app(requests_per_minute=1),
        client=("203.0.113.10", 40000),
    )
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as client:
        first = await client.get("/probe", headers={"X-Agent-Tenant": "tenant-a"})
        bypass = await client.get("/probe", headers={"X-Agent-Tenant": "tenant-b"})

    assert first.status_code == 200
    assert bypass.status_code == 429
    assert bypass.json()["error"]["code"] == "RATE_LIMITED"


@pytest.mark.asyncio
async def test_forwarded_for_is_used_only_from_an_explicit_trusted_proxy() -> None:
    untrusted_transport = httpx.ASGITransport(
        app=_app(requests_per_minute=1, trusted_proxy_cidrs=("10.0.0.0/8",)),
        client=("203.0.113.10", 40000),
    )
    async with httpx.AsyncClient(
        transport=untrusted_transport,
        base_url="http://testserver",
    ) as client:
        first = await client.get("/probe", headers={"X-Forwarded-For": "198.51.100.1"})
        bypass = await client.get("/probe", headers={"X-Forwarded-For": "198.51.100.2"})

    assert first.status_code == 200
    assert bypass.status_code == 429

    trusted_transport = httpx.ASGITransport(
        app=_app(requests_per_minute=1, trusted_proxy_cidrs=("10.0.0.0/8",)),
        client=("10.0.0.10", 40000),
    )
    async with httpx.AsyncClient(
        transport=trusted_transport,
        base_url="http://testserver",
    ) as client:
        first_client = await client.get(
            "/probe",
            headers={"X-Forwarded-For": "198.51.100.1"},
        )
        second_client = await client.get(
            "/probe",
            headers={"X-Forwarded-For": "198.51.100.2"},
        )

    assert first_client.status_code == 200
    assert second_client.status_code == 200


@pytest.mark.asyncio
async def test_chunked_json_body_is_bounded_by_observed_bytes() -> None:
    async def chunks() -> AsyncIterator[bytes]:
        yield b'{"value":"'
        yield b"x" * 80
        yield b'"}'

    transport = httpx.ASGITransport(app=_app(max_request_bytes=32))
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as client:
        response = await client.post(
            "/echo",
            headers={"Content-Type": "application/json"},
            content=chunks(),
        )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "REQUEST_TOO_LARGE"
