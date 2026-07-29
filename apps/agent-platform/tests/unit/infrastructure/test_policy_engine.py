from __future__ import annotations

import httpx
import pytest

from agent_platform.infrastructure.policy.engine import OpaPolicyEngine


@pytest.mark.asyncio
async def test_opa_policy_engine_returns_versioned_decision() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/data/agent/tool/result"
        return httpx.Response(
            200,
            json={
                "result": {
                    "allowed": True,
                    "reason_codes": [],
                    "approval_required": False,
                    "data_scope": {"tenant_id": "tenant-a"},
                    "policy_version": "bundle-7",
                }
            },
        )

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://opa.invalid",
    )
    engine = OpaPolicyEngine(
        base_url="http://opa.invalid",
        client=client,
        fail_closed=True,
    )

    decision = await engine.evaluate(
        "agent/tool/result",
        {"request": {"data_scope": {"tenant_id": "tenant-a"}}},
    )

    assert decision.allowed is True
    assert decision.policy_version == "bundle-7"
    assert decision.data_scope == {"tenant_id": "tenant-a"}
    await client.aclose()


@pytest.mark.asyncio
async def test_opa_policy_engine_fails_closed_when_opa_is_unavailable() -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("OPA is unavailable")

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://opa.invalid",
    )
    engine = OpaPolicyEngine(
        base_url="http://opa.invalid",
        client=client,
        fail_closed=True,
    )

    decision = await engine.evaluate("agent/tool/result", {"tool": {"effect": "read"}})

    assert decision.allowed is False
    assert decision.reason_codes == ("policy_unavailable",)
    assert decision.policy_version == "unavailable"
    await client.aclose()


@pytest.mark.asyncio
async def test_opa_policy_engine_rejects_missing_result() -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={})

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://opa.invalid",
    )
    engine = OpaPolicyEngine(
        base_url="http://opa.invalid",
        client=client,
        fail_closed=True,
    )

    decision = await engine.evaluate("agent/tool/result", {})

    assert decision.allowed is False
    assert decision.reason_codes == ("invalid_policy_response",)
    await client.aclose()
