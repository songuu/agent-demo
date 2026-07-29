from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.application.reliability import CircuitState
from agent_platform.infrastructure.credential_broker import WorkloadCredentialGrant
from agent_platform.tools.adapters.enterprise_gateway import (
    EnterpriseGatewayReliabilityConfig,
    EnterpriseToolGatewayAdapter,
)
from agent_platform.tools.models import ToolDefinition


def _definition() -> ToolDefinition:
    return ToolDefinition.model_validate(
        {
            "name": "knowledge.search",
            "version": "1.0.0",
            "description": "Strict enterprise search.",
            "capability_name": "knowledge.search",
            "effect": "read",
            "input_schema": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
                "additionalProperties": False,
            },
            "output_schema": {
                "type": "object",
                "properties": {"items": {"type": "array"}},
                "required": ["items"],
                "additionalProperties": False,
            },
            "risk": "medium",
            "required_scopes": ["knowledge:read"],
            "supported_data_classes": ["internal"],
            "allowed_network_targets": ["enterprise-knowledge"],
            "timeout_seconds": 5,
            "max_result_bytes": 10_000,
            "idempotency": "none",
            "approval_policy": "none",
            "adapter_ref": "enterprise.knowledge.v1",
        }
    )


def _grant() -> WorkloadCredentialGrant:
    now = datetime.now(UTC)
    return WorkloadCredentialGrant(
        tenant_id="tenant-a",
        principal_id="user-1",
        scopes=frozenset({"knowledge:read"}),
        secret_reference="broker://knowledge",
        issued_at=now,
        expires_at=now + timedelta(seconds=60),
    )


def _response(request: httpx.Request) -> httpx.Response:
    payload: dict[str, Any] = json.loads(request.content)
    return httpx.Response(
        200,
        json={
            "protocol_version": "1.0",
            "request_id": payload["request_id"],
            "catalog_digest": payload["catalog_digest"],
            "definition_hash": payload["tool"]["definition_hash"],
            "tool_name": payload["tool"]["name"],
            "tool_version": payload["tool"]["version"],
            "operation": payload["operation"],
            "status": "succeeded",
            "provider_request_id": "provider-1",
            "completed_at": datetime.now(UTC).isoformat(),
            "result": {"items": []},
        },
    )


def _adapter(
    handler: httpx.AsyncBaseTransport,
    *,
    reliability: EnterpriseGatewayReliabilityConfig,
) -> tuple[httpx.AsyncClient, EnterpriseToolGatewayAdapter]:
    client = httpx.AsyncClient(transport=handler, trust_env=False)
    return client, EnterpriseToolGatewayAdapter(
        definition=_definition(),
        client=client,
        gateway_url="https://tool-gateway.platform.svc",
        catalog_digest="sha256:" + "a" * 64,
        reliability=reliability,
    )


@pytest.mark.asyncio
async def test_provider_failures_open_tool_endpoint_circuit() -> None:
    calls = 0

    def unavailable(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503)

    client, adapter = _adapter(
        httpx.MockTransport(unavailable),
        reliability=EnterpriseGatewayReliabilityConfig(
            circuit_failure_threshold=1,
            circuit_recovery_timeout_seconds=60,
        ),
    )
    async with client:
        with pytest.raises(PlatformError, match="TOOL_PROVIDER_UNAVAILABLE"):
            await adapter.read({"query": "first"}, _grant())
        with pytest.raises(PlatformError, match="CIRCUIT_OPEN"):
            await adapter.read({"query": "second"}, _grant())

    assert calls == 1
    assert adapter.circuit_state is CircuitState.OPEN


@pytest.mark.asyncio
async def test_local_backpressure_does_not_poison_provider_circuit() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    async def slow_success(request: httpx.Request) -> httpx.Response:
        entered.set()
        await release.wait()
        return _response(request)

    client, adapter = _adapter(
        httpx.MockTransport(slow_success),
        reliability=EnterpriseGatewayReliabilityConfig(
            max_in_flight=1,
            max_queued=0,
            queue_timeout_seconds=0.1,
            circuit_failure_threshold=1,
        ),
    )
    async with client:
        first = asyncio.create_task(adapter.read({"query": "first"}, _grant()))
        await asyncio.wait_for(entered.wait(), timeout=1)
        with pytest.raises(PlatformError, match="BACKPRESSURE_REJECTED"):
            await adapter.read({"query": "second"}, _grant())
        assert adapter.circuit_state is CircuitState.CLOSED
        release.set()
        assert (await first).data == {"items": []}
