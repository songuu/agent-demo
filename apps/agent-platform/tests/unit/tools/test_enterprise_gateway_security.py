from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import httpx
import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.infrastructure.credential_broker import WorkloadCredentialGrant
from agent_platform.tools.adapters.enterprise_gateway import EnterpriseToolGatewayAdapter
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


def _grant(
    *,
    tenant_id: str = "tenant-a",
    scopes: frozenset[str] = frozenset({"knowledge:read"}),
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> WorkloadCredentialGrant:
    now = datetime.now(UTC)
    return WorkloadCredentialGrant(
        tenant_id=tenant_id,
        principal_id="user-1",
        scopes=scopes,
        secret_reference="broker://knowledge",
        issued_at=issued_at or now,
        expires_at=expires_at or now + timedelta(seconds=60),
    )


def _response(
    request: httpx.Request,
    *,
    result: Any,
    completed_at: datetime | None = None,
) -> httpx.Response:
    payload = json.loads(request.content)
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
            "completed_at": (completed_at or datetime.now(UTC)).isoformat(),
            "result": result,
        },
    )


@pytest.mark.asyncio
async def test_scope_and_grant_lifetime_are_rechecked_before_provider_io() -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        trust_env=False,
    ) as client:
        adapter = EnterpriseToolGatewayAdapter(
            definition=_definition(),
            client=client,
            gateway_url="https://tool-gateway.platform.svc",
            catalog_digest="sha256:" + "a" * 64,
        )
        with pytest.raises(PlatformError, match="WORKLOAD_CREDENTIAL_SCOPE_DENIED"):
            await adapter.read({"query": "x"}, _grant(scopes=frozenset()))
        with pytest.raises(PlatformError, match="WORKLOAD_CREDENTIAL_GRANT_EXPIRED"):
            await adapter.read(
                {"query": "x"},
                _grant(expires_at=datetime.now(UTC) - timedelta(seconds=1)),
            )
        with pytest.raises(PlatformError, match="WORKLOAD_CREDENTIAL_GRANT_INVALID"):
            await adapter.read(
                {"query": "x"},
                _grant(
                    issued_at=datetime.now(UTC) - timedelta(minutes=6),
                    expires_at=datetime.now(UTC) + timedelta(minutes=6),
                ),
            )

    assert calls == 0


def test_ambient_http_credentials_are_forbidden() -> None:
    client = httpx.AsyncClient(
        headers={"Authorization": "Bearer ambient-secret"},
        transport=httpx.MockTransport(lambda _: httpx.Response(500)),
        trust_env=False,
    )
    with pytest.raises(ValueError, match="TOOL_GATEWAY_AMBIENT_CREDENTIAL_FORBIDDEN"):
        EnterpriseToolGatewayAdapter(
            definition=_definition(),
            client=client,
            gateway_url="https://tool-gateway.platform.svc",
            catalog_digest="sha256:" + "a" * 64,
        )


@pytest.mark.asyncio
async def test_untrusted_provider_output_and_stale_response_fail_closed() -> None:
    def invalid_output(request: httpx.Request) -> httpx.Response:
        return _response(request, result={"unexpected": True})

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(invalid_output),
        trust_env=False,
    ) as client:
        adapter = EnterpriseToolGatewayAdapter(
            definition=_definition(),
            client=client,
            gateway_url="https://tool-gateway.platform.svc",
            catalog_digest="sha256:" + "a" * 64,
        )
        with pytest.raises(PlatformError, match="TOOL_PROVIDER_OUTPUT_SCHEMA_FAILED"):
            await adapter.read({"query": "x"}, _grant())

    def stale(request: httpx.Request) -> httpx.Response:
        return _response(
            request,
            result={"items": []},
            completed_at=datetime.now(UTC) - timedelta(minutes=11),
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(stale),
        trust_env=False,
    ) as client:
        adapter = EnterpriseToolGatewayAdapter(
            definition=_definition(),
            client=client,
            gateway_url="https://tool-gateway.platform.svc",
            catalog_digest="sha256:" + "a" * 64,
        )
        with pytest.raises(PlatformError, match="TOOL_PROVIDER_RESPONSE_STALE"):
            await adapter.read({"query": "x"}, _grant())


@pytest.mark.asyncio
async def test_verify_rejects_cross_tenant_action_before_provider_io() -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    action = type(
        "Action",
        (),
        {
            "action_id": UUID("10000000-0000-0000-0000-000000000001"),
            "run_id": UUID("20000000-0000-0000-0000-000000000002"),
            "tenant_id": "tenant-b",
            "principal_id": "user-1",
            "tool_name": "knowledge.search",
            "tool_version": "1.0.0",
            "payload_hash": "c" * 64,
            "idempotency_key": "business-1",
        },
    )()
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        trust_env=False,
    ) as client:
        adapter = EnterpriseToolGatewayAdapter(
            definition=_definition(),
            client=client,
            gateway_url="https://tool-gateway.platform.svc",
            catalog_digest="sha256:" + "a" * 64,
        )
        with pytest.raises(PlatformError, match="ACTION_PROVIDER_SUBJECT_MISMATCH"):
            await adapter.verify(action, {"id": "receipt-1"}, _grant())

    assert calls == 0
