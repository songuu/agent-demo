from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import httpx
import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.domain.enums import ToolEffect
from agent_platform.infrastructure.credential_broker import WorkloadCredentialGrant
from agent_platform.tools.adapters.enterprise_gateway import (
    AdapterInvocationResult,
    EnterpriseToolGatewayAdapter,
)
from agent_platform.tools.models import ToolDefinition


def _definition() -> ToolDefinition:
    return ToolDefinition.model_validate(
        {
            "name": "knowledge.search",
            "version": "2.1.0",
            "description": "Search an enterprise knowledge gateway.",
            "capability_name": "knowledge.search",
            "effect": "read",
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "minLength": 1},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 20},
                },
                "required": ["query", "limit"],
                "additionalProperties": False,
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "items": {"type": "array"},
                    "row_count": {"type": "integer", "minimum": 0},
                },
                "required": ["items", "row_count"],
                "additionalProperties": False,
            },
            "risk": "medium",
            "required_scopes": ["knowledge:read"],
            "commit_scopes": [],
            "supported_data_classes": ["internal"],
            "allowed_network_targets": ["enterprise-knowledge"],
            "timeout_seconds": 5,
            "max_result_bytes": 100_000,
            "idempotency": "none",
            "approval_policy": "none",
            "adapter_ref": "enterprise.knowledge.search.v2",
        }
    )


def _grant() -> WorkloadCredentialGrant:
    now = datetime.now(UTC)
    return WorkloadCredentialGrant(
        tenant_id="tenant-a",
        principal_id="user-7",
        scopes=frozenset({"knowledge:read"}),
        secret_reference="broker://tenant-a/knowledge-reader",
        issued_at=now,
        expires_at=now + timedelta(seconds=60),
    )


def _success_response(request: httpx.Request, result: Any) -> httpx.Response:
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
            "provider_request_id": "provider-request-42",
            "completed_at": datetime.now(UTC).isoformat(),
            "result": result,
        },
    )


@pytest.mark.asyncio
async def test_read_uses_fixed_gateway_protocol_and_opaque_credential_reference() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        captured["payload"] = json.loads(request.content)
        return _success_response(request, {"items": [{"source_id": "s-1"}], "row_count": 1})

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
        response = await adapter.read({"query": "revenue", "limit": 5}, (grant := _grant()))

    assert isinstance(response, AdapterInvocationResult)
    assert response.data == {"items": [{"source_id": "s-1"}], "row_count": 1}
    assert response.provider_request_id == "provider-request-42"
    request = captured["request"]
    payload = captured["payload"]
    assert request.url.path == "/v1/tool-operations"
    assert "authorization" not in request.headers
    assert payload["operation"] == "read"
    assert payload["credential_grant"] == {
        "tenant_id": "tenant-a",
        "principal_id": "user-7",
        "scopes": ["knowledge:read"],
        "secret_reference": "broker://tenant-a/knowledge-reader",
        "issued_at": grant.issued_at.isoformat(),
        "expires_at": grant.expires_at.isoformat(),
    }
    assert payload["tool"]["adapter_ref"] == "enterprise.knowledge.search.v2"
    assert UUID(payload["request_id"])


@pytest.mark.asyncio
async def test_commit_protocol_preserves_idempotency_and_provider_evidence() -> None:
    operations: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        operations.append(payload)
        if payload["operation"] == "lookup":
            result = None
        elif payload["operation"] == "commit":
            result = {
                "external_operation_id": "mail-9",
                "idempotency_key": payload["idempotency_key"],
                "committed_at": datetime.now(UTC).isoformat(),
                "result_summary": {"status": "accepted"},
            }
        elif payload["operation"] == "verify":
            result = {"passed": True, "method": "provider_read_after_write"}
        else:
            result = {"compensated": True}
        return _success_response(request, result)

    definition = _definition().model_copy(
        update={
            "name": "email.prepare",
            "capability_name": "email.prepare",
            "effect": ToolEffect.PREPARE,
            "required_scopes": frozenset({"email:prepare"}),
            "commit_scopes": frozenset({"email:commit"}),
            "output_schema": {"type": "object"},
            "adapter_ref": "enterprise.email.v1",
        }
    )
    commit_grant = WorkloadCredentialGrant(
        tenant_id="tenant-a",
        principal_id="approver-1",
        scopes=frozenset({"email:commit"}),
        secret_reference="broker://tenant-a/email-committer",
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(seconds=60),
    )
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        trust_env=False,
    ) as client:
        adapter = EnterpriseToolGatewayAdapter(
            definition=definition,
            client=client,
            gateway_url="https://tool-gateway.platform.svc",
            catalog_digest="sha256:" + "b" * 64,
        )
        assert await adapter.lookup_by_idempotency_key("business-7", commit_grant) is None
        receipt = await adapter.commit(
            {"recipients": ["leader@example.com"]},
            commit_grant,
            "business-7",
        )
        verification = await adapter.verify(
            type(
                "Action",
                (),
                {
                    "action_id": UUID("10000000-0000-0000-0000-000000000001"),
                    "run_id": UUID("20000000-0000-0000-0000-000000000002"),
                    "tenant_id": "tenant-a",
                    "principal_id": "approver-1",
                    "tool_name": "email.prepare",
                    "tool_version": "2.1.0",
                    "payload_hash": "c" * 64,
                    "idempotency_key": "business-7",
                },
            )(),
            receipt,
            commit_grant,
        )

    assert receipt["provider_request_id"] == "provider-request-42"
    assert receipt["idempotency_key"] == "business-7"
    assert verification == {
        "passed": True,
        "method": "provider_read_after_write",
        "provider_request_id": "provider-request-42",
    }
    assert [item["operation"] for item in operations] == ["lookup", "commit", "verify"]
    assert operations[1]["idempotency_key"] == "business-7"
    assert operations[2]["action"]["payload_hash"] == "c" * 64


@pytest.mark.asyncio
async def test_gateway_response_must_bind_request_catalog_tool_and_operation() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        response = _success_response(request, {"items": [], "row_count": 0})
        payload = json.loads(response.content)
        payload["tool_version"] = "9.9.9"
        return httpx.Response(200, json=payload)

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
        with pytest.raises(PlatformError, match="TOOL_PROVIDER_BINDING_MISMATCH"):
            await adapter.read({"query": "revenue", "limit": 5}, _grant())


@pytest.mark.asyncio
async def test_gateway_fails_closed_for_wrong_credential_and_provider_failure() -> None:
    async def not_called(_: httpx.Request) -> httpx.Response:
        raise AssertionError("invalid credential must fail before provider I/O")

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(not_called),
        trust_env=False,
    ) as client:
        adapter = EnterpriseToolGatewayAdapter(
            definition=_definition(),
            client=client,
            gateway_url="https://tool-gateway.platform.svc",
            catalog_digest="sha256:" + "a" * 64,
        )
        with pytest.raises(PlatformError, match="WORKLOAD_CREDENTIAL_GRANT_REQUIRED"):
            await adapter.read({"query": "revenue", "limit": 5}, object())

    def unavailable(_: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "provider unavailable"})

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(unavailable),
        trust_env=False,
    ) as client:
        adapter = EnterpriseToolGatewayAdapter(
            definition=_definition(),
            client=client,
            gateway_url="https://tool-gateway.platform.svc",
            catalog_digest="sha256:" + "a" * 64,
        )
        with pytest.raises(PlatformError, match="TOOL_PROVIDER_UNAVAILABLE") as caught:
            await adapter.read({"query": "revenue", "limit": 5}, _grant())

    assert caught.value.retryable is True


def test_production_gateway_requires_https_and_bounded_catalog_digest() -> None:
    with pytest.raises(ValueError, match="TOOL_GATEWAY_TLS_REQUIRED"):
        EnterpriseToolGatewayAdapter(
            definition=_definition(),
            client=httpx.AsyncClient(transport=httpx.MockTransport(lambda _: None)),
            gateway_url="http://tool-gateway.platform.svc",
            catalog_digest="sha256:" + "a" * 64,
        )
    with pytest.raises(ValueError, match="TOOL_CATALOG_DIGEST_INVALID"):
        EnterpriseToolGatewayAdapter(
            definition=_definition(),
            client=httpx.AsyncClient(transport=httpx.MockTransport(lambda _: None)),
            gateway_url="https://tool-gateway.platform.svc",
            catalog_digest="not-a-digest",
        )
