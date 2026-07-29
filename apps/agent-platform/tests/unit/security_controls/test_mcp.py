from __future__ import annotations

import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.domain.enums import ToolEffect, TrustLevel
from agent_platform.tools.mcp import (
    McpRegistry,
    McpServerRegistration,
    McpTool,
)


def server(*, tools: tuple[McpTool, ...] | None = None) -> McpServerRegistration:
    return McpServerRegistration(
        server_id="enterprise-knowledge",
        tenant_id="tenant-a",
        base_url="https://mcp.example.test/v1",
        certificate_organization="Example Corp",
        certificate_fingerprint_sha256="a" * 64,
        ca_bundle_ref="configmap://mcp/example-ca",
        client_certificate_ref="secret://mcp/example-client",
        tools=tools
        or (
            McpTool(
                name="knowledge.search",
                version="1.0.0",
                capability_name="knowledge.search",
                effect=ToolEffect.READ,
            ),
        ),
    )


def test_mcp_registration_requires_https_managed_certificates_and_no_commit() -> None:
    with pytest.raises(ValueError, match="MCP_HTTPS_REQUIRED"):
        server().model_copy(update={"base_url": "http://mcp.example.test"}).model_validate(
            {
                **server().model_dump(),
                "base_url": "http://mcp.example.test",
            }
        )

    with pytest.raises(ValueError, match="MCP_CERTIFICATE_REF_REQUIRED"):
        McpServerRegistration(
            **{
                **server().model_dump(),
                "client_certificate_ref": "-----BEGIN PRIVATE KEY-----",
            }
        )

    with pytest.raises(ValueError, match="MCP_COMMIT_TOOL_FORBIDDEN"):
        server(
            tools=(
                McpTool(
                    name="payments.commit",
                    version="1.0.0",
                    capability_name="payments.commit",
                    effect=ToolEffect.COMMIT,
                ),
            )
        )


def test_mcp_call_is_resolved_from_registration_and_filtered_by_task() -> None:
    registry = McpRegistry()
    registry.register(server())

    call = registry.authorize_call(
        server_id="enterprise-knowledge",
        tenant_id="tenant-a",
        tool_name="knowledge.search",
        task_id="research-a",
        allowed_capabilities={"knowledge.search"},
    )

    assert call.endpoint == "https://mcp.example.test/v1"
    assert not hasattr(call, "override_url")
    assert call.task_id == "research-a"

    with pytest.raises(PlatformError, match="MCP_SERVER_NOT_FOUND"):
        registry.authorize_call(
            server_id="enterprise-knowledge",
            tenant_id="tenant-b",
            tool_name="knowledge.search",
            task_id="research-a",
            allowed_capabilities={"knowledge.search"},
        )
    with pytest.raises(PlatformError, match="MCP_TOOL_NOT_AUTHORIZED"):
        registry.authorize_call(
            server_id="enterprise-knowledge",
            tenant_id="tenant-a",
            tool_name="knowledge.search",
            task_id="research-a",
            allowed_capabilities=set(),
        )


def test_mcp_peer_identity_and_output_taint_are_fail_closed() -> None:
    registry = McpRegistry()
    registry.register(server())
    registry.verify_peer_certificate(
        server_id="enterprise-knowledge",
        tenant_id="tenant-a",
        organization="Example Corp",
        fingerprint_sha256="a" * 64,
    )
    with pytest.raises(PlatformError, match="MCP_CERTIFICATE_IDENTITY_MISMATCH"):
        registry.verify_peer_certificate(
            server_id="enterprise-knowledge",
            tenant_id="tenant-a",
            organization="Attacker Corp",
            fingerprint_sha256="a" * 64,
        )

    call = registry.authorize_call(
        server_id="enterprise-knowledge",
        tenant_id="tenant-a",
        tool_name="knowledge.search",
        task_id="research-a",
        allowed_capabilities={"knowledge.search"},
    )
    output = registry.normalize_output(call, {"items": [{"title": "external"}]})

    assert output.trust is TrustLevel.UNTRUSTED
    assert {"external", "mcp"} <= output.taint
    assert len(output.content_hash) == 64
