from __future__ import annotations

import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.domain.enums import ToolEffect
from agent_platform.tools.mcp import McpRegistry, McpServerRegistration, McpTool


class _Observer:
    def __init__(self) -> None:
        self.samples: list[tuple[str, bool, int]] = []

    def record_mcp_server(
        self,
        *,
        server: str,
        healthy: bool,
        result_bytes: int = 0,
    ) -> None:
        self.samples.append((server, healthy, result_bytes))


def _registration() -> McpServerRegistration:
    return McpServerRegistration(
        server_id="crm-search",
        tenant_id="tenant-a",
        base_url="https://mcp.example.test",
        certificate_organization="Example Corp",
        certificate_fingerprint_sha256="a" * 64,
        ca_bundle_ref="configmap://mcp/ca",
        client_certificate_ref="secret://mcp/client",
        tools=(
            McpTool(
                name="crm.search",
                version="1.0.0",
                capability_name="crm.search",
                effect=ToolEffect.READ,
            ),
        ),
    )


def test_mcp_certificate_and_result_boundaries_emit_real_health_and_size() -> None:
    observer = _Observer()
    registry = McpRegistry(observer)
    registry.register(_registration())
    registry.verify_peer_certificate(
        server_id="crm-search",
        tenant_id="tenant-a",
        organization="Example Corp",
        fingerprint_sha256="a" * 64,
    )
    call = registry.authorize_call(
        server_id="crm-search",
        tenant_id="tenant-a",
        tool_name="crm.search",
        task_id="task-1",
        allowed_capabilities={"crm.search"},
    )

    output = registry.normalize_output(call, {"records": [1, 2]})

    assert output.size_bytes > 0
    assert observer.samples == [
        ("crm-search", True, 0),
        ("crm-search", True, output.size_bytes),
    ]


def test_mcp_certificate_mismatch_emits_unhealthy_sample() -> None:
    observer = _Observer()
    registry = McpRegistry(observer)
    registry.register(_registration())

    with pytest.raises(PlatformError, match="MCP_CERTIFICATE_IDENTITY_MISMATCH"):
        registry.verify_peer_certificate(
            server_id="crm-search",
            tenant_id="tenant-a",
            organization="Attacker",
            fingerprint_sha256="b" * 64,
        )

    assert observer.samples == [("crm-search", False, 0)]
