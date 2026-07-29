from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from agent_platform import bootstrap
from agent_platform.config import Settings
from agent_platform.tools.adapters.enterprise_gateway import EnterpriseToolGatewayAdapter

PLATFORM_ROOT = Path(__file__).resolve().parents[2]
TOOL_CATALOG = PLATFORM_ROOT / "deploy" / "catalogs" / "tool-catalog.v1.json"


@pytest.mark.asyncio
async def test_configured_runtime_uses_only_hash_bound_enterprise_adapters() -> None:
    settings = Settings(
        environment="test",
        auth_disabled=True,
        tool_catalog_path=str(TOOL_CATALOG),
        tool_catalog_sha256="sha256:" + hashlib.sha256(TOOL_CATALOG.read_bytes()).hexdigest(),
        tool_gateway_url="https://tool-gateway.platform.svc",
        tool_gateway_health_url="https://tool-gateway.platform.svc/health",
        tool_gateway_egress_proxy_url="http://tool-egress-proxy.platform.svc:3128",
        tool_gateway_max_in_flight=7,
        tool_gateway_max_queued=11,
    )

    registry, client, catalog = await bootstrap._build_runtime_tool_registry(settings)
    try:
        assert client is not None
        assert catalog is not None
        assert catalog.catalog_id == "enterprise-tools-2026-07-24"
        registered = [
            await registry.resolve(definition.name, "tenant-a")
            for definition in catalog.definitions
        ]
        assert registered
        assert all(isinstance(item.adapter, EnterpriseToolGatewayAdapter) for item in registered)
        assert all(not item.definition.adapter_ref.startswith("reference.") for item in registered)
    finally:
        if client is not None:
            await client.aclose()


@pytest.mark.asyncio
async def test_reference_registry_remains_development_only_fallback() -> None:
    settings = Settings(environment="test", auth_disabled=True)

    registry, client, catalog = await bootstrap._build_runtime_tool_registry(settings)

    assert client is None
    assert catalog is None
    assert {item.name for item in registry.definitions()} == {
        "email.prepare",
        "knowledge.search",
    }
