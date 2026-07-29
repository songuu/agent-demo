from __future__ import annotations

import hashlib
import json
from pathlib import Path

import httpx
import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.tools.adapters.enterprise_gateway import EnterpriseToolGatewayAdapter
from agent_platform.tools.production_catalog import (
    build_enterprise_registry,
    load_production_tool_catalog,
)


def _tool(*, name: str = "knowledge.search", adapter_ref: str = "enterprise.knowledge.v1") -> dict:
    return {
        "name": name,
        "version": "1.2.3",
        "description": "A production catalog tool.",
        "capability_name": name,
        "effect": "read",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string", "minLength": 1}},
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
        "commit_scopes": [],
        "supported_data_classes": ["internal"],
        "allowed_network_targets": ["enterprise-knowledge"],
        "timeout_seconds": 10,
        "max_result_bytes": 1_000_000,
        "idempotency": "none",
        "approval_policy": "none",
        "adapter_ref": adapter_ref,
        "enabled": True,
    }


def _write_catalog(path: Path, tools: list[dict]) -> str:
    raw = json.dumps(
        {
            "schema_version": "1.0",
            "catalog_id": "enterprise-tools-2026-07-24",
            "tools": tools,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    path.write_bytes(raw)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def test_catalog_is_bound_to_exact_file_digest_and_builds_external_adapters(
    tmp_path: Path,
) -> None:
    path = tmp_path / "catalog.json"
    expected_digest = _write_catalog(path, [_tool()])

    catalog = load_production_tool_catalog(path, expected_sha256=expected_digest)
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(500)),
        trust_env=False,
    )
    registry = build_enterprise_registry(
        catalog,
        client=client,
        gateway_url="https://tool-gateway.platform.svc",
    )

    assert catalog.digest == expected_digest
    assert catalog.catalog_id == "enterprise-tools-2026-07-24"
    assert len(registry.definitions()) == 1
    registered = registry._tools[("knowledge.search", "1.2.3")]
    assert isinstance(registered.adapter, EnterpriseToolGatewayAdapter)


def test_catalog_tampering_and_missing_digest_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "catalog.json"
    expected_digest = _write_catalog(path, [_tool()])
    path.write_text(path.read_text() + "\n", encoding="utf-8")

    with pytest.raises(PlatformError, match="TOOL_CATALOG_DIGEST_MISMATCH"):
        load_production_tool_catalog(path, expected_sha256=expected_digest)
    with pytest.raises(PlatformError, match="TOOL_CATALOG_DIGEST_REQUIRED"):
        load_production_tool_catalog(path, expected_sha256="")


def test_catalog_rejects_reference_adapter_and_duplicate_version(tmp_path: Path) -> None:
    reference_path = tmp_path / "reference.json"
    reference_digest = _write_catalog(
        reference_path,
        [_tool(adapter_ref="reference.knowledge")],
    )
    with pytest.raises(PlatformError, match="PRODUCTION_ADAPTER_REF_REQUIRED"):
        load_production_tool_catalog(reference_path, expected_sha256=reference_digest)

    duplicate_path = tmp_path / "duplicate.json"
    duplicate_digest = _write_catalog(duplicate_path, [_tool(), _tool()])
    with pytest.raises(PlatformError, match="TOOL_CATALOG_DUPLICATE_VERSION"):
        load_production_tool_catalog(duplicate_path, expected_sha256=duplicate_digest)


def test_catalog_rejects_commit_tool_exposure_and_unbounded_file(tmp_path: Path) -> None:
    commit_tool = _tool(name="email.commit")
    commit_tool["effect"] = "commit"
    path = tmp_path / "commit.json"
    digest = _write_catalog(path, [commit_tool])
    catalog = load_production_tool_catalog(path, expected_sha256=digest)
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(500)),
        trust_env=False,
    )

    registry = build_enterprise_registry(
        catalog,
        client=client,
        gateway_url="https://tool-gateway.platform.svc",
    )
    assert registry._agent_visible == set()

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    oversized_digest = "sha256:" + hashlib.sha256(oversized.read_bytes()).hexdigest()
    with pytest.raises(PlatformError, match="TOOL_CATALOG_TOO_LARGE"):
        load_production_tool_catalog(oversized, expected_sha256=oversized_digest)
