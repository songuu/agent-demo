from __future__ import annotations

import hashlib
from pathlib import Path

from agent_platform.domain.enums import ToolEffect
from agent_platform.tools.production_catalog import load_production_tool_catalog

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def test_example_production_catalog_is_strict_and_hash_loadable() -> None:
    path = PROJECT_ROOT / "deploy" / "catalogs" / "tool-catalog.v1.json"
    raw = path.read_bytes()
    catalog = load_production_tool_catalog(
        path,
        expected_sha256="sha256:" + hashlib.sha256(raw).hexdigest(),
    )

    definitions = {item.name: item for item in catalog.definitions}
    assert definitions.keys() == {"knowledge.search", "email.prepare"}
    assert definitions["knowledge.search"].effect is ToolEffect.READ
    assert definitions["email.prepare"].effect is ToolEffect.PREPARE
    assert definitions["email.prepare"].commit_scopes == frozenset({"email:commit"})
    assert all(item.adapter_ref.startswith("enterprise.") for item in definitions.values())
    assert all(
        item.input_schema.get("additionalProperties") is False for item in definitions.values()
    )
