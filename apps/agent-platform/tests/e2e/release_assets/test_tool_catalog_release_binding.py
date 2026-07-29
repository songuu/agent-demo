from __future__ import annotations

import json
from pathlib import Path

PLATFORM_ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = PLATFORM_ROOT.parents[1] / ".github" / "workflows" / "agent-platform-release.yml"


def test_release_candidate_binds_versioned_tool_catalog_by_digest() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "deploy/catalogs/tool-catalog.v1.json" in workflow
    assert 'tool_catalog_sha256="sha256:$(sha256sum ' in workflow
    assert '--tool-catalog-sha256 "${tool_catalog_sha256}"' in workflow
    assert "--tool-catalog deploy/catalogs/tool-catalog.v1.json" in workflow


def test_release_evidence_schema_requires_tool_catalog_identity() -> None:
    schema = json.loads(
        (PLATFORM_ROOT / "deploy" / "ci" / "release-evidence.schema.json").read_text(
            encoding="utf-8"
        )
    )

    assert {"tool_catalog_id", "tool_catalog_digest"} <= set(schema["required"])
    assert schema["properties"]["tool_catalog_digest"]["pattern"] == ("^sha256:[0-9a-f]{64}$")
