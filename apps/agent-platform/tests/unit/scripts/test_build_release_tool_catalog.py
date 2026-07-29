from __future__ import annotations

from pathlib import Path

import pytest
from scripts.build_release_evidence import build_evidence
from tests.unit.scripts.test_build_release_evidence_approvals import _arguments

from agent_platform.application.errors import PlatformError


def test_release_evidence_binds_production_tool_catalog(tmp_path: Path) -> None:
    evidence = build_evidence(_arguments(tmp_path))

    assert evidence["tool_catalog_id"] == "enterprise-tools-2026-07-24"
    assert evidence["tool_catalog_digest"].startswith("sha256:")
    assert evidence["tool_versions"] == {
        "email.prepare": "1.0.0",
        "knowledge.search": "1.0.0",
    }


def test_release_evidence_rejects_tool_catalog_digest_drift(tmp_path: Path) -> None:
    arguments = _arguments(tmp_path)
    arguments.tool_catalog_sha256 = "sha256:" + "0" * 64

    with pytest.raises(PlatformError, match="TOOL_CATALOG_DIGEST_MISMATCH"):
        build_evidence(arguments)
