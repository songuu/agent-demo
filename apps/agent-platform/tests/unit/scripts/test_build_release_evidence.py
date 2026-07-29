from __future__ import annotations

from pathlib import Path

import pytest
from jsonschema import ValidationError
from scripts.build_release_evidence import build_evidence
from tests.unit.scripts.test_build_release_evidence_approvals import _arguments


def test_release_evidence_uses_repository_prompt_tool_and_policy_versions(
    tmp_path: Path,
) -> None:
    evidence = build_evidence(_arguments(tmp_path))

    assert evidence["git_sha"] == "a" * 40
    assert evidence["image_digest"] == "sha256:" + "b" * 64
    assert evidence["policy_bundle_version"] == "1.0.0"
    publication = evidence["evidence_publication"]
    assert (
        evidence["candidate_manifest_uri"]
        == (publication["assets"]["candidate_manifest"]["content_uri"])
    )
    assert (
        evidence["candidate_results_uri"]
        == (publication["assets"]["candidate_results"]["content_uri"])
    )
    assert (
        evidence["human_review_evidence_uri"]
        == (publication["assets"]["human_review"]["content_uri"])
    )
    assert evidence["prompt_versions"] == {
        "classifier": "1.0.0",
        "finalizer": "1.0.0",
        "planner": "1.0.0",
        "verifier": "1.0.0",
        "worker": "1.0.0",
    }
    assert evidence["tool_versions"] == {
        "email.prepare": "1.0.0",
        "knowledge.search": "1.0.0",
    }
    assert len(evidence["approvals"]) == 4


def test_release_evidence_rejects_mutable_or_malformed_release_identity(
    tmp_path: Path,
) -> None:
    malformed_sha = _arguments(tmp_path)
    malformed_sha.git_sha = "main"
    with pytest.raises((ValueError, ValidationError)):
        build_evidence(malformed_sha)

    mutable_image = _arguments(tmp_path)
    mutable_image.image_digest = "agent-platform:latest"
    with pytest.raises((ValueError, ValidationError)):
        build_evidence(mutable_image)
