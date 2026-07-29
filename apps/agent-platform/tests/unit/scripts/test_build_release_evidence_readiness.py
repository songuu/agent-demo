from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.build_release_evidence import build_evidence
from tests.unit.scripts.test_build_release_evidence_approvals import _arguments


def _readiness_arguments(tmp_path: Path):
    return _arguments(tmp_path)


def test_release_evidence_binds_validated_operational_readiness(tmp_path: Path) -> None:
    evidence = build_evidence(_readiness_arguments(tmp_path))

    assert evidence["base_image_digest"] == (
        "sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90"
    )
    assert evidence["platform_versions"]["alembic_revision"] == "20260727_0009"
    assert evidence["operational_readiness_uri"].startswith("https://")
    assert evidence["operational_readiness_sha256"].startswith("sha256:")
    assert evidence["operational_readiness_validation"]["validated"] is True
    assert len(evidence["operational_readiness_validation"]["gate_raw_evidence"]) == 12
    assert set(evidence["operational_readiness_validation"]["training_populations"]) == {
        "business-users",
        "approvers",
        "on-call",
    }


def test_release_evidence_rejects_validation_without_gate_raw_evidence(
    tmp_path: Path,
) -> None:
    args = _readiness_arguments(tmp_path)
    validation = json.loads(args.operational_readiness_validation.read_text(encoding="utf-8"))
    validation.pop("gate_raw_evidence")
    args.operational_readiness_validation.write_text(json.dumps(validation), encoding="utf-8")

    with pytest.raises(ValueError, match="OPERATIONAL_GATE_RAW_EVIDENCE_VALIDATION_REQUIRED"):
        build_evidence(args)


def test_release_evidence_rejects_mutable_gate_raw_reference(tmp_path: Path) -> None:
    args = _readiness_arguments(tmp_path)
    validation = json.loads(args.operational_readiness_validation.read_text(encoding="utf-8"))
    raw_digest = validation["gate_raw_evidence"]["staging_e2e"]["sha256"]
    validation["gate_raw_evidence"]["staging_e2e"]["uri"] = (
        f"https://evidence.example.test/raw/staging_e2e/{raw_digest}-mutable/latest"
    )
    args.operational_readiness_validation.write_text(json.dumps(validation), encoding="utf-8")

    with pytest.raises(ValueError, match="OPERATIONAL_GATE_RAW_EVIDENCE_REFERENCE_INVALID"):
        build_evidence(args)


def test_release_evidence_rejects_incomplete_operational_readiness(
    tmp_path: Path,
) -> None:
    args = _readiness_arguments(tmp_path)
    readiness = json.loads(args.operational_readiness.read_text(encoding="utf-8"))
    readiness["training"]["records"] = readiness["training"]["records"][:2]
    args.operational_readiness.write_text(json.dumps(readiness), encoding="utf-8")

    with pytest.raises(ValueError, match="OPERATIONAL_READINESS_TRAINING_INCOMPLETE"):
        build_evidence(args)


def test_release_evidence_rejects_base_image_digest_not_pinned_by_dockerfile(
    tmp_path: Path,
) -> None:
    args = _readiness_arguments(tmp_path)
    readiness = json.loads(args.operational_readiness.read_text(encoding="utf-8"))
    readiness["versions"]["base_image_digest"] = f"sha256:{'9' * 64}"
    args.operational_readiness.write_text(json.dumps(readiness), encoding="utf-8")

    with pytest.raises(ValueError, match="BASE_IMAGE_DIGEST_MISMATCH"):
        build_evidence(args)
