from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.build_release_evidence import build_evidence
from tests.unit.scripts.test_build_release_evidence_approvals import _arguments


def test_release_evidence_binds_verified_canary_assets(tmp_path: Path) -> None:
    evidence = build_evidence(_arguments(tmp_path))
    publication = evidence["evidence_publication"]["assets"]

    assert evidence["canary_evidence_uri"] == publication["canary"]["content_uri"]
    assert (
        evidence["canary_signature_bundle_uri"]
        == publication["canary_signature_bundle"]["content_uri"]
    )
    assert evidence["canary_validation_uri"] == publication["canary_validation"]["content_uri"]
    validation = evidence["canary_validation"]
    assert validation["validated"] is True
    assert validation["canary_evidence_sha256"] == publication["canary"]["sha256"]
    assert validation["signature_bundle_sha256"] == publication["canary_signature_bundle"]["sha256"]


@pytest.mark.parametrize(
    ("field", "value", "error"),
    (
        (
            "canary_evidence_sha256",
            "sha256:" + "0" * 64,
            "CANARY_VALIDATION_EVIDENCE_DIGEST_MISMATCH",
        ),
        (
            "signature_bundle_sha256",
            "sha256:" + "0" * 64,
            "CANARY_VALIDATION_SIGNATURE_BUNDLE_DIGEST_MISMATCH",
        ),
        ("release_id", "wrong-release", "CANARY_VALIDATION_IDENTITY_MISMATCH"),
        ("git_sha", "f" * 40, "CANARY_VALIDATION_IDENTITY_MISMATCH"),
        (
            "image_digest",
            "sha256:" + "f" * 64,
            "CANARY_VALIDATION_IDENTITY_MISMATCH",
        ),
        ("validated", False, "CANARY_VALIDATION_REQUIRED"),
    ),
)
def test_release_evidence_rejects_unbound_canary_validation(
    tmp_path: Path,
    field: str,
    value: object,
    error: str,
) -> None:
    args = _arguments(tmp_path)
    report = json.loads(args.canary_validation.read_text(encoding="utf-8"))
    report[field] = value
    args.canary_validation.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=error):
        build_evidence(args)


def test_release_evidence_rejects_unpublished_canary_validation_bytes(
    tmp_path: Path,
) -> None:
    args = _arguments(tmp_path)
    args.canary_validation.write_bytes(args.canary_validation.read_bytes() + b" ")

    with pytest.raises(
        ValueError,
        match="CANARY_VALIDATION_PUBLICATION_DIGEST_MISMATCH",
    ):
        build_evidence(args)
