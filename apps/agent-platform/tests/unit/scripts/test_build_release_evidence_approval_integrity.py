from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.build_release_evidence import build_evidence
from tests.unit.scripts.test_build_release_evidence_approvals import _arguments


def test_release_evidence_binds_verified_release_approval_assets(tmp_path: Path) -> None:
    evidence = build_evidence(_arguments(tmp_path))
    publication = evidence["evidence_publication"]["assets"]

    assert evidence["approvals_bundle_uri"] == publication["release_approvals"]["content_uri"]
    assert (
        evidence["release_approvals_signature_bundle_uri"]
        == publication["release_approvals_signature_bundle"]["content_uri"]
    )
    assert (
        evidence["release_approvals_validation_uri"]
        == publication["release_approvals_validation"]["content_uri"]
    )
    validation = evidence["release_approvals_validation"]
    assert validation["validated"] is True
    assert validation["release_approvals_sha256"] == publication["release_approvals"]["sha256"]
    assert (
        validation["signature_bundle_sha256"]
        == (publication["release_approvals_signature_bundle"]["sha256"])
    )


@pytest.mark.parametrize(
    ("field", "value", "error"),
    (
        (
            "release_approvals_sha256",
            "sha256:" + "0" * 64,
            "RELEASE_APPROVAL_VALIDATION_SOURCE_DIGEST_MISMATCH",
        ),
        (
            "signature_bundle_sha256",
            "sha256:" + "0" * 64,
            "RELEASE_APPROVAL_VALIDATION_SIGNATURE_BUNDLE_DIGEST_MISMATCH",
        ),
        ("release_id", "wrong-release", "RELEASE_APPROVAL_VALIDATION_IDENTITY_MISMATCH"),
        ("git_sha", "f" * 40, "RELEASE_APPROVAL_VALIDATION_IDENTITY_MISMATCH"),
        (
            "image_digest",
            "sha256:" + "f" * 64,
            "RELEASE_APPROVAL_VALIDATION_IDENTITY_MISMATCH",
        ),
        ("validated", False, "RELEASE_APPROVAL_VALIDATION_REQUIRED"),
    ),
)
def test_release_evidence_rejects_unbound_release_approval_validation(
    tmp_path: Path,
    field: str,
    value: object,
    error: str,
) -> None:
    args = _arguments(tmp_path)
    report = json.loads(args.approvals_validation.read_text(encoding="utf-8"))
    report[field] = value
    args.approvals_validation.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=error):
        build_evidence(args)


@pytest.mark.parametrize(
    ("path_field", "error"),
    (
        ("approvals_bundle", "RELEASE_APPROVAL_PUBLICATION_DIGEST_MISMATCH"),
        (
            "approvals_signature_bundle",
            "RELEASE_APPROVAL_SIGNATURE_BUNDLE_PUBLICATION_DIGEST_MISMATCH",
        ),
        ("approvals_validation", "RELEASE_APPROVAL_VALIDATION_PUBLICATION_DIGEST_MISMATCH"),
    ),
)
def test_release_evidence_rejects_unpublished_release_approval_bytes(
    tmp_path: Path,
    path_field: str,
    error: str,
) -> None:
    args = _arguments(tmp_path)
    path = getattr(args, path_field)
    path.write_bytes(path.read_bytes() + b" ")

    with pytest.raises(ValueError, match=error):
        build_evidence(args)
