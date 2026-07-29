from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.build_release_evidence import build_evidence
from tests.unit.scripts.test_build_release_evidence_approvals import _arguments


def test_release_evidence_binds_verified_foundation_assets(tmp_path: Path) -> None:
    evidence = build_evidence(_arguments(tmp_path))
    publication = evidence["evidence_publication"]["assets"]

    assert (
        evidence["foundation_attestation_uri"]
        == publication["foundation_attestation"]["content_uri"]
    )
    assert (
        evidence["foundation_attestation_signature_bundle_uri"]
        == publication["foundation_attestation_signature_bundle"]["content_uri"]
    )
    assert (
        evidence["foundation_attestation_validation_uri"]
        == publication["foundation_attestation_validation"]["content_uri"]
    )
    validation = evidence["foundation_attestation_validation"]
    assert validation["signature_verified"] is True
    assert validation["terraform_version"] == "1.9.8"
    assert (
        validation["foundation_attestation_sha256"]
        == (publication["foundation_attestation"]["sha256"])
    )


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        (
            "foundation_attestation_sha256",
            "sha256:" + "0" * 64,
            "FOUNDATION_ATTESTATION_PUBLICATION_DIGEST_MISMATCH",
        ),
        (
            "signature_verified",
            False,
            "FOUNDATION_ATTESTATION_VALIDATION_REQUIRED",
        ),
        (
            "git_sha",
            "f" * 40,
            "FOUNDATION_ATTESTATION_VALIDATION_IDENTITY_MISMATCH",
        ),
    ],
)
def test_release_evidence_rejects_unbound_foundation_validation(
    tmp_path: Path,
    field: str,
    value: object,
    error: str,
) -> None:
    args = _arguments(tmp_path)
    report = json.loads(args.foundation_attestation_validation.read_text(encoding="utf-8"))
    report[field] = value
    args.foundation_attestation_validation.write_text(
        json.dumps(report, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=error):
        build_evidence(args)
