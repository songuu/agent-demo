from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest
from deploy.ci import validate_foundation_attestation as validator


def test_cosign_verification_is_fail_closed_and_binds_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "foundation.json"
    bundle = tmp_path / "foundation.sigstore.json"
    evidence.write_text("{}", encoding="utf-8")
    bundle.write_text('{\n  "bundle": "signed"\n}', encoding="utf-8")
    captured: list[str] = []

    def verified(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        captured.extend(command)
        return subprocess.CompletedProcess(command, 0, stdout="Verified OK", stderr="")

    monkeypatch.setattr(validator.subprocess, "run", verified)

    digest = validator.verify_cosign_signature(
        evidence_path=evidence,
        signature_bundle_path=bundle,
        expected_signer_identity="https://github.com/example/foundation.yml@refs/heads/main",
        expected_signer_issuer="https://token.actions.githubusercontent.com",
    )

    assert digest == "sha256:" + hashlib.sha256(b'{"bundle":"signed"}').hexdigest()
    assert captured[:2] == ["cosign", "verify-blob"]
    assert "--certificate-identity" in captured
    assert "--certificate-oidc-issuer" in captured
    assert captured[-1] == str(evidence)


def test_cosign_verification_rejects_invalid_signature(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "foundation.json"
    bundle = tmp_path / "foundation.sigstore.json"
    evidence.write_text("{}", encoding="utf-8")
    bundle.write_text("{}", encoding="utf-8")

    def rejected(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="invalid")

    monkeypatch.setattr(validator.subprocess, "run", rejected)

    with pytest.raises(ValueError, match="FOUNDATION_ATTESTATION_SIGNATURE_INVALID"):
        validator.verify_cosign_signature(
            evidence_path=evidence,
            signature_bundle_path=bundle,
            expected_signer_identity="expected",
            expected_signer_issuer="https://issuer.example",
        )


def test_semantic_validator_rejects_noncanonical_signed_json() -> None:
    from tests.e2e.release_assets.test_foundation_attestation_validator import (
        SCHEMA_PATH,
        _digest_uri,
        foundation_attestation,
    )

    evidence = foundation_attestation()
    pretty = json.dumps(evidence, indent=2, sort_keys=True).encode()
    source_sha256 = "sha256:" + hashlib.sha256(pretty).hexdigest()
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    with pytest.raises(
        ValueError,
        match="FOUNDATION_ATTESTATION_SIGNED_CONTENT_NOT_CANONICAL",
    ):
        validator.validate_foundation_attestation(
            evidence,
            schema,
            source_bytes=pretty,
            source_uri=_digest_uri(source_sha256),
            expected_release_id=evidence["release_id"],
            expected_git_sha=evidence["git_sha"],
            expected_image_digest=evidence["image_digest"],
            expected_terraform_version="1.9.8",
            expected_signer_identity=evidence["signer"]["identity"],
            expected_signer_issuer=evidence["signer"]["issuer"],
            maximum_age_seconds=86400,
        )
