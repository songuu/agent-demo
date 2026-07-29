from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

PLATFORM_ROOT = Path(__file__).parents[3]
VALIDATOR = PLATFORM_ROOT / "deploy" / "ci" / "validate_release_approvals.py"
SCHEMA = PLATFORM_ROOT / "deploy" / "ci" / "release-approvals.schema.json"
RELEASE_ID = "12345-1"
GIT_SHA = "a" * 40
IMAGE_DIGEST = f"sha256:{'b' * 64}"
SIGNER_IDENTITY = (
    "https://github.com/example/approval-service/"
    ".github/workflows/publish-release-approvals.yml@refs/heads/main"
)
SIGNER_ISSUER = "https://token.actions.githubusercontent.com"
SIGNATURE_BUNDLE_BYTES = b'{"bundle":"verified-release-approval-fixture"}'


def canonical_bytes(bundle: dict[str, Any]) -> bytes:
    return json.dumps(
        bundle,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def approval_bundle(*, approved_at: datetime | None = None) -> dict[str, Any]:
    timestamp = approved_at or datetime.now(UTC) - timedelta(minutes=5)
    authenticated_at = timestamp - timedelta(minutes=1)
    return {
        "schema_version": "1.1",
        "release_id": RELEASE_ID,
        "git_sha": GIT_SHA,
        "image_digest": IMAGE_DIGEST,
        "issued_at": timestamp.isoformat(),
        "signer": {
            "identity": SIGNER_IDENTITY,
            "issuer": SIGNER_ISSUER,
        },
        "approvals": [
            {
                "release_id": RELEASE_ID,
                "git_sha": GIT_SHA,
                "image_digest": IMAGE_DIGEST,
                "actor": f"{role}-approver",
                "role": role,
                "decision": "approved",
                "approved_at": timestamp.isoformat(),
                "authentication": {
                    "assurance": "phishing-resistant",
                    "method": "webauthn",
                    "authenticated_at": authenticated_at.isoformat(),
                },
                "evidence_uri": (f"https://approvals.example.test/releases/{RELEASE_ID}/{role}"),
            }
            for role in ("security", "business", "sre", "data-system-owner")
        ],
    }


def _run(
    tmp_path: Path,
    bundle: dict[str, Any],
    *,
    source_bytes: bytes | None = None,
    source_uri: str | None = None,
    expected_signer_identity: str = SIGNER_IDENTITY,
    expected_signer_issuer: str = SIGNER_ISSUER,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    bundle_path = tmp_path / "release-approvals.json"
    signature_bundle_path = tmp_path / "release-approvals.json.sigstore.json"
    report_path = tmp_path / "approval-validation.json"
    exact_bytes = source_bytes if source_bytes is not None else canonical_bytes(bundle)
    bundle_path.write_bytes(exact_bytes)
    signature_bundle_path.write_bytes(SIGNATURE_BUNDLE_BYTES)
    immutable_uri = source_uri or (
        "https://approvals.example.test/releases/sha256:" + hashlib.sha256(exact_bytes).hexdigest()
    )
    completed = subprocess.run(  # noqa: S603 - repository-owned validator and fixed interpreter
        [
            sys.executable,
            str(VALIDATOR),
            "--approvals",
            str(bundle_path),
            "--signature-bundle",
            str(signature_bundle_path),
            "--schema",
            str(SCHEMA),
            "--source-uri",
            immutable_uri,
            "--expected-release-id",
            RELEASE_ID,
            "--expected-git-sha",
            GIT_SHA,
            "--expected-image-digest",
            IMAGE_DIGEST,
            "--expected-signer-identity",
            expected_signer_identity,
            "--expected-signer-issuer",
            expected_signer_issuer,
            "--maximum-age-seconds",
            "604800",
            "--output",
            str(report_path),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    return completed, report_path


def test_release_approval_schema_is_valid() -> None:
    Draft202012Validator.check_schema(json.loads(SCHEMA.read_text(encoding="utf-8")))


def test_release_approvals_bind_exact_signed_bytes_and_four_independent_actors(
    tmp_path: Path,
) -> None:
    bundle = approval_bundle()
    source = canonical_bytes(bundle)
    completed, report_path = _run(tmp_path, bundle, source_bytes=source)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["validated"] is True
    assert report["release_approvals_sha256"] == ("sha256:" + hashlib.sha256(source).hexdigest())
    assert report["signature_bundle_sha256"] == (
        "sha256:" + hashlib.sha256(SIGNATURE_BUNDLE_BYTES).hexdigest()
    )
    assert report["signer_identity"] == SIGNER_IDENTITY
    assert report["signer_issuer"] == SIGNER_ISSUER
    assert set(report["roles"]) == {"security", "business", "sre", "data-system-owner"}
    assert len(report["actors"]) == len(set(report["actors"])) == 4
    assert set(report["authentication_methods"].values()) == {"webauthn"}


def test_release_approvals_reject_duplicate_actor_and_wrong_digest(tmp_path: Path) -> None:
    bundle = approval_bundle()
    bundle["approvals"][1]["actor"] = bundle["approvals"][0]["actor"]
    bundle["approvals"][2]["image_digest"] = f"sha256:{'c' * 64}"

    blocked, _ = _run(tmp_path, bundle)

    assert blocked.returncode == 2
    assert "RELEASE_APPROVAL_ACTORS_NOT_UNIQUE" in blocked.stderr
    assert "RELEASE_APPROVAL_IMAGE_DIGEST_MISMATCH" in blocked.stderr


def test_release_approvals_reject_weak_or_expired_evidence(tmp_path: Path) -> None:
    bundle = approval_bundle(approved_at=datetime.now(UTC) - timedelta(days=8))
    bundle["approvals"][0]["authentication"]["assurance"] = "password"

    blocked, _ = _run(tmp_path, bundle)

    assert blocked.returncode == 2
    assert "RELEASE_APPROVAL_SCHEMA_INVALID" in blocked.stderr
    assert "RELEASE_APPROVAL_EXPIRED" in blocked.stderr
    assert "RELEASE_APPROVAL_BUNDLE_EXPIRED" in blocked.stderr


def test_release_approvals_reject_noncanonical_signed_bytes(tmp_path: Path) -> None:
    bundle = approval_bundle()
    noncanonical = (json.dumps(bundle, ensure_ascii=False, indent=2) + "\n").encode()

    blocked, _ = _run(tmp_path, bundle, source_bytes=noncanonical)

    assert blocked.returncode == 2
    assert "RELEASE_APPROVAL_SIGNED_CONTENT_NOT_CANONICAL" in blocked.stderr


def test_release_approvals_reject_non_nfc_signed_bytes(tmp_path: Path) -> None:
    bundle = approval_bundle()
    bundle["approvals"][0]["actor"] = "Jose\u0301"

    blocked, _ = _run(tmp_path, bundle)

    assert blocked.returncode == 2
    assert "RELEASE_APPROVAL_SIGNED_CONTENT_NOT_CANONICAL" in blocked.stderr


def test_release_approvals_reject_mutable_source_or_untrusted_signer(tmp_path: Path) -> None:
    bundle = approval_bundle()
    blocked, _ = _run(
        tmp_path,
        bundle,
        source_uri="https://approvals.example.test/releases/latest.json",
        expected_signer_identity="https://github.com/example/untrusted/workflow.yml@refs/heads/main",
    )

    assert blocked.returncode == 2
    assert "RELEASE_APPROVAL_SOURCE_URI_DIGEST_MISMATCH" in blocked.stderr
    assert "RELEASE_APPROVAL_SIGNER_IDENTITY_MISMATCH" in blocked.stderr
