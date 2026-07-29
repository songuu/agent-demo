"""Validate signed, content-addressed, independent release control approvals."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from agent_platform.application.errors import PlatformError
from agent_platform.infrastructure.artifacts.sanitizer import ArtifactContentSanitizer

JsonObject = dict[str, Any]
REQUIRED_ROLES = {"security", "business", "sre", "data-system-owner"}
PHISHING_RESISTANT_METHODS = {"webauthn", "fido2-security-key", "piv"}
DIGEST_URI_PATTERN = re.compile(r"^https://[^\s]+/(sha256:[0-9a-f]{64})$")
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024


def _load_object(path: Path) -> JsonObject:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _load_source(source_bytes: bytes, *, label: str) -> JsonObject:
    value = json.loads(source_bytes.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return value


def _timestamp(value: object, *, field: str, errors: list[str]) -> datetime | None:
    if not isinstance(value, str):
        errors.append(f"RELEASE_APPROVAL_TIMESTAMP_INVALID: {field}")
        return None
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"RELEASE_APPROVAL_TIMESTAMP_INVALID: {field}")
        return None
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        errors.append(f"RELEASE_APPROVAL_TIMESTAMP_TIMEZONE_MISSING: {field}")
        return None
    return timestamp.astimezone(UTC)


def _mapping(value: object) -> JsonObject:
    return value if isinstance(value, dict) else {}


def validate_approval_bundle(
    bundle: JsonObject,
    schema: JsonObject,
    *,
    expected_release_id: str,
    expected_git_sha: str,
    expected_image_digest: str,
    maximum_age_seconds: int,
    source_bytes: bytes,
    source_uri: str,
    signature_bundle_bytes: bytes,
    expected_signer_identity: str,
    expected_signer_issuer: str,
    now: datetime | None = None,
) -> JsonObject:
    errors: list[str] = []
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for error in sorted(validator.iter_errors(bundle), key=lambda item: list(item.path)):
        location = ".".join(str(part) for part in error.path) or "$"
        errors.append(f"RELEASE_APPROVAL_SCHEMA_INVALID: {location}: {error.message}")

    expected_identity = (
        ("release_id", expected_release_id),
        ("git_sha", expected_git_sha),
        ("image_digest", expected_image_digest),
    )
    for field, expected in expected_identity:
        if bundle.get(field) != expected:
            errors.append(f"RELEASE_APPROVAL_BUNDLE_{field.upper()}_MISMATCH")

    source_sha256 = "sha256:" + hashlib.sha256(source_bytes).hexdigest()
    try:
        canonical_source = (
            ArtifactContentSanitizer()
            .sanitize(
                source_bytes,
                "application/json",
            )
            .content
        )
    except PlatformError:
        errors.append("RELEASE_APPROVAL_SIGNED_CONTENT_NOT_CANONICAL")
    else:
        if source_bytes != canonical_source:
            errors.append("RELEASE_APPROVAL_SIGNED_CONTENT_NOT_CANONICAL")
    source_match = DIGEST_URI_PATTERN.fullmatch(source_uri)
    if source_match is None or source_match.group(1) != source_sha256:
        errors.append("RELEASE_APPROVAL_SOURCE_URI_DIGEST_MISMATCH")

    signer = _mapping(bundle.get("signer"))
    if signer.get("identity") != expected_signer_identity:
        errors.append("RELEASE_APPROVAL_SIGNER_IDENTITY_MISMATCH")
    if signer.get("issuer") != expected_signer_issuer:
        errors.append("RELEASE_APPROVAL_SIGNER_ISSUER_MISMATCH")

    raw_approvals = bundle.get("approvals")
    approvals = raw_approvals if isinstance(raw_approvals, list) else []
    if len(approvals) != len(REQUIRED_ROLES):
        errors.append("RELEASE_APPROVAL_EXACTLY_FOUR_REQUIRED")
    actors: list[str] = []
    roles: list[str] = []
    authentication_methods: dict[str, str] = {}
    approval_timestamps: list[datetime] = []
    current_time = (now or datetime.now(UTC)).astimezone(UTC)
    if maximum_age_seconds <= 0:
        errors.append("RELEASE_APPROVAL_MAXIMUM_AGE_INVALID")
        oldest_allowed = current_time
    else:
        oldest_allowed = current_time - timedelta(seconds=maximum_age_seconds)

    for index, raw_approval in enumerate(approvals):
        if not isinstance(raw_approval, dict):
            errors.append(f"RELEASE_APPROVAL_ROW_INVALID: index={index}")
            continue
        actor = str(raw_approval.get("actor", ""))
        role = str(raw_approval.get("role", ""))
        actors.append(actor)
        roles.append(role)
        for field, expected in expected_identity:
            if raw_approval.get(field) != expected:
                errors.append(f"RELEASE_APPROVAL_{field.upper()}_MISMATCH: role={role or index}")
        approved_at = _timestamp(
            raw_approval.get("approved_at"),
            field=f"approvals.{index}.approved_at",
            errors=errors,
        )
        authentication = _mapping(raw_approval.get("authentication"))
        assurance = authentication.get("assurance")
        method = str(authentication.get("method", ""))
        if assurance != "phishing-resistant":
            errors.append(
                f"RELEASE_APPROVAL_PHISHING_RESISTANT_AUTH_REQUIRED: role={role or index}"
            )
        if method not in PHISHING_RESISTANT_METHODS:
            errors.append(f"RELEASE_APPROVAL_AUTH_METHOD_INVALID: role={role or index}")
        elif role:
            authentication_methods[role] = method
        authenticated_at = _timestamp(
            authentication.get("authenticated_at"),
            field=f"approvals.{index}.authentication.authenticated_at",
            errors=errors,
        )
        if approved_at is not None:
            approval_timestamps.append(approved_at)
            if approved_at < oldest_allowed:
                errors.append(f"RELEASE_APPROVAL_EXPIRED: role={role or index}")
            if approved_at > current_time + timedelta(minutes=5):
                errors.append(f"RELEASE_APPROVAL_FROM_FUTURE: role={role or index}")
        if approved_at is not None and authenticated_at is not None:
            authentication_gap = approved_at - authenticated_at
            if authentication_gap < timedelta(0) or authentication_gap > timedelta(minutes=15):
                errors.append(
                    f"RELEASE_APPROVAL_AUTHENTICATION_WINDOW_INVALID: role={role or index}"
                )

    if len(actors) != len(set(actors)):
        errors.append("RELEASE_APPROVAL_ACTORS_NOT_UNIQUE")
    if len(roles) != len(set(roles)):
        errors.append("RELEASE_APPROVAL_ROLES_NOT_UNIQUE")
    missing_roles = sorted(REQUIRED_ROLES - set(roles))
    if missing_roles:
        errors.append(f"RELEASE_APPROVAL_REQUIRED_ROLES_MISSING: {missing_roles}")

    issued_at = _timestamp(bundle.get("issued_at"), field="issued_at", errors=errors)
    if issued_at is not None:
        if issued_at < oldest_allowed:
            errors.append("RELEASE_APPROVAL_BUNDLE_EXPIRED")
        if issued_at > current_time + timedelta(minutes=5):
            errors.append("RELEASE_APPROVAL_BUNDLE_FROM_FUTURE")
        if any(approved_at > issued_at for approved_at in approval_timestamps):
            errors.append("RELEASE_APPROVAL_BUNDLE_ISSUED_BEFORE_APPROVAL")

    if not signature_bundle_bytes:
        errors.append("RELEASE_APPROVAL_SIGNATURE_BUNDLE_EMPTY")
    signature_bundle_sha256 = "sha256:" + hashlib.sha256(signature_bundle_bytes).hexdigest()
    if errors:
        raise ValueError("\n".join(dict.fromkeys(errors)))
    return {
        "schema_version": "1.1",
        "release_id": expected_release_id,
        "git_sha": expected_git_sha,
        "image_digest": expected_image_digest,
        "source_uri": source_uri,
        "release_approvals_sha256": source_sha256,
        "signature_bundle_sha256": signature_bundle_sha256,
        "signer_identity": expected_signer_identity,
        "signer_issuer": expected_signer_issuer,
        "roles": sorted(REQUIRED_ROLES),
        "actors": sorted(actors),
        "authentication_methods": dict(sorted(authentication_methods.items())),
        "issued_at": bundle["issued_at"],
        "validated_at": current_time.isoformat(),
        "validated": True,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate signed exact-release Security/Business/SRE/Data approvals"
    )
    parser.add_argument("--approvals", type=Path, required=True)
    parser.add_argument("--signature-bundle", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--source-uri", required=True)
    parser.add_argument("--expected-release-id", required=True)
    parser.add_argument("--expected-git-sha", required=True)
    parser.add_argument("--expected-image-digest", required=True)
    parser.add_argument("--expected-signer-identity", required=True)
    parser.add_argument("--expected-signer-issuer", required=True)
    parser.add_argument("--maximum-age-seconds", type=int, default=604800)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.approvals.stat().st_size > MAX_EVIDENCE_BYTES:
            raise ValueError("RELEASE_APPROVAL_BUNDLE_TOO_LARGE")
        if args.signature_bundle.stat().st_size > MAX_EVIDENCE_BYTES:
            raise ValueError("RELEASE_APPROVAL_SIGNATURE_BUNDLE_TOO_LARGE")
        source_bytes = args.approvals.read_bytes()
        signature_bundle_bytes = args.signature_bundle.read_bytes()
        report = validate_approval_bundle(
            _load_source(source_bytes, label=str(args.approvals)),
            _load_object(args.schema),
            expected_release_id=args.expected_release_id,
            expected_git_sha=args.expected_git_sha,
            expected_image_digest=args.expected_image_digest,
            maximum_age_seconds=args.maximum_age_seconds,
            source_bytes=source_bytes,
            source_uri=args.source_uri,
            signature_bundle_bytes=signature_bundle_bytes,
            expected_signer_identity=args.expected_signer_identity,
            expected_signer_issuer=args.expected_signer_issuer,
        )
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        print(f"release approval validation failed:\n{exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
