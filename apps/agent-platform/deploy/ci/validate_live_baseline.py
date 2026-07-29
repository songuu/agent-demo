"""Validate signed, content-addressed live release baselines."""

from __future__ import annotations

import argparse
import hashlib
import json
import re

# Cosign is invoked as a fixed argv list with shell=False below.
import subprocess  # nosec B404
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker

from agent_platform.application.errors import PlatformError
from agent_platform.infrastructure.artifacts.sanitizer import ArtifactContentSanitizer

JsonObject = dict[str, Any]
MAXIMUM_INPUT_BYTES = 2 * 1024 * 1024
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
DIGEST_PATH_PATTERN = re.compile(r"/(sha256:[0-9a-f]{64})$")


def _load_object(path: Path) -> JsonObject:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _mapping(value: object) -> JsonObject:
    return value if isinstance(value, dict) else {}


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _timestamp(value: object, *, field: str, errors: list[str]) -> datetime | None:
    if not isinstance(value, str):
        errors.append(f"LIVE_BASELINE_TIMESTAMP_INVALID: {field}")
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"LIVE_BASELINE_TIMESTAMP_INVALID: {field}")
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        errors.append(f"LIVE_BASELINE_TIMESTAMP_TIMEZONE_REQUIRED: {field}")
        return None
    return parsed.astimezone(UTC)


def _uri_digest(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return None
    matched = DIGEST_PATH_PATTERN.search(parsed.path)
    return matched.group(1) if matched is not None else None


def validate_live_baseline(
    baseline: JsonObject,
    schema: JsonObject,
    *,
    source_bytes: bytes,
    source_uri: str,
    signature_bundle_sha256: str,
    expected_environment: str,
    expected_signer_identity: str,
    expected_signer_issuer: str,
    maximum_age_seconds: int,
    now: datetime | None = None,
) -> JsonObject:
    """Validate baseline semantics after the exact signed bytes were verified."""
    errors: list[str] = []
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for error in sorted(validator.iter_errors(baseline), key=lambda item: list(item.path)):
        location = ".".join(str(part) for part in error.path) or "$"
        errors.append(f"LIVE_BASELINE_SCHEMA_INVALID: {location}: {error.message}")

    signer = _mapping(baseline.get("signer"))
    if baseline.get("environment") != expected_environment:
        errors.append("LIVE_BASELINE_ENVIRONMENT_MISMATCH")
    if signer.get("identity") != expected_signer_identity:
        errors.append("LIVE_BASELINE_SIGNER_IDENTITY_MISMATCH")
    if signer.get("issuer") != expected_signer_issuer:
        errors.append("LIVE_BASELINE_SIGNER_ISSUER_MISMATCH")
    if SHA256_PATTERN.fullmatch(signature_bundle_sha256) is None:
        errors.append("LIVE_BASELINE_SIGNATURE_BUNDLE_DIGEST_INVALID")

    source_sha256 = _sha256(source_bytes)
    try:
        canonical_source = (
            ArtifactContentSanitizer().sanitize(source_bytes, "application/json").content
        )
    except PlatformError:
        errors.append("LIVE_BASELINE_SIGNED_CONTENT_INVALID")
        canonical_source = b""
    if canonical_source != source_bytes:
        errors.append("LIVE_BASELINE_SIGNED_CONTENT_NOT_CANONICAL")
    if _uri_digest(source_uri) != source_sha256:
        errors.append("LIVE_BASELINE_SOURCE_URI_DIGEST_MISMATCH")

    raw_evidence = _mapping(baseline.get("raw_evidence"))
    if _uri_digest(raw_evidence.get("uri")) != raw_evidence.get("sha256"):
        errors.append("LIVE_BASELINE_RAW_EVIDENCE_DIGEST_URI_MISMATCH")

    current_time = (now or datetime.now(UTC)).astimezone(UTC)
    if maximum_age_seconds <= 0:
        errors.append("LIVE_BASELINE_MAXIMUM_AGE_INVALID")
    sampling = _mapping(baseline.get("sampling"))
    window_started_at = _timestamp(
        sampling.get("window_started_at"),
        field="sampling.window_started_at",
        errors=errors,
    )
    window_ended_at = _timestamp(
        sampling.get("window_ended_at"),
        field="sampling.window_ended_at",
        errors=errors,
    )
    issued_at = _timestamp(baseline.get("issued_at"), field="issued_at", errors=errors)
    expires_at = _timestamp(baseline.get("expires_at"), field="expires_at", errors=errors)
    if all(
        value is not None for value in (window_started_at, window_ended_at, issued_at, expires_at)
    ):
        assert window_started_at is not None
        assert window_ended_at is not None
        assert issued_at is not None
        assert expires_at is not None
        if not window_started_at < window_ended_at <= issued_at < expires_at:
            errors.append("LIVE_BASELINE_SAMPLING_TIMELINE_INVALID")
        oldest_allowed = current_time - timedelta(seconds=maximum_age_seconds)
        if window_ended_at < oldest_allowed or issued_at < oldest_allowed:
            errors.append("LIVE_BASELINE_STALE")
        future_tolerance = current_time + timedelta(minutes=5)
        if window_ended_at > future_tolerance or issued_at > future_tolerance:
            errors.append("LIVE_BASELINE_FROM_FUTURE")
        if expires_at <= current_time:
            errors.append("LIVE_BASELINE_EXPIRED")

    if errors:
        raise ValueError("\n".join(dict.fromkeys(errors)))

    return {
        "schema_version": "1.0",
        "kind": "live-baseline-validation",
        "environment": expected_environment,
        "baseline_uri": source_uri,
        "baseline_sha256": source_sha256,
        "signature_bundle_sha256": signature_bundle_sha256,
        "prior_release": _mapping(baseline["prior_release"]),
        "sampling": _mapping(baseline["sampling"]),
        "metrics": _mapping(baseline["metrics"]),
        "raw_evidence": raw_evidence,
        "signer": signer,
        "issued_at": baseline["issued_at"],
        "expires_at": baseline["expires_at"],
        "validated_at": current_time.isoformat(),
        "signature_verified": True,
        "validated": True,
    }


def verify_cosign_signature(
    *,
    evidence_path: Path,
    signature_bundle_path: Path,
    expected_signer_identity: str,
    expected_signer_issuer: str,
) -> str:
    """Verify the baseline bytes with keyless Cosign and return the bundle digest."""
    try:
        if evidence_path.stat().st_size > MAXIMUM_INPUT_BYTES:
            raise ValueError("LIVE_BASELINE_TOO_LARGE")
        bundle_bytes = signature_bundle_path.read_bytes()
    except OSError as exc:
        raise ValueError(
            f"LIVE_BASELINE_SIGNATURE_BUNDLE_READ_FAILED: {type(exc).__name__}"
        ) from exc
    if not bundle_bytes or len(bundle_bytes) > MAXIMUM_INPUT_BYTES:
        raise ValueError("LIVE_BASELINE_SIGNATURE_BUNDLE_SIZE_INVALID")
    try:
        bundle = json.loads(bundle_bytes)
    except json.JSONDecodeError as exc:
        raise ValueError("LIVE_BASELINE_SIGNATURE_BUNDLE_INVALID") from exc
    if not isinstance(bundle, dict):
        raise ValueError("LIVE_BASELINE_SIGNATURE_BUNDLE_INVALID")

    command = [
        "cosign",
        "verify-blob",
        "--bundle",
        str(signature_bundle_path),
        "--certificate-identity",
        expected_signer_identity,
        "--certificate-oidc-issuer",
        expected_signer_issuer,
        str(evidence_path),
    ]
    try:
        completed = subprocess.run(  # noqa: S603  # nosec B603
            command,
            check=False,
            shell=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"LIVE_BASELINE_SIGNATURE_VERIFIER_FAILED: {type(exc).__name__}") from exc
    if completed.returncode != 0:
        raise ValueError("LIVE_BASELINE_SIGNATURE_INVALID")
    return _sha256(bundle_bytes)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate a signed, content-addressed live release baseline"
    )
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--source-uri", required=True)
    parser.add_argument("--signature-bundle", type=Path, required=True)
    parser.add_argument("--expected-environment", required=True)
    parser.add_argument("--expected-signer-identity", required=True)
    parser.add_argument("--expected-signer-issuer", required=True)
    parser.add_argument("--maximum-age-seconds", type=int, default=604800)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.evidence.stat().st_size > MAXIMUM_INPUT_BYTES:
            raise ValueError("LIVE_BASELINE_TOO_LARGE")
        evidence_bytes = args.evidence.read_bytes()
        signature_bundle_sha256 = verify_cosign_signature(
            evidence_path=args.evidence,
            signature_bundle_path=args.signature_bundle,
            expected_signer_identity=args.expected_signer_identity,
            expected_signer_issuer=args.expected_signer_issuer,
        )
        report = validate_live_baseline(
            _load_object(args.evidence),
            _load_object(args.schema),
            source_bytes=evidence_bytes,
            source_uri=args.source_uri,
            signature_bundle_sha256=signature_bundle_sha256,
            expected_environment=args.expected_environment,
            expected_signer_identity=args.expected_signer_identity,
            expected_signer_issuer=args.expected_signer_issuer,
            maximum_age_seconds=args.maximum_age_seconds,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"live baseline validation failed:\n{exc}", file=sys.stderr)
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
