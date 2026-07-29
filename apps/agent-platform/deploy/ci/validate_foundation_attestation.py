"""Validate signed, content-addressed production foundation readback evidence."""

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

from jsonschema import Draft202012Validator, FormatChecker

from agent_platform.application.errors import PlatformError
from agent_platform.infrastructure.artifacts.sanitizer import ArtifactContentSanitizer

JsonObject = dict[str, Any]
DIGEST_URI_PATTERN = re.compile(r"/(sha256:[0-9a-f]{64})$")
REQUIRED_EGRESS_PROXIES = {
    "agent",
    "artifact-scan",
    "commit",
    "control",
    "delivery",
    "quota-redis",
    "retention",
}
REQUIRED_WORKLOAD_IDENTITIES = {
    "agent-worker",
    "api",
    "commit-worker",
    "migration",
    "outbox",
    "retention",
}
REQUIRED_SECRETS = {
    "action-payload-encryption",
    "agent-broker",
    "commit-broker",
    "database-api",
    "database-commit",
    "database-management",
    "database-migration",
    "database-outbox",
    "database-retention",
    "database-worker",
    "memory-encryption",
    "openai",
    "quota-redis",
    "webhook-signing",
}
REQUIRED_KMS_KEYS = {"action-payload", "artifact", "memory", "release-evidence"}


def _load_object(path: Path) -> JsonObject:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _timestamp(value: object, *, field: str, errors: list[str]) -> datetime | None:
    if not isinstance(value, str):
        errors.append(f"FOUNDATION_ATTESTATION_TIMESTAMP_INVALID: {field}")
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"FOUNDATION_ATTESTATION_TIMESTAMP_INVALID: {field}")
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        errors.append(f"FOUNDATION_ATTESTATION_TIMESTAMP_TIMEZONE_REQUIRED: {field}")
        return None
    return parsed.astimezone(UTC)


def _uri_digest(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    match = DIGEST_URI_PATTERN.search(value)
    return match.group(1) if match is not None else None


def _mapping(value: object) -> JsonObject:
    return value if isinstance(value, dict) else {}


def _provider_id_matches(provider: str, value: object) -> bool:
    if not isinstance(value, str):
        return False
    if provider == "aws":
        return value.startswith("arn:aws")
    if provider == "gcp":
        return value.startswith("//")
    if provider == "azure":
        return value.startswith("/subscriptions/")
    return False


def _validate_provider_resource_ids(evidence: JsonObject, errors: list[str]) -> None:
    provider = _mapping(evidence.get("provider"))
    provider_name = str(provider.get("name", ""))
    resources = _mapping(evidence.get("resources"))
    kubernetes = _mapping(resources.get("kubernetes"))
    postgres = _mapping(resources.get("postgres"))
    storage = _mapping(resources.get("artifact_storage"))
    final_bucket = _mapping(storage.get("final"))
    staging_bucket = _mapping(storage.get("staging"))
    egress = _mapping(resources.get("egress"))
    secrets = _mapping(resources.get("secrets"))
    required_provider_ids: list[tuple[str, object]] = [
        ("provider.account_resource_id", provider.get("account_resource_id")),
        ("resources.kubernetes.resource_id", kubernetes.get("resource_id")),
        ("resources.postgres.resource_id", postgres.get("resource_id")),
        ("resources.postgres.kms_key_id", postgres.get("kms_key_id")),
        ("resources.artifact_storage.final.resource_id", final_bucket.get("resource_id")),
        ("resources.artifact_storage.final.kms_key_id", final_bucket.get("kms_key_id")),
        ("resources.artifact_storage.staging.resource_id", staging_bucket.get("resource_id")),
        ("resources.artifact_storage.staging.kms_key_id", staging_bucket.get("kms_key_id")),
        ("resources.egress.policy_resource_id", egress.get("policy_resource_id")),
        ("resources.secrets.manager_resource_id", secrets.get("manager_resource_id")),
    ]
    for field, value in required_provider_ids:
        if not _provider_id_matches(provider_name, value):
            errors.append(f"FOUNDATION_ATTESTATION_PROVIDER_RESOURCE_ID_MISMATCH: {field}")
    for field in (
        "proxy_resource_ids",
        "workload_identity_resource_ids",
        "secret_resource_ids",
        "kms_key_resource_ids",
    ):
        container = egress if field == "proxy_resource_ids" else secrets
        for name, resource_id in _mapping(container.get(field)).items():
            if not _provider_id_matches(provider_name, resource_id):
                errors.append(
                    "FOUNDATION_ATTESTATION_PROVIDER_RESOURCE_ID_MISMATCH: "
                    f"resources.{'egress' if field == 'proxy_resource_ids' else 'secrets'}."
                    f"{field}.{name}"
                )


def _validate_resource_semantics(evidence: JsonObject, errors: list[str]) -> None:
    provider = _mapping(evidence.get("provider"))
    provider_regions = {
        str(region) for region in provider.get("regions", []) if isinstance(region, str)
    }
    resources = _mapping(evidence.get("resources"))
    storage = _mapping(resources.get("artifact_storage"))
    region_fields = {
        "kubernetes": _mapping(resources.get("kubernetes")).get("region"),
        "postgres": _mapping(resources.get("postgres")).get("region"),
        "artifact_storage.final": _mapping(storage.get("final")).get("region"),
        "artifact_storage.staging": _mapping(storage.get("staging")).get("region"),
        "secrets": _mapping(resources.get("secrets")).get("region"),
    }
    for field, region in region_fields.items():
        if region not in provider_regions:
            errors.append(f"FOUNDATION_ATTESTATION_REGION_OUT_OF_SCOPE: {field}")
    temporal_regions = _mapping(resources.get("temporal")).get("regions")
    if not isinstance(temporal_regions, list) or not set(temporal_regions).issubset(
        provider_regions
    ):
        errors.append("FOUNDATION_ATTESTATION_TEMPORAL_REGION_OUT_OF_SCOPE")

    postgres = _mapping(resources.get("postgres"))
    if _uri_digest(postgres.get("restore_test_evidence_uri")) != postgres.get(
        "restore_test_evidence_sha256"
    ):
        errors.append("FOUNDATION_ATTESTATION_RESTORE_TEST_DIGEST_URI_MISMATCH")
    opa = _mapping(resources.get("opa"))
    if _uri_digest(opa.get("bundle_uri")) != opa.get("bundle_digest"):
        errors.append("FOUNDATION_ATTESTATION_OPA_BUNDLE_DIGEST_URI_MISMATCH")

    egress = _mapping(resources.get("egress"))
    proxy_names = set(_mapping(egress.get("proxy_resource_ids")))
    missing_proxies = sorted(REQUIRED_EGRESS_PROXIES - proxy_names)
    if missing_proxies:
        errors.append(f"FOUNDATION_ATTESTATION_EGRESS_PROXIES_MISSING: {missing_proxies}")

    secrets = _mapping(resources.get("secrets"))
    required_sets = (
        (
            "WORKLOAD_IDENTITIES",
            REQUIRED_WORKLOAD_IDENTITIES,
            set(_mapping(secrets.get("workload_identity_resource_ids"))),
        ),
        ("SECRETS", REQUIRED_SECRETS, set(_mapping(secrets.get("secret_resource_ids")))),
        ("KMS_KEYS", REQUIRED_KMS_KEYS, set(_mapping(secrets.get("kms_key_resource_ids")))),
    )
    for label, required, actual in required_sets:
        missing = sorted(required - actual)
        if missing:
            errors.append(f"FOUNDATION_ATTESTATION_{label}_MISSING: {missing}")

    kms_ids = [
        str(postgres.get("kms_key_id", "")),
        str(_mapping(storage.get("final")).get("kms_key_id", "")),
        str(_mapping(storage.get("staging")).get("kms_key_id", "")),
        *(str(value) for value in _mapping(secrets.get("kms_key_resource_ids")).values()),
    ]
    if len(kms_ids) != len(set(kms_ids)):
        errors.append("FOUNDATION_ATTESTATION_KMS_KEYS_NOT_INDEPENDENT")


def validate_foundation_attestation(
    evidence: JsonObject,
    schema: JsonObject,
    *,
    source_bytes: bytes,
    source_uri: str,
    expected_release_id: str,
    expected_git_sha: str,
    expected_image_digest: str,
    expected_terraform_version: str,
    expected_signer_identity: str,
    expected_signer_issuer: str,
    maximum_age_seconds: int,
    now: datetime | None = None,
) -> JsonObject:
    """Validate content and cloud-resource semantics after cryptographic verification."""
    errors: list[str] = []
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for error in sorted(validator.iter_errors(evidence), key=lambda item: list(item.path)):
        location = ".".join(str(part) for part in error.path) or "$"
        errors.append(f"FOUNDATION_ATTESTATION_SCHEMA_INVALID: {location}: {error.message}")

    expected_identity = {
        "release_id": expected_release_id,
        "git_sha": expected_git_sha,
        "image_digest": expected_image_digest,
    }
    for field, expected in expected_identity.items():
        if evidence.get(field) != expected:
            errors.append(f"FOUNDATION_ATTESTATION_{field.upper()}_MISMATCH")

    terraform = _mapping(evidence.get("terraform"))
    execution = _mapping(evidence.get("execution"))
    signer = _mapping(evidence.get("signer"))
    if terraform.get("version") != expected_terraform_version:
        errors.append("FOUNDATION_ATTESTATION_TERRAFORM_VERSION_MISMATCH")
    if signer.get("identity") != expected_signer_identity:
        errors.append("FOUNDATION_ATTESTATION_SIGNER_IDENTITY_MISMATCH")
    if signer.get("issuer") != expected_signer_issuer:
        errors.append("FOUNDATION_ATTESTATION_SIGNER_ISSUER_MISMATCH")

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
        errors.append("FOUNDATION_ATTESTATION_SIGNED_CONTENT_INVALID")
        canonical_source = b""
    if canonical_source != source_bytes:
        errors.append("FOUNDATION_ATTESTATION_SIGNED_CONTENT_NOT_CANONICAL")
    if not source_uri.startswith("https://"):
        errors.append("FOUNDATION_ATTESTATION_SOURCE_URI_INVALID")
    if _uri_digest(source_uri) != source_sha256:
        errors.append("FOUNDATION_ATTESTATION_SOURCE_URI_DIGEST_MISMATCH")
    if _uri_digest(terraform.get("plan_uri")) != terraform.get("plan_sha256"):
        errors.append("FOUNDATION_ATTESTATION_PLAN_DIGEST_URI_MISMATCH")
    if _uri_digest(execution.get("evidence_uri")) != execution.get("evidence_sha256"):
        errors.append("FOUNDATION_ATTESTATION_EXECUTION_DIGEST_URI_MISMATCH")
    if _uri_digest(execution.get("resource_readback_uri")) != execution.get(
        "resource_readback_sha256"
    ):
        errors.append("FOUNDATION_ATTESTATION_READBACK_DIGEST_URI_MISMATCH")
    if execution.get("mode") == "terraform-apply-readback":
        if execution.get("applied_plan_sha256") != terraform.get("plan_sha256"):
            errors.append("FOUNDATION_ATTESTATION_APPLIED_PLAN_MISMATCH")
        if (
            execution.get("tool") != "terraform"
            or execution.get("tool_version") != expected_terraform_version
        ):
            errors.append("FOUNDATION_ATTESTATION_EXECUTION_TERRAFORM_VERSION_MISMATCH")

    current_time = (now or datetime.now(UTC)).astimezone(UTC)
    if maximum_age_seconds <= 0:
        errors.append("FOUNDATION_ATTESTATION_MAXIMUM_AGE_INVALID")
    attested_at = _timestamp(evidence.get("attested_at"), field="attested_at", errors=errors)
    plan_generated_at = _timestamp(
        terraform.get("generated_at"),
        field="terraform.generated_at",
        errors=errors,
    )
    completed_at = _timestamp(
        execution.get("completed_at"),
        field="execution.completed_at",
        errors=errors,
    )
    oldest_allowed = current_time - timedelta(seconds=maximum_age_seconds)
    if attested_at is not None:
        if attested_at < oldest_allowed:
            errors.append("FOUNDATION_ATTESTATION_EXPIRED")
        if attested_at > current_time + timedelta(minutes=5):
            errors.append("FOUNDATION_ATTESTATION_FROM_FUTURE")
    if (
        plan_generated_at is not None
        and completed_at is not None
        and attested_at is not None
        and not plan_generated_at <= completed_at <= attested_at
    ):
        errors.append("FOUNDATION_ATTESTATION_EXECUTION_TIMELINE_INVALID")

    approvals = evidence.get("approvals")
    approval_rows = approvals if isinstance(approvals, list) else []
    actors: list[str] = []
    roles: set[str] = set()
    for index, raw_approval in enumerate(approval_rows):
        approval = _mapping(raw_approval)
        actor = str(approval.get("actor", ""))
        role = str(approval.get("role", ""))
        actors.append(actor)
        roles.add(role)
        for field, expected in expected_identity.items():
            if approval.get(field) != expected:
                errors.append(f"FOUNDATION_ATTESTATION_APPROVAL_{field.upper()}_MISMATCH: {index}")
        approved_at = _timestamp(
            approval.get("approved_at"),
            field=f"approvals.{index}.approved_at",
            errors=errors,
        )
        if approved_at is not None and attested_at is not None:
            if approved_at < oldest_allowed:
                errors.append(f"FOUNDATION_ATTESTATION_APPROVAL_EXPIRED: {index}")
            if approved_at > attested_at + timedelta(minutes=5):
                errors.append(f"FOUNDATION_ATTESTATION_APPROVAL_FROM_FUTURE: {index}")
    if len(actors) != len(set(actors)):
        errors.append("FOUNDATION_ATTESTATION_APPROVERS_NOT_UNIQUE")
    if "infrastructure-owner" not in roles or not roles.intersection({"security", "sre"}):
        errors.append("FOUNDATION_ATTESTATION_INDEPENDENT_APPROVALS_REQUIRED")

    _validate_provider_resource_ids(evidence, errors)
    _validate_resource_semantics(evidence, errors)
    resources = _mapping(evidence.get("resources"))
    postgres = _mapping(resources.get("postgres"))
    restore_tested_at = _timestamp(
        postgres.get("restore_tested_at"),
        field="resources.postgres.restore_tested_at",
        errors=errors,
    )
    if restore_tested_at is not None:
        if restore_tested_at < current_time - timedelta(days=90):
            errors.append("FOUNDATION_ATTESTATION_RESTORE_TEST_EXPIRED")
        if restore_tested_at > current_time + timedelta(minutes=5):
            errors.append("FOUNDATION_ATTESTATION_RESTORE_TEST_FROM_FUTURE")

    if errors:
        raise ValueError("\n".join(dict.fromkeys(errors)))

    storage = _mapping(resources["artifact_storage"])
    return {
        "schema_version": "1.0",
        **expected_identity,
        "source_uri": source_uri,
        "foundation_attestation_sha256": source_sha256,
        "terraform_version": expected_terraform_version,
        "execution_mode": execution["mode"],
        "provider": _mapping(evidence["provider"])["name"],
        "provider_regions": _mapping(evidence["provider"])["regions"],
        "resource_ids": {
            "kubernetes": _mapping(resources["kubernetes"])["resource_id"],
            "postgres": postgres["resource_id"],
            "artifact_final": _mapping(storage["final"])["resource_id"],
            "artifact_staging": _mapping(storage["staging"])["resource_id"],
            "temporal": _mapping(resources["temporal"])["resource_id"],
            "opa": _mapping(resources["opa"])["resource_id"],
            "egress_policy": _mapping(resources["egress"])["policy_resource_id"],
            "secret_manager": _mapping(resources["secrets"])["manager_resource_id"],
        },
        "approved_by": sorted(actors),
        "attested_at": evidence["attested_at"],
        "validated_at": current_time.isoformat(),
        "validated": True,
    }


def verify_cosign_signature(
    *,
    evidence_path: Path,
    signature_bundle_path: Path,
    expected_signer_identity: str,
    expected_signer_issuer: str,
) -> str:
    """Run keyless cosign verification without a shell and return governed bundle digest."""
    maximum_bytes = 2 * 1024 * 1024
    try:
        if evidence_path.stat().st_size > maximum_bytes:
            raise ValueError("FOUNDATION_ATTESTATION_TOO_LARGE")
        bundle_bytes = signature_bundle_path.read_bytes()
    except OSError as exc:
        raise ValueError(
            f"FOUNDATION_ATTESTATION_SIGNATURE_BUNDLE_READ_FAILED: {type(exc).__name__}"
        ) from exc
    if not bundle_bytes or len(bundle_bytes) > maximum_bytes:
        raise ValueError("FOUNDATION_ATTESTATION_SIGNATURE_BUNDLE_SIZE_INVALID")
    try:
        canonical_bundle = (
            ArtifactContentSanitizer()
            .sanitize(
                bundle_bytes,
                "application/json",
            )
            .content
        )
    except PlatformError as exc:
        raise ValueError("FOUNDATION_ATTESTATION_SIGNATURE_BUNDLE_INVALID") from exc
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
        # The executable and subcommand are fixed; remaining values are argv, never shell text.
        completed = subprocess.run(  # noqa: S603  # nosec B603
            command,
            check=False,
            shell=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(
            f"FOUNDATION_ATTESTATION_SIGNATURE_VERIFIER_FAILED: {type(exc).__name__}"
        ) from exc
    if completed.returncode != 0:
        raise ValueError("FOUNDATION_ATTESTATION_SIGNATURE_INVALID")
    return "sha256:" + hashlib.sha256(canonical_bundle).hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate signed production foundation attestation"
    )
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--source-uri", required=True)
    parser.add_argument("--signature-bundle", type=Path, required=True)
    parser.add_argument("--expected-release-id", required=True)
    parser.add_argument("--expected-git-sha", required=True)
    parser.add_argument("--expected-image-digest", required=True)
    parser.add_argument("--expected-terraform-version", required=True)
    parser.add_argument("--expected-signer-identity", required=True)
    parser.add_argument("--expected-signer-issuer", required=True)
    parser.add_argument("--maximum-age-seconds", type=int, default=86400)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.evidence.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("FOUNDATION_ATTESTATION_TOO_LARGE")
        evidence_bytes = args.evidence.read_bytes()
        signature_bundle_sha256 = verify_cosign_signature(
            evidence_path=args.evidence,
            signature_bundle_path=args.signature_bundle,
            expected_signer_identity=args.expected_signer_identity,
            expected_signer_issuer=args.expected_signer_issuer,
        )
        report = validate_foundation_attestation(
            _load_object(args.evidence),
            _load_object(args.schema),
            source_bytes=evidence_bytes,
            source_uri=args.source_uri,
            expected_release_id=args.expected_release_id,
            expected_git_sha=args.expected_git_sha,
            expected_image_digest=args.expected_image_digest,
            expected_terraform_version=args.expected_terraform_version,
            expected_signer_identity=args.expected_signer_identity,
            expected_signer_issuer=args.expected_signer_issuer,
            maximum_age_seconds=args.maximum_age_seconds,
        )
        report["signature_bundle_sha256"] = signature_bundle_sha256
        report["signer_identity"] = args.expected_signer_identity
        report["signer_issuer"] = args.expected_signer_issuer
        report["signature_verified"] = True
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"foundation attestation validation failed:\n{exc}", file=sys.stderr)
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
