"""Build and validate a release evidence record from immutable repository manifests."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from deploy.ci.validate_external_release_preflight import (
    PreflightInputError,
    parse_requirements,
    verify_preflight_report,
)
from deploy.ci.validate_operational_readiness import (
    is_content_addressed_uri,
    validate_readiness,
)
from deploy.ci.validate_release_approvals import validate_approval_bundle
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from agent_platform.application.errors import PlatformError
from agent_platform.tools.production_catalog import (
    ProductionToolCatalog,
    load_production_tool_catalog,
)

PLATFORM_ROOT = Path(__file__).resolve().parents[1]
POLICY_VERSION_PATTERN = re.compile(r'^version\s*:=\s*"([^"]+)"\s*$', re.MULTILINE)
RUNTIME_BASE_IMAGE_PATTERNS = (
    re.compile(
        r"^ARG PYTHON_RUNTIME_IMAGE=[^@\s]+@(?P<digest>sha256:[0-9a-f]{64})$",
        re.MULTILINE,
    ),
    re.compile(
        r"^ARG PYTHON_BASE_IMAGE=[^@\s]+@(?P<digest>sha256:[0-9a-f]{64})$",
        re.MULTILINE,
    ),
)
PUBLISHED_EVIDENCE_URI_FIELDS = {
    "sbom": "sbom_uri",
    "provenance": "provenance_uri",
    "eval_results": "eval_results_uri",
    "candidate_manifest": "candidate_manifest_uri",
    "candidate_results": "candidate_results_uri",
    "human_review": "human_review_evidence_uri",
    "canary": "canary_evidence_uri",
    "canary_signature_bundle": "canary_signature_bundle_uri",
    "canary_validation": "canary_validation_uri",
    "staging_verification": "staging_verification_uri",
    "production_verification": "production_verification_uri",
    "foundation_attestation": "foundation_attestation_uri",
    "foundation_attestation_signature_bundle": "foundation_attestation_signature_bundle_uri",
    "foundation_attestation_validation": "foundation_attestation_validation_uri",
    "release_approvals": "approvals_bundle_uri",
    "release_approvals_signature_bundle": "release_approvals_signature_bundle_uri",
    "release_approvals_validation": "release_approvals_validation_uri",
    "external_release_preflight": "external_release_preflight_uri",
}
REQUIRED_PUBLISHED_EVIDENCE_ASSETS = frozenset(
    {
        *PUBLISHED_EVIDENCE_URI_FIELDS,
        "operational_readiness",
        "operational_readiness_validation",
        "deployment_approval",
        "production_observability",
    }
)


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _prompt_versions() -> dict[str, str]:
    manifest = _load_object(PLATFORM_ROOT / "prompts" / "manifest.json")
    prompts = manifest.get("prompts")
    if not isinstance(prompts, dict) or not prompts:
        raise ValueError("PROMPT_MANIFEST_EMPTY")
    versions: dict[str, str] = {}
    for role, raw_entry in prompts.items():
        if not isinstance(raw_entry, dict) or raw_entry.get("status") != "approved":
            raise ValueError(f"PROMPT_NOT_APPROVED: {role}")
        version = raw_entry.get("version")
        if not isinstance(version, str) or not version:
            raise ValueError(f"PROMPT_VERSION_MISSING: {role}")
        versions[str(role)] = version
    return versions


def _tool_versions(catalog: ProductionToolCatalog) -> dict[str, str]:
    versions = {definition.name: definition.version for definition in catalog.definitions}
    if not versions:
        raise ValueError("TOOL_REGISTRY_EMPTY")
    return versions


def _policy_bundle_version() -> str:
    source = (PLATFORM_ROOT / "policies" / "bundle.rego").read_text(encoding="utf-8")
    match = POLICY_VERSION_PATTERN.search(source)
    if match is None:
        raise ValueError("POLICY_BUNDLE_VERSION_MISSING")
    return match.group(1)


def _base_image_digest() -> str:
    source = (PLATFORM_ROOT / "deploy" / "docker" / "Dockerfile").read_text(encoding="utf-8")
    for pattern in RUNTIME_BASE_IMAGE_PATTERNS:
        if match := pattern.search(source):
            return match.group("digest")
    raise ValueError("BASE_IMAGE_DIGEST_NOT_PINNED")


def _alembic_head() -> str:
    revisions: set[str] = set()
    parent_revisions: set[str] = set()
    for path in sorted((PLATFORM_ROOT / "migrations" / "versions").glob("*.py")):
        source = path.read_text(encoding="utf-8")
        metadata: dict[str, object] = {}
        for node in ast.parse(source, filename=str(path)).body:
            target_name: str | None = None
            value_node: ast.expr | None = None
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name):
                    target_name = target.id
                    value_node = node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                target_name = node.target.id
                value_node = node.value
            if target_name in {"revision", "down_revision"} and value_node is not None:
                try:
                    metadata[target_name] = ast.literal_eval(value_node)
                except (ValueError, TypeError):
                    raise ValueError(f"ALEMBIC_REVISION_METADATA_INVALID: {path.name}") from None
        revision = metadata.get("revision")
        parents = metadata.get("down_revision")
        if not isinstance(revision, str) or not revision:
            raise ValueError(f"ALEMBIC_REVISION_METADATA_INVALID: {path.name}")
        if parents is None:
            normalized_parents: tuple[str, ...] = ()
        elif isinstance(parents, str) and parents:
            normalized_parents = (parents,)
        elif isinstance(parents, tuple) and all(
            isinstance(parent, str) and parent for parent in parents
        ):
            normalized_parents = parents
        else:
            raise ValueError(f"ALEMBIC_REVISION_METADATA_INVALID: {path.name}")
        if revision in revisions:
            raise ValueError(f"ALEMBIC_REVISION_DUPLICATED: {revision}")
        revisions.add(revision)
        parent_revisions.update(normalized_parents)
    heads = revisions - parent_revisions
    if len(heads) != 1:
        raise ValueError(f"ALEMBIC_HEAD_AMBIGUOUS: {sorted(heads)}")
    return next(iter(heads))


def _deployment_gate(path: Path, *, expected_environment: str) -> dict[str, Any]:
    gate = _load_object(path)
    if (
        gate.get("decision") != "approved"
        or gate.get("environment") != expected_environment
        or gate.get("actor_type") != "User"
    ):
        raise ValueError("PRODUCTION_ENVIRONMENT_APPROVAL_INVALID")
    return gate


def _timestamp(value: object, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"PUBLISHED_EVIDENCE_TIMESTAMP_INVALID: {field}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"PUBLISHED_EVIDENCE_TIMESTAMP_INVALID: {field}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"PUBLISHED_EVIDENCE_TIMESTAMP_TIMEZONE_REQUIRED: {field}")
    return parsed.astimezone(UTC)


def _published_evidence(args: argparse.Namespace) -> dict[str, Any]:
    receipt = _load_object(args.published_assets)
    publication_schema = _load_object(
        PLATFORM_ROOT / "deploy" / "ci" / "published-evidence-assets.schema.json"
    )
    Draft202012Validator(
        publication_schema,
        format_checker=FormatChecker(),
    ).validate(receipt)
    if receipt.get("kind") != "release-evidence-component":
        raise ValueError("PUBLISHED_EVIDENCE_KIND_MISMATCH")
    expected_identity = {
        "release_id": args.release_id,
        "git_sha": args.git_sha,
        "image_digest": args.image_digest,
    }
    for field, expected in expected_identity.items():
        if receipt.get(field) != expected:
            raise ValueError(f"PUBLISHED_EVIDENCE_IDENTITY_MISMATCH: {field}")
    assets = receipt.get("assets")
    if not isinstance(assets, dict):
        raise ValueError("PUBLISHED_EVIDENCE_ASSETS_INVALID")
    asset_names = set(assets)
    if asset_names != REQUIRED_PUBLISHED_EVIDENCE_ASSETS:
        missing = sorted(REQUIRED_PUBLISHED_EVIDENCE_ASSETS - asset_names)
        unexpected = sorted(asset_names - REQUIRED_PUBLISHED_EVIDENCE_ASSETS)
        raise ValueError(
            f"PUBLISHED_EVIDENCE_ASSET_SET_MISMATCH: missing={missing}, unexpected={unexpected}"
        )
    published_at = _timestamp(receipt.get("published_at"), field="published_at")
    now = datetime.now(UTC)
    if args.maximum_publication_age_seconds <= 0:
        raise ValueError("PUBLISHED_EVIDENCE_MAXIMUM_AGE_INVALID")
    if published_at > now + timedelta(minutes=5):
        raise ValueError("PUBLISHED_EVIDENCE_FROM_FUTURE")
    if now - published_at > timedelta(seconds=args.maximum_publication_age_seconds):
        raise ValueError("PUBLISHED_EVIDENCE_EXPIRED")
    minimum_retain_until = published_at + timedelta(days=args.minimum_evidence_retention_days)
    artifact_ids: set[str] = set()
    content_uris: set[str] = set()
    for name, raw_asset in assets.items():
        if not isinstance(raw_asset, dict):
            raise ValueError(f"PUBLISHED_EVIDENCE_ASSET_INVALID: {name}")
        artifact_id = str(raw_asset["artifact_id"])
        content_uri = str(raw_asset["content_uri"])
        digest = str(raw_asset["sha256"])
        if not content_uri.endswith(f"/content/{digest}"):
            raise ValueError(f"PUBLISHED_EVIDENCE_DIGEST_URI_MISMATCH: {name}")
        if raw_asset.get("release_binding") != expected_identity:
            raise ValueError(f"PUBLISHED_EVIDENCE_RELEASE_BINDING_MISMATCH: {name}")
        retention_policy = raw_asset.get("retention_policy")
        retention_match = (
            re.fullmatch(
                r"release-evidence@1:immutable:([0-9]{3,4})d",
                retention_policy,
            )
            if isinstance(retention_policy, str)
            else None
        )
        if (
            retention_match is None
            or int(retention_match.group(1)) < args.minimum_evidence_retention_days
        ):
            raise ValueError(f"PUBLISHED_EVIDENCE_RETENTION_POLICY_INVALID: {name}")
        retain_until = _timestamp(
            raw_asset.get("object_retain_until"),
            field=f"assets.{name}.object_retain_until",
        )
        expires_at = _timestamp(
            raw_asset.get("expires_at"),
            field=f"assets.{name}.expires_at",
        )
        if retain_until < minimum_retain_until:
            raise ValueError(f"PUBLISHED_EVIDENCE_RETENTION_TOO_SHORT: {name}")
        if expires_at < minimum_retain_until:
            raise ValueError(f"PUBLISHED_EVIDENCE_EXPIRY_TOO_SOON: {name}")
        if artifact_id in artifact_ids or content_uri in content_uris:
            raise ValueError(f"PUBLISHED_EVIDENCE_ASSET_REUSED: {name}")
        artifact_ids.add(artifact_id)
        content_uris.add(content_uri)
    return receipt


def _validate_external_release_preflight(
    args: argparse.Namespace,
    published_assets: dict[str, Any],
) -> None:
    source_bytes = args.external_release_preflight.read_bytes()
    report_value: object = json.loads(source_bytes)
    if not isinstance(report_value, dict):
        raise ValueError("EXTERNAL_RELEASE_PREFLIGHT_REPORT_INVALID")
    report = cast(dict[str, Any], report_value)
    requirements = parse_requirements(
        _load_object(PLATFORM_ROOT / "deploy" / "ci" / "external-release-preflight.json")
    )
    try:
        verified_report = verify_preflight_report(
            report,
            requirements,
            repository=args.repository,
            release_tag=args.release_tag,
            git_sha=args.git_sha,
            release_id=args.release_id,
        )
    except PreflightInputError as exc:
        raise ValueError(f"EXTERNAL_RELEASE_PREFLIGHT_REPORT_INVALID: {exc}") from exc
    if verified_report.get("passed") is not True:
        issues = json.dumps(
            verified_report.get("issues", []),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        raise ValueError(f"EXTERNAL_RELEASE_PREFLIGHT_VERIFICATION_FAILED: issues={issues}")
    source_sha256 = "sha256:" + hashlib.sha256(source_bytes).hexdigest()
    if published_assets["external_release_preflight"]["sha256"] != source_sha256:
        raise ValueError("EXTERNAL_RELEASE_PREFLIGHT_PUBLICATION_DIGEST_MISMATCH")


def _foundation_attestation_validation(
    args: argparse.Namespace,
    published_assets: dict[str, Any],
) -> dict[str, Any]:
    report = _load_object(args.foundation_attestation_validation)
    expected_identity = {
        "release_id": args.release_id,
        "git_sha": args.git_sha,
        "image_digest": args.image_digest,
    }
    for field, expected in expected_identity.items():
        if report.get(field) != expected:
            raise ValueError(f"FOUNDATION_ATTESTATION_VALIDATION_IDENTITY_MISMATCH: {field}")
    if report.get("validated") is not True or report.get("signature_verified") is not True:
        raise ValueError("FOUNDATION_ATTESTATION_VALIDATION_REQUIRED")
    if report.get("terraform_version") != "1.9.8":
        raise ValueError("FOUNDATION_ATTESTATION_TERRAFORM_VERSION_MISMATCH")
    if report.get("execution_mode") not in {
        "terraform-apply-readback",
        "cloud-api-read-only",
    }:
        raise ValueError("FOUNDATION_ATTESTATION_EXECUTION_MODE_INVALID")
    attestation_asset = published_assets["foundation_attestation"]
    signature_asset = published_assets["foundation_attestation_signature_bundle"]
    validation_asset = published_assets["foundation_attestation_validation"]
    if report.get("foundation_attestation_sha256") != attestation_asset["sha256"]:
        raise ValueError("FOUNDATION_ATTESTATION_PUBLICATION_DIGEST_MISMATCH")
    if report.get("signature_bundle_sha256") != signature_asset["sha256"]:
        raise ValueError("FOUNDATION_ATTESTATION_SIGNATURE_BUNDLE_DIGEST_MISMATCH")
    source_uri = report.get("source_uri")
    if not isinstance(source_uri, str) or not source_uri.endswith(
        "/" + attestation_asset["sha256"]
    ):
        raise ValueError("FOUNDATION_ATTESTATION_SOURCE_URI_MISMATCH")
    canonical_validation = json.dumps(
        report,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    validation_sha256 = "sha256:" + hashlib.sha256(canonical_validation).hexdigest()
    if validation_sha256 != validation_asset["sha256"]:
        raise ValueError("FOUNDATION_ATTESTATION_VALIDATION_PUBLICATION_DIGEST_MISMATCH")
    resource_ids = report.get("resource_ids")
    if not isinstance(resource_ids, dict) or set(resource_ids) != {
        "kubernetes",
        "postgres",
        "artifact_final",
        "artifact_staging",
        "temporal",
        "opa",
        "egress_policy",
        "secret_manager",
    }:
        raise ValueError("FOUNDATION_ATTESTATION_RESOURCE_SET_INVALID")
    approved_by = report.get("approved_by")
    if (
        not isinstance(approved_by, list)
        or len(approved_by) < 2
        or len(approved_by) != len(set(approved_by))
    ):
        raise ValueError("FOUNDATION_ATTESTATION_APPROVAL_SET_INVALID")
    validated_at = _timestamp(report.get("validated_at"), field="foundation.validated_at")
    now = datetime.now(UTC)
    if validated_at > now + timedelta(minutes=5):
        raise ValueError("FOUNDATION_ATTESTATION_VALIDATION_FROM_FUTURE")
    if now - validated_at > timedelta(seconds=args.maximum_publication_age_seconds):
        raise ValueError("FOUNDATION_ATTESTATION_VALIDATION_EXPIRED")
    return report


def _canary_validation(
    args: argparse.Namespace,
    published_assets: dict[str, Any],
) -> dict[str, Any]:
    validation_bytes = args.canary_validation.read_bytes()
    report = _load_object(args.canary_validation)
    expected_identity = {
        "release_id": args.release_id,
        "git_sha": args.git_sha,
        "image_digest": args.image_digest,
    }
    for field, expected in expected_identity.items():
        if report.get(field) != expected:
            raise ValueError(f"CANARY_VALIDATION_IDENTITY_MISMATCH: {field}")
    if report.get("validated") is not True:
        raise ValueError("CANARY_VALIDATION_REQUIRED")

    canary_asset = published_assets["canary"]
    signature_asset = published_assets["canary_signature_bundle"]
    validation_asset = published_assets["canary_validation"]
    if report.get("canary_evidence_sha256") != canary_asset["sha256"]:
        raise ValueError("CANARY_VALIDATION_EVIDENCE_DIGEST_MISMATCH")
    if report.get("signature_bundle_sha256") != signature_asset["sha256"]:
        raise ValueError("CANARY_VALIDATION_SIGNATURE_BUNDLE_DIGEST_MISMATCH")
    source_uri = report.get("source_uri")
    if not isinstance(source_uri, str) or not source_uri.endswith("/" + canary_asset["sha256"]):
        raise ValueError("CANARY_VALIDATION_SOURCE_URI_MISMATCH")
    validation_sha256 = "sha256:" + hashlib.sha256(validation_bytes).hexdigest()
    if validation_sha256 != validation_asset["sha256"]:
        raise ValueError("CANARY_VALIDATION_PUBLICATION_DIGEST_MISMATCH")
    return report


def _release_approvals_validation(
    args: argparse.Namespace,
    published_assets: dict[str, Any],
    approval_bundle: dict[str, Any],
    approval_schema: dict[str, Any],
) -> dict[str, Any]:
    approval_bytes = args.approvals_bundle.read_bytes()
    signature_bundle_bytes = args.approvals_signature_bundle.read_bytes()
    validation_bytes = args.approvals_validation.read_bytes()
    report = _load_object(args.approvals_validation)
    expected_identity = {
        "release_id": args.release_id,
        "git_sha": args.git_sha,
        "image_digest": args.image_digest,
    }
    for field, expected in expected_identity.items():
        if report.get(field) != expected:
            raise ValueError(f"RELEASE_APPROVAL_VALIDATION_IDENTITY_MISMATCH: {field}")
    if report.get("validated") is not True:
        raise ValueError("RELEASE_APPROVAL_VALIDATION_REQUIRED")
    if report.get("signer_identity") != args.approvals_signer_identity:
        raise ValueError("RELEASE_APPROVAL_VALIDATION_SIGNER_IDENTITY_MISMATCH")
    if report.get("signer_issuer") != args.approvals_signer_issuer:
        raise ValueError("RELEASE_APPROVAL_VALIDATION_SIGNER_ISSUER_MISMATCH")

    approval_asset = published_assets["release_approvals"]
    signature_asset = published_assets["release_approvals_signature_bundle"]
    validation_asset = published_assets["release_approvals_validation"]
    if report.get("release_approvals_sha256") != approval_asset["sha256"]:
        raise ValueError("RELEASE_APPROVAL_VALIDATION_SOURCE_DIGEST_MISMATCH")
    if report.get("signature_bundle_sha256") != signature_asset["sha256"]:
        raise ValueError("RELEASE_APPROVAL_VALIDATION_SIGNATURE_BUNDLE_DIGEST_MISMATCH")
    source_uri = report.get("source_uri")
    if not isinstance(source_uri, str) or not source_uri.endswith("/" + approval_asset["sha256"]):
        raise ValueError("RELEASE_APPROVAL_VALIDATION_SOURCE_URI_MISMATCH")

    approval_sha256 = "sha256:" + hashlib.sha256(approval_bytes).hexdigest()
    if approval_sha256 != approval_asset["sha256"]:
        raise ValueError("RELEASE_APPROVAL_PUBLICATION_DIGEST_MISMATCH")
    signature_sha256 = "sha256:" + hashlib.sha256(signature_bundle_bytes).hexdigest()
    if signature_sha256 != signature_asset["sha256"]:
        raise ValueError("RELEASE_APPROVAL_SIGNATURE_BUNDLE_PUBLICATION_DIGEST_MISMATCH")
    validation_sha256 = "sha256:" + hashlib.sha256(validation_bytes).hexdigest()
    if validation_sha256 != validation_asset["sha256"]:
        raise ValueError("RELEASE_APPROVAL_VALIDATION_PUBLICATION_DIGEST_MISMATCH")

    validated_at = _timestamp(report.get("validated_at"), field="approvals.validated_at")
    now = datetime.now(UTC)
    if validated_at > now + timedelta(minutes=5):
        raise ValueError("RELEASE_APPROVAL_VALIDATION_FROM_FUTURE")
    if now - validated_at > timedelta(seconds=args.maximum_publication_age_seconds):
        raise ValueError("RELEASE_APPROVAL_VALIDATION_EXPIRED")
    local_report = validate_approval_bundle(
        approval_bundle,
        approval_schema,
        expected_release_id=args.release_id,
        expected_git_sha=args.git_sha,
        expected_image_digest=args.image_digest,
        maximum_age_seconds=args.maximum_approval_age_seconds,
        source_bytes=approval_bytes,
        source_uri=source_uri,
        signature_bundle_bytes=signature_bundle_bytes,
        expected_signer_identity=args.approvals_signer_identity,
        expected_signer_issuer=args.approvals_signer_issuer,
        now=validated_at,
    )
    for field, expected in local_report.items():
        if report.get(field) != expected:
            raise ValueError(f"RELEASE_APPROVAL_VALIDATION_REPORT_MISMATCH: {field}")
    return report


def build_evidence(args: argparse.Namespace) -> dict[str, Any]:
    approval_bundle = _load_object(args.approvals_bundle)
    approval_schema = _load_object(
        PLATFORM_ROOT / "deploy" / "ci" / "release-approvals.schema.json"
    )
    deployment_gate = _deployment_gate(
        args.deployment_approval,
        expected_environment=getattr(
            args,
            "production_environment",
            "agent-platform-production",
        ),
    )
    published_evidence = _published_evidence(args)
    published_assets = published_evidence["assets"]
    _validate_external_release_preflight(args, published_assets)
    release_approvals_validation = _release_approvals_validation(
        args,
        published_assets,
        approval_bundle,
        approval_schema,
    )
    foundation_attestation_validation = _foundation_attestation_validation(
        args,
        published_assets,
    )
    canary_validation = _canary_validation(args, published_assets)
    readiness_bytes = args.operational_readiness.read_bytes()
    operational_readiness = _load_object(args.operational_readiness)
    base_image_digest = _base_image_digest()
    if operational_readiness["versions"]["base_image_digest"] != base_image_digest:
        raise ValueError("BASE_IMAGE_DIGEST_MISMATCH")
    if operational_readiness["versions"]["alembic_revision"] != _alembic_head():
        raise ValueError("ALEMBIC_REVISION_MISMATCH")
    readiness_schema = _load_object(
        PLATFORM_ROOT / "deploy" / "ci" / "operational-readiness.schema.json"
    )
    readiness_source_sha256 = "sha256:" + hashlib.sha256(readiness_bytes).hexdigest()
    local_readiness_validation = validate_readiness(
        operational_readiness,
        readiness_schema,
        expected_release_id=args.release_id,
        expected_git_sha=args.git_sha,
        expected_image_digest=args.image_digest,
        expected_signer_identity=args.operational_readiness_signer_identity,
        expected_signer_issuer=args.operational_readiness_signer_issuer,
        maximum_age_seconds=args.maximum_readiness_age_seconds,
        minimum_retention_days=args.minimum_evidence_retention_days,
        source_sha256=readiness_source_sha256,
    )
    readiness_validation_bytes = args.operational_readiness_validation.read_bytes()
    readiness_validation_sha256 = "sha256:" + hashlib.sha256(readiness_validation_bytes).hexdigest()
    readiness_validation = _load_object(args.operational_readiness_validation)
    readiness_asset = published_assets["operational_readiness"]
    if readiness_asset["sha256"] != readiness_source_sha256:
        raise ValueError("PUBLISHED_OPERATIONAL_READINESS_DIGEST_MISMATCH")
    readiness_validation_asset = published_assets["operational_readiness_validation"]
    for field, expected in local_readiness_validation.items():
        if readiness_validation.get(field) != expected:
            raise ValueError(f"OPERATIONAL_READINESS_VALIDATION_MISMATCH: {field}")
    expected_gate_reports = {
        gate_id: gate["report_sha256"] for gate_id, gate in operational_readiness["gates"].items()
    }
    if readiness_validation.get("gate_reports_validated") is not True:
        raise ValueError("OPERATIONAL_GATE_REPORT_VALIDATION_REQUIRED")
    if readiness_validation.get("gate_report_sha256") != expected_gate_reports:
        raise ValueError("OPERATIONAL_GATE_REPORT_VALIDATION_MISMATCH")
    gate_raw_evidence = readiness_validation.get("gate_raw_evidence")
    if not isinstance(gate_raw_evidence, dict) or set(gate_raw_evidence) != set(
        expected_gate_reports
    ):
        raise ValueError("OPERATIONAL_GATE_RAW_EVIDENCE_VALIDATION_REQUIRED")
    raw_digest_pattern = re.compile(r"^sha256:[0-9a-f]{64}$")
    for gate_id, raw_reference in gate_raw_evidence.items():
        if not isinstance(raw_reference, dict):
            raise ValueError(f"OPERATIONAL_GATE_RAW_EVIDENCE_REFERENCE_INVALID: {gate_id}")
        raw_uri = raw_reference.get("uri")
        raw_digest = raw_reference.get("sha256")
        if (
            not isinstance(raw_digest, str)
            or raw_digest_pattern.fullmatch(raw_digest) is None
            or not is_content_addressed_uri(raw_uri, raw_digest)
        ):
            raise ValueError(f"OPERATIONAL_GATE_RAW_EVIDENCE_REFERENCE_INVALID: {gate_id}")
    if readiness_validation_asset["sha256"] != readiness_validation_sha256:
        raise ValueError("PUBLISHED_OPERATIONAL_READINESS_VALIDATION_DIGEST_MISMATCH")
    evidence_store = operational_readiness["evidence_store"]
    if evidence_store["uri"] != args.operational_readiness_uri:
        raise ValueError("OPERATIONAL_READINESS_URI_MISMATCH")
    tool_catalog = load_production_tool_catalog(
        args.tool_catalog,
        expected_sha256=args.tool_catalog_sha256,
    )
    evidence = {
        "release_id": args.release_id,
        "git_sha": args.git_sha,
        "image_digest": args.image_digest,
        "evidence_publication": published_evidence,
        "external_release_preflight_uri": published_assets["external_release_preflight"][
            "content_uri"
        ],
        "sbom_uri": published_assets["sbom"]["content_uri"],
        "provenance_uri": published_assets["provenance"]["content_uri"],
        "foundation_attestation_uri": published_assets["foundation_attestation"]["content_uri"],
        "foundation_attestation_signature_bundle_uri": published_assets[
            "foundation_attestation_signature_bundle"
        ]["content_uri"],
        "foundation_attestation_validation_uri": published_assets[
            "foundation_attestation_validation"
        ]["content_uri"],
        "foundation_attestation_validation": foundation_attestation_validation,
        "base_image_digest": base_image_digest,
        "platform_versions": operational_readiness["versions"],
        "operational_readiness_uri": readiness_asset["content_uri"],
        "operational_readiness_sha256": readiness_source_sha256,
        "operational_readiness_validation_uri": readiness_validation_asset["content_uri"],
        "operational_readiness_validation_sha256": readiness_validation_sha256,
        "operational_readiness_validation": readiness_validation,
        "prompt_versions": _prompt_versions(),
        "tool_catalog_id": tool_catalog.catalog_id,
        "tool_catalog_digest": tool_catalog.digest,
        "tool_versions": _tool_versions(tool_catalog),
        "policy_bundle_version": _policy_bundle_version(),
        "eval_results_uri": published_assets["eval_results"]["content_uri"],
        "candidate_manifest_uri": published_assets["candidate_manifest"]["content_uri"],
        "candidate_results_uri": published_assets["candidate_results"]["content_uri"],
        "human_review_evidence_uri": published_assets["human_review"]["content_uri"],
        "canary_evidence_uri": published_assets["canary"]["content_uri"],
        "canary_signature_bundle_uri": published_assets["canary_signature_bundle"]["content_uri"],
        "canary_validation_uri": published_assets["canary_validation"]["content_uri"],
        "canary_validation": canary_validation,
        "staging_verification_uri": published_assets["staging_verification"]["content_uri"],
        "production_verification_uri": published_assets["production_verification"]["content_uri"],
        "approvals_bundle_uri": published_assets["release_approvals"]["content_uri"],
        "release_approvals_signature_bundle_uri": published_assets[
            "release_approvals_signature_bundle"
        ]["content_uri"],
        "release_approvals_validation_uri": published_assets["release_approvals_validation"][
            "content_uri"
        ],
        "release_approvals_validation": release_approvals_validation,
        "approvals": approval_bundle["approvals"],
        "deployment_gate": deployment_gate,
        "created_at": datetime.now(UTC).isoformat(),
    }
    schema = _load_object(PLATFORM_ROOT / "deploy" / "ci" / "release-evidence.schema.json")
    Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    ).validate(evidence)
    return evidence


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build Agent Platform release evidence")
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--git-sha", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--published-assets", required=True, type=Path)
    parser.add_argument("--external-release-preflight", required=True, type=Path)
    parser.add_argument("--foundation-attestation-validation", required=True, type=Path)
    parser.add_argument("--canary-validation", required=True, type=Path)
    parser.add_argument("--operational-readiness", required=True, type=Path)
    parser.add_argument("--operational-readiness-validation", required=True, type=Path)
    parser.add_argument("--operational-readiness-uri", required=True)
    parser.add_argument("--operational-readiness-signer-identity", required=True)
    parser.add_argument("--operational-readiness-signer-issuer", required=True)
    parser.add_argument("--maximum-readiness-age-seconds", type=int, default=86400)
    parser.add_argument("--minimum-evidence-retention-days", type=int, default=365)
    parser.add_argument("--maximum-publication-age-seconds", type=int, default=3600)
    parser.add_argument("--tool-catalog", required=True, type=Path)
    parser.add_argument("--tool-catalog-sha256", required=True)
    parser.add_argument("--approvals-bundle", required=True, type=Path)
    parser.add_argument("--approvals-signature-bundle", required=True, type=Path)
    parser.add_argument("--approvals-validation", required=True, type=Path)
    parser.add_argument("--approvals-signer-identity", required=True)
    parser.add_argument("--approvals-signer-issuer", required=True)
    parser.add_argument("--deployment-approval", required=True, type=Path)
    parser.add_argument(
        "--production-environment",
        default="agent-platform-production",
    )
    parser.add_argument(
        "--maximum-approval-age-seconds",
        type=int,
        default=604800,
    )
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        evidence = build_evidence(args)
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        ValidationError,
        PlatformError,
    ) as exc:
        print(f"release evidence failed: {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            evidence,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    print(json.dumps(evidence, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
