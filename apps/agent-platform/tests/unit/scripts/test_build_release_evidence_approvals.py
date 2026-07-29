from __future__ import annotations

import hashlib
import json
from argparse import Namespace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

import pytest
from deploy.ci.validate_foundation_attestation import validate_foundation_attestation
from deploy.ci.validate_operational_readiness import validate_readiness
from deploy.ci.validate_release_approvals import validate_approval_bundle
from scripts.build_release_evidence import build_evidence
from tests.e2e.release_assets.test_foundation_attestation_validator import (
    SIGNER_IDENTITY as FOUNDATION_SIGNER_IDENTITY,
)
from tests.e2e.release_assets.test_foundation_attestation_validator import (
    SIGNER_ISSUER as FOUNDATION_SIGNER_ISSUER,
)
from tests.e2e.release_assets.test_foundation_attestation_validator import (
    foundation_attestation,
)
from tests.e2e.release_assets.test_operational_readiness_validator import (
    readiness_evidence,
)
from tests.e2e.release_assets.test_release_approval_validator import (
    GIT_SHA,
    IMAGE_DIGEST,
    RELEASE_ID,
    approval_bundle,
)
from tests.e2e.release_assets.test_release_approval_validator import (
    SIGNATURE_BUNDLE_BYTES as APPROVAL_SIGNATURE_BUNDLE_BYTES,
)
from tests.e2e.release_assets.test_release_approval_validator import (
    SIGNER_IDENTITY as APPROVAL_SIGNER_IDENTITY,
)
from tests.e2e.release_assets.test_release_approval_validator import (
    SIGNER_ISSUER as APPROVAL_SIGNER_ISSUER,
)

PUBLISHED_ASSET_NAMES = (
    "sbom",
    "provenance",
    "eval_results",
    "candidate_manifest",
    "candidate_results",
    "human_review",
    "canary",
    "canary_signature_bundle",
    "canary_validation",
    "staging_verification",
    "production_verification",
    "foundation_attestation",
    "foundation_attestation_signature_bundle",
    "foundation_attestation_validation",
    "operational_readiness",
    "operational_readiness_validation",
    "release_approvals",
    "release_approvals_signature_bundle",
    "release_approvals_validation",
    "deployment_approval",
    "production_observability",
    "external_release_preflight",
)
REPOSITORY = "example/platform"
RELEASE_TAG = "agent-platform-v1.0.0"
RELEASE_ENVIRONMENTS = (
    "agent-platform-staging",
    "agent-platform-production-canary",
    "agent-platform-production",
)


def _published_assets_receipt(
    path: Path,
    *,
    digest_overrides: dict[str, str] | None = None,
) -> Path:
    published_at = datetime.now(UTC)
    retain_until = (published_at + timedelta(days=366)).isoformat()
    assets: dict[str, object] = {}
    for name in PUBLISHED_ASSET_NAMES:
        artifact_id = uuid5(NAMESPACE_URL, f"agent-platform-evidence:{name}")
        digest = (digest_overrides or {}).get(
            name,
            hashlib.sha256(name.encode()).hexdigest(),
        )
        assets[name] = {
            "artifact_id": str(artifact_id),
            "content_uri": (
                f"https://artifacts.example.test/v1/artifacts/{artifact_id}/content/sha256:{digest}"
            ),
            "sha256": f"sha256:{digest}",
            "size_bytes": 100,
            "classification": "restricted",
            "release_binding": {
                "release_id": RELEASE_ID,
                "git_sha": GIT_SHA,
                "image_digest": IMAGE_DIGEST,
            },
            "retention_policy": "release-evidence@1:immutable:365d",
            "scan_status": "malware_clean",
            "object_version_id": f"version-{name}",
            "object_retain_until": retain_until,
            "legal_hold_status": "none",
            "expires_at": retain_until,
            "readback_verified": True,
        }
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "kind": "release-evidence-component",
                "release_id": RELEASE_ID,
                "git_sha": GIT_SHA,
                "image_digest": IMAGE_DIGEST,
                "assets": assets,
                "published_at": published_at.isoformat(),
                "verified": True,
            }
        ),
        encoding="utf-8",
    )
    return path


def _arguments(tmp_path: Path, *, approvals: dict[str, object] | None = None) -> Namespace:
    tool_catalog = (
        Path(__file__).resolve().parents[3] / "deploy" / "catalogs" / "tool-catalog.v1.json"
    )
    foundation = foundation_attestation()
    foundation_binding = {
        "release_id": RELEASE_ID,
        "git_sha": GIT_SHA,
        "image_digest": IMAGE_DIGEST,
    }
    foundation.update(foundation_binding)
    for foundation_approval in foundation["approvals"]:
        foundation_approval.update(foundation_binding)
    foundation_payload = json.dumps(
        foundation,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    foundation_digest = hashlib.sha256(foundation_payload).hexdigest()
    foundation_path = tmp_path / "foundation-attestation.json"
    foundation_path.write_bytes(foundation_payload)
    foundation_schema = json.loads(
        (
            Path(__file__).resolve().parents[3]
            / "deploy"
            / "ci"
            / "foundation-attestation.schema.json"
        ).read_text(encoding="utf-8")
    )
    foundation_source_uri = "https://foundation.example.test/immutable/sha256:" + foundation_digest
    foundation_validation = validate_foundation_attestation(
        foundation,
        foundation_schema,
        source_bytes=foundation_payload,
        source_uri=foundation_source_uri,
        expected_release_id=RELEASE_ID,
        expected_git_sha=GIT_SHA,
        expected_image_digest=IMAGE_DIGEST,
        expected_terraform_version="1.9.8",
        expected_signer_identity=FOUNDATION_SIGNER_IDENTITY,
        expected_signer_issuer=FOUNDATION_SIGNER_ISSUER,
        maximum_age_seconds=86400,
    )
    signature_bundle_payload = b'{"bundle":"verified-test-fixture"}'
    signature_bundle_digest = hashlib.sha256(signature_bundle_payload).hexdigest()
    foundation_validation.update(
        {
            "signature_bundle_sha256": "sha256:" + signature_bundle_digest,
            "signer_identity": FOUNDATION_SIGNER_IDENTITY,
            "signer_issuer": FOUNDATION_SIGNER_ISSUER,
            "signature_verified": True,
        }
    )
    foundation_validation_payload = json.dumps(
        foundation_validation,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    foundation_validation_path = tmp_path / "foundation-attestation-validation.json"
    foundation_validation_path.write_bytes(foundation_validation_payload)
    canary_digest = hashlib.sha256(b"canary").hexdigest()
    canary_signature_bundle_digest = hashlib.sha256(b"canary_signature_bundle").hexdigest()
    canary_validation = {
        "schema_version": "1.1",
        "release_id": RELEASE_ID,
        "git_sha": GIT_SHA,
        "image_digest": IMAGE_DIGEST,
        "source_uri": f"https://rollouts.example.test/evidence/sha256:{canary_digest}",
        "canary_evidence_sha256": f"sha256:{canary_digest}",
        "signature_bundle_sha256": f"sha256:{canary_signature_bundle_digest}",
        "policy_version": "1.1",
        "policy_sha256": f"sha256:{'c' * 64}",
        "controller_rollout_id": "controller-rollout-123",
        "rollback_owner_actor": "production-rollback-owner",
        "signer_identity": (
            "https://github.com/example/release-controller/"
            ".github/workflows/canary.yml@refs/heads/main"
        ),
        "signer_issuer": "https://token.actions.githubusercontent.com",
        "validated_phase_ids": ["1%", "10%", "50%", "100%"],
        "metric_snapshot_sha256": {
            phase: f"sha256:{index:064x}"
            for index, phase in enumerate(("1%", "10%", "50%", "100%"), start=1)
        },
        "observed_duration_seconds": 60300,
        "validated_at": datetime.now(UTC).isoformat(),
        "validated": True,
    }
    canary_validation_payload = (
        json.dumps(canary_validation, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode()
    canary_validation_path = tmp_path / "canary-validation.json"
    canary_validation_path.write_bytes(canary_validation_payload)
    approval_data = approvals or approval_bundle()
    approval_payload = json.dumps(
        approval_data,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    approval_digest = hashlib.sha256(approval_payload).hexdigest()
    approvals_path = tmp_path / "release-approvals.json"
    approvals_path.write_bytes(approval_payload)
    approvals_signature_bundle_path = tmp_path / "release-approvals.json.sigstore.json"
    approvals_signature_bundle_path.write_bytes(APPROVAL_SIGNATURE_BUNDLE_BYTES)
    approval_signature_bundle_digest = hashlib.sha256(APPROVAL_SIGNATURE_BUNDLE_BYTES).hexdigest()
    approval_source_uri = "https://approvals.example.test/releases/sha256:" + approval_digest
    approval_schema = json.loads(
        (
            Path(__file__).resolve().parents[3] / "deploy" / "ci" / "release-approvals.schema.json"
        ).read_text(encoding="utf-8")
    )
    approval_validation = validate_approval_bundle(
        approval_data,
        approval_schema,
        expected_release_id=RELEASE_ID,
        expected_git_sha=GIT_SHA,
        expected_image_digest=IMAGE_DIGEST,
        maximum_age_seconds=604800,
        source_bytes=approval_payload,
        source_uri=approval_source_uri,
        signature_bundle_bytes=APPROVAL_SIGNATURE_BUNDLE_BYTES,
        expected_signer_identity=APPROVAL_SIGNER_IDENTITY,
        expected_signer_issuer=APPROVAL_SIGNER_ISSUER,
    )
    approval_validation_payload = (
        json.dumps(
            approval_validation,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode()
    approvals_validation_path = tmp_path / "release-approvals-validation.json"
    approvals_validation_path.write_bytes(approval_validation_payload)
    published_assets = _published_assets_receipt(
        tmp_path / "published-assets.json",
        digest_overrides={
            "foundation_attestation": foundation_digest,
            "foundation_attestation_signature_bundle": signature_bundle_digest,
            "foundation_attestation_validation": hashlib.sha256(
                foundation_validation_payload
            ).hexdigest(),
            "canary": canary_digest,
            "canary_signature_bundle": canary_signature_bundle_digest,
            "canary_validation": hashlib.sha256(canary_validation_payload).hexdigest(),
            "release_approvals": approval_digest,
            "release_approvals_signature_bundle": approval_signature_bundle_digest,
            "release_approvals_validation": hashlib.sha256(approval_validation_payload).hexdigest(),
        },
    )
    deployment_approval_path = tmp_path / "deployment-approval.json"
    deployment_approval_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "actor": "production-environment-reviewer",
                "actor_type": "User",
                "role": "github-environment-reviewer",
                "decision": "approved",
                "environment": "agent-platform-production",
                "comment": "Promote.",
                "recorded_at": datetime.now(UTC).isoformat(),
                "source_uri": (
                    "https://api.github.com/repos/example/platform/actions/runs/123/approvals"
                ),
            }
        ),
        encoding="utf-8",
    )
    readiness = readiness_evidence()
    for gate in readiness["gates"].values():
        gate["evidence_uri"] = "https://evidence.example.test/gates/" + gate["report_sha256"]
    readiness_path = tmp_path / "operational-readiness.json"
    readiness_path.write_text(json.dumps(readiness), encoding="utf-8")
    readiness_schema = json.loads(
        (
            Path(__file__).resolve().parents[3]
            / "deploy"
            / "ci"
            / "operational-readiness.schema.json"
        ).read_text(encoding="utf-8")
    )
    readiness_validation = validate_readiness(
        readiness,
        readiness_schema,
        expected_release_id=RELEASE_ID,
        expected_git_sha=GIT_SHA,
        expected_image_digest=IMAGE_DIGEST,
        expected_signer_identity=readiness["evidence_store"]["signer_identity"],
        expected_signer_issuer=readiness["evidence_store"]["signer_issuer"],
        maximum_age_seconds=86400,
        minimum_retention_days=365,
        source_sha256=("sha256:" + hashlib.sha256(readiness_path.read_bytes()).hexdigest()),
    )
    readiness_validation["gate_report_sha256"] = {
        gate_id: gate["report_sha256"] for gate_id, gate in readiness["gates"].items()
    }
    readiness_validation["gate_raw_evidence"] = {}
    for gate_id in readiness["gates"]:
        raw_digest = hashlib.sha256(f"raw:{gate_id}".encode()).hexdigest()
        readiness_validation["gate_raw_evidence"][gate_id] = {
            "uri": f"https://evidence.example.test/raw/{gate_id}/sha256:{raw_digest}",
            "sha256": f"sha256:{raw_digest}",
        }
    readiness_validation["gate_reports_validated"] = True
    readiness_validation_path = tmp_path / "operational-readiness-validation.json"
    readiness_validation_path.write_text(
        json.dumps(readiness_validation),
        encoding="utf-8",
    )
    external_release_preflight = {
        "schema_version": "1.0",
        "passed": True,
        "repository": REPOSITORY,
        "default_branch": "main",
        "release_tag": RELEASE_TAG,
        "git_sha": GIT_SHA,
        "release_id": RELEASE_ID,
        "validated_at": datetime.now(UTC).isoformat(),
        "operational_failure": False,
        "main_protection_source": "ruleset",
        "validated_environments": list(RELEASE_ENVIRONMENTS),
        "checks": [
            {"id": "repository-and-release-identity", "passed": True},
            {"id": "main-branch-protection", "passed": True, "source": "ruleset"},
            *(
                {"id": f"environment:{environment}", "passed": True}
                for environment in RELEASE_ENVIRONMENTS
            ),
        ],
        "issues": [],
        "secret_values_accessed": False,
    }
    external_release_preflight_payload = json.dumps(
        external_release_preflight,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    external_release_preflight_path = tmp_path / "external-release-preflight.json"
    external_release_preflight_path.write_bytes(external_release_preflight_payload)
    publication_receipt = json.loads(published_assets.read_text(encoding="utf-8"))
    for asset_name, source_path in (
        ("operational_readiness", readiness_path),
        ("operational_readiness_validation", readiness_validation_path),
        ("external_release_preflight", external_release_preflight_path),
    ):
        digest = "sha256:" + hashlib.sha256(source_path.read_bytes()).hexdigest()
        asset = publication_receipt["assets"][asset_name]
        asset["sha256"] = digest
        asset["content_uri"] = (
            f"https://artifacts.example.test/v1/artifacts/{asset['artifact_id']}/content/{digest}"
        )
    published_assets.write_text(json.dumps(publication_receipt), encoding="utf-8")
    return Namespace(
        release_id=RELEASE_ID,
        git_sha=GIT_SHA,
        image_digest=IMAGE_DIGEST,
        repository=REPOSITORY,
        release_tag=RELEASE_TAG,
        published_assets=published_assets,
        external_release_preflight=external_release_preflight_path,
        foundation_attestation_validation=foundation_validation_path,
        canary_validation=canary_validation_path,
        maximum_publication_age_seconds=3600,
        sbom_uri="https://github.example.test/evidence/sbom",
        provenance_uri="https://github.example.test/evidence/provenance",
        operational_readiness=readiness_path,
        operational_readiness_validation=readiness_validation_path,
        operational_readiness_uri=readiness["evidence_store"]["uri"],
        operational_readiness_signer_identity=readiness["evidence_store"]["signer_identity"],
        operational_readiness_signer_issuer=readiness["evidence_store"]["signer_issuer"],
        maximum_readiness_age_seconds=86400,
        minimum_evidence_retention_days=365,
        eval_results_uri="https://github.example.test/evidence/live-evals",
        candidate_manifest_uri="https://github.example.test/evidence/candidate-manifest",
        candidate_results_uri="https://github.example.test/evidence/candidate-results",
        human_review_evidence_uri="https://github.example.test/evidence/human-review",
        canary_evidence_uri="https://github.example.test/evidence/canary",
        staging_verification_uri="https://github.example.test/evidence/staging",
        production_verification_uri="https://github.example.test/evidence/production",
        tool_catalog=tool_catalog,
        tool_catalog_sha256=("sha256:" + hashlib.sha256(tool_catalog.read_bytes()).hexdigest()),
        approvals_bundle=approvals_path,
        approvals_signature_bundle=approvals_signature_bundle_path,
        approvals_validation=approvals_validation_path,
        approvals_signer_identity=APPROVAL_SIGNER_IDENTITY,
        approvals_signer_issuer=APPROVAL_SIGNER_ISSUER,
        deployment_approval=deployment_approval_path,
        maximum_approval_age_seconds=604800,
    )


def test_release_evidence_embeds_all_independent_approvals(tmp_path: Path) -> None:
    evidence = build_evidence(_arguments(tmp_path))

    assert evidence["release_id"] == RELEASE_ID
    assert {approval["role"] for approval in evidence["approvals"]} == {
        "security",
        "business",
        "sre",
        "data-system-owner",
    }
    assert evidence["approvals_bundle_uri"].startswith("https://")
    assert evidence["deployment_gate"]["environment"] == "agent-platform-production"


def test_release_evidence_rejects_stale_external_approval_bundle(tmp_path: Path) -> None:
    stale = approval_bundle(approved_at=datetime.now(UTC) - timedelta(days=8))

    with pytest.raises(ValueError, match="RELEASE_APPROVAL_EXPIRED"):
        build_evidence(_arguments(tmp_path, approvals=stale))
