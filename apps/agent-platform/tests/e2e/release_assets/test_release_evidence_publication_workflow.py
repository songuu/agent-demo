from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

PLATFORM_ROOT = Path(__file__).parents[3]
REPOSITORY_ROOT = PLATFORM_ROOT.parents[1]
WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "agent-platform-release.yml"
COMPONENT_ASSETS = {
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
}


def _production() -> dict[str, Any]:
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    return workflow["jobs"]["production"]


def _step(name: str) -> dict[str, Any]:
    for step in _production()["steps"]:
        if step.get("name") == name:
            return step
    raise AssertionError(f"workflow step not found: {name}")


def test_components_are_published_and_read_back_before_evidence_is_built() -> None:
    production = _production()
    component_step = _step("Publish and read back governed component evidence")
    component = component_step["run"]
    build = _step("Build complete release evidence")["run"]
    step_names = [step.get("name") for step in production["steps"]]

    assert production["permissions"]["id-token"] == "write"
    assert "AGENT_PLATFORM_EVIDENCE_PUBLISH_TOKEN" not in production["env"]
    assert component_step["env"]["AGENT_PLATFORM_EVIDENCE_PUBLISH_TOKEN"] == (
        "${{ secrets.AGENT_PLATFORM_EVIDENCE_PUBLISH_TOKEN }}"
    )
    assert (
        ': "${AGENT_PLATFORM_EVIDENCE_PUBLISH_TOKEN:'
        '?AGENT_PLATFORM_EVIDENCE_PUBLISH_TOKEN is required}"'
    ) in component
    assert step_names.index("Publish and read back governed component evidence") < (
        step_names.index("Build complete release evidence")
    )
    assert "--kind release-evidence-component" in component
    assert "--minimum-retention-days 365" in component
    assert {
        line.strip().split("=", 1)[0].removeprefix("--asset ")
        for line in component.splitlines()
        if line.strip().startswith("--asset ")
    } == COMPONENT_ASSETS
    assert "--published-assets" in build
    assert (
        "--asset external_release_preflight="
        "../../.artifacts/production/external-release-preflight-validation.json"
    ) in component
    assert (
        "../../.artifacts/external-release-preflight/external-release-preflight.json"
        not in component
    )
    assert '--repository "${GITHUB_REPOSITORY}"' in build
    assert '--release-tag "${GITHUB_REF_NAME}"' in build
    assert (
        "--external-release-preflight "
        "../../.artifacts/production/component-evidence-readback/"
        "external_release_preflight"
    ) in build
    assert (
        "--approvals-bundle "
        "../../.artifacts/production/component-evidence-readback/release_approvals"
    ) in build
    assert (
        "--canary-validation "
        "../../.artifacts/production/component-evidence-readback/canary_validation"
    ) in build
    assert "--maximum-publication-age-seconds 3600" in build
    assert component.count("cosign verify-blob") == 3
    assert '"${component_readback}/canary_signature_bundle"' in component
    assert '"${component_readback}/canary"' in component
    assert '"${component_readback}/release_approvals_signature_bundle"' in component
    assert '"${component_readback}/release_approvals"' in component
    assert (
        "--approvals-signature-bundle "
        "../../.artifacts/production/component-evidence-readback/"
        "release_approvals_signature_bundle"
    ) in build
    assert (
        "--approvals-validation "
        "../../.artifacts/production/component-evidence-readback/"
        "release_approvals_validation"
    ) in build
    assert "evidence_base=" not in build
    assert "#sbom" not in build
    assert "--sbom-uri" not in build
    assert "--eval-results-uri" not in build


def test_final_evidence_is_signed_published_read_back_and_verified_again() -> None:
    final = _step("Sign, publish, and read back final release evidence")
    run = final["run"]

    assert final["id"] == "publish_final_evidence"
    assert final["env"]["AGENT_PLATFORM_EVIDENCE_PUBLISH_TOKEN"] == (
        "${{ secrets.AGENT_PLATFORM_EVIDENCE_PUBLISH_TOKEN }}"
    )
    assert (
        ': "${AGENT_PLATFORM_EVIDENCE_PUBLISH_TOKEN:'
        '?AGENT_PLATFORM_EVIDENCE_PUBLISH_TOKEN is required}"'
    ) in run
    assert run.count("cosign verify-blob") == 2
    assert "cosign sign-blob --yes" in run
    assert "--kind release-evidence" in run
    assert "--asset release_evidence=" in run
    assert "--asset detached_digest=" in run
    assert "--asset signature_bundle=" in run
    assert "--readback-dir" in run
    assert "final-evidence-readback/release_evidence" not in run
    assert '"${readback}/release_evidence"' in run
    assert '"${readback}/detached_digest"' in run
    assert '"${readback}/signature_bundle"' in run
    assert "Published release evidence detached digest mismatch" in run
    assert "EVIDENCE_SIGNED_ASSET_NOT_CANONICAL" in (
        PLATFORM_ROOT / "scripts" / "publish_evidence_assets.py"
    ).read_text(encoding="utf-8")


def test_release_summary_uses_digest_addressed_artifact_as_primary_evidence() -> None:
    summary = _step("Publish verified release summary")

    assert summary["env"]["FINAL_EVIDENCE_URI"] == (
        "${{ steps.publish_final_evidence.outputs.final_uri }}"
    )
    assert "Immutable evidence: ${FINAL_EVIDENCE_URI}" in summary["run"]
    assert "GitHub evidence copy" in summary["run"]
