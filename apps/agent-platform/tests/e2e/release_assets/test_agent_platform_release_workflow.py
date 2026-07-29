from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

PLATFORM_ROOT = Path(__file__).parents[3]
REPOSITORY_ROOT = PLATFORM_ROOT.parents[1]
WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "agent-platform-release.yml"


def _workflow() -> dict[str, Any]:
    value = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _job_text(job: dict[str, Any]) -> str:
    values: list[str] = []

    def collect(value: object) -> None:
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, dict):
            for nested in value.values():
                collect(nested)
        elif isinstance(value, list):
            for nested in value:
                collect(nested)

    collect(job)
    return "\n".join(values)


def test_release_source_is_signed_tag_on_main_and_github_verified_annotated_object() -> None:
    workflow = _workflow()
    quality = workflow["jobs"]["quality"]
    steps = {step["name"]: step for step in quality["steps"]}
    gate = steps["Restrict release source"]
    gate_source = gate["run"]

    assert workflow["permissions"]["contents"] == "read"
    assert gate["env"]["GITHUB_TOKEN"] == "${{ github.token }}"
    assert "+refs/heads/main:refs/remotes/origin/main" in gate_source
    assert "git merge-base --is-ancestor" in gate_source
    assert '"${GITHUB_SHA}" "refs/remotes/origin/main"' in gate_source
    assert "checked_out_sha" in gate_source
    assert '"${checked_out_sha}" != "${GITHUB_SHA}"' in gate_source
    assert (
        '"${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}/git/ref/tags/${encoded_tag_name}"'
    ) in gate_source
    assert (
        '"${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}/git/tags/${tag_object_sha}"'
    ) in gate_source
    assert '"${tag_object_type}" != "tag"' in gate_source
    assert '"${tag_target_type}" != "commit"' in gate_source
    assert '"${tag_target_sha}" != "${GITHUB_SHA}"' in gate_source
    assert '"${verification_verified}" != "true"' in gate_source
    assert '"${verification_reason}" != "valid"' in gate_source
    assert "Authorization: Bearer ${GITHUB_TOKEN}" in gate_source
    assert "X-GitHub-Api-Version: 2026-03-10" in gate_source
    assert "--proto '=https' --tlsv1.2" in gate_source
    assert "refs/tags/agent-platform-v*) ;;" in gate_source
    assert "refs/heads/main|refs/tags/agent-platform-v*" not in gate_source
    assert 'if [[ "${GITHUB_REF}" != refs/tags/* ]]; then' not in gate_source
    assert gate_source.count("'.object.type // \"\"'") == 2
    assert gate_source.count("'.object.sha // \"\"'") == 2
    assert "'.verification.verified // false'" in gate_source
    assert "'.verification.reason // \"\"'" in gate_source
    assert '"${resolved_tag_name}" != "${tag_name}"' in gate_source
    assert '"${resolved_tag_sha}" != "${tag_object_sha}"' in gate_source

    step_names = [step["name"] for step in quality["steps"]]
    assert step_names.index("Restrict release source") < step_names.index(
        "Install locked dependencies"
    )


def test_release_builds_and_pushes_one_immutable_image_with_supply_chain_evidence() -> None:
    workflow = _workflow()
    jobs = workflow["jobs"]
    build = jobs["build_image"]
    build_text = _job_text(build)
    entire_workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert build["needs"] == "quality"
    assert build["outputs"]["image_digest"] == "${{ steps.build.outputs.digest }}"
    assert build["outputs"]["image_repository"] == "${{ steps.image.outputs.repository }}"
    assert entire_workflow.count("docker/build-push-action@") == 2
    assert "push: true" in entire_workflow
    assert "tags: ${{ steps.image.outputs.repository }}:${{ github.sha }}" in entire_workflow
    assert "docker/login-action@" in build_text
    assert "anchore/sbom-action@" in build_text
    assert build_text.count("actions/attest@") == 2
    assert "sigstore/cosign-installer@" in build_text
    assert "cosign sign --yes" in build_text
    assert "cosign verify" in build_text
    assert "push-to-registry" in entire_workflow
    assert ":latest" not in entire_workflow


def test_pull_request_builds_scans_attests_and_signs_ephemeral_oci_image() -> None:
    job = _workflow()["jobs"]["pr_image"]
    job_text = _job_text(job)

    assert job["if"] == "github.event_name == 'pull_request'"
    assert job["needs"] == "quality"
    assert job["permissions"]["id-token"] == "write"
    assert "docker/build-push-action@" in job_text
    assert "push: false" in WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "type=oci" in job_text
    assert "sbom: true" in WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "provenance: mode=max" in WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "verify_oci_attestations.py" in job_text
    assert "aquasecurity/trivy-action@" in job_text
    assert "input: .artifacts/pr-image/agent-platform-pr.oci.tar" in WORKFLOW_PATH.read_text(
        encoding="utf-8"
    )
    assert "anchore/sbom-action/download-syft@" in job_text
    assert "cosign sign-blob --yes" in job_text
    assert "cosign verify-blob" in job_text
    assert "actions/upload-artifact@" in job_text


def test_staging_deploys_exact_digest_then_runs_identity_smoke_and_live_gates() -> None:
    jobs = _workflow()["jobs"]
    staging = jobs["staging"]
    staging_text = _job_text(staging)

    assert set(staging["needs"]) == {"quality", "build_image"}
    assert staging["environment"] == "agent-platform-staging"
    assert staging["env"]["IMAGE_DIGEST"] == "${{ needs.build_image.outputs.image_digest }}"
    assert staging["env"]["IMAGE_REPOSITORY"] == (
        "${{ needs.build_image.outputs.image_repository }}"
    )
    assert "Azure/setup-helm@" in staging_text
    assert "Azure/setup-kubectl@" in staging_text
    assert "helm upgrade --install agent-platform" in staging_text
    assert "--atomic" in staging_text
    assert 'global.imageDigest="${IMAGE_DIGEST}"' in staging_text
    assert 'global.gitSha="${GITHUB_SHA}"' in staging_text
    assert "scripts/verify_release.py" in staging_text
    assert 'expected-image-digest", "${IMAGE_DIGEST}"' not in staging_text
    assert '--expected-image-digest "${IMAGE_DIGEST}"' in staging_text
    assert "evals/run_live_release_evals.py" in staging_text
    assert "evals/graders/release_gate.py" in staging_text
    assert staging["timeout-minutes"] >= 360
    assert "AGENT_PLATFORM_RELEASE_TOKEN" in staging_text
    assert "LIVE_BASELINE_B64" not in staging_text
    assert "AGENT_PLATFORM_STAGING_LIVE_BASELINE_B64" not in staging_text
    assert staging["env"]["LIVE_BASELINE_URI"] == (
        "${{ vars.AGENT_PLATFORM_STAGING_LIVE_BASELINE_URI }}"
    )
    assert staging["env"]["LIVE_BASELINE_SIGNER_IDENTITY"] == (
        "${{ vars.AGENT_PLATFORM_STAGING_LIVE_BASELINE_SIGNER_IDENTITY }}"
    )
    assert staging["env"]["LIVE_BASELINE_SIGNER_ISSUER"] == (
        "${{ vars.AGENT_PLATFORM_STAGING_LIVE_BASELINE_SIGNER_ISSUER }}"
    )
    assert "^https://.+/sha256:[0-9a-f]{64}$" in staging_text
    assert 'bundle_path="${baseline_path}.sigstore.json"' in staging_text
    assert '"${LIVE_BASELINE_URI}.sigstore.json"' in staging_text
    assert "cosign verify-blob" in staging_text
    assert '--certificate-identity "${LIVE_BASELINE_SIGNER_IDENTITY}"' in staging_text
    assert '--certificate-oidc-issuer "${LIVE_BASELINE_SIGNER_ISSUER}"' in staging_text
    assert "deploy/ci/validate_live_baseline.py" in staging_text
    assert "--maximum-age-seconds 604800" in staging_text
    assert "--baseline-validation" in staging_text
    assert "AGENT_PLATFORM_HUMAN_REVIEW_TOKEN" in staging_text
    assert "HUMAN_REVIEW_SERVICE_URL" in staging_text
    assert "HUMAN_REVIEW_B64" not in staging_text
    assert "AGENT_PLATFORM_STAGING_HUMAN_REVIEW_B64" not in staging_text
    assert "human-review-evidence.schema.json" in staging_text
    assert "--candidate-manifest-output" in staging_text
    assert "--candidate-results-output" in staging_text
    assert "--human-review-output" in staging_text
    assert "--review-service-url" in staging_text
    assert "--human-review " not in staging_text


def test_canary_consumes_external_controller_evidence_and_fails_closed() -> None:
    jobs = _workflow()["jobs"]
    canary = jobs["production_canary"]
    canary_text = _job_text(canary)

    assert set(canary["needs"]) == {"build_image", "staging"}
    assert canary["environment"] == "agent-platform-production-canary"
    assert canary["env"]["IMAGE_DIGEST"] == "${{ needs.build_image.outputs.image_digest }}"
    assert "scripts/verify_release.py" in canary_text
    assert "CANARY_EVIDENCE_URI" in canary_text
    assert "CANARY_EVIDENCE_BASE_URL" not in canary_text
    assert "CANARY_EVIDENCE_BEARER_TOKEN" in canary_text
    assert "CANARY_EVIDENCE_SIGNER_IDENTITY" in canary_text
    assert "CANARY_EVIDENCE_SIGNER_ISSUER" in canary_text
    assert "curl --fail --silent --show-error --proto '=https'" in canary_text
    assert "sigstore/cosign-installer@" in canary_text
    assert "cosign verify-blob" in canary_text
    assert '.sigstore.json"' in canary_text
    assert "^https://.+/sha256:[0-9a-f]{64}$" in canary_text
    assert "sha256sum" in canary_text
    assert "deploy/ci/validate_canary_evidence.py" in canary_text
    assert (
        "--signature-bundle "
        + "../../.artifacts/canary/external-canary-evidence.json.sigstore.json"
        in canary_text
    )
    assert '--source-uri "${CANARY_EVIDENCE_URI}"' in canary_text
    assert '--expected-git-sha "${GITHUB_SHA}"' in canary_text
    assert '--expected-image-digest "${IMAGE_DIGEST}"' in canary_text
    assert '--expected-release-id "${RELEASE_ID}"' in canary_text
    assert '--expected-signer-identity "${CANARY_EVIDENCE_SIGNER_IDENTITY}"' in canary_text
    assert '--expected-signer-issuer "${CANARY_EVIDENCE_SIGNER_ISSUER}"' in canary_text
    assert "--maximum-age-seconds 86400" in canary_text
    assert "--minimum-observation-seconds" in canary_text
    assert "mock" not in canary_text.lower()
    assert "fake" not in canary_text.lower()


def test_production_requires_recorded_environment_approval_and_never_rebuilds() -> None:
    jobs = _workflow()["jobs"]
    production = jobs["production"]
    production_text = _job_text(production)

    assert set(production["needs"]) == {"build_image", "production_canary"}
    assert production["environment"] == "agent-platform-production"
    assert production["env"]["IMAGE_DIGEST"] == "${{ needs.build_image.outputs.image_digest }}"
    assert "docker/build-push-action" not in production_text
    assert production["env"]["APPROVALS_URI"] == (
        "${{ vars.AGENT_PLATFORM_RELEASE_APPROVALS_URI }}"
    )
    assert production["env"]["APPROVALS_SIGNER_IDENTITY"] == (
        "${{ vars.AGENT_PLATFORM_RELEASE_APPROVALS_SIGNER_IDENTITY }}"
    )
    assert production["env"]["APPROVALS_SIGNER_ISSUER"] == (
        "${{ vars.AGENT_PLATFORM_RELEASE_APPROVALS_SIGNER_ISSUER }}"
    )
    assert "APPROVALS_BASE_URL" not in production_text
    assert "actions/runs/${GITHUB_RUN_ID}/approvals" in production_text
    assert "deploy/ci/validate_environment_approval.py" in production_text
    assert "helm upgrade --install agent-platform" in production_text
    assert "--atomic" in production_text
    assert 'global.imageDigest="${IMAGE_DIGEST}"' in production_text
    assert "scripts/verify_release.py" in production_text
    assert '--expected-image-digest "${IMAGE_DIGEST}"' in production_text
    assert "--skip-smoke" not in production_text
    assert "scripts/build_release_evidence.py" in production_text
    assert "actions/upload-artifact@" in production_text
    assert "release-evidence.json" in production_text


def test_production_rolls_back_to_the_signed_predeployment_revision_on_post_deploy_failure() -> (
    None
):
    production = _workflow()["jobs"]["production"]
    steps = {step["name"]: step for step in production["steps"]}

    target = steps["Verify signed rollback target before deployment"]
    assert "previous_helm_revision" in target["run"]
    assert "previous_image_digest" in target["run"]
    assert "helm get manifest" in target["run"]
    assert "ROLLBACK_REVISION" in target["run"]

    deploy = steps["Deploy the same immutable digest to production"]
    assert deploy["id"] == "deploy_production"
    assert "helm upgrade --install agent-platform" in deploy["run"]
    assert "rollout status" not in deploy["run"]

    rollback = steps["Roll back production after post-deployment failure"]
    assert rollback["if"] == ("${{ failure() && steps.deploy_production.outcome == 'success' }}")
    assert "helm rollback" in rollback["run"]
    assert "--no-hooks" in rollback["run"]
    assert "scripts/verify_release.py" in rollback["run"]
    assert '--expected-image-digest "${ROLLBACK_IMAGE_DIGEST}"' in rollback["run"]
    assert "helm-status-after.json" in rollback["run"]
    assert "deployments-after.json" in rollback["run"]

    rollback_upload = steps["Upload production rollback evidence"]
    assert "always()" in rollback_upload["if"]
    assert rollback_upload["with"]["retention-days"] == 365


def test_quality_job_runs_repository_gates_before_build() -> None:
    quality_text = _job_text(_workflow()["jobs"]["quality"])

    for command in (
        "pnpm --filter @agent-demo/agent-platform lint",
        "pnpm --filter @agent-demo/agent-platform format:check",
        "pnpm typecheck",
        "pnpm test",
        "pnpm build",
        "check --strict policies",
        "test policies tests/policy",
        "run_release_evals.py",
        "--mode offline",
        "helm lint",
        "docker compose",
    ):
        assert command in quality_text
