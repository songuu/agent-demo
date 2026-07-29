from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

PLATFORM_ROOT = Path(__file__).parents[3]
REPOSITORY_ROOT = PLATFORM_ROOT.parents[1]
WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "agent-platform-release.yml"

EXPECTED_STEP_CREDENTIALS = {
    "staging": {
        "Materialize short-lived staging inputs": {
            "HELM_VALUES_B64": "${{ secrets.AGENT_PLATFORM_STAGING_HELM_VALUES_B64 }}",
            "KUBECONFIG_B64": "${{ secrets.AGENT_PLATFORM_STAGING_KUBECONFIG_B64 }}",
        },
        "Apply and verify staging observability assets": {
            "GRAFANA_API_TOKEN": "${{ secrets.AGENT_PLATFORM_GRAFANA_API_TOKEN }}",
            "ALERTMANAGER_API_TOKEN": ("${{ secrets.AGENT_PLATFORM_ALERTMANAGER_API_TOKEN }}"),
            "ALERT_DELIVERY_RECEIPT_TOKEN": (
                "${{ secrets.AGENT_PLATFORM_ALERT_DELIVERY_RECEIPT_TOKEN }}"
            ),
        },
        "Verify staging release identity and read-only smoke": {
            "AGENT_PLATFORM_RELEASE_TOKEN": ("${{ secrets.AGENT_PLATFORM_STAGING_RELEASE_TOKEN }}"),
        },
        "Run credentialed live release evaluations": {
            "AGENT_PLATFORM_RELEASE_TOKEN": ("${{ secrets.AGENT_PLATFORM_STAGING_RELEASE_TOKEN }}"),
            "AGENT_PLATFORM_HUMAN_REVIEW_TOKEN": (
                "${{ secrets.AGENT_PLATFORM_STAGING_HUMAN_REVIEW_SERVICE_TOKEN }}"
            ),
            "AGENT_PLATFORM_EVAL_FAULT_TOKEN": ("${{ secrets.AGENT_PLATFORM_EVAL_FAULT_TOKEN }}"),
        },
    },
    "production_canary": {
        "Verify the controller-deployed canary is the exact release": {
            "AGENT_PLATFORM_RELEASE_TOKEN": ("${{ secrets.AGENT_PLATFORM_CANARY_RELEASE_TOKEN }}"),
        },
        "Fetch and verify signed external provider canary evidence": {
            "CANARY_EVIDENCE_BEARER_TOKEN": (
                "${{ secrets.AGENT_PLATFORM_CANARY_EVIDENCE_BEARER_TOKEN }}"
            ),
        },
    },
    "production": {
        "Materialize short-lived production inputs": {
            "HELM_VALUES_B64": "${{ secrets.AGENT_PLATFORM_PRODUCTION_HELM_VALUES_B64 }}",
            "KUBECONFIG_B64": ("${{ secrets.AGENT_PLATFORM_PRODUCTION_KUBECONFIG_B64 }}"),
        },
        "Fetch and validate independent control approvals": {
            "APPROVALS_BEARER_TOKEN": (
                "${{ secrets.AGENT_PLATFORM_RELEASE_APPROVALS_BEARER_TOKEN }}"
            ),
        },
        "Fetch and validate operational release readiness": {
            "OPERATIONAL_READINESS_BEARER_TOKEN": (
                "${{ secrets.AGENT_PLATFORM_OPERATIONAL_READINESS_BEARER_TOKEN }}"
            ),
        },
        "Fetch, verify, and validate production foundation": {
            "FOUNDATION_ATTESTATION_BEARER_TOKEN": (
                "${{ secrets.AGENT_PLATFORM_FOUNDATION_ATTESTATION_BEARER_TOKEN }}"
            ),
        },
        "Read back the real GitHub production environment approval": {
            "GITHUB_TOKEN": "${{ github.token }}",
        },
        "Apply and verify production observability assets": {
            "GRAFANA_API_TOKEN": "${{ secrets.AGENT_PLATFORM_GRAFANA_API_TOKEN }}",
            "ALERTMANAGER_API_TOKEN": ("${{ secrets.AGENT_PLATFORM_ALERTMANAGER_API_TOKEN }}"),
            "ALERT_DELIVERY_RECEIPT_TOKEN": (
                "${{ secrets.AGENT_PLATFORM_ALERT_DELIVERY_RECEIPT_TOKEN }}"
            ),
        },
        "Verify exact production identity, dependencies, and smoke run": {
            "AGENT_PLATFORM_RELEASE_TOKEN": (
                "${{ secrets.AGENT_PLATFORM_PRODUCTION_RELEASE_TOKEN }}"
            ),
        },
        "Publish and read back governed component evidence": {
            "AGENT_PLATFORM_EVIDENCE_PUBLISH_TOKEN": (
                "${{ secrets.AGENT_PLATFORM_EVIDENCE_PUBLISH_TOKEN }}"
            ),
        },
        "Sign, publish, and read back final release evidence": {
            "AGENT_PLATFORM_EVIDENCE_PUBLISH_TOKEN": (
                "${{ secrets.AGENT_PLATFORM_EVIDENCE_PUBLISH_TOKEN }}"
            ),
        },
        "Roll back production after post-deployment failure": {
            "AGENT_PLATFORM_RELEASE_TOKEN": (
                "${{ secrets.AGENT_PLATFORM_PRODUCTION_RELEASE_TOKEN }}"
            ),
        },
    },
}

NON_DECODED_CREDENTIALS = {
    job_name: {
        step_name: set(credentials) - {"HELM_VALUES_B64", "KUBECONFIG_B64"}
        for step_name, credentials in steps.items()
    }
    for job_name, steps in EXPECTED_STEP_CREDENTIALS.items()
}


def _workflow() -> dict[str, Any]:
    value = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _steps(job: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {step["name"]: step for step in job["steps"]}


def _is_credential_expression(value: object) -> bool:
    return isinstance(value, str) and ("secrets." in value or "github.token" in value)


def _credential_env(step: dict[str, Any]) -> dict[str, str]:
    return {
        name: value
        for name, value in step.get("env", {}).items()
        if _is_credential_expression(value)
    }


def test_release_jobs_do_not_expose_credentials_at_job_scope() -> None:
    jobs = _workflow()["jobs"]

    for job_name, job in jobs.items():
        leaked = {
            name: value
            for name, value in job.get("env", {}).items()
            if _is_credential_expression(value)
        }
        assert leaked == {}, f"{job_name} exposes credentials to every step: {leaked}"


def test_release_credentials_are_scoped_to_only_the_steps_that_consume_them() -> None:
    jobs = _workflow()["jobs"]

    for job_name, expected in EXPECTED_STEP_CREDENTIALS.items():
        actual = {
            step_name: credentials
            for step_name, step in _steps(jobs[job_name]).items()
            if (credentials := _credential_env(step))
        }
        assert actual == expected


def test_non_decoded_credentials_are_checked_by_their_consuming_step() -> None:
    jobs = _workflow()["jobs"]

    for job_name, expected_steps in NON_DECODED_CREDENTIALS.items():
        steps = _steps(jobs[job_name])
        for step_name, credential_names in expected_steps.items():
            script = steps[step_name].get("run", "")
            for credential_name in credential_names:
                marker = f': "${{{credential_name}:?{credential_name} is required}}"'
                assert marker in script


def test_materialize_steps_only_validate_secrets_that_they_decode() -> None:
    jobs = _workflow()["jobs"]
    forbidden_by_job = {
        "staging": {
            "AGENT_PLATFORM_RELEASE_TOKEN",
            "AGENT_PLATFORM_HUMAN_REVIEW_TOKEN",
            "AGENT_PLATFORM_EVAL_FAULT_TOKEN",
            "GRAFANA_API_TOKEN",
            "ALERTMANAGER_API_TOKEN",
            "ALERT_DELIVERY_RECEIPT_TOKEN",
        },
        "production": {
            "AGENT_PLATFORM_RELEASE_TOKEN",
            "AGENT_PLATFORM_EVIDENCE_PUBLISH_TOKEN",
            "APPROVALS_BEARER_TOKEN",
            "OPERATIONAL_READINESS_BEARER_TOKEN",
            "FOUNDATION_ATTESTATION_BEARER_TOKEN",
            "GRAFANA_API_TOKEN",
            "ALERTMANAGER_API_TOKEN",
            "ALERT_DELIVERY_RECEIPT_TOKEN",
        },
    }

    for job_name, forbidden in forbidden_by_job.items():
        step_name = f"Materialize short-lived {job_name} inputs"
        script = _steps(jobs[job_name])[step_name]["run"]
        for credential_name in forbidden:
            assert credential_name not in script


def test_short_lived_deployment_files_are_deleted_with_exact_always_cleanup() -> None:
    jobs = _workflow()["jobs"]
    expected = {
        "staging": {
            "Delete short-lived staging Helm values": (
                'rm -f -- "${RUNNER_TEMP}/staging-values.yaml"'
            ),
            "Delete short-lived staging kubeconfig": 'rm -f -- "${KUBECONFIG}"',
        },
        "production": {
            "Delete short-lived production Helm values": (
                'rm -f -- "${RUNNER_TEMP}/production-values.yaml"'
            ),
            "Delete short-lived production kubeconfig": 'rm -f -- "${KUBECONFIG}"',
        },
    }

    for job_name, expected_steps in expected.items():
        steps = _steps(jobs[job_name])
        for step_name, command in expected_steps.items():
            assert steps[step_name]["if"] == "${{ always() }}"
            assert steps[step_name]["run"].strip() == command

    staging_names = list(_steps(jobs["staging"]))
    assert staging_names.index("Delete short-lived staging Helm values") > staging_names.index(
        "Deploy exact digest to staging"
    )
    assert staging_names.index("Delete short-lived staging kubeconfig") > staging_names.index(
        "Apply and verify staging observability assets"
    )

    production_names = list(_steps(jobs["production"]))
    assert production_names.index(
        "Delete short-lived production Helm values"
    ) > production_names.index("Deploy the same immutable digest to production")
    assert production_names.index(
        "Delete short-lived production kubeconfig"
    ) > production_names.index("Roll back production after post-deployment failure")


def test_canary_job_does_not_keep_unused_image_repository() -> None:
    canary = _workflow()["jobs"]["production_canary"]

    assert "IMAGE_REPOSITORY" not in canary["env"]
