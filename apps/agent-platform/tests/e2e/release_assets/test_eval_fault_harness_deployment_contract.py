from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

PLATFORM_ROOT = Path(__file__).parents[3]
REPOSITORY_ROOT = PLATFORM_ROOT.parents[1]
WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "agent-platform-release.yml"
CHART_ROOT = PLATFORM_ROOT / "deploy" / "helm" / "agent-platform"


def _workflow() -> dict[str, Any]:
    value = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _step(job: dict[str, Any], name: str) -> dict[str, Any]:
    for step in job["steps"]:
        if step.get("name") == name:
            return step
    raise AssertionError(f"missing workflow step: {name}")


def _step_script(job: dict[str, Any], name: str) -> str:
    script = _step(job, name).get("run")
    assert isinstance(script, str)
    return script


def test_staging_environment_materializes_all_fault_harness_inputs_fail_closed() -> None:
    staging = _workflow()["jobs"]["staging"]
    environment = staging["env"]
    live_eval = _step(staging, "Run credentialed live release evaluations")

    assert "AGENT_PLATFORM_EVAL_FAULT_TOKEN" not in environment
    assert live_eval["env"]["AGENT_PLATFORM_EVAL_FAULT_TOKEN"] == (
        "${{ secrets.AGENT_PLATFORM_EVAL_FAULT_TOKEN }}"
    )
    assert (
        ': "${AGENT_PLATFORM_EVAL_FAULT_TOKEN:?AGENT_PLATFORM_EVAL_FAULT_TOKEN is required}"'
        in live_eval["run"]
    )
    assert environment["AGENT_PLATFORM_EVAL_FAULT_RECEIPT_PUBLIC_KEY_B64"] == (
        "${{ vars.AGENT_PLATFORM_EVAL_FAULT_RECEIPT_PUBLIC_KEY_B64 }}"
    )
    assert environment["AGENT_PLATFORM_EVAL_FAULT_RECEIPT_SIGNER_IDENTITY"] == (
        "${{ vars.AGENT_PLATFORM_EVAL_FAULT_RECEIPT_SIGNER_IDENTITY }}"
    )
    assert environment["EVAL_FAULT_HARNESS_URL"] == (
        "${{ vars.AGENT_PLATFORM_EVAL_FAULT_HARNESS_URL }}"
    )
    assert environment["EVAL_FAULT_HARNESS_SECRET_NAME"] == (
        "${{ vars.AGENT_PLATFORM_EVAL_FAULT_HARNESS_SECRET_NAME }}"
    )
    assert environment["EVAL_FAULT_HARNESS_TOKEN_KEY"] == (
        "${{ vars.AGENT_PLATFORM_EVAL_FAULT_HARNESS_TOKEN_KEY }}"
    )

    materialize = _step_script(staging, "Materialize short-lived staging inputs")
    for variable in (
        "AGENT_PLATFORM_EVAL_FAULT_RECEIPT_PUBLIC_KEY_B64",
        "AGENT_PLATFORM_EVAL_FAULT_RECEIPT_SIGNER_IDENTITY",
        "EVAL_FAULT_HARNESS_URL",
        "EVAL_FAULT_HARNESS_SECRET_NAME",
        "EVAL_FAULT_HARNESS_TOKEN_KEY",
    ):
        assert variable in materialize
    assert "AGENT_PLATFORM_EVAL_FAULT_TOKEN" not in materialize
    assert "EVAL_FAULT_HARNESS_URL must use credential-free HTTPS" in materialize


def test_staging_helm_uses_only_controller_url_and_secret_reference() -> None:
    staging = _workflow()["jobs"]["staging"]
    deploy = _step_script(staging, "Deploy exact digest to staging")

    assert 'config.evalFaultHarnessUrl="${EVAL_FAULT_HARNESS_URL}"' in deploy
    assert 'secrets.evalFaultHarnessSecretName="${EVAL_FAULT_HARNESS_SECRET_NAME}"' in deploy
    assert 'secrets.evalFaultHarnessTokenKey="${EVAL_FAULT_HARNESS_TOKEN_KEY}"' in deploy
    assert "AGENT_PLATFORM_EVAL_FAULT_TOKEN" not in deploy
    assert "AGENT_PLATFORM_EVAL_FAULT_RECEIPT_PUBLIC_KEY_B64" not in deploy
    assert "AGENT_PLATFORM_EVAL_FAULT_RECEIPT_SIGNER_IDENTITY" not in deploy


def test_quality_helm_render_supplies_nonsecret_fault_harness_contract_values() -> None:
    quality = _workflow()["jobs"]["quality"]
    render = _step_script(quality, "Validate deployment assets")

    assert (
        "config.evalFaultHarnessUrl=https://eval-fault-harness.staging.example.invalid"
    ) in render
    assert "secrets.evalFaultHarnessSecretName=agent-platform-eval-fault-harness" in render
    assert "secrets.evalFaultHarnessTokenKey=token" in render
    assert "AGENT_PLATFORM_EVAL_FAULT_TOKEN" not in render


def test_chart_exposes_url_only_in_staging_and_token_only_from_secret_key_ref() -> None:
    values = (CHART_ROOT / "values.yaml").read_text(encoding="utf-8")
    parsed_values = yaml.safe_load(values)
    configmap = (CHART_ROOT / "templates" / "configmap.yaml").read_text(encoding="utf-8")
    deployment = (CHART_ROOT / "templates" / "api-deployment.yaml").read_text(encoding="utf-8")
    chart = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(CHART_ROOT.rglob("*")) if path.is_file()
    )

    assert "evalFaultHarnessUrl:" in values
    assert "evalFaultHarnessSecretName:" in values
    assert "evalFaultHarnessTokenKey:" in values
    assert parsed_values["config"]["evalFaultHarnessUrl"] == ""
    assert parsed_values["secrets"]["evalFaultHarnessSecretName"] == ""
    assert parsed_values["secrets"]["evalFaultHarnessTokenKey"] == ""
    assert "AGENT_EVAL_FAULT_HARNESS_URL" not in configmap
    assert "AGENT_EVAL_FAULT_HARNESS_TOKEN" not in configmap
    assert "AGENT_PLATFORM_EVAL_FAULT_RECEIPT_HMAC_KEY" not in chart
    assert "AGENT_PLATFORM_EVAL_FAULT_RECEIPT_HMAC_KEY" not in WORKFLOW_PATH.read_text(
        encoding="utf-8"
    )

    assert "AGENT_EVAL_FAULT_HARNESS_URL" in deployment
    assert "config.evalFaultHarnessUrl is required in staging" in deployment
    assert "AGENT_EVAL_FAULT_HARNESS_TOKEN" in deployment
    assert "secretKeyRef:" in deployment
    assert "optional: false" in deployment
    assert "secrets.evalFaultHarnessSecretName is required in staging" in deployment
    assert "secrets.evalFaultHarnessTokenKey is required in staging" in deployment
    assert "value: {{ .Values.secrets.evalFaultHarness" not in deployment
    assert '{{ if eq .Values.global.environment "staging" }}' not in configmap
    assert '{{ if eq .Values.global.environment "staging" }}' in deployment
