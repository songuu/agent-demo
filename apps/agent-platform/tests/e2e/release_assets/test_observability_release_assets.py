from __future__ import annotations

from pathlib import Path

PLATFORM_ROOT = Path(__file__).parents[3]
REPOSITORY_ROOT = PLATFORM_ROOT.parents[1]
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "agent-platform-release.yml"
DEPLOY_SCRIPT = PLATFORM_ROOT / "deploy" / "ci" / "deploy_observability_assets.sh"


def test_release_workflow_applies_observability_assets_in_staging_and_production() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert workflow.count("deploy/ci/deploy_observability_assets.sh") == 2
    assert workflow.count("deploy/ci/validate_observability_evidence.py") == 2
    assert workflow.count('--release-id "${RELEASE_ID}"') >= 2
    assert '--git-sha "${GITHUB_SHA}"' in workflow
    assert '--image-digest "${IMAGE_DIGEST}"' in workflow
    for external_input in (
        "GRAFANA_API_URL",
        "GRAFANA_API_TOKEN",
        "ALERTMANAGER_API_URL",
        "ALERTMANAGER_API_TOKEN",
        "ALERT_DELIVERY_RECEIPT_BASE_URL",
        "ALERT_DELIVERY_RECEIPT_TOKEN",
    ):
        assert workflow.count(external_input) >= 2
    assert "staging-observability.json" in workflow
    assert "production-observability.json" in workflow


def test_observability_deployer_fails_closed_and_binds_assets_to_release() -> None:
    script = DEPLOY_SCRIPT.read_text(encoding="utf-8")

    assert "set -euo pipefail" in script
    assert "prometheusrules.monitoring.coreos.com" in script
    assert "grafana_dashboard" in script
    assert 'select(.name == "LABEL" and .value == "grafana_dashboard")' in script
    assert 'select(.name == "NAMESPACE" and .value == "ALL")' in script
    assert "otel-collector" in script
    assert "13133" in script
    assert "port-forward" in script
    assert "deploy/observability/prometheus-rules.yaml" in script
    assert "deploy/observability/dashboards" in script
    assert "agent-platform/release-git-sha" in script
    assert "agent-platform/release-image-digest" in script
    assert "agent-platform-release-id:" in script
    assert "agent-platform-git-sha:" in script
    assert "agent-platform-image-digest:" in script
    assert "kubectl apply" in script
    assert "get prometheusrule agent-platform" in script
    assert "get configmap" in script
    assert "agent-platform-grafana-dashboards" in script


def test_observability_deployer_requires_authenticated_runtime_api_readback() -> None:
    script = DEPLOY_SCRIPT.read_text(encoding="utf-8")

    for required in (
        "--release-id",
        "--grafana-api-url",
        "--grafana-token-env",
        "--alertmanager-api-url",
        "--alertmanager-token-env",
        "--alert-receipt-base-url",
        "--alert-receipt-token-env",
        "--http-timeout-seconds",
        "--delivery-timeout-seconds",
        "--proto '=https'",
        "--tlsv1.2",
        "Authorization: Bearer",
        "/api/dashboards/uid/",
        "/api/v2/alerts",
        "synthetic_alert_submitted",
        "alertmanager_api_readback",
        "synthetic_alert_resolved",
        "immutable_receipt_readback",
        "receipt_evidence_uri",
        "receipt_evidence_sha256",
    ):
        assert required in script

    assert "--insecure" not in script
    assert "--location" not in script
