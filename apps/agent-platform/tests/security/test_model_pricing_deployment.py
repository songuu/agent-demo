from __future__ import annotations

from pathlib import Path

PLATFORM_ROOT = Path(__file__).parents[2]
CHART = PLATFORM_ROOT / "deploy" / "helm" / "agent-platform"


def _read(relative_path: str) -> str:
    return (CHART / relative_path).read_text(encoding="utf-8")


def test_agent_worker_mounts_an_external_versioned_model_pricing_catalog() -> None:
    values = _read("values.yaml")
    agent = _read("templates/agent-worker-deployment.yaml")
    commit = _read("templates/commit-worker-deployment.yaml")

    assert "modelPricingCatalogConfigMapName:" in values
    assert "modelPricingCatalogKey:" in values
    assert "AGENT_MODEL_PRICING_CATALOG_PATH" in agent
    assert "/etc/agent-platform/model-pricing/catalog.json" in agent
    assert ".Values.config.modelPricingCatalogConfigMapName" in agent
    assert ".Values.config.modelPricingCatalogKey" in agent
    assert "readOnly: true" in agent

    assert "AGENT_MODEL_PRICING_CATALOG_PATH" not in commit
    assert "model-pricing" not in commit


def test_helm_keeps_trace_content_capture_disabled_by_default() -> None:
    values = _read("values.yaml")
    config = _read("templates/configmap.yaml")

    assert "traceContentCapture: false" in values
    assert "AGENT_TRACE_CONTENT_CAPTURE" in config
    assert ".Values.observability.traceContentCapture" in config
