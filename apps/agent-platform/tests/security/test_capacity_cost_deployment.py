from __future__ import annotations

import hashlib
import json
from pathlib import Path

PLATFORM_ROOT = Path(__file__).resolve().parents[2]
CHART_ROOT = PLATFORM_ROOT / "deploy" / "helm" / "agent-platform"


def _read(relative_path: str) -> str:
    return (PLATFORM_ROOT / relative_path).read_text(encoding="utf-8")


def test_helm_packages_the_exact_digest_bound_cost_rate_catalog() -> None:
    canonical = PLATFORM_ROOT / "deploy" / "catalogs" / "platform-cost-rates.v1.json"
    packaged = CHART_ROOT / "files" / "platform-cost-rates.v1.json"
    values = _read("deploy/helm/agent-platform/values.yaml")
    template = _read("deploy/helm/agent-platform/templates/cost-rate-catalog-configmap.yaml")
    catalog = json.loads(canonical.read_text(encoding="utf-8"))
    digest = f"sha256:{hashlib.sha256(canonical.read_bytes()).hexdigest()}"

    assert packaged.read_bytes() == canonical.read_bytes()
    assert f"costRateCatalogId: {catalog['catalog_id']}" in values
    assert f"costRateCatalogDigest: {digest}" in values
    assert '.Files.Get "files/platform-cost-rates.v1.json"' in template
    assert "sha256sum" in template
    assert "fail" in template
    assert "immutable: true" in template


def test_agent_mounts_cost_catalog_and_all_platform_planes_share_redis_control() -> None:
    config = _read("deploy/helm/agent-platform/templates/configmap.yaml")
    agent = _read("deploy/helm/agent-platform/templates/agent-worker-deployment.yaml")
    commit = _read("deploy/helm/agent-platform/templates/commit-worker-deployment.yaml")
    policies = _read("deploy/helm/agent-platform/templates/networkpolicies.yaml")

    assert 'AGENT_COST_RATE_CATALOG_PATH: "/etc/agent-platform/cost-rates/catalog.json"' in config
    assert "AGENT_COST_RATE_CATALOG_SHA256:" in config
    assert "mountPath: /etc/agent-platform/cost-rates" in agent
    assert "name: agent-platform-cost-rates" in agent
    for workload in (agent, commit):
        assert "AGENT_QUOTA_REDIS_URL" in workload
        assert "AGENT_QUOTA_KEY_HMAC_SECRET" in workload
        assert ".Values.secrets.quotaSecretName" in workload
    for policy_name in ("agent-worker-egress", "commit-worker-egress"):
        policy = policies.split(f"name: {policy_name}", maxsplit=1)[1].split("---", maxsplit=1)[0]
        assert "quota-redis-proxy" in policy
        assert "port: 6380" in policy


def test_hpa_uses_request_rate_and_temporal_queue_pressure_with_stabilization() -> None:
    hpa = _read("deploy/helm/agent-platform/templates/autoscaling.yaml")
    rules = _read("deploy/observability/prometheus-rules.yaml")

    assert hpa.count("kind: HorizontalPodAutoscaler") == 3
    assert "name: agent_run_accept_rate5m" in hpa
    assert hpa.count("name: agent_queue_backlog") >= 4
    assert hpa.count("name: agent_queue_oldest_age_seconds") >= 4
    assert "scaleUp:" in hpa
    assert "scaleDown:" in hpa
    assert "stabilizationWindowSeconds:" in hpa
    assert "agent:run_accept:rate5m" in rules
    assert "max by (environment, queue) (agent_queue_backlog)" in rules
