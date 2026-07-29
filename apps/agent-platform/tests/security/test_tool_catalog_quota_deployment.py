from __future__ import annotations

import hashlib
import json
from pathlib import Path

PLATFORM_ROOT = Path(__file__).resolve().parents[2]
CHART_ROOT = PLATFORM_ROOT / "deploy" / "helm" / "agent-platform"


def read(relative_path: str) -> str:
    return (PLATFORM_ROOT / relative_path).read_text(encoding="utf-8")


def test_helm_packages_the_exact_versioned_tool_catalog() -> None:
    canonical = PLATFORM_ROOT / "deploy" / "catalogs" / "tool-catalog.v1.json"
    packaged = CHART_ROOT / "files" / "tool-catalog.v1.json"
    values = read("deploy/helm/agent-platform/values.yaml")
    template = read("deploy/helm/agent-platform/templates/tool-catalog-configmap.yaml")
    catalog = json.loads(canonical.read_text(encoding="utf-8"))
    digest = f"sha256:{hashlib.sha256(canonical.read_bytes()).hexdigest()}"

    assert packaged.read_bytes() == canonical.read_bytes()
    assert f"toolCatalogId: {catalog['catalog_id']}" in values
    assert f"toolCatalogDigest: {digest}" in values
    assert '.Files.Get "files/tool-catalog.v1.json"' in template
    assert "sha256sum" in template
    assert "fail" in template
    assert "immutable: true" in template
    assert "tool-catalog.json:" in template


def test_helm_mounts_catalog_and_binds_digest_in_every_platform_plane() -> None:
    config = read("deploy/helm/agent-platform/templates/configmap.yaml")
    workloads = [
        read("deploy/helm/agent-platform/templates/api-deployment.yaml"),
        read("deploy/helm/agent-platform/templates/agent-worker-deployment.yaml"),
        read("deploy/helm/agent-platform/templates/commit-worker-deployment.yaml"),
    ]

    assert 'AGENT_TOOL_CATALOG_PATH: "/etc/agent-platform/tool-catalog/tool-catalog.json"' in config
    assert "AGENT_TOOL_CATALOG_SHA256:" in config
    assert ".Values.global.toolCatalogDigest" in config
    for workload in workloads:
        assert "name: tool-catalog" in workload
        assert "mountPath: /etc/agent-platform/tool-catalog" in workload
        assert 'include "agent-platform.toolCatalogConfigMapName"' in workload
        assert "readOnly: true" in workload


def test_api_uses_shared_tls_redis_quota_with_secret_backed_keys() -> None:
    values = read("deploy/helm/agent-platform/values.yaml")
    config = read("deploy/helm/agent-platform/templates/configmap.yaml")
    api = read("deploy/helm/agent-platform/templates/api-deployment.yaml")

    assert "quota:\n  backend: redis" in values
    for setting in (
        "AGENT_QUOTA_BACKEND",
        "AGENT_PRE_AUTH_IP_REQUESTS_PER_MINUTE",
        "AGENT_USER_REQUESTS_PER_MINUTE",
        "AGENT_TENANT_REQUESTS_PER_MINUTE",
        "AGENT_USE_CASE_REQUESTS_PER_MINUTE",
        "AGENT_IP_REQUESTS_PER_MINUTE",
    ):
        assert setting in config
    for setting in ("AGENT_QUOTA_REDIS_URL", "AGENT_QUOTA_KEY_HMAC_SECRET"):
        assert setting in api
        assert (
            "secretKeyRef:"
            in api.split(f"name: {setting}", maxsplit=1)[1].split("- name:", maxsplit=1)[0]
        )
    assert ".Values.secrets.quotaSecretName" in api
    assert "rediss://" not in values


def test_workers_use_explicit_gateway_reliability_settings_and_proxies() -> None:
    values = read("deploy/helm/agent-platform/values.yaml")
    config = read("deploy/helm/agent-platform/templates/configmap.yaml")
    agent = read("deploy/helm/agent-platform/templates/agent-worker-deployment.yaml")
    commit = read("deploy/helm/agent-platform/templates/commit-worker-deployment.yaml")

    assert "toolGateway:" in values
    assert "url: https://" in values
    assert "healthUrl: https://" in values
    for setting in (
        "AGENT_TOOL_GATEWAY_URL",
        "AGENT_TOOL_GATEWAY_HEALTH_URL",
        "AGENT_TOOL_GATEWAY_TIMEOUT_SECONDS",
        "AGENT_TOOL_GATEWAY_MAX_IN_FLIGHT",
        "AGENT_TOOL_GATEWAY_MAX_QUEUED",
        "AGENT_TOOL_GATEWAY_QUEUE_TIMEOUT_SECONDS",
        "AGENT_TOOL_GATEWAY_CIRCUIT_FAILURE_THRESHOLD",
        "AGENT_TOOL_GATEWAY_CIRCUIT_RECOVERY_SECONDS",
    ):
        assert setting in config
    for workload, proxy_value in (
        (agent, ".Values.egress.agentProxyUrl"),
        (commit, ".Values.egress.commitProxyUrl"),
    ):
        assert "AGENT_TOOL_GATEWAY_EGRESS_PROXY_URL" in workload
        assert proxy_value in workload


def test_agent_model_reliability_and_project_are_explicit() -> None:
    values = read("deploy/helm/agent-platform/values.yaml")
    agent = read("deploy/helm/agent-platform/templates/agent-worker-deployment.yaml")

    assert "modelReliability:" in values
    for setting in (
        "AGENT_MODEL_MAX_IN_FLIGHT",
        "AGENT_MODEL_MAX_QUEUED",
        "AGENT_MODEL_QUEUE_TIMEOUT_SECONDS",
        "AGENT_MODEL_CIRCUIT_FAILURE_THRESHOLD",
        "AGENT_MODEL_CIRCUIT_RECOVERY_SECONDS",
    ):
        assert setting in agent
    project = agent.split("name: AGENT_OPENAI_PROJECT", maxsplit=1)[1].split("- name:", maxsplit=1)[
        0
    ]
    assert "secretKeyRef:" in project
    assert ".Values.secrets.openAISecretName" in project
    assert ".Values.secrets.openAIProjectKey" in project


def test_network_policy_only_allows_required_redis_and_gateway_paths() -> None:
    policies = read("deploy/helm/agent-platform/templates/networkpolicies.yaml")
    api_policy = policies.split("name: agent-api-ingress", maxsplit=1)[1].split("---", maxsplit=1)[
        0
    ]
    agent_policy = policies.split("name: agent-worker-egress", maxsplit=1)[1].split(
        "---", maxsplit=1
    )[0]
    commit_policy = policies.split("name: commit-worker-egress", maxsplit=1)[1].split(
        "---", maxsplit=1
    )[0]

    assert "quota-redis-proxy" in api_policy
    assert "port: 6380" in api_policy
    assert "artifact-scan-egress-proxy" in api_policy
    assert "agent-egress-proxy" in agent_policy
    assert "commit-egress-proxy" in commit_policy
    assert "tool-gateway" not in agent_policy
    assert "tool-gateway" not in commit_policy
    assert "0.0.0.0/0" not in policies


def test_compose_uses_plain_redis_only_for_explicit_dev_profile() -> None:
    compose = read("deploy/docker/docker-compose.yml")

    assert "redis:" in compose
    assert "redis:7.4.9@sha256:" in compose
    assert "redis-cli" in compose
    assert "AGENT_QUOTA_BACKEND: redis" in compose
    assert "AGENT_QUOTA_REDIS_URL: redis://redis:6379/0" in compose
    assert "AGENT_QUOTA_KEY_HMAC_SECRET:" in compose
    assert "AGENT_ENVIRONMENT: dev" in compose
    assert "Never promote this manifest" in compose
    assert "rediss://redis" not in compose
