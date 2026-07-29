from __future__ import annotations

import re
from pathlib import Path

PLATFORM_ROOT = Path(__file__).parents[2]
DEPLOY_ROOT = PLATFORM_ROOT / "deploy"


def _read(relative_path: str) -> str:
    return (PLATFORM_ROOT / relative_path).read_text(encoding="utf-8")


def test_env_example_uses_real_settings_names_and_no_secret_values() -> None:
    environment = _read(".env.example")

    assert 'AGENT_MODEL_ALLOWLIST=["gpt-5.6-sol","gpt-5.6-terra","gpt-5.6-luna"]' in environment
    assert "AGENT_OPENAI_MODEL_ALLOWLIST=" not in environment
    assert "AGENT_ARTIFACT_PRESIGN_ENABLED=false" in environment
    assert "AGENT_SECRET_BACKEND=directory" in environment
    assert "AGENT_WEBHOOK_EGRESS_PROXY_URL=" in environment
    assert "AGENT_TEMPORAL_TLS=false" in environment
    assert "AGENT_TRUSTED_PROXY_CIDRS=[]" in environment


def test_container_runs_as_a_non_root_user_with_a_healthcheck() -> None:
    dockerfile = _read("deploy/docker/Dockerfile")

    assert " AS runtime" in dockerfile
    assert re.search(r"^USER\s+(?!0\b|root\b)\S+", dockerfile, re.MULTILINE)
    assert "HEALTHCHECK" in dockerfile
    assert "--no-cache-dir" in dockerfile
    assert ":latest" not in dockerfile


def test_compose_is_explicitly_local_and_has_all_required_dependencies() -> None:
    compose = _read("deploy/docker/docker-compose.yml")

    for service in (
        "postgres:",
        "temporal:",
        "minio:",
        "opa:",
        "agent-api:",
        "agent-worker:",
        "commit-worker:",
    ):
        assert service in compose
    assert "agent-local-only" in compose
    assert "AGENT_ENVIRONMENT: dev" in compose
    assert 'profiles: ["local"]' in compose
    assert "production" not in compose.lower()


def test_helm_separates_api_agent_commit_and_sandbox_identities() -> None:
    service_accounts = _read("deploy/helm/agent-platform/templates/serviceaccounts.yaml")
    agent_worker = _read("deploy/helm/agent-platform/templates/agent-worker-deployment.yaml")
    commit_worker = _read("deploy/helm/agent-platform/templates/commit-worker-deployment.yaml")
    sandbox = _read("deploy/helm/agent-platform/templates/sandbox-job.yaml")

    for identity in ("agent-api", "agent-worker", "commit-worker", "sandbox"):
        assert f"name: {identity}" in service_accounts
    assert "serviceAccountName: agent-worker" in agent_worker
    assert "serviceAccountName: commit-worker" in commit_worker
    assert "serviceAccountName: sandbox" in sandbox
    assert "automountServiceAccountToken: false" in agent_worker
    assert "automountServiceAccountToken: false" in commit_worker
    assert "automountServiceAccountToken: false" in sandbox
    assert "business-system-credentials" not in agent_worker
    assert "openai-prod" not in commit_worker


def test_workloads_enforce_restricted_pod_security() -> None:
    workload_paths = (
        "deploy/helm/agent-platform/templates/api-deployment.yaml",
        "deploy/helm/agent-platform/templates/agent-worker-deployment.yaml",
        "deploy/helm/agent-platform/templates/commit-worker-deployment.yaml",
        "deploy/helm/agent-platform/templates/sandbox-job.yaml",
    )

    for relative_path in workload_paths:
        manifest = _read(relative_path)
        assert "runAsNonRoot: true" in manifest, relative_path
        assert "allowPrivilegeEscalation: false" in manifest, relative_path
        assert "readOnlyRootFilesystem: true" in manifest, relative_path
        assert 'drop: ["ALL"]' in manifest, relative_path
        assert "seccompProfile:" in manifest, relative_path
        assert "type: RuntimeDefault" in manifest, relative_path

    sandbox = _read("deploy/helm/agent-platform/templates/sandbox-job.yaml")
    assert "runtimeClassName: gvisor" in sandbox
    assert "activeDeadlineSeconds: 300" in sandbox
    assert "backoffLimit: 0" in sandbox
    assert "ttlSecondsAfterFinished: 300" in sandbox


def test_network_policies_are_default_deny_and_commit_is_not_public() -> None:
    policies = _read("deploy/helm/agent-platform/templates/networkpolicies.yaml")
    agent_policy = policies.split("name: agent-worker-egress", maxsplit=1)[1].split(
        "---", maxsplit=1
    )[0]
    commit_policy = policies.split("name: commit-worker-egress", maxsplit=1)[1].split(
        "---", maxsplit=1
    )[0]
    assert "credential-broker" not in agent_policy
    assert "business-system" not in agent_policy
    assert "model-gateway" in agent_policy
    assert "tool-gateway" not in commit_policy
    assert "model-gateway" not in commit_policy
    assert "credential-broker" in commit_policy

    for policy in (
        "default-deny",
        "runtime-common-egress",
        "agent-worker-egress",
        "commit-worker-egress",
        "outbox-worker-egress",
        "retention-worker-egress",
        "sandbox-default-deny",
    ):
        assert f"name: {policy}" in policies
    assert "policyTypes: [Ingress, Egress]" in policies
    assert "0.0.0.0/0" not in policies
    assert "kube-dns" in policies
    assert "egress-proxy" in policies
    assert "otel-collector" in policies
    assert "port: 443" in agent_policy
    assert "port: 8443" in policies
    assert "port: 7233" in policies
    assert "port: 5432" in policies

    service = _read("deploy/helm/agent-platform/templates/services.yaml")
    assert "name: agent-api" in service
    assert "name: commit-worker" not in service


def test_helm_production_config_satisfies_settings_and_role_boundaries() -> None:
    values = _read("deploy/helm/agent-platform/values.yaml")
    config = _read("deploy/helm/agent-platform/templates/configmap.yaml")
    api = _read("deploy/helm/agent-platform/templates/api-deployment.yaml")
    agent = _read("deploy/helm/agent-platform/templates/agent-worker-deployment.yaml")
    commit = _read("deploy/helm/agent-platform/templates/commit-worker-deployment.yaml")

    for setting in (
        "AGENT_WORKFLOW_BACKEND: temporal",
        "AGENT_PERSISTENCE_BACKEND: postgres",
        "AGENT_ARTIFACT_BACKEND: s3",
        "AGENT_POLICY_BACKEND: opa",
        'AGENT_AUTH_DISABLED: "false"',
        "AGENT_JWT_ISSUER",
        "AGENT_JWT_AUDIENCE",
        "AGENT_JWT_JWKS_URL",
        "AGENT_TRUSTED_PROXY_CIDRS",
        "AGENT_ARTIFACT_REGION",
        "AGENT_RELEASE_GIT_SHA",
        "AGENT_RELEASE_IMAGE_DIGEST",
        "AGENT_ARTIFACT_PRESIGN_ENABLED",
        "AGENT_SECRET_BACKEND",
        "AGENT_SECRETS_MANAGER_PREFIX",
        "AGENT_TEMPORAL_TLS",
    ):
        assert setting in config

    assert "gitSha:" in values
    assert "openAIBaseUrl:" in values
    assert "cryptoSecretName:" in values
    assert "secretsManagerPrefix:" in values
    assert "webhookSecretName:" not in values
    assert "webhook-secrets" not in api

    assert 'value: "api"' in api
    assert 'value: "agent-worker"' in agent
    assert 'value: "commit-worker"' in commit
    assert "AGENT_MANAGEMENT_DATABASE_DSN" in api
    assert "AGENT_OPENAI_BASE_URL" in agent
    assert "AGENT_OPENAI_API_KEY" in agent
    assert "AGENT_AGENT_CREDENTIAL_REF" in agent
    assert "business-system-credentials" not in agent
    assert "AGENT_BUSINESS_CREDENTIAL_REF" in commit
    assert "AGENT_OPENAI_API_KEY" not in commit
    assert "AGENT_AGENT_CREDENTIAL_REF" not in commit

    for workload in (api, agent, commit):
        assert ".Values.secrets.cryptoSecretName" in workload
        assert "AGENT_ACTION_PAYLOAD_ENCRYPTION_KEY" in workload
        assert "AGENT_MEMORY_ENCRYPTION_KEY" in workload


def test_helm_has_isolated_outbox_and_retention_workloads() -> None:
    service_accounts = _read("deploy/helm/agent-platform/templates/serviceaccounts.yaml")
    outbox = _read("deploy/helm/agent-platform/templates/outbox-worker-deployment.yaml")
    retention = _read("deploy/helm/agent-platform/templates/retention-cronjob.yaml")
    disruption_budgets = _read("deploy/helm/agent-platform/templates/poddisruptionbudgets.yaml")

    for identity in ("outbox-worker", "retention-worker"):
        assert f"name: {identity}" in service_accounts

    assert "kind: Deployment" in outbox
    assert "serviceAccountName: outbox-worker" in outbox
    assert 'command: ["agent-platform-outbox"]' in outbox
    assert 'value: "outbox-worker"' in outbox
    assert "outbox-dsn" in outbox
    assert "AGENT_OPENAI_API_KEY" not in outbox
    assert "AGENT_BUSINESS_CREDENTIAL_REF" not in outbox
    assert "name: outbox-worker" in disruption_budgets
    assert "minAvailable: 1" in disruption_budgets

    assert "kind: CronJob" in retention
    assert "serviceAccountName: retention-worker" in retention
    assert 'command: ["agent-platform-retention"]' in retention
    assert 'value: "retention-worker"' in retention
    assert "retention-dsn" in retention
    assert "AGENT_ARTIFACT_KMS_KEY" in retention
    assert ".Values.secrets.cryptoSecretName" in retention
    assert ".Values.secrets.artifactKmsKeyIdKey" in retention
    assert "concurrencyPolicy: Forbid" in retention
    assert "AGENT_OPENAI_API_KEY" not in retention
    assert "AGENT_BUSINESS_CREDENTIAL_REF" not in retention

    assert ".Values.secrets.cryptoSecretName" not in outbox
    for workload in (outbox, retention):
        assert "AGENT_ACTION_PAYLOAD_ENCRYPTION_KEY" not in workload
        assert "AGENT_MEMORY_ENCRYPTION_KEY" not in workload
        assert "automountServiceAccountToken: false" in workload
        assert "runAsNonRoot: true" in workload
        assert "allowPrivilegeEscalation: false" in workload
        assert "readOnlyRootFilesystem: true" in workload
        assert 'drop: ["ALL"]' in workload


def test_helm_migration_uses_alembic_database_url_and_configured_secret() -> None:
    migration = _read("deploy/helm/agent-platform/templates/migration-job.yaml")

    assert "AGENT_DATABASE_URL" in migration
    assert "AGENT_DATABASE_DSN" not in migration
    assert ".Values.secrets.databaseSecretName" in migration


def test_helm_values_fail_closed_and_do_not_embed_secret_values() -> None:
    values = _read("deploy/helm/agent-platform/values.yaml")

    assert "sandbox:\n  enabled: false" in values

    for invariant in (
        "failClosed: true",
        "defaultEgress: deny",
        "traceContentCapture: false",
        "versioning: true",
        "defaultRetentionDays: 90",
        "runtimeClassName: gvisor",
        "podSecurityStandard: restricted",
    ):
        assert invariant in values
    assert "apiKey:" not in values
    assert "password:" not in values
    assert "secretKey:" not in values


def test_kustomize_and_terraform_keep_environment_and_digest_boundaries() -> None:
    base = _read("deploy/kustomize/base/kustomization.yaml")
    prod = _read("deploy/kustomize/overlays/prod/kustomization.yaml")
    namespace = _read("deploy/kustomize/overlays/prod/namespace-patch.yaml")
    variables = _read("deploy/terraform/variables.tf")
    main = _read("deploy/terraform/main.tf")

    assert "default-deny.yaml" in base
    assert "resource-quota.yaml" in base
    assert "environment: prod" in prod
    assert "pod-security.kubernetes.io/enforce: restricted" in namespace
    assert "image_digest" in variables
    assert "sha256:" in variables
    for contract in (
        "foundation_plan",
        "postgres",
        "artifact_storage",
        "temporal",
        "opa_bundle",
        "egress",
        "secret_manager",
    ):
        assert contract in variables
        assert contract in main
    assert "release_contract" in main
    assert "api_key" not in main.lower()
    assert "password" not in main.lower()
