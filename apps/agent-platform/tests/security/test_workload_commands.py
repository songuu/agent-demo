from __future__ import annotations

from pathlib import Path

PLATFORM_ROOT = Path(__file__).parents[2]
TEMPLATE_ROOT = PLATFORM_ROOT / "deploy" / "helm" / "agent-platform" / "templates"


def _template(name: str) -> str:
    return (TEMPLATE_ROOT / name).read_text(encoding="utf-8")


def test_helm_overrides_the_image_entrypoint_for_each_workload() -> None:
    api = _template("api-deployment.yaml")
    worker = _template("agent-worker-deployment.yaml")
    commit = _template("commit-worker-deployment.yaml")
    sandbox = _template("sandbox-job.yaml")

    assert 'command: ["agent-platform-api"]' in api
    assert 'args: ["agent-platform-api"]' not in api
    assert 'command: ["agent-platform-agent-worker"]' in worker
    assert "AGENT_TEMPORAL_TASK_QUEUE" in worker
    assert ".Values.worker.taskQueue" in worker
    assert 'command: ["agent-platform-commit-worker"]' in commit
    assert "AGENT_TEMPORAL_COMMIT_TASK_QUEUE" in commit
    assert ".Values.commitWorker.taskQueue" in commit
    assert 'command: ["python", "-c"]' in sandbox
    assert "agent_platform.infrastructure.sandbox" in sandbox
    assert "agent_platform.sandbox.entrypoint" not in sandbox


def test_compose_does_not_duplicate_the_api_image_entrypoint() -> None:
    compose = (PLATFORM_ROOT / "deploy" / "docker" / "docker-compose.yml").read_text(
        encoding="utf-8"
    )
    api_service = compose.split("  agent-api:", maxsplit=1)[1].split("  agent-worker:", maxsplit=1)[
        0
    ]

    assert 'command: ["agent-platform-api"]' not in api_service


def test_compose_enables_and_connects_the_complete_local_backend_stack() -> None:
    compose = (PLATFORM_ROOT / "deploy" / "docker" / "docker-compose.yml").read_text(
        encoding="utf-8"
    )

    assert compose.count("AGENT_ENVIRONMENT: dev") == 5
    assert "DB: postgres12" in compose
    assert '["CMD", "tctl", "--address", "temporal:7233", "cluster", "health"]' in compose
    assert "127.0.0.1:7233" not in compose
    assert "  commit-worker:" in compose
    assert compose.count("AGENT_PERSISTENCE_BACKEND: postgres") == 5
    assert compose.count("AGENT_WORKFLOW_BACKEND: temporal") == 3
    assert compose.count("AGENT_ARTIFACT_BACKEND: s3") == 4
    assert compose.count("AGENT_POLICY_BACKEND: opa") == 3

    assert compose.count("AGENT_ARTIFACT_ENDPOINT_URL: http://minio:9000") == 4
    assert compose.count("AWS_ACCESS_KEY_ID: minio") == 4
    assert compose.count("AWS_SECRET_ACCESS_KEY: minio-local-only") == 4
    assert "  minio-init:" in compose
    assert "  webhook-secret-init:" in compose
    assert "mc alias set local http://minio:9000" in compose
    assert "mc mb --ignore-existing local/agent-platform-local" in compose
    assert "condition: service_completed_successfully" in compose


def test_compose_separates_agent_and_commit_worker_processes_and_credentials() -> None:
    compose = (PLATFORM_ROOT / "deploy" / "docker" / "docker-compose.yml").read_text(
        encoding="utf-8"
    )
    agent_worker = compose.split("  agent-worker:", maxsplit=1)[1].split(
        "  commit-worker:", maxsplit=1
    )[0]
    commit_worker = compose.split("  commit-worker:", maxsplit=1)[1].split("volumes:", maxsplit=1)[
        0
    ]

    assert 'entrypoint: ["agent-platform-agent-worker"]' in agent_worker
    assert "AGENT_TEMPORAL_TASK_QUEUE: agent-runs" in agent_worker
    assert "AGENT_BUSINESS_CREDENTIAL_REF" not in agent_worker

    assert 'entrypoint: ["agent-platform-commit-worker"]' in commit_worker
    assert "AGENT_TEMPORAL_COMMIT_TASK_QUEUE: agent-commits" in commit_worker
    assert "AGENT_BUSINESS_CREDENTIAL_REF" in commit_worker
    assert "AGENT_OPENAI_API_KEY" not in commit_worker


def test_single_node_console_token_is_injected_only_into_the_api() -> None:
    override = (PLATFORM_ROOT / "deploy" / "docker" / "docker-compose.single-node.yml").read_text(
        encoding="utf-8"
    )
    api = override.split("  agent-api:", maxsplit=1)[1].split("  agent-worker:", maxsplit=1)[0]
    workers = override.split("  agent-worker:", maxsplit=1)[1]

    assert "AGENT_DEVELOPMENT_CONSOLE_TOKEN" in api
    assert "AGENT_PLATFORM_SINGLE_NODE_CONSOLE_TOKEN is required" in api
    assert "AGENT_DEVELOPMENT_CONSOLE_TOKEN" not in workers


def test_compose_has_isolated_outbox_and_retention_processes() -> None:
    compose = (PLATFORM_ROOT / "deploy" / "docker" / "docker-compose.yml").read_text(
        encoding="utf-8"
    )
    outbox = compose.split("  outbox-worker:", maxsplit=1)[1].split(
        "  retention-worker:", maxsplit=1
    )[0]
    retention = compose.split("  retention-worker:", maxsplit=1)[1].split("volumes:", maxsplit=1)[0]

    assert 'entrypoint: ["agent-platform-outbox"]' in outbox
    assert "AGENT_PROCESS_ROLE: outbox-worker" in outbox
    assert "AGENT_WEBHOOK_SECRET_DIR" in outbox
    assert "webhook-secret-init:" in outbox
    assert "condition: service_completed_successfully" in outbox
    assert "AGENT_OPENAI_API_KEY" not in outbox
    assert "AGENT_BUSINESS_CREDENTIAL_REF" not in outbox

    assert 'entrypoint: ["agent-platform-retention"]' in retention
    assert "AGENT_PROCESS_ROLE: retention-worker" in retention
    assert "AGENT_OPENAI_API_KEY" not in retention
    assert "AGENT_BUSINESS_CREDENTIAL_REF" not in retention
    assert "healthcheck: {disable: true}" in retention


def test_compose_initializes_local_secret_volume_without_privileging_runtime() -> None:
    compose = (PLATFORM_ROOT / "deploy" / "docker" / "docker-compose.yml").read_text(
        encoding="utf-8"
    )
    initializer = compose.split("  webhook-secret-init:", maxsplit=1)[1].split(
        "  agent-api:", maxsplit=1
    )[0]
    api = compose.split("  agent-api:", maxsplit=1)[1].split("  agent-worker:", maxsplit=1)[0]

    assert 'user: "0:0"' in initializer
    assert "chown 10001:10001 /secrets" in initializer
    assert "chmod 0700 /secrets" in initializer
    assert "healthcheck: {disable: true}" in initializer
    assert 'user: "0:0"' not in api
    assert "webhook-secret-init:" in api
    assert "condition: service_completed_successfully" in api


def test_compose_uses_role_specific_healthchecks() -> None:
    compose = (PLATFORM_ROOT / "deploy" / "docker" / "docker-compose.yml").read_text(
        encoding="utf-8"
    )
    migration = compose.split("  migration:", maxsplit=1)[1].split("  agent-api:", maxsplit=1)[0]
    agent_worker = compose.split("  agent-worker:", maxsplit=1)[1].split(
        "  commit-worker:", maxsplit=1
    )[0]
    commit_worker = compose.split("  commit-worker:", maxsplit=1)[1].split("volumes:", maxsplit=1)[
        0
    ]

    for worker in (agent_worker, commit_worker):
        assert "http://127.0.0.1:8081/health" in worker
        assert "http://127.0.0.1:8080/health" not in worker
    assert "healthcheck: {disable: true}" in migration


def test_compose_runs_database_migrations_before_application_workloads() -> None:
    dockerfile = (PLATFORM_ROOT / "deploy" / "docker" / "Dockerfile").read_text(encoding="utf-8")
    compose = (PLATFORM_ROOT / "deploy" / "docker" / "docker-compose.yml").read_text(
        encoding="utf-8"
    )

    assert "COPY migrations ./migrations" in dockerfile
    assert "COPY alembic.ini ./alembic.ini" in dockerfile
    assert "  migration:" in compose
    assert 'entrypoint: ["alembic", "upgrade", "head"]' in compose
    assert (
        "AGENT_DATABASE_URL: postgresql+asyncpg://agent:agent-local-only@postgres/agent_platform"
        in compose
    )


def test_runtime_healthcheck_targets_the_api_listener() -> None:
    dockerfile = (PLATFORM_ROOT / "deploy" / "docker" / "Dockerfile").read_text(encoding="utf-8")

    assert "http://127.0.0.1:8080/health" in dockerfile
    assert "http://127.0.0.1:8081/health" not in dockerfile


def test_helm_api_probes_and_metrics_target_the_real_listener() -> None:
    api = _template("api-deployment.yaml")
    services = _template("services.yaml")

    assert "{name: health, containerPort: 8081}" not in api
    assert "{name: metrics, containerPort: 9464}" not in api
    assert "httpGet: {path: /ready, port: http}" in api
    assert "httpGet: {path: /health, port: http}" in api
    assert "{name: metrics, port: 9464, targetPort: http}" in services


def test_helm_passes_role_specific_activity_concurrency_to_workers() -> None:
    worker = _template("agent-worker-deployment.yaml")
    commit = _template("commit-worker-deployment.yaml")

    assert "AGENT_MAX_CONCURRENT_ACTIVITIES" in worker
    assert ".Values.worker.maxConcurrentActivities" in worker
    assert "AGENT_MAX_CONCURRENT_ACTIVITIES" in commit
    assert ".Values.commitWorker.maxConcurrentActivities" in commit
