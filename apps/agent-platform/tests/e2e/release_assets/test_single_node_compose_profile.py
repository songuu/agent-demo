from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[5]
BASE_COMPOSE = REPO_ROOT / "apps" / "agent-platform" / "deploy" / "docker" / "docker-compose.yml"
SINGLE_NODE_COMPOSE = BASE_COMPOSE.with_name("docker-compose.single-node.yml")

TEST_GIT_SHA = "0123456789abcdef0123456789abcdef01234567"
TEST_IMAGE_DIGEST = "sha256:" + "a" * 64

REQUIRED_ENV = {
    "AGENT_PLATFORM_IMAGE": "registry.invalid/agent-platform:test-single-node",
    "AGENT_PLATFORM_RELEASE_GIT_SHA": TEST_GIT_SHA,
    "AGENT_PLATFORM_RELEASE_IMAGE_DIGEST": TEST_IMAGE_DIGEST,
    "AGENT_PLATFORM_SINGLE_NODE_POSTGRES_USER": "single_node_db_user",
    "AGENT_PLATFORM_SINGLE_NODE_POSTGRES_PASSWORD": "test-postgres-password",
    "AGENT_PLATFORM_SINGLE_NODE_MINIO_ROOT_USER": "test-minio-access-key",
    "AGENT_PLATFORM_SINGLE_NODE_MINIO_ROOT_PASSWORD": "test-minio-secret-key",
    "AGENT_PLATFORM_SINGLE_NODE_QUOTA_HMAC_SECRET": (
        "dGVzdC1zaW5nbGUtbm9kZS1xdW90YS1obWFjLWtleQ=="
    ),
}

APP_SERVICES = {
    "migration",
    "webhook-secret-init",
    "agent-api",
    "agent-worker",
    "commit-worker",
    "outbox-worker",
    "retention-worker",
}

EXPECTED_PORTS = {
    "postgres": ("127.0.0.1", "15432", 5432),
    "redis": ("127.0.0.1", "16379", 6379),
    "temporal": ("127.0.0.1", "17233", 7233),
    "minio": [
        ("127.0.0.1", "19000", 9000),
        ("127.0.0.1", "19001", 9001),
    ],
    "opa": ("127.0.0.1", "18181", 8181),
    "agent-api": ("127.0.0.1", "5181", 8080),
}


def _compose_env(**overrides: str | None) -> dict[str, str]:
    env = os.environ.copy()
    for name, value in REQUIRED_ENV.items():
        env[name] = value
    for name, value in overrides.items():
        if value is None:
            env.pop(name, None)
        else:
            env[name] = value
    return env


def _compose_config(*, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    docker = shutil.which("docker")
    assert docker is not None, "Docker CLI is required for release-asset validation"
    # The executable is resolved to an absolute path and every argument is static.
    return subprocess.run(  # noqa: S603
        [
            docker,
            "compose",
            "--profile",
            "local",
            "-f",
            str(BASE_COMPOSE),
            "-f",
            str(SINGLE_NODE_COMPOSE),
            "config",
            "--format",
            "json",
        ],
        cwd=REPO_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


def _render_config() -> dict[str, Any]:
    result = _compose_config(env=_compose_env())
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _normalized_ports(service: dict[str, Any]) -> list[tuple[str, str, int]]:
    return sorted(
        (
            str(port["host_ip"]),
            str(port["published"]),
            int(port["target"]),
        )
        for port in service.get("ports", [])
    )


def test_single_node_compose_requires_external_credentials() -> None:
    for variable in (
        "AGENT_PLATFORM_SINGLE_NODE_POSTGRES_USER",
        "AGENT_PLATFORM_SINGLE_NODE_POSTGRES_PASSWORD",
        "AGENT_PLATFORM_SINGLE_NODE_MINIO_ROOT_USER",
        "AGENT_PLATFORM_SINGLE_NODE_MINIO_ROOT_PASSWORD",
        "AGENT_PLATFORM_SINGLE_NODE_QUOTA_HMAC_SECRET",
        "AGENT_PLATFORM_RELEASE_GIT_SHA",
        "AGENT_PLATFORM_RELEASE_IMAGE_DIGEST",
    ):
        result = _compose_config(env=_compose_env(**{variable: None}))

        assert result.returncode != 0
        assert variable in result.stderr


def test_single_node_compose_is_complete_local_only_and_image_driven() -> None:
    config = _render_config()
    services = config["services"]

    assert config["name"] == "agent-platform-single-node"
    assert set(services) == {
        "postgres",
        "redis",
        "temporal",
        "minio",
        "minio-init",
        "opa",
        *APP_SERVICES,
    }

    for service in services.values():
        assert service["profiles"] == ["local"]
        assert service["labels"]["com.songuu.agent-platform.deployment-mode"] == (
            "single-node-development-only"
        )
        assert float(service["cpus"]) > 0
        assert int(service["mem_limit"]) > 0

    for service_name in APP_SERVICES:
        service = services[service_name]
        assert service["image"] == REQUIRED_ENV["AGENT_PLATFORM_IMAGE"]
        assert "build" not in service
        assert service["pull_policy"] == "never"

    assert services["agent-api"]["environment"]["AGENT_ENVIRONMENT"] == "dev"
    assert services["agent-api"]["environment"]["AGENT_AUTH_DISABLED"] == "true"

    default_image_config = json.loads(
        _compose_config(env=_compose_env(AGENT_PLATFORM_IMAGE=None)).stdout
    )
    for service_name in APP_SERVICES:
        assert default_image_config["services"][service_name]["image"] == (
            "agent-platform:single-node"
        )


def test_single_node_profile_binds_release_identity_and_declares_degraded_scanner_policy() -> None:
    services = _render_config()["services"]

    for service_name in (
        "agent-api",
        "agent-worker",
        "commit-worker",
        "outbox-worker",
        "retention-worker",
    ):
        environment = services[service_name]["environment"]
        assert environment["AGENT_RELEASE_GIT_SHA"] == TEST_GIT_SHA
        assert environment["AGENT_RELEASE_IMAGE_DIGEST"] == TEST_IMAGE_DIGEST

    api = services["agent-api"]
    assert api["environment"]["AGENT_ARTIFACT_MALWARE_SCAN_MODE"] == "structural_only"
    assert api["healthcheck"]["timeout"] == "15s"
    for worker_name in ("agent-worker", "commit-worker"):
        worker_healthcheck = services[worker_name]["healthcheck"]
        assert "/ready" in " ".join(worker_healthcheck["test"])
        assert worker_healthcheck["timeout"] == "15s"
        assert worker_healthcheck["start_period"] == "1m0s"
        assert worker_healthcheck["retries"] == 5
    for service_name in (
        "agent-api",
        "agent-worker",
        "commit-worker",
        "retention-worker",
    ):
        assert (
            services[service_name]["environment"]["AGENT_ARTIFACT_ALLOW_UNENCRYPTED_LOCAL"]
            == "true"
        )


def test_single_node_profile_recovers_after_daemon_restart_and_schedules_retention() -> None:
    services = _render_config()["services"]

    for service_name in (
        "postgres",
        "redis",
        "temporal",
        "minio",
        "opa",
        "agent-api",
        "agent-worker",
        "commit-worker",
        "outbox-worker",
        "retention-worker",
    ):
        assert services[service_name]["restart"] == "unless-stopped"

    retention_entrypoint = " ".join(services["retention-worker"]["entrypoint"])
    assert "agent-platform-retention" in retention_entrypoint
    assert "sleep 86400" in retention_entrypoint

    for worker_name in ("agent-worker", "commit-worker"):
        assert (
            services[worker_name]["environment"]["AGENT_TEMPORAL_WORKER_VERSIONING_ENABLED"]
            == "false"
        )


def test_single_node_compose_fits_the_two_cpu_swap_budget() -> None:
    services = _render_config()["services"]

    assert sum(float(service["cpus"]) for service in services.values()) <= 2
    assert sum(int(service["mem_limit"]) for service in services.values()) <= 1760 * 1024**2
    for service in services.values():
        assert int(service["memswap_limit"]) == 2 * int(service["mem_limit"])


def test_single_node_compose_binds_only_reserved_loopback_ports() -> None:
    services = _render_config()["services"]

    for service_name, expected in EXPECTED_PORTS.items():
        expected_ports = expected if isinstance(expected, list) else [expected]
        assert _normalized_ports(services[service_name]) == sorted(expected_ports)

    for service in services.values():
        for port in service.get("ports", []):
            assert port["host_ip"] == "127.0.0.1"


def test_single_node_compose_replaces_local_credentials_and_limits_concurrency() -> None:
    config = _render_config()
    services = config["services"]
    serialized = json.dumps(config, sort_keys=True)

    assert "agent-local-only" not in serialized
    assert "minio-local-only" not in serialized
    assert "bG9jYWwtZGV2LXF1b3RhLWhtYWMta2V5LTMyYnl0ZXM=" not in serialized

    postgres_environment = services["postgres"]["environment"]
    assert (
        postgres_environment["POSTGRES_USER"]
        == REQUIRED_ENV["AGENT_PLATFORM_SINGLE_NODE_POSTGRES_USER"]
    )
    assert (
        postgres_environment["POSTGRES_PASSWORD"]
        == REQUIRED_ENV["AGENT_PLATFORM_SINGLE_NODE_POSTGRES_PASSWORD"]
    )
    postgres_healthcheck = " ".join(services["postgres"]["healthcheck"]["test"])
    assert "POSTGRES_USER" in postgres_healthcheck
    assert "POSTGRES_DB" in postgres_healthcheck

    minio_environment = services["minio"]["environment"]
    assert (
        minio_environment["MINIO_ROOT_USER"]
        == REQUIRED_ENV["AGENT_PLATFORM_SINGLE_NODE_MINIO_ROOT_USER"]
    )
    assert (
        minio_environment["MINIO_ROOT_PASSWORD"]
        == REQUIRED_ENV["AGENT_PLATFORM_SINGLE_NODE_MINIO_ROOT_PASSWORD"]
    )

    api_environment = services["agent-api"]["environment"]
    assert (
        api_environment["AGENT_QUOTA_KEY_HMAC_SECRET"]
        == REQUIRED_ENV["AGENT_PLATFORM_SINGLE_NODE_QUOTA_HMAC_SECRET"]
    )

    for worker_name in ("agent-worker", "commit-worker"):
        assert services[worker_name]["environment"]["AGENT_MAX_CONCURRENT_ACTIVITIES"] == "1"
    assert services["outbox-worker"]["environment"]["AGENT_WEBHOOK_WORKER_BATCH_SIZE"] == "1"

    assert services["agent-worker"]["environment"]["AGENT_OPENAI_API_KEY"] == ""
    for service_name in APP_SERVICES - {"agent-worker"}:
        assert "AGENT_OPENAI_API_KEY" not in services[service_name].get("environment", {})
