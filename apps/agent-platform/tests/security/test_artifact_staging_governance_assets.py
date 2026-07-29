from __future__ import annotations

from pathlib import Path

PLATFORM_ROOT = Path(__file__).resolve().parents[2]


def _read(path: str) -> str:
    return (PLATFORM_ROOT / path).read_text(encoding="utf-8")


def test_helm_injects_a_distinct_multipart_staging_bucket() -> None:
    values = _read("deploy/helm/agent-platform/values.yaml")
    configmap = _read("deploy/helm/agent-platform/templates/configmap.yaml")

    assert "artifactBucket: agent-platform-prod" in values
    assert "artifactStagingBucket: agent-platform-prod-staging" in values
    assert "AGENT_ARTIFACT_STAGING_BUCKET" in configmap
    assert ".Values.config.artifactStagingBucket" in configmap


def test_local_minio_separates_locked_final_objects_from_short_lived_staging() -> None:
    compose = _read("deploy/docker/docker-compose.yml")

    assert "mc mb --ignore-existing --with-lock local/agent-platform-local" in compose
    assert "mc version enable local/agent-platform-local" in compose
    assert "mc mb --ignore-existing local/agent-platform-local-staging" in compose
    assert "mc ilm rule add --expire-days 1 local/agent-platform-local-staging" in compose
    assert compose.count(
        "AGENT_ARTIFACT_STAGING_BUCKET: agent-platform-local-staging"
    ) == 4


def test_cloud_foundation_contract_requires_unlocked_isolated_staging_controls() -> None:
    variables = _read("deploy/terraform/variables.tf")
    main = _read("deploy/terraform/main.tf")

    assert 'artifact_storage" {' in variables
    assert "staging = object({" in variables
    assert "abort_incomplete_multipart_days" in variables
    assert "noncurrent_version_expiration_days" in variables
    assert "!var.artifact_storage.staging.object_lock_enabled" in main
    assert (
        "var.artifact_storage.staging.bucket_reference !="
        " var.artifact_storage.final.bucket_reference"
    ) in main
