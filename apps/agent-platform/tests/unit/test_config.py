from __future__ import annotations

import base64

import pytest
from pydantic import SecretStr, ValidationError

from agent_platform.config import Settings

MALWARE_SETTINGS = {
    "artifact_malware_scan_mode": "external",
    "artifact_malware_scan_url": "https://scanner.security.example.test/v1/scan",
    "artifact_malware_health_url": "https://scanner.security.example.test/health",
    "artifact_malware_egress_proxy_url": "http://artifact-scan-egress-proxy:8443",
}
CATALOG_SETTINGS = {
    "tool_catalog_path": "/etc/agent-platform/tool-catalog.v1.json",
    "tool_catalog_sha256": "sha256:" + "c" * 64,
}
TOOL_GATEWAY_SETTINGS = {
    "tool_gateway_url": "https://tool-gateway.platform.svc",
    "tool_gateway_health_url": "https://tool-gateway.platform.svc/health",
    "tool_gateway_egress_proxy_url": "http://tool-egress-proxy.platform.svc:3128",
}
QUOTA_SETTINGS = {
    "quota_backend": "redis",
    "quota_redis_url": SecretStr("rediss://quota-redis.platform.svc:6379/0"),
    "quota_key_hmac_secret": SecretStr(base64.b64encode(b"q" * 32).decode()),
}
KMS_SETTINGS = {
    "artifact_kms_key": "arn:aws:kms:ap-southeast-1:111122223333:key/general",
    "artifact_restricted_kms_key": ("arn:aws:kms:ap-southeast-1:111122223333:key/restricted"),
    "artifact_secret_kms_key": "arn:aws:kms:ap-southeast-1:111122223333:key/secret",
}


def test_test_environment_can_use_explicit_ephemeral_backends() -> None:
    settings = Settings(
        environment="test",
        database_dsn=SecretStr("postgresql+asyncpg://test:test@localhost/test"),
        temporal_address="localhost:7233",
        temporal_namespace="test",
        openai_api_key=SecretStr(""),
        artifact_bucket="test",
        opa_url="http://opa.test",
        auth_disabled=True,
        workflow_backend="inline",
        persistence_backend="memory",
        artifact_backend="memory",
    )

    assert settings.model_allowlist == (
        "gpt-5.6-sol",
        "gpt-5.6-terra",
        "gpt-5.6-luna",
    )
    assert "test:test" not in repr(settings)


def test_production_rejects_insecure_backends_and_missing_identity_contract() -> None:
    with pytest.raises(ValidationError) as caught:
        Settings(
            environment="prod",
            database_dsn=SecretStr("postgresql+asyncpg://localhost/prod"),
            temporal_address="temporal:7233",
            temporal_namespace="prod",
            openai_api_key=SecretStr(""),
            artifact_bucket="prod",
            opa_url="http://opa:8181",
            auth_disabled=True,
            workflow_backend="inline",
            persistence_backend="memory",
            artifact_backend="memory",
        )

    message = str(caught.value)
    assert "PRODUCTION_AUTH_REQUIRED" in message
    assert "PRODUCTION_TEMPORAL_REQUIRED" in message
    assert "PRODUCTION_POSTGRES_REQUIRED" in message
    assert "PRODUCTION_OBJECT_STORE_REQUIRED" in message
    assert "PRODUCTION_OPA_REQUIRED" in message
    assert "ARTIFACT_MALWARE_EXTERNAL_SCANNER_REQUIRED" in message
    assert "PRODUCTION_ARTIFACT_PRESIGN_REQUIRED" in message
    assert "PRODUCTION_EXTERNAL_SECRET_BROKER_REQUIRED" in message
    assert "PRODUCTION_MANAGEMENT_DATABASE_DSN_REQUIRED" in message
    assert "PRODUCTION_GIT_SHA_REQUIRED" in message
    assert "PRODUCTION_IMAGE_DIGEST_REQUIRED" in message
    assert "ACTION_PAYLOAD_ENCRYPTION_KEY_REQUIRED" in message
    assert "MEMORY_ENCRYPTION_KEY_REQUIRED" in message
    assert "WEBHOOK_SECRET_DIR_REQUIRED" in message
    assert "ARTIFACT_REGION_REQUIRED" in message


def test_encryption_keys_are_strict_base64_encoded_32_byte_values() -> None:
    with pytest.raises(ValidationError, match="ENCRYPTION_KEY_BASE64_INVALID"):
        Settings(
            environment="test",
            auth_disabled=True,
            action_payload_encryption_key=SecretStr("not-base64"),
        )

    too_short = base64.b64encode(b"short").decode()
    with pytest.raises(ValidationError, match="ENCRYPTION_KEY_MUST_BE_32_BYTES"):
        Settings(
            environment="test",
            auth_disabled=True,
            memory_encryption_key=SecretStr(too_short),
        )


def test_staging_fails_closed_without_secret_provider_configuration() -> None:
    with pytest.raises(ValidationError) as caught:
        Settings(environment="staging")

    message = str(caught.value)
    assert "ACTION_PAYLOAD_ENCRYPTION_KEY_REQUIRED" in message
    assert "MEMORY_ENCRYPTION_KEY_REQUIRED" in message
    assert "WEBHOOK_SECRET_DIR_REQUIRED" in message
    assert "ARTIFACT_REGION_REQUIRED" in message


def test_staging_accepts_explicit_security_material_and_distributed_backends() -> None:
    encoded_key = base64.b64encode(b"s" * 32).decode()
    settings = Settings(
        environment="staging",
        **MALWARE_SETTINGS,
        **CATALOG_SETTINGS,
        **QUOTA_SETTINGS,
        **KMS_SETTINGS,
        process_role="api",
        database_dsn=SecretStr("postgresql+asyncpg://agent@postgres/staging"),
        management_database_dsn=SecretStr("postgresql+asyncpg://agent_management@postgres/staging"),
        temporal_address="temporal-staging:7233",
        temporal_namespace="agent-platform-staging",
        auth_disabled=False,
        jwt_issuer="https://identity.staging.example.test",
        jwt_audience="agent-platform-staging",
        workflow_backend="temporal",
        persistence_backend="postgres",
        artifact_backend="s3",
        artifact_bucket="agent-platform-staging",
        artifact_staging_bucket="agent-platform-staging-upload",
        artifact_region="ap-southeast-1",
        policy_backend="opa",
        opa_url="http://opa:8181",
        webhook_secret_dir="/var/run/secrets/agent-platform/webhooks",
        action_payload_encryption_key=SecretStr(encoded_key),
        memory_encryption_key=SecretStr(encoded_key),
        release_git_sha="a" * 40,
        release_image_digest="sha256:" + "b" * 64,
    )

    assert settings.environment == "staging"
    assert settings.persistence_backend == "postgres"
    assert settings.workflow_backend == "temporal"
    assert settings.secret_backend == "directory"
    assert settings.webhook_secret_dir.endswith("/webhooks")


def test_eval_fault_harness_configuration_is_paired_and_staging_only() -> None:
    with pytest.raises(ValidationError, match="EVAL_FAULT_HARNESS_TOKEN_REQUIRED"):
        Settings(
            environment="test",
            eval_fault_harness_url="https://fault-controller.staging.example.test",
        )

    with pytest.raises(ValidationError, match="EVAL_FAULT_HARNESS_URL_REQUIRED"):
        Settings(
            environment="test",
            eval_fault_harness_token=SecretStr("short-lived-token"),
        )

    configured = Settings(
        environment="test",
        eval_fault_harness_url="https://fault-controller.staging.example.test/",
        eval_fault_harness_token=SecretStr("short-lived-token"),
    )
    assert configured.eval_fault_harness_url == "https://fault-controller.staging.example.test"
    assert "short-lived-token" not in repr(configured)

    with pytest.raises(
        ValidationError,
        match="PRODUCTION_EVAL_FAULT_HARNESS_FORBIDDEN",
    ):
        Settings(
            environment="prod",
            eval_fault_harness_url="https://fault-controller.example.test",
            eval_fault_harness_token=SecretStr("short-lived-token"),
        )


@pytest.mark.parametrize(
    "url",
    (
        "http://fault-controller.staging.example.test",
        "https://user:secret@fault-controller.staging.example.test",
        "https://fault-controller.staging.example.test?token=secret",
    ),
)
def test_eval_fault_harness_requires_credential_free_https_url(url: str) -> None:
    with pytest.raises(ValidationError, match="EVAL_FAULT_HARNESS_TLS_REQUIRED"):
        Settings(
            environment="test",
            eval_fault_harness_url=url,
            eval_fault_harness_token=SecretStr("short-lived-token"),
        )


def test_staging_requires_an_unlocked_bucket_distinct_from_final_objects() -> None:
    with pytest.raises(ValidationError, match="ARTIFACT_STAGING_BUCKET_REQUIRED"):
        Settings(environment="staging")

    with pytest.raises(ValidationError, match="ARTIFACT_STAGING_BUCKET_MUST_DIFFER"):
        Settings(
            environment="staging",
            artifact_bucket="artifact-staging",
            artifact_staging_bucket="artifact-staging",
        )


def test_secure_production_secret_fields_are_redacted() -> None:
    encoded_key = base64.b64encode(b"k" * 32).decode()
    settings = Settings(
        environment="prod",
        **MALWARE_SETTINGS,
        **CATALOG_SETTINGS,
        **QUOTA_SETTINGS,
        **KMS_SETTINGS,
        auth_disabled=False,
        jwt_issuer="https://identity.example.test",
        jwt_audience="agent-platform",
        workflow_backend="temporal",
        persistence_backend="postgres",
        artifact_backend="s3",
        policy_backend="opa",
        policy_fail_closed=True,
        artifact_presign_enabled=True,
        artifact_staging_bucket="agent-platform-prod-upload",
        secret_backend="aws-secrets-manager",
        management_database_dsn=SecretStr(
            "postgresql+asyncpg://agent_admin:placeholder@postgres/admin"
        ),
        otlp_endpoint="http://otel-collector:4317",
        openai_api_key=SecretStr("openai-test-placeholder"),
        release_git_sha="a" * 40,
        release_image_digest="sha256:" + "b" * 64,
        artifact_region="ap-southeast-1",
        webhook_secret_dir="/var/run/secrets/agent-platform/webhooks",
        action_payload_encryption_key=SecretStr(encoded_key),
        memory_encryption_key=SecretStr(encoded_key),
        temporal_api_key=SecretStr("temporal-test-placeholder"),
        temporal_tls=True,
    )

    rendered = repr(settings)
    assert encoded_key not in rendered
    assert "temporal-test-placeholder" not in rendered
    assert settings.artifact_presign_ttl_seconds == 300
    assert settings.webhook_worker_batch_size == 50
    assert settings.policy_fail_closed is True
    assert settings.otlp_endpoint == "http://otel-collector:4317"


def test_unknown_model_alias_is_rejected_at_configuration_boundary() -> None:
    with pytest.raises(ValidationError, match="MODEL_ALLOWLIST_INVALID"):
        Settings(
            environment="test",
            database_dsn=SecretStr("postgresql+asyncpg://test:test@localhost/test"),
            temporal_address="localhost:7233",
            temporal_namespace="test",
            openai_api_key=SecretStr(""),
            artifact_bucket="test",
            opa_url="http://opa.test",
            auth_disabled=True,
            workflow_backend="inline",
            persistence_backend="memory",
            artifact_backend="memory",
            model_allowlist=("gpt-5.6-sol", "user-supplied-model"),
        )


def test_unencrypted_artifact_storage_is_allowed_only_for_local_development() -> None:
    settings = Settings(
        environment="dev",
        artifact_allow_unencrypted_local=True,
    )

    assert settings.artifact_allow_unencrypted_local is True

    for environment in ("test", "staging", "prod"):
        with pytest.raises(
            ValidationError,
            match="ARTIFACT_UNENCRYPTED_LOCAL_FORBIDDEN",
        ):
            Settings(
                environment=environment,
                artifact_allow_unencrypted_local=True,
            )

    with pytest.raises(
        ValidationError,
        match="ARTIFACT_ENCRYPTION_CONFIG_CONFLICT",
    ):
        Settings(
            environment="dev",
            artifact_allow_unencrypted_local=True,
            artifact_kms_key="kms-local",
        )


def test_only_agent_worker_requires_openai_key_in_production() -> None:
    encoded_key = base64.b64encode(b"k" * 32).decode()
    common = {
        "environment": "prod",
        **MALWARE_SETTINGS,
        **CATALOG_SETTINGS,
        **TOOL_GATEWAY_SETTINGS,
        **QUOTA_SETTINGS,
        **KMS_SETTINGS,
        "auth_disabled": False,
        "jwt_issuer": "https://identity.example.test",
        "jwt_audience": "agent-platform",
        "workflow_backend": "temporal",
        "persistence_backend": "postgres",
        "artifact_backend": "s3",
        "policy_backend": "opa",
        "artifact_presign_enabled": True,
        "artifact_staging_bucket": "agent-platform-prod-upload",
        "secret_backend": "aws-secrets-manager",
        "management_database_dsn": SecretStr(
            "postgresql+asyncpg://agent_admin:placeholder@postgres/admin"
        ),
        "agent_credential_ref": "broker://agent-read-prepare",
        "model_pricing_catalog_path": "/etc/agent-platform/model-pricing-v1.json",
        "cost_rate_catalog_path": "/etc/agent-platform/platform-cost-rates.v1.json",
        "cost_rate_catalog_sha256": "sha256:" + "d" * 64,
        "business_credential_ref": "broker://business-system",
        "release_git_sha": "a" * 40,
        "release_image_digest": "sha256:" + "b" * 64,
        "artifact_region": "ap-southeast-1",
        "openai_project": "proj_agent_platform",
        "webhook_secret_dir": "/var/run/secrets/agent-platform/webhooks",
        "webhook_egress_proxy_url": "http://webhook-egress-proxy:3128",
        "action_payload_encryption_key": SecretStr(encoded_key),
        "memory_encryption_key": SecretStr(encoded_key),
    }

    for role in (
        "api",
        "commit-worker",
        "outbox-worker",
        "retention-worker",
        "migration",
    ):
        settings = Settings.model_validate(
            {
                **common,
                "process_role": role,
                "openai_api_key": SecretStr(""),
            }
        )
        assert settings.openai_api_key.get_secret_value() == ""

    with pytest.raises(ValidationError, match="PRODUCTION_OPENAI_KEY_REQUIRED"):
        Settings.model_validate(
            {
                **common,
                "process_role": "agent-worker",
                "openai_api_key": SecretStr(""),
            }
        )

    with pytest.raises(
        ValidationError,
        match="PRODUCTION_MODEL_GATEWAY_URL_REQUIRED",
    ):
        Settings.model_validate(
            {
                **common,
                "process_role": "agent-worker",
                "openai_api_key": SecretStr("openai-test-placeholder"),
            }
        )

    with pytest.raises(ValidationError, match="OPENAI_PROJECT_REQUIRED"):
        Settings.model_validate(
            {
                **common,
                "process_role": "agent-worker",
                "openai_api_key": SecretStr("openai-test-placeholder"),
                "openai_base_url": "https://model-gateway.agent-platform.svc/v1/",
                "openai_project": "",
            }
        )

    with pytest.raises(
        ValidationError,
        match="PRODUCTION_MODEL_PRICING_CATALOG_REQUIRED",
    ):
        Settings.model_validate(
            {
                **common,
                "process_role": "agent-worker",
                "openai_api_key": SecretStr("openai-test-placeholder"),
                "openai_base_url": "https://model-gateway.agent-platform.svc/v1/",
                "model_pricing_catalog_path": "",
            }
        )

    agent_settings = Settings.model_validate(
        {
            **common,
            "process_role": "agent-worker",
            "openai_api_key": SecretStr("openai-test-placeholder"),
            "openai_base_url": "https://model-gateway.agent-platform.svc/v1/",
        }
    )
    assert agent_settings.process_role == "agent-worker"
    assert agent_settings.openai_base_url == "https://model-gateway.agent-platform.svc/v1"

    with pytest.raises(
        ValidationError,
        match="PRODUCTION_AGENT_CREDENTIAL_REF_REQUIRED",
    ):
        Settings.model_validate(
            {
                **common,
                "process_role": "agent-worker",
                "agent_credential_ref": "",
                "openai_api_key": SecretStr("openai-test-placeholder"),
                "openai_base_url": "https://model-gateway.agent-platform.svc/v1",
            }
        )

    with pytest.raises(
        ValidationError,
        match="PRODUCTION_POLICY_FAIL_CLOSED_REQUIRED",
    ):
        Settings.model_validate({**common, "policy_fail_closed": False})

    with pytest.raises(
        ValidationError,
        match="PRODUCTION_BUSINESS_CREDENTIAL_REF_REQUIRED",
    ):
        Settings.model_validate(
            {
                **common,
                "process_role": "commit-worker",
                "business_credential_ref": "",
            }
        )

    with pytest.raises(
        ValidationError,
        match="PRODUCTION_MODEL_GATEWAY_TLS_REQUIRED",
    ):
        Settings.model_validate(
            {
                **common,
                "process_role": "agent-worker",
                "openai_api_key": SecretStr("openai-test-placeholder"),
                "openai_base_url": "http://model-gateway.agent-platform.svc/v1",
            }
        )

    with pytest.raises(ValidationError, match="WORKER_HEALTH_PORTS_MUST_DIFFER"):
        Settings.model_validate(
            {
                **common,
                "worker_health_port": 8081,
                "worker_metrics_port": 8081,
            }
        )
