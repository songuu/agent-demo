"""Validated runtime configuration.

Configuration is intentionally stricter in production: development fallbacks
must never silently become a production control-plane dependency.
"""

from __future__ import annotations

import base64
import binascii
import re
from decimal import Decimal
from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

SUPPORTED_MODELS = frozenset({"gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"})
DIRECTORY_BACKEND = "directory"
AWS_MANAGER_BACKEND = "aws-secrets-manager"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AGENT_",
        env_nested_delimiter="__",
        extra="ignore",
        case_sensitive=False,
    )

    environment: Literal["dev", "test", "staging", "prod"] = "dev"
    process_role: Literal[
        "api",
        "agent-worker",
        "commit-worker",
        "outbox-worker",
        "retention-worker",
        "migration",
    ] = "api"
    service_name: str = "agent-api"
    database_dsn: SecretStr = SecretStr(
        "postgresql+asyncpg://agent_api:local-only@localhost:5432/agent_platform"
    )
    management_database_dsn: SecretStr = SecretStr("")
    temporal_address: str = "localhost:7233"
    temporal_namespace: str = "agent-platform-local"
    temporal_task_queue: str = "agent-runs"
    temporal_commit_task_queue: str = "agent-commits"
    temporal_api_key: SecretStr = SecretStr("")
    worker_health_port: int = Field(default=8081, ge=1, le=65_535)
    worker_metrics_port: int = Field(default=9464, ge=1, le=65_535)
    max_concurrent_activities: int = Field(default=20, ge=1, le=1_000)
    temporal_tls: bool | None = None
    temporal_worker_versioning_enabled: bool = True
    openai_api_key: SecretStr = SecretStr("")
    openai_base_url: str | None = None
    openai_project: str | None = None
    model_allowlist: tuple[str, ...] = (
        "gpt-5.6-sol",
        "gpt-5.6-terra",
        "gpt-5.6-luna",
    )
    model_pricing_catalog_path: str = ""
    cost_rate_catalog_path: str = ""
    cost_rate_catalog_sha256: str = ""
    model_max_in_flight: int = Field(default=20, ge=1, le=1_000)
    model_max_queued: int = Field(default=100, ge=0, le=10_000)
    model_queue_timeout_seconds: float = Field(default=5, gt=0, le=300)
    model_circuit_failure_threshold: int = Field(default=5, ge=1, le=100)
    model_circuit_recovery_seconds: float = Field(default=30, gt=0, le=3_600)
    tool_catalog_path: str = ""
    tool_catalog_sha256: str = ""
    tool_gateway_url: str | None = None
    tool_gateway_health_url: str | None = None
    tool_gateway_egress_proxy_url: str | None = None
    tool_gateway_timeout_seconds: float = Field(default=15, gt=0, le=300)
    tool_gateway_max_in_flight: int = Field(default=20, ge=1, le=1_000)
    tool_gateway_max_queued: int = Field(default=100, ge=0, le=10_000)
    tool_gateway_queue_timeout_seconds: float = Field(default=5, gt=0, le=300)
    tool_gateway_circuit_failure_threshold: int = Field(default=5, ge=1, le=100)
    tool_gateway_circuit_recovery_seconds: float = Field(default=30, gt=0, le=3_600)
    artifact_bucket: str = "agent-platform-local"
    artifact_staging_bucket: str | None = None
    artifact_kms_key: str | None = None
    artifact_restricted_kms_key: str | None = None
    artifact_secret_kms_key: str | None = None
    # Local MinIO has no KMS backend. This escape hatch is rejected outside dev.
    artifact_allow_unencrypted_local: bool = False
    artifact_retention_public_days: int = Field(default=90, ge=1, le=3_650)
    artifact_retention_internal_days: int = Field(default=90, ge=1, le=3_650)
    artifact_retention_confidential_days: int = Field(default=90, ge=1, le=3_650)
    artifact_retention_restricted_days: int = Field(default=90, ge=1, le=3_650)
    artifact_retention_secret_days: int = Field(default=90, ge=1, le=3_650)
    artifact_endpoint_url: str | None = None
    artifact_region: str | None = None
    artifact_presign_ttl_seconds: int = Field(default=300, ge=60, le=3_600)
    artifact_presign_enabled: bool = False
    artifact_malware_scan_mode: Literal["structural_only", "external"] = "structural_only"
    artifact_malware_scan_url: str | None = None
    artifact_malware_health_url: str | None = None
    artifact_malware_egress_proxy_url: str | None = None
    artifact_malware_scan_timeout_seconds: float = Field(default=10, gt=0, le=60)
    artifact_malware_max_result_age_seconds: int = Field(default=300, ge=30, le=3_600)
    opa_url: str = "http://localhost:8181"
    policy_fail_closed: bool = True
    otlp_endpoint: str | None = None
    max_request_bytes: int = Field(default=1_048_576, ge=1_024, le=10_485_760)
    artifact_max_upload_bytes: int = Field(
        default=200 * 1024 * 1024,
        ge=1024 * 1024,
        le=200 * 1024 * 1024,
    )
    artifact_max_in_memory_bytes: int = Field(
        default=8 * 1024 * 1024,
        ge=1024 * 1024,
        le=16 * 1024 * 1024,
    )
    quota_backend: Literal["memory", "redis"] = "memory"
    quota_redis_url: SecretStr = SecretStr("")
    quota_key_hmac_secret: SecretStr = SecretStr("")
    pre_auth_ip_requests_per_minute: int = Field(default=120, ge=1, le=1_000_000)
    user_requests_per_minute: int = Field(default=120, ge=1, le=1_000_000)
    tenant_requests_per_minute: int = Field(default=1_200, ge=1, le=1_000_000)
    use_case_requests_per_minute: int = Field(default=300, ge=1, le=1_000_000)
    ip_requests_per_minute: int = Field(default=120, ge=1, le=1_000_000)
    tenant_max_active_runs: int = Field(default=100, ge=1, le=100_000)
    queue_backlog_soft_limit: int = Field(default=500, ge=1, le=10_000_000)
    queue_oldest_age_soft_limit_seconds: float = Field(default=60, gt=0, le=86_400)
    critical_queue_multiplier: int = Field(default=2, ge=1, le=10)
    capacity_reservation_grace_seconds: int = Field(default=300, ge=30, le=3_600)
    tenant_daily_budget_usd: Decimal = Field(
        default=Decimal("1000"), gt=0, max_digits=18, decimal_places=6
    )
    tenant_monthly_budget_usd: Decimal = Field(
        default=Decimal("20000"), gt=0, max_digits=18, decimal_places=6
    )
    default_run_timeout_seconds: int = Field(default=900, ge=5, le=86_400)
    default_max_cost_usd: float = Field(default=5.0, gt=0, le=100_000)
    tracing_sample_ratio: float = Field(default=1.0, ge=0, le=1)
    trace_content_capture: bool = False
    store_model_content: bool = False

    auth_disabled: bool = False
    development_console_token: SecretStr = SecretStr("")
    jwt_issuer: str | None = None
    jwt_audience: str | None = None
    jwt_jwks_url: str | None = None
    trusted_proxy_cidrs: tuple[str, ...] = ()
    workflow_backend: Literal["inline", "temporal"] = "inline"
    persistence_backend: Literal["memory", "postgres"] = "memory"
    artifact_backend: Literal["memory", "s3"] = "memory"
    policy_backend: Literal["builtin", "opa"] = "builtin"
    enable_admin_api: bool = True
    api_base_path: str = ""
    release_git_sha: str = "development"
    release_image_digest: str = "development"
    eval_fault_harness_url: str | None = None
    eval_fault_harness_token: SecretStr = SecretStr("")
    shutdown_grace_seconds: int = Field(default=30, ge=1, le=300)
    webhook_replay_window_seconds: int = Field(default=300, ge=30, le=3_600)
    webhook_secret_dir: str = ""
    webhook_egress_proxy_url: str | None = None
    secret_backend: Literal["directory", "aws-secrets-manager"] = "directory"
    secrets_manager_prefix: str = "agent-platform"
    agent_credential_ref: str = ""
    business_credential_ref: str = ""
    prompt_registry_path: str = "prompts"
    webhook_worker_batch_size: int = Field(default=50, ge=1, le=1_000)
    webhook_worker_poll_seconds: float = Field(default=1.0, gt=0, le=60)
    webhook_delivery_timeout_seconds: int = Field(default=10, ge=1, le=300)
    webhook_delivery_max_attempts: int = Field(default=8, ge=1, le=20)
    action_payload_encryption_key: SecretStr = SecretStr("")
    memory_encryption_key: SecretStr = SecretStr("")

    @field_validator("openai_base_url")
    @classmethod
    def validate_openai_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().rstrip("/")
        parsed = urlsplit(normalized)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("OPENAI_BASE_URL_INVALID")
        return normalized

    @field_validator("tool_catalog_sha256")
    @classmethod
    def validate_tool_catalog_sha256(cls, value: str) -> str:
        normalized = value.strip()
        if normalized and not re.fullmatch(r"sha256:[0-9a-f]{64}", normalized):
            raise ValueError("TOOL_CATALOG_DIGEST_INVALID")
        return normalized

    @field_validator("cost_rate_catalog_sha256")
    @classmethod
    def validate_cost_rate_catalog_sha256(cls, value: str) -> str:
        normalized = value.strip()
        if normalized and not re.fullmatch(r"sha256:[0-9a-f]{64}", normalized):
            raise ValueError("COST_RATE_CATALOG_DIGEST_INVALID")
        return normalized

    @field_validator("eval_fault_harness_url")
    @classmethod
    def validate_eval_fault_harness_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().rstrip("/")
        parsed = urlsplit(normalized)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("EVAL_FAULT_HARNESS_TLS_REQUIRED")
        return normalized

    @field_validator("tool_gateway_url", "tool_gateway_health_url")
    @classmethod
    def validate_tool_gateway_https_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().rstrip("/")
        parsed = urlsplit(normalized)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("TOOL_GATEWAY_TLS_REQUIRED")
        return normalized

    @field_validator("tool_gateway_egress_proxy_url")
    @classmethod
    def validate_tool_gateway_proxy_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().rstrip("/")
        parsed = urlsplit(normalized)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("TOOL_GATEWAY_EGRESS_PROXY_INVALID")
        return normalized

    @field_validator("quota_redis_url")
    @classmethod
    def validate_quota_redis_url(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value().strip()
        if not raw:
            return SecretStr("")
        parsed = urlsplit(raw)
        if (
            parsed.scheme not in {"redis", "rediss"}
            or not parsed.hostname
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("QUOTA_REDIS_URL_INVALID")
        return SecretStr(raw)

    @field_validator("artifact_malware_scan_url", "artifact_malware_health_url")
    @classmethod
    def validate_artifact_malware_https_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().rstrip("/")
        parsed = urlsplit(normalized)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("ARTIFACT_MALWARE_SCAN_URL_INVALID")
        return normalized

    @field_validator("artifact_malware_egress_proxy_url")
    @classmethod
    def validate_artifact_malware_proxy_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().rstrip("/")
        parsed = urlsplit(normalized)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("ARTIFACT_MALWARE_EGRESS_PROXY_URL_INVALID")
        return normalized

    @field_validator("webhook_egress_proxy_url")
    @classmethod
    def validate_webhook_egress_proxy_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().rstrip("/")
        parsed = urlsplit(normalized)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("WEBHOOK_EGRESS_PROXY_URL_INVALID")
        return normalized

    @field_validator("model_allowlist", mode="before")
    @classmethod
    def parse_model_allowlist(cls, value: object) -> object:
        if isinstance(value, str):
            return tuple(part.strip() for part in value.split(",") if part.strip())
        return value

    @field_validator("model_allowlist")
    @classmethod
    def validate_model_allowlist(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        unknown = sorted(set(value) - SUPPORTED_MODELS)
        if unknown or not value:
            raise ValueError(f"MODEL_ALLOWLIST_INVALID: unknown={unknown!r}")
        return value

    @field_validator(
        "action_payload_encryption_key",
        "memory_encryption_key",
        "quota_key_hmac_secret",
    )
    @classmethod
    def validate_encryption_key(cls, value: SecretStr) -> SecretStr:
        encoded = value.get_secret_value()
        if not encoded:
            return value
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("ENCRYPTION_KEY_BASE64_INVALID") from exc
        if len(decoded) != 32:
            raise ValueError("ENCRYPTION_KEY_MUST_BE_32_BYTES")
        return value

    @model_validator(mode="after")
    def enforce_production_boundaries(self) -> Settings:
        violations: list[str] = []
        console_token = self.development_console_token.get_secret_value().strip()
        if console_token and len(console_token) < 32:
            violations.append("DEVELOPMENT_CONSOLE_TOKEN_TOO_SHORT")
        if console_token and self.environment not in {"dev", "test"}:
            violations.append("DEVELOPMENT_CONSOLE_TOKEN_ENVIRONMENT_FORBIDDEN")
        if console_token and not self.auth_disabled:
            violations.append("DEVELOPMENT_CONSOLE_TOKEN_REQUIRES_DISABLED_AUTH")
        fault_harness_url_configured = self.eval_fault_harness_url is not None
        fault_harness_token_configured = bool(
            self.eval_fault_harness_token.get_secret_value().strip()
        )
        if fault_harness_url_configured and not fault_harness_token_configured:
            violations.append("EVAL_FAULT_HARNESS_TOKEN_REQUIRED")
        if fault_harness_token_configured and not fault_harness_url_configured:
            violations.append("EVAL_FAULT_HARNESS_URL_REQUIRED")
        if self.environment == "prod" and (
            fault_harness_url_configured or fault_harness_token_configured
        ):
            violations.append("PRODUCTION_EVAL_FAULT_HARNESS_FORBIDDEN")
        if self.artifact_max_in_memory_bytes > self.artifact_max_upload_bytes:
            violations.append("ARTIFACT_MEMORY_LIMIT_EXCEEDS_UPLOAD_LIMIT")
        if self.environment in {"staging", "prod"} and self.store_model_content:
            violations.append("MODEL_RAW_CONTENT_STORAGE_FORBIDDEN")
        if self.artifact_malware_scan_mode == "external":
            if not self.artifact_malware_scan_url:
                violations.append("ARTIFACT_MALWARE_SCAN_URL_REQUIRED")
            if not self.artifact_malware_health_url:
                violations.append("ARTIFACT_MALWARE_HEALTH_URL_REQUIRED")
            if not self.artifact_malware_egress_proxy_url:
                violations.append("ARTIFACT_MALWARE_EGRESS_PROXY_REQUIRED")
        elif self.environment in {"staging", "prod"}:
            violations.append("ARTIFACT_MALWARE_EXTERNAL_SCANNER_REQUIRED")
        if self.artifact_allow_unencrypted_local and self.environment != "dev":
            violations.append("ARTIFACT_UNENCRYPTED_LOCAL_FORBIDDEN")
        if self.artifact_allow_unencrypted_local and any(
            (self.artifact_kms_key, self.artifact_restricted_kms_key, self.artifact_secret_kms_key)
        ):
            violations.append("ARTIFACT_ENCRYPTION_CONFIG_CONFLICT")

        if self.environment not in {"staging", "prod"}:
            if violations:
                raise ValueError("; ".join(violations))
            return self

        platform_roles = {"api", "agent-worker", "commit-worker"}
        if (
            self.process_role == "api"
            and not self.management_database_dsn.get_secret_value().strip()
        ):
            violations.append("PRODUCTION_MANAGEMENT_DATABASE_DSN_REQUIRED")
        if self.process_role in platform_roles:
            if self.quota_backend != "redis":
                violations.append("SHARED_REDIS_CONTROL_REQUIRED")
            quota_url = self.quota_redis_url.get_secret_value()
            if not quota_url:
                violations.append("QUOTA_REDIS_URL_REQUIRED")
            elif urlsplit(quota_url).scheme != "rediss":
                violations.append("QUOTA_REDIS_TLS_REQUIRED")
            if not self.quota_key_hmac_secret.get_secret_value():
                violations.append("QUOTA_KEY_HMAC_SECRET_REQUIRED")
            if not self.action_payload_encryption_key.get_secret_value():
                violations.append("ACTION_PAYLOAD_ENCRYPTION_KEY_REQUIRED")
            if not self.memory_encryption_key.get_secret_value():
                violations.append("MEMORY_ENCRYPTION_KEY_REQUIRED")
            if self.secret_backend == DIRECTORY_BACKEND and not self.webhook_secret_dir.strip():
                violations.append("WEBHOOK_SECRET_DIR_REQUIRED")
            if not self.artifact_region:
                violations.append("ARTIFACT_REGION_REQUIRED")
            staging_bucket = (self.artifact_staging_bucket or "").strip()
            if not staging_bucket:
                violations.append("ARTIFACT_STAGING_BUCKET_REQUIRED")
            elif staging_bucket == self.artifact_bucket.strip():
                violations.append("ARTIFACT_STAGING_BUCKET_MUST_DIFFER")
            if not (self.artifact_kms_key or "").strip():
                violations.append("ARTIFACT_KMS_KEY_REQUIRED")
            if not (self.artifact_restricted_kms_key or "").strip():
                violations.append("ARTIFACT_RESTRICTED_KMS_KEY_REQUIRED")
            if not (self.artifact_secret_kms_key or "").strip():
                violations.append("ARTIFACT_SECRET_KMS_KEY_REQUIRED")
            if not self.tool_catalog_path.strip():
                violations.append("TOOL_CATALOG_PATH_REQUIRED")
            if not self.tool_catalog_sha256:
                violations.append("TOOL_CATALOG_DIGEST_REQUIRED")
            if self.process_role in {"agent-worker", "commit-worker"}:
                if not self.tool_gateway_url:
                    violations.append("TOOL_GATEWAY_URL_REQUIRED")
                if not self.tool_gateway_health_url:
                    violations.append("TOOL_GATEWAY_HEALTH_URL_REQUIRED")
                if not self.tool_gateway_egress_proxy_url:
                    violations.append("TOOL_GATEWAY_EGRESS_PROXY_REQUIRED")
            if self.process_role == "agent-worker" and not (self.openai_project or "").strip():
                violations.append("OPENAI_PROJECT_REQUIRED")

        elif self.process_role == "retention-worker":
            if not self.artifact_region:
                violations.append("ARTIFACT_REGION_REQUIRED")
            if not (self.artifact_kms_key or "").strip():
                violations.append("RETENTION_ARCHIVE_KMS_KEY_REQUIRED")

        if self.environment != "prod":
            if violations:
                raise ValueError("; ".join(violations))
            return self

        if self.trace_content_capture:
            violations.append("PRODUCTION_TRACE_CONTENT_CAPTURE_FORBIDDEN")

        if self.process_role in platform_roles:
            if self.workflow_backend != "temporal":
                violations.append("PRODUCTION_TEMPORAL_REQUIRED")
            if self.persistence_backend != "postgres":
                violations.append("PRODUCTION_POSTGRES_REQUIRED")
            if self.artifact_backend != "s3":
                violations.append("PRODUCTION_OBJECT_STORE_REQUIRED")
            if self.policy_backend != "opa":
                violations.append("PRODUCTION_OPA_REQUIRED")
            if not self.policy_fail_closed:
                violations.append("PRODUCTION_POLICY_FAIL_CLOSED_REQUIRED")
            if self.secret_backend != AWS_MANAGER_BACKEND:
                violations.append("PRODUCTION_EXTERNAL_SECRET_BROKER_REQUIRED")
        elif self.process_role == "outbox-worker":
            if self.persistence_backend != "postgres":
                violations.append("PRODUCTION_POSTGRES_REQUIRED")
            if self.secret_backend != AWS_MANAGER_BACKEND:
                violations.append("PRODUCTION_EXTERNAL_SECRET_BROKER_REQUIRED")
            if not self.webhook_egress_proxy_url:
                violations.append("PRODUCTION_WEBHOOK_EGRESS_PROXY_REQUIRED")
        elif self.process_role == "retention-worker":
            if self.persistence_backend != "postgres":
                violations.append("PRODUCTION_POSTGRES_REQUIRED")
            if self.artifact_backend != "s3":
                violations.append("PRODUCTION_OBJECT_STORE_REQUIRED")
        elif self.process_role == "migration" and self.persistence_backend != "postgres":
            violations.append("PRODUCTION_POSTGRES_REQUIRED")

        if self.process_role == "api":
            if self.auth_disabled or not self.jwt_issuer or not self.jwt_audience:
                violations.append("PRODUCTION_AUTH_REQUIRED")
            if not self.artifact_presign_enabled:
                violations.append("PRODUCTION_ARTIFACT_PRESIGN_REQUIRED")

        if self.process_role == "commit-worker" and not self.business_credential_ref.strip():
            violations.append("PRODUCTION_BUSINESS_CREDENTIAL_REF_REQUIRED")
        if self.process_role == "agent-worker":
            if not self.openai_api_key.get_secret_value():
                violations.append("PRODUCTION_OPENAI_KEY_REQUIRED")
            if not self.agent_credential_ref.strip():
                violations.append("PRODUCTION_AGENT_CREDENTIAL_REF_REQUIRED")
            if not self.model_pricing_catalog_path.strip():
                violations.append("PRODUCTION_MODEL_PRICING_CATALOG_REQUIRED")
            if not self.cost_rate_catalog_path.strip():
                violations.append("PRODUCTION_COST_RATE_CATALOG_REQUIRED")
            if not self.cost_rate_catalog_sha256:
                violations.append("PRODUCTION_COST_RATE_CATALOG_DIGEST_REQUIRED")
            if not self.openai_base_url:
                violations.append("PRODUCTION_MODEL_GATEWAY_URL_REQUIRED")
            elif urlsplit(self.openai_base_url).scheme != "https":
                violations.append("PRODUCTION_MODEL_GATEWAY_TLS_REQUIRED")
        if self.worker_health_port == self.worker_metrics_port:
            violations.append("WORKER_HEALTH_PORTS_MUST_DIFFER")
        if self.release_git_sha == "development":
            violations.append("PRODUCTION_GIT_SHA_REQUIRED")
        if self.release_image_digest == "development":
            violations.append("PRODUCTION_IMAGE_DIGEST_REQUIRED")
        if violations:
            raise ValueError("; ".join(violations))
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def clear_settings_cache() -> None:
    """Allow isolated tests and controlled configuration reloads."""

    get_settings.cache_clear()
