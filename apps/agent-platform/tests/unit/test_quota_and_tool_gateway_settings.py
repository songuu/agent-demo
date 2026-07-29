from __future__ import annotations

import base64

import pytest
from pydantic import SecretStr, ValidationError
from tests.unit.test_config import CATALOG_SETTINGS, MALWARE_SETTINGS, QUOTA_SETTINGS

from agent_platform.config import Settings


def _staging_api() -> dict[str, object]:
    encoded_key = base64.b64encode(b"s" * 32).decode()
    return {
        "environment": "staging",
        **MALWARE_SETTINGS,
        **CATALOG_SETTINGS,
        **QUOTA_SETTINGS,
        "process_role": "api",
        "workflow_backend": "temporal",
        "persistence_backend": "postgres",
        "artifact_backend": "s3",
        "artifact_region": "ap-southeast-1",
        "policy_backend": "opa",
        "webhook_secret_dir": "/var/run/secrets/agent-platform/webhooks",
        "action_payload_encryption_key": SecretStr(encoded_key),
        "memory_encryption_key": SecretStr(encoded_key),
        "release_git_sha": "a" * 40,
        "release_image_digest": "sha256:" + "b" * 64,
    }


def test_staging_api_requires_hash_bound_catalog_and_shared_tls_redis() -> None:
    with pytest.raises(ValidationError) as caught:
        Settings.model_validate(
            {
                **_staging_api(),
                "tool_catalog_path": "",
                "tool_catalog_sha256": "",
                "quota_backend": "memory",
                "quota_redis_url": SecretStr(""),
                "quota_key_hmac_secret": SecretStr(""),
            }
        )

    message = str(caught.value)
    assert "TOOL_CATALOG_PATH_REQUIRED" in message
    assert "TOOL_CATALOG_DIGEST_REQUIRED" in message
    assert "SHARED_REDIS_CONTROL_REQUIRED" in message
    assert "QUOTA_REDIS_URL_REQUIRED" in message
    assert "QUOTA_KEY_HMAC_SECRET_REQUIRED" in message


def test_staging_api_rejects_non_tls_redis_and_catalog_digest_drift() -> None:
    with pytest.raises(ValidationError, match="QUOTA_REDIS_TLS_REQUIRED"):
        Settings.model_validate(
            {
                **_staging_api(),
                "quota_redis_url": SecretStr("redis://quota-redis.platform.svc:6379/0"),
            }
        )

    with pytest.raises(ValidationError, match="TOOL_CATALOG_DIGEST_INVALID"):
        Settings.model_validate(
            {
                **_staging_api(),
                "tool_catalog_sha256": "sha256:mutable",
            }
        )
