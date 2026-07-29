from __future__ import annotations

import base64

import pytest
from pydantic import SecretStr, ValidationError
from tests.unit.test_config import (
    CATALOG_SETTINGS,
    KMS_SETTINGS,
    MALWARE_SETTINGS,
    QUOTA_SETTINGS,
    TOOL_GATEWAY_SETTINGS,
)

from agent_platform.config import Settings


def _staging_agent_worker() -> dict[str, object]:
    encoded_key = base64.b64encode(b"s" * 32).decode()
    return {
        "environment": "staging",
        "process_role": "agent-worker",
        **MALWARE_SETTINGS,
        **CATALOG_SETTINGS,
        **TOOL_GATEWAY_SETTINGS,
        **QUOTA_SETTINGS,
        **KMS_SETTINGS,
        "artifact_bucket": "agent-platform-staging",
        "artifact_staging_bucket": "agent-platform-staging-upload",
        "artifact_region": "ap-southeast-1",
        "webhook_secret_dir": "/var/run/secrets/agent-platform/webhooks",
        "action_payload_encryption_key": SecretStr(encoded_key),
        "memory_encryption_key": SecretStr(encoded_key),
    }


def test_staging_agent_requires_explicit_openai_project_for_circuit_isolation() -> None:
    with pytest.raises(ValidationError, match="OPENAI_PROJECT_REQUIRED"):
        Settings.model_validate(_staging_agent_worker())

    settings = Settings.model_validate(
        {
            **_staging_agent_worker(),
            "openai_project": "proj_agent_platform",
        }
    )
    assert settings.openai_project == "proj_agent_platform"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("model_max_in_flight", 0),
        ("model_max_queued", -1),
        ("model_queue_timeout_seconds", 0),
        ("model_circuit_failure_threshold", 0),
        ("model_circuit_recovery_seconds", 0),
    ),
)
def test_model_reliability_limits_are_bounded(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        Settings(environment="test", auth_disabled=True, **{field: value})
