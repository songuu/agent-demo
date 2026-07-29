from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_platform.config import Settings
from agent_platform.infrastructure.persistence.models import ToolInvocation


def test_staging_and_production_forbid_persisting_raw_model_content() -> None:
    for environment in ("staging", "prod"):
        with pytest.raises(ValidationError) as caught:
            Settings(
                environment=environment,
                store_model_content=True,
            )

        assert "MODEL_RAW_CONTENT_STORAGE_FORBIDDEN" in str(caught.value)


def test_tool_invocation_persists_only_redacted_args_hash_and_artifact_reference() -> None:
    columns = set(ToolInvocation.__table__.columns.keys())

    assert {"args_hash", "args_redacted", "result_hash", "result_artifact_id"}.issubset(columns)
    assert {
        "args_json",
        "raw_args",
        "result_json",
        "raw_result",
        "result_content",
    }.isdisjoint(columns)
