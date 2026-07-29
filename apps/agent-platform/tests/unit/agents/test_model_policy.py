from __future__ import annotations

from decimal import Decimal

import pytest

from agent_platform.agents.model_router import ModelPolicy
from agent_platform.domain.enums import RiskLevel


def test_model_routes_match_risk_and_role_policy() -> None:
    policy = ModelPolicy(allowlist=("gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"))

    critical = policy.route("verifier", RiskLevel.CRITICAL, 0, 0.8, Decimal("5"))
    assert critical.model == "gpt-5.6-sol"
    assert critical.reasoning == {"mode": "pro", "effort": "high"}
    assert critical.parallel_tool_calls is False

    worker = policy.route("worker", RiskLevel.MEDIUM, 0, 0.5, Decimal("5"))
    assert worker.model == "gpt-5.6-terra"
    assert worker.parallel_tool_calls is True

    classifier = policy.route("classifier", RiskLevel.LOW, 0, 0.2, Decimal("1"))
    assert classifier.model == "gpt-5.6-luna"


def test_retry_escalates_worker_and_user_cannot_select_model() -> None:
    policy = ModelPolicy(allowlist=("gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"))
    route = policy.route("worker", RiskLevel.MEDIUM, 1, 0.5, Decimal("5"))
    assert route.model == "gpt-5.6-sol"

    with pytest.raises(ValueError, match="MODEL_NOT_ALLOWED"):
        ModelPolicy(allowlist=("gpt-5.6-sol",)).validate_model("gpt-4o")
