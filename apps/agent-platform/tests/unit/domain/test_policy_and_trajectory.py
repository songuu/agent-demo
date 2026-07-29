from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).parents[3] / "src"))

from agent_platform.domain import (
    DataClassification,
    DataScope,
    PolicyDecision,
    PolicyDecisionAction,
    RiskLevel,
    TrajectoryDecision,
)


def scope() -> DataScope:
    return DataScope(
        tenant_id="tenant-1",
        resource_types={"knowledge"},
        resource_ids={"doc-1"},
        allowed_fields={"title", "body"},
        classifications={DataClassification.INTERNAL},
    )


def test_allow_policy_carries_versioned_bounded_grant() -> None:
    decision = PolicyDecision(
        action=PolicyDecisionAction.ALLOW,
        reason_code="AUTHORIZED",
        policy_version="bundle-42",
        data_scope=scope(),
        credential_scope={"knowledge:read"},
        allowed_network_targets={"knowledge.internal.test"},
        classification=DataClassification.INTERNAL,
        risk=RiskLevel.MEDIUM,
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )

    assert decision.allowed
    assert not decision.approval_required


def test_deny_and_pause_decisions_cannot_smuggle_grants() -> None:
    for action in (PolicyDecisionAction.DENY, PolicyDecisionAction.PAUSE):
        with pytest.raises(ValidationError, match="POLICY_NON_ALLOWING_GRANT"):
            PolicyDecision(
                action=action,
                reason_code="BOUNDARY_DENIED",
                policy_version="bundle-42",
                credential_scope={"knowledge:read"},
            )


def test_approval_policy_requires_named_policy_and_count() -> None:
    with pytest.raises(ValidationError, match="POLICY_APPROVAL_REQUIREMENTS_MISSING"):
        PolicyDecision(
            action=PolicyDecisionAction.APPROVAL_REQUIRED,
            reason_code="HIGH_RISK_ACTION",
            policy_version="bundle-42",
            required_approvals=0,
        )


def test_trajectory_control_is_deterministic_and_fail_closed() -> None:
    decision = TrajectoryDecision(
        action="restrict",
        risk_score=0.85,
        reason_codes=["REPEATED_SCOPE_PROBING"],
        disabled_capabilities={"network.http", "email.prepare"},
        required_approval="security_review",
        evidence_event_ids=[11, 12],
    )
    assert decision.disabled_capabilities == {
        "network.http",
        "email.prepare",
    }

    with pytest.raises(ValidationError, match="TRAJECTORY_CONTROL_REASON_REQUIRED"):
        TrajectoryDecision(
            action="pause",
            risk_score=0.9,
            reason_codes=[],
            evidence_event_ids=[11],
        )

    with pytest.raises(ValidationError, match="TRAJECTORY_RISK_ACTION_MISMATCH"):
        TrajectoryDecision(
            action="continue",
            risk_score=0.99,
            reason_codes=["HIGH_RISK"],
            evidence_event_ids=[11],
        )
