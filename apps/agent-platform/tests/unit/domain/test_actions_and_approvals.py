from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).parents[3] / "src"))

from agent_platform.domain import (
    ActionPreview,
    ActionStatus,
    ApprovalDecision,
    ApprovalRecord,
    PreparedAction,
    RiskLevel,
    validate_action_approvals,
)
from agent_platform.domain.errors import DomainInvariantError
from agent_platform.domain.hashing import payload_hash


def prepared_action(
    *,
    risk: RiskLevel = RiskLevel.HIGH,
    required_approvals: int = 1,
    expires_at: datetime | None = None,
) -> PreparedAction:
    canonical_payload = {
        "recipients": ["reviewer@example.test"],
        "subject": "Verified report",
    }
    return PreparedAction(
        action_id=uuid4(),
        run_id=uuid4(),
        tenant_id="tenant-1",
        principal_id="requester-1",
        action_type="email.send",
        tool_name="email.prepare",
        tool_version="1.0.0",
        canonical_payload=canonical_payload,
        payload_hash=payload_hash(canonical_payload),
        preview=ActionPreview(
            summary="Send one report email",
            target="reviewer@example.test",
            normalized_parameters=canonical_payload,
            expected_effects=["One email may be sent"],
        ),
        risk=risk,
        approval_policy="high-risk-v1",
        required_approvals=required_approvals,
        require_initiator_separation=True,
        status=ActionStatus.PENDING_APPROVAL,
        idempotency_key="a" * 64,
        policy_version="policy-2026-07",
        expires_at=expires_at or datetime.now(UTC) + timedelta(minutes=30),
    )


def approval(
    action: PreparedAction,
    *,
    actor_id: str,
    decision: ApprovalDecision = ApprovalDecision.APPROVED,
    payload_digest: str | None = None,
) -> ApprovalRecord:
    return ApprovalRecord(
        approval_id=uuid4(),
        action_id=action.action_id,
        actor_id=actor_id,
        actor_roles={"action_approver"},
        auth_strength="phishing_resistant",
        decision=decision,
        comment="Reviewed canonical parameters",
        policy_version=action.policy_version,
        payload_hash=payload_digest or action.payload_hash,
        decided_at=datetime.now(UTC),
    )


def test_prepared_action_rejects_payload_hash_mismatch() -> None:
    with pytest.raises(ValueError, match="ACTION_PAYLOAD_HASH_MISMATCH"):
        prepared_action().model_copy(
            update={"payload_hash": "f" * 64},
        ).model_validate(
            {
                **prepared_action().model_dump(),
                "payload_hash": "f" * 64,
            }
        )


def test_approval_is_bound_to_action_payload_policy_and_expiry() -> None:
    action = prepared_action()
    validate_action_approvals(action, [approval(action, actor_id="approver-1")])

    with pytest.raises(DomainInvariantError) as stale:
        validate_action_approvals(
            action,
            [
                approval(
                    action,
                    actor_id="approver-1",
                    payload_digest="b" * 64,
                )
            ],
        )
    assert stale.value.code == "STALE_ACTION_HASH"

    expired = prepared_action(expires_at=datetime.now(UTC) - timedelta(seconds=1))
    with pytest.raises(DomainInvariantError) as expiry:
        validate_action_approvals(
            expired,
            [approval(expired, actor_id="approver-1")],
        )
    assert expiry.value.code == "ACTION_EXPIRED"


def test_multi_party_approval_requires_distinct_non_initiators() -> None:
    action = prepared_action(
        risk=RiskLevel.CRITICAL,
        required_approvals=2,
    )

    with pytest.raises(DomainInvariantError) as duplicate:
        validate_action_approvals(
            action,
            [
                approval(action, actor_id="approver-1"),
                approval(action, actor_id="approver-1"),
            ],
        )
    assert duplicate.value.code == "APPROVAL_ACTOR_DUPLICATE"

    with pytest.raises(DomainInvariantError) as self_approval:
        validate_action_approvals(
            action,
            [
                approval(action, actor_id="requester-1"),
                approval(action, actor_id="approver-2"),
            ],
        )
    assert self_approval.value.code == "APPROVAL_INITIATOR_CONFLICT"

    validate_action_approvals(
        action,
        [
            approval(action, actor_id="approver-1"),
            approval(action, actor_id="approver-2"),
        ],
    )


def test_rejection_prevents_commit_even_when_other_actors_approved() -> None:
    action = prepared_action(required_approvals=1)
    with pytest.raises(DomainInvariantError) as rejected:
        validate_action_approvals(
            action,
            [
                approval(action, actor_id="approver-1"),
                approval(
                    action,
                    actor_id="approver-2",
                    decision=ApprovalDecision.REJECTED,
                ),
            ],
        )
    assert rejected.value.code == "ACTION_REJECTED"
