"""Deterministic policy and approval decisions outside model reasoning."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Self

from pydantic import Field, model_validator

from .base import JsonValue, StrictDomainModel, UtcDateTime, normalize_utc_datetime
from .enums import (
    ApprovalDecision,
    DataClassification,
    PolicyDecisionAction,
    RiskLevel,
    TrajectoryAction,
)
from .errors import DomainInvariantError
from .models import ApprovalRecord, DataScope, PreparedAction


class PolicyDecision(StrictDomainModel):
    action: PolicyDecisionAction
    reason_code: str = Field(min_length=1, max_length=256)
    policy_version: str = Field(min_length=1, max_length=256)
    data_scope: DataScope | None = None
    credential_scope: frozenset[str] = Field(default_factory=frozenset)
    allowed_network_targets: frozenset[str] = Field(default_factory=frozenset)
    field_restrictions: dict[str, JsonValue] = Field(default_factory=dict)
    rate_limit: int | None = Field(default=None, ge=1)
    classification: DataClassification | None = None
    risk: RiskLevel | None = None
    approval_policy: str | None = Field(default=None, min_length=1, max_length=256)
    required_approvals: int = Field(default=0, ge=0, le=10)
    require_initiator_separation: bool = False
    expires_at: UtcDateTime | None = None

    @model_validator(mode="after")
    def validate_decision_contract(self) -> Self:
        if self.action is PolicyDecisionAction.APPROVAL_REQUIRED and (
            not self.approval_policy or self.required_approvals < 1
        ):
            raise ValueError(
                "POLICY_APPROVAL_REQUIREMENTS_MISSING: "
                "approval_required needs a policy and at least one approver"
            )
        if self.action in {
            PolicyDecisionAction.DENY,
            PolicyDecisionAction.PAUSE,
        } and (
            self.data_scope is not None
            or self.credential_scope
            or self.allowed_network_targets
            or self.field_restrictions
            or self.rate_limit is not None
        ):
            raise ValueError(
                "POLICY_NON_ALLOWING_GRANT: deny/pause decisions cannot carry grants"
            )
        if self.action in {
            PolicyDecisionAction.ALLOW,
            PolicyDecisionAction.RESTRICT,
            PolicyDecisionAction.APPROVAL_REQUIRED,
        } and self.expires_at is None:
            raise ValueError(
                "POLICY_EXPIRY_REQUIRED: an allowing decision must be short-lived"
            )
        if (
            self.action is not PolicyDecisionAction.APPROVAL_REQUIRED
            and self.required_approvals
        ):
            raise ValueError(
                "POLICY_APPROVAL_ACTION_MISMATCH: approvals only apply to approval_required"
            )
        return self

    @property
    def allowed(self) -> bool:
        return self.action in {
            PolicyDecisionAction.ALLOW,
            PolicyDecisionAction.RESTRICT,
            PolicyDecisionAction.APPROVAL_REQUIRED,
        }

    @property
    def approval_required(self) -> bool:
        return self.action is PolicyDecisionAction.APPROVAL_REQUIRED


class TrajectoryDecision(StrictDomainModel):
    action: TrajectoryAction
    risk_score: float = Field(ge=0, le=1)
    reason_codes: list[str] = Field(default_factory=list, max_length=100)
    disabled_capabilities: frozenset[str] = Field(default_factory=frozenset)
    required_approval: str | None = Field(default=None, min_length=1, max_length=256)
    evidence_event_ids: list[int] = Field(default_factory=list, max_length=1_000)

    @model_validator(mode="after")
    def validate_control_evidence(self) -> Self:
        controlled = self.action in {
            TrajectoryAction.RESTRICT,
            TrajectoryAction.PAUSE,
            TrajectoryAction.TERMINATE,
        }
        if controlled and (not self.reason_codes or not self.evidence_event_ids):
            raise ValueError(
                "TRAJECTORY_CONTROL_REASON_REQUIRED: "
                "restrict/pause/terminate needs reasons and evidence events"
            )
        if self.action is TrajectoryAction.CONTINUE and self.risk_score >= 0.8:
            raise ValueError(
                "TRAJECTORY_RISK_ACTION_MISMATCH: high-risk trajectory cannot continue"
            )
        if self.action is TrajectoryAction.RESTRICT and not self.disabled_capabilities:
            raise ValueError(
                "TRAJECTORY_RESTRICTION_REQUIRED: restrict must disable a capability"
            )
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise ValueError("TRAJECTORY_DUPLICATE_REASON: reason codes must be unique")
        if len(set(self.evidence_event_ids)) != len(self.evidence_event_ids):
            raise ValueError("TRAJECTORY_DUPLICATE_EVENT: event ids must be unique")
        if any(event_id < 1 for event_id in self.evidence_event_ids):
            raise ValueError("TRAJECTORY_EVENT_ID_INVALID: event ids must be positive")
        return self


_AUTH_STRENGTH = {
    "password": 0,  # nosec B105 - authentication-strength category.
    "mfa": 1,
    "phishing_resistant": 2,
}


def validate_action_approvals(
    action: PreparedAction,
    approvals: list[ApprovalRecord],
    *,
    at: datetime | None = None,
) -> tuple[ApprovalRecord, ...]:
    """Prove approvals apply to exactly this immutable, unexpired action."""
    now = normalize_utc_datetime(at or datetime.now(UTC))
    if now >= action.expires_at:
        raise DomainInvariantError(
            "ACTION_EXPIRED",
            "prepared action expired before commit authorization",
            context={"action_id": str(action.action_id)},
        )
    for record in approvals:
        if record.action_id != action.action_id:
            raise DomainInvariantError(
                "APPROVAL_ACTION_MISMATCH",
                "approval belongs to another action",
                context={
                    "action_id": str(action.action_id),
                    "approval_action_id": str(record.action_id),
                },
            )
        if record.payload_hash != action.payload_hash:
            raise DomainInvariantError(
                "STALE_ACTION_HASH",
                "approval payload hash no longer matches the prepared action",
                context={
                    "action_id": str(action.action_id),
                    "expected_payload_hash": action.payload_hash,
                    "approval_payload_hash": record.payload_hash,
                },
            )
        if record.policy_version != action.policy_version:
            raise DomainInvariantError(
                "STALE_POLICY_VERSION",
                "approval used a different policy version",
                context={
                    "action_id": str(action.action_id),
                    "expected_policy_version": action.policy_version,
                    "approval_policy_version": record.policy_version,
                },
            )
        if record.decision is ApprovalDecision.REJECTED:
            raise DomainInvariantError(
                "ACTION_REJECTED",
                "an approver rejected the action",
                context={
                    "action_id": str(action.action_id),
                    "actor_id": record.actor_id,
                },
            )

    approved = [
        record
        for record in approvals
        if record.decision is ApprovalDecision.APPROVED
    ]
    actor_ids = [record.actor_id for record in approved]
    if len(actor_ids) != len(set(actor_ids)):
        raise DomainInvariantError(
            "APPROVAL_ACTOR_DUPLICATE",
            "one actor cannot satisfy multiple required approvals",
            context={"action_id": str(action.action_id)},
        )
    if action.require_initiator_separation and action.principal_id in actor_ids:
        raise DomainInvariantError(
            "APPROVAL_INITIATOR_CONFLICT",
            "the action initiator cannot approve this action",
            context={
                "action_id": str(action.action_id),
                "principal_id": action.principal_id,
            },
        )
    for record in approved:
        if (
            _AUTH_STRENGTH[record.auth_strength]
            < _AUTH_STRENGTH[action.minimum_auth_strength]
        ):
            raise DomainInvariantError(
                "APPROVAL_AUTH_STRENGTH_INSUFFICIENT",
                "approval did not use the required step-up authentication",
                context={
                    "action_id": str(action.action_id),
                    "actor_id": record.actor_id,
                    "required": action.minimum_auth_strength,
                    "actual": record.auth_strength,
                },
            )
        if action.required_approver_roles and not (
            record.actor_roles & action.required_approver_roles
        ):
            raise DomainInvariantError(
                "APPROVAL_ROLE_REQUIRED",
                "approver does not hold a required role",
                context={
                    "action_id": str(action.action_id),
                    "actor_id": record.actor_id,
                },
            )
    if len(approved) < action.required_approvals:
        raise DomainInvariantError(
            "APPROVAL_COUNT_INSUFFICIENT",
            "not enough valid distinct approvals",
            context={
                "action_id": str(action.action_id),
                "required": action.required_approvals,
                "actual": len(approved),
            },
        )
    return tuple(approved)
