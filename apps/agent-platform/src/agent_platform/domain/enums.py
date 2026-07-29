"""Stable domain enumerations shared by API, workflow, policy, and persistence."""

from __future__ import annotations

from enum import StrEnum


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


RISK_ORDER: dict[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


def max_risk(*levels: RiskLevel) -> RiskLevel:
    if not levels:
        raise ValueError("RISK_LEVEL_REQUIRED: at least one risk level is required")
    return max(levels, key=RISK_ORDER.__getitem__)


class RunStatus(StrEnum):
    RECEIVED = "received"
    CLASSIFIED = "classified"
    PLANNING = "planning"
    AUTHORIZED = "authorized"
    EXECUTING = "executing"
    REPLANNING = "replanning"
    VERIFYING = "verifying"
    WAITING_APPROVAL = "waiting_approval"
    COMMITTING = "committing"
    COMPENSATING = "compensating"
    # Controlled extension: the normative API defines resume while the base
    # enum omitted a durable paused state. Persisting it prevents fake resume.
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


class ActionStatus(StrEnum):
    PROPOSED = "proposed"
    PREPARED = "prepared"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    COMMITTING = "committing"
    UNKNOWN = "unknown"
    COMMITTED = "committed"
    VERIFY_FAILED = "verify_failed"
    COMPENSATING = "compensating"
    COMPENSATED = "compensated"
    COMPENSATION_FAILED = "compensation_failed"
    CANCELLED = "cancelled"


class ToolEffect(StrEnum):
    READ = "read"
    PREPARE = "prepare"
    COMMIT = "commit"


class PolicyDecisionAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"
    REQUIRE_APPROVAL = "approval_required"
    RESTRICT = "restrict"
    PAUSE = "pause"


class TrustLevel(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    GENERATED = "generated"


class TrajectoryAction(StrEnum):
    CONTINUE = "continue"
    WARN = "warn"
    RESTRICT = "restrict"
    PAUSE = "pause"
    TERMINATE = "terminate"


class DataClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    SECRET = "secret"  # nosec B105 - classification label, not a credential.


class ApprovalDecision(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"
