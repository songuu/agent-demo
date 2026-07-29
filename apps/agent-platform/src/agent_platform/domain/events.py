"""Immutable event contracts for replay, SSE, audit, and outbox delivery."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Self
from uuid import UUID, uuid4

from pydantic import Field, model_validator

from .base import JsonValue, StrictDomainModel, UtcDateTime
from .hashing import payload_hash


class RunEventType(StrEnum):
    RUN_STATUS_CHANGED = "run.status_changed"
    PLAN_CREATED = "plan.created"
    PLAN_REVISED = "plan.revised"
    TASK_STARTED = "task.started"
    TASK_COMPLETED = "task.completed"
    TASK_FAILED = "task.failed"
    ARTIFACT_CREATED = "artifact.created"
    ACTION_PREPARED = "action.prepared"
    ACTION_APPROVAL_REQUIRED = "action.approval_required"
    ACTION_APPROVED = "action.approved"
    ACTION_REJECTED = "action.rejected"
    ACTION_EXPIRED = "action.expired"
    ACTION_COMMITTED = "action.committed"
    ACTION_UNKNOWN = "action.unknown"
    ACTION_FAILED = "action.failed"
    POLICY_DENIED = "policy.denied"
    BUDGET_WARNING = "budget.warning"
    BUDGET_EXHAUSTED = "budget.exhausted"
    TRAJECTORY_DECISION = "trajectory.decision"
    RUN_COMPLETED = "run.completed"
    RUN_FAILED = "run.failed"
    RUN_CANCELLED = "run.cancelled"


ActionExpiryReason = Literal["workflow_approval_timeout", "retention_fallback"]


def action_expired_event_payload(
    *,
    run_id: UUID,
    action_id: UUID,
    payload_digest: str,
    previous_status: str,
    scheduled_expires_at: datetime,
    expired_at: datetime,
    reason: ActionExpiryReason,
) -> dict[str, JsonValue]:
    if len(payload_digest) != 64:
        raise ValueError("ACTION_EXPIRY_PAYLOAD_HASH_INVALID")
    if reason not in {"workflow_approval_timeout", "retention_fallback"}:
        raise ValueError("ACTION_EXPIRY_REASON_INVALID")
    return {
        "run_id": str(run_id),
        "action_id": str(action_id),
        "payload_hash": payload_digest,
        "previous_status": previous_status,
        "scheduled_expires_at": scheduled_expires_at.isoformat(),
        "expired_at": expired_at.isoformat(),
        "reason": reason,
    }


_SENSITIVE_KEYS = {
    "api_key",
    "authorization",
    "cookie",
    "credentials",
    "password",
    "private_key",
    "secret",
    "token",
}


def _find_sensitive_key(value: JsonValue, *, path: str = "payload") -> str | None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = key.strip().lower().replace("-", "_")
            if (
                normalized in _SENSITIVE_KEYS
                or normalized.endswith("_password")
                or normalized.endswith("_secret")
                or normalized.endswith("_token")
            ):
                return f"{path}.{key}"
            nested = _find_sensitive_key(item, path=f"{path}.{key}")
            if nested:
                return nested
    elif isinstance(value, list):
        for index, item in enumerate(value):
            nested = _find_sensitive_key(item, path=f"{path}[{index}]")
            if nested:
                return nested
    return None


class DomainEvent(StrictDomainModel):
    schema_version: str = Field(default="1.0", pattern=r"^\d+\.\d+$")
    event_id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    tenant_id: str = Field(min_length=1, max_length=256)
    sequence_no: int = Field(ge=0)
    event_type: RunEventType
    actor_type: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(min_length=1, max_length=256)
    correlation_id: str = Field(min_length=1, max_length=256)
    occurred_at: UtcDateTime = Field(default_factory=lambda: datetime.now(UTC))
    payload: dict[str, JsonValue] = Field(default_factory=dict)
    payload_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_audit_payload(self) -> Self:
        sensitive_path = _find_sensitive_key(self.payload)
        if sensitive_path:
            raise ValueError(
                "EVENT_SENSITIVE_FIELD_FORBIDDEN: "
                f"{sensitive_path} cannot enter events or audit logs"
            )
        computed_hash = payload_hash(self.payload)
        if self.payload_hash is not None and self.payload_hash != computed_hash:
            raise ValueError("EVENT_PAYLOAD_HASH_MISMATCH: payload changed after hashing")
        if self.payload_hash is None:
            object.__setattr__(self, "payload_hash", computed_hash)
        return self
