from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SuccessCriterionRequest(ApiModel):
    id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    description: str = Field(min_length=1, max_length=2_000)
    severity: Literal["must", "should"] = "must"
    verification: Literal["schema", "evidence", "environment", "human"] = "evidence"


class BudgetRequest(ApiModel):
    max_cost_usd: Decimal = Field(gt=0, max_digits=14, decimal_places=6)
    max_duration_seconds: int = Field(ge=5, le=86_400)
    max_tool_calls: int = Field(default=100, ge=0, le=10_000)


class RequestedOutput(ApiModel):
    format: str = Field(min_length=1, max_length=128)


class CreateRunRequest(ApiModel):
    goal: str = Field(min_length=1, max_length=10_000)
    success_criteria: list[SuccessCriterionRequest] = Field(min_length=1, max_length=50)
    allowed_capabilities: list[str] = Field(min_length=1, max_length=50)
    constraints: dict[str, Any] = Field(default_factory=dict)
    budget: BudgetRequest
    external_write_policy: Literal["deny", "prepare_only", "approval"] = "deny"
    requested_output: RequestedOutput


class ResourceLinks(ApiModel):
    self: str
    events: str
    actions: str


class RunAcceptedResponse(ApiModel):
    run_id: UUID
    status: str
    created_at: datetime
    links: ResourceLinks


class ProgressView(ApiModel):
    completed_tasks: int
    total_tasks: int
    percent: int = Field(ge=0, le=100)


class BudgetView(ApiModel):
    cost_usd: Decimal
    cost_limit_usd: Decimal
    tool_calls: int
    elapsed_seconds: int


class PendingActionView(ApiModel):
    action_id: UUID
    action_type: str
    risk: str
    expires_at: datetime


class RunView(ApiModel):
    run_id: UUID
    status: str
    plan_version: int
    progress: ProgressView
    budget: BudgetView
    current_step: str
    pending_actions: list[PendingActionView]
    result: Any | None
    version: int
    updated_at: datetime


class CancelRunRequest(ApiModel):
    reason: str = Field(min_length=1, max_length=1_000)


class PauseRunRequest(ApiModel):
    reason: str = Field(min_length=1, max_length=1_000)


class ResumeRunRequest(ApiModel):
    constraints: dict[str, Any] | None = None


class ApprovalRequest(ApiModel):
    payload_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    comment: str | None = Field(default=None, max_length=2_000)


class RejectionRequest(ApiModel):
    payload_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str = Field(min_length=1, max_length=2_000)


class ActionRecoveryRequest(ApiModel):
    operation: Literal["reconcile", "compensate"]
    reason: str | None = Field(default=None, max_length=2_000)

    @model_validator(mode="after")
    def require_compensation_reason(self) -> ActionRecoveryRequest:
        if self.operation == "compensate" and not (self.reason or "").strip():
            raise ValueError("ACTION_RECOVERY_COMPENSATION_REASON_REQUIRED")
        return self


class ActionRecoveryAccepted(ApiModel):
    action_id: UUID
    run_id: UUID
    operation: Literal["reconcile", "compensate"]
    workflow_id: str
    status: Literal["accepted"] = "accepted"


class ActionView(ApiModel):
    action_id: UUID
    run_id: UUID
    action_type: str
    preview: dict[str, Any]
    payload_hash: str
    risk: str
    approval_policy: str
    required_approvals: int
    approvals_received: int
    status: str
    expires_at: datetime
    receipt: Any | None = None
    verification: Any | None = None


class ArtifactMetadataView(ApiModel):
    artifact_id: UUID
    run_id: UUID | None
    kind: str
    media_type: str
    size_bytes: int
    sha256: str
    classification: str
    retention_policy: str
    scan_status: str
    scan_provenance: dict[str, Any]
    object_version_id: str | None
    object_retain_until: datetime | None
    legal_hold_status: str
    expires_at: datetime | None


class CapabilityView(ApiModel):
    name: str
    version: str
    effect: str
    risk: str
    enabled: bool
    disabled_reason: str | None = None


class DisableCapabilityRequest(ApiModel):
    reason: str = Field(min_length=1, max_length=1_000)
    scope: Literal["capability", "tenant", "environment", "global"] = "capability"


class ErrorDetail(ApiModel):
    code: str
    message: str
    retryable: bool
    correlation_id: str
    details: dict[str, Any] = Field(default_factory=dict)


class ErrorResponse(ApiModel):
    error: ErrorDetail
