"""Durable record shapes used by repositories and API projections."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from agent_platform.domain.enums import (
    ActionStatus,
    DataClassification,
    RiskLevel,
    RunStatus,
    ToolEffect,
)


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(slots=True)
class RunRecord:
    run_id: UUID
    tenant_id: str
    principal_id: str
    contract: Any
    idempotency_key: str
    request_hash: str
    workflow_id: str
    status: RunStatus = RunStatus.RECEIVED
    plan: Any | None = None
    outputs: dict[str, Any] = field(default_factory=dict)
    result: Any | None = None
    failure_code: str | None = None
    progress: float = 0.0
    cost_actual_usd: Decimal = Decimal("0")
    token_input: int = 0
    token_output: int = 0
    tool_call_count: int = 0
    version: int = 1
    current_plan_version: int = 0
    cancellation_requested: bool = False
    pause_requested: bool = False
    paused_from: RunStatus | None = None
    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)
    completed_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class EventRecord:
    event_id: str
    run_id: UUID
    tenant_id: str
    sequence_no: int
    event_type: str
    payload: dict[str, Any]
    correlation_id: str
    created_at: datetime = field(default_factory=utcnow)
    schema_version: str = "1.0"
    actor_type: str = "application"
    actor_id: str | None = None
    task_id: str | None = None
    action_id: UUID | None = None
    payload_hash: str = ""


@dataclass(slots=True)
class ActionRecord:
    action_id: UUID
    run_id: UUID
    tenant_id: str
    principal_id: str
    action_type: str
    tool_name: str
    tool_version: str
    canonical_payload: dict[str, Any]
    payload_hash: str
    preview: dict[str, Any]
    risk: RiskLevel
    approval_policy: str
    required_approvals: int
    idempotency_key: str
    policy_version: str
    expires_at: datetime
    status: ActionStatus = ActionStatus.PREPARED
    approvals: list[Any] = field(default_factory=list)
    receipt: Any | None = None
    verification: Any | None = None
    failure_code: str | None = None
    version: int = 1
    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Append-only business event staged inside a repository transaction."""

    event_type: str
    payload: dict[str, Any]
    correlation_id: str
    actor_type: str = "application"
    actor_id: str | None = None
    task_id: str | None = None
    action_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class PlanExecutionRecord:
    plan_id: UUID
    run_id: UUID
    tenant_id: str
    plan_version: int
    schema_version: str
    plan_json: dict[str, Any]
    plan_hash: str
    planner_model: str
    prompt_id: str
    prompt_version: str
    validation_status: str = "validated"
    created_at: datetime = field(default_factory=utcnow)


@dataclass(slots=True)
class TaskExecutionRecord:
    task_execution_id: UUID
    run_id: UUID
    tenant_id: str
    plan_version: int
    task_id: str
    task_kind: str
    attempt: int
    status: str
    model_name: str | None = None
    model_settings: dict[str, Any] | None = None
    prompt_id: str | None = None
    prompt_version: str | None = None
    input_refs: list[Any] = field(default_factory=list)
    output_json: dict[str, Any] | None = None
    output_artifact_id: UUID | None = None
    error_code: str | None = None
    usage_json: dict[str, Any] = field(default_factory=dict)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime = field(default_factory=utcnow)


@dataclass(slots=True)
class ToolInvocationRecord:
    invocation_id: UUID
    run_id: UUID
    tenant_id: str
    plan_version: int
    task_id: str
    tool_name: str
    tool_version: str
    effect: ToolEffect
    args_hash: str
    data_scope_hash: str
    policy_decision_id: str
    policy_version: str
    status: str
    args_redacted: dict[str, Any] = field(default_factory=dict)
    result_hash: str | None = None
    result_artifact_id: UUID | None = None
    error_code: str | None = None
    latency_ms: int | None = None
    provider_request_id: str | None = None
    created_at: datetime = field(default_factory=utcnow)
    completed_at: datetime | None = None


@dataclass(slots=True)
class ActionAuditTransaction:
    """Locked Action plus immutable events/tool calls committed as one unit."""

    action: ActionRecord
    events: list[AuditEvent] = field(default_factory=list)
    tool_invocations: list[ToolInvocationRecord] = field(default_factory=list)

    def append_event(self, event: AuditEvent) -> None:
        if event.action_id not in {None, self.action.action_id}:
            raise ValueError("AUDIT_EVENT_ACTION_MISMATCH")
        self.events.append(event)

    def append_tool_invocation(self, invocation: ToolInvocationRecord) -> None:
        if invocation.run_id != self.action.run_id:
            raise ValueError("TOOL_INVOCATION_RUN_MISMATCH")
        self.tool_invocations.append(invocation)


@dataclass(slots=True, init=False)
class ArtifactRecord:
    artifact_id: UUID
    tenant_id: str
    run_id: UUID | None
    kind: str
    media_type: str
    content: bytes
    size_bytes: int
    sha256: str
    classification: DataClassification
    created_by: str
    retention_policy: str = "default"
    encryption_key_ref: str | None = None
    object_version_id: str | None = None
    object_retain_until: datetime | None = None
    legal_hold_status: str = "none"
    expires_at: datetime | None = None
    deleted_at: datetime | None = None
    lifecycle_status: str = "available"
    delete_requested_at: datetime | None = None
    delete_attempts: int = 0
    delete_last_error_code: str | None = None
    scan_status: str = "not_scanned"
    scan_provenance: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=utcnow)

    def __init__(
        self,
        artifact_id: UUID,
        tenant_id: str,
        run_id: UUID | None,
        kind: str,
        media_type: str,
        content: bytes,
        sha256: str,
        classification: DataClassification | str,
        created_by: str,
        size_bytes: int | None = None,
        retention_policy: str = "default",
        encryption_key_ref: str | None = None,
        object_version_id: str | None = None,
        object_retain_until: datetime | None = None,
        legal_hold_status: str = "none",
        expires_at: datetime | None = None,
        deleted_at: datetime | None = None,
        lifecycle_status: str = "available",
        delete_requested_at: datetime | None = None,
        delete_attempts: int = 0,
        delete_last_error_code: str | None = None,
        scan_status: str = "not_scanned",
        scan_provenance: dict[str, Any] | None = None,
        created_at: datetime | None = None,
    ) -> None:
        self.artifact_id = artifact_id
        self.tenant_id = tenant_id
        self.run_id = run_id
        self.kind = kind
        self.media_type = media_type
        self.content = content
        resolved_size = len(content) if size_bytes is None else size_bytes
        if resolved_size < 0 or (content and resolved_size != len(content)):
            raise ValueError("ARTIFACT_SIZE_INVALID: size does not match content")
        self.size_bytes = resolved_size
        self.sha256 = sha256
        try:
            self.classification = DataClassification(classification)
        except ValueError as exc:
            raise ValueError(
                "ARTIFACT_CLASSIFICATION_INVALID: classification is not recognized"
            ) from exc
        self.created_by = created_by
        if not retention_policy.strip():
            raise ValueError("ARTIFACT_RETENTION_POLICY_REQUIRED")
        if encryption_key_ref is not None and not encryption_key_ref.strip():
            raise ValueError("ARTIFACT_ENCRYPTION_KEY_REF_INVALID")
        if object_version_id is not None and not object_version_id.strip():
            raise ValueError("ARTIFACT_OBJECT_VERSION_ID_INVALID")
        if object_retain_until is not None and (
            object_retain_until.tzinfo is None or object_retain_until.utcoffset() is None
        ):
            raise ValueError("ARTIFACT_OBJECT_RETAIN_UNTIL_TIMEZONE_REQUIRED")
        if legal_hold_status not in {"none", "on"}:
            raise ValueError("ARTIFACT_LEGAL_HOLD_STATUS_INVALID")
        self.retention_policy = retention_policy
        self.encryption_key_ref = encryption_key_ref
        self.object_version_id = object_version_id
        self.object_retain_until = object_retain_until or expires_at
        self.legal_hold_status = legal_hold_status
        self.expires_at = expires_at
        self.deleted_at = deleted_at
        if lifecycle_status not in {"available", "delete_pending", "deleted"}:
            raise ValueError("ARTIFACT_LIFECYCLE_STATUS_INVALID")
        if delete_attempts < 0:
            raise ValueError("ARTIFACT_DELETE_ATTEMPTS_INVALID")
        self.lifecycle_status = lifecycle_status
        self.delete_requested_at = delete_requested_at
        self.delete_attempts = delete_attempts
        self.delete_last_error_code = delete_last_error_code
        self.scan_status = scan_status
        self.scan_provenance = copy.deepcopy(scan_provenance or {})
        self.created_at = created_at or utcnow()


@dataclass(frozen=True, slots=True)
class ArtifactDownload:
    """Short-lived, principal-bound download issued by production stores."""

    artifact_id: UUID
    url: str
    expires_at: datetime


@dataclass(slots=True)
class CapabilityRecord:
    name: str
    version: str
    effect: str
    risk: str
    enabled: bool = True
    disabled_reason: str | None = None
    policy_version: str = "builtin-1"


@dataclass(slots=True)
class WebhookEndpointRecord:
    endpoint_id: UUID = field(default_factory=uuid4)
    tenant_id: str = ""
    endpoint_name: str = ""
    url: str = ""
    event_types: tuple[str, ...] = ()
    signing_secret_ref: str = ""
    enabled: bool = True
    created_at: datetime = field(default_factory=utcnow)
