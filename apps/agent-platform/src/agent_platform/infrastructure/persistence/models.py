"""SQLAlchemy mappings for the durable snapshot, event, and audit stores."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    ARRAY,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Numeric,
    PrimaryKeyConstraint,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class RunStatus(enum.StrEnum):
    RECEIVED = "received"
    CLASSIFIED = "classified"
    PLANNING = "planning"
    AUTHORIZED = "authorized"
    EXECUTING = "executing"
    REPLANNING = "replanning"
    VERIFYING = "verifying"
    WAITING_APPROVAL = "waiting_approval"
    PAUSED = "paused"
    COMMITTING = "committing"
    COMPENSATING = "compensating"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskStatus(enum.StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


class ActionStatus(enum.StrEnum):
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


class ApprovalDecision(enum.StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"


class RiskLevel(enum.StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ToolEffect(enum.StrEnum):
    READ = "read"
    PREPARE = "prepare"
    COMMIT = "commit"


RUN_STATUS = Enum(RunStatus, name="run_status", values_callable=lambda e: [v.value for v in e])
TASK_STATUS = Enum(TaskStatus, name="task_status", values_callable=lambda e: [v.value for v in e])
ACTION_STATUS = Enum(
    ActionStatus,
    name="action_status",
    values_callable=lambda e: [v.value for v in e],
)
APPROVAL_DECISION = Enum(
    ApprovalDecision,
    name="approval_decision",
    values_callable=lambda e: [v.value for v in e],
)
RISK_LEVEL = Enum(RiskLevel, name="risk_level", values_callable=lambda e: [v.value for v in e])
TOOL_EFFECT = Enum(ToolEffect, name="tool_effect", values_callable=lambda e: [v.value for v in e])


class Base(DeclarativeBase):
    """Declarative base shared by repository adapters."""


class AgentRun(Base):
    __tablename__ = "agent_runs"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_run_tenant_idempotency"),
        CheckConstraint("current_plan_version >= 0", name="ck_run_plan_version"),
        CheckConstraint("cost_limit_usd > 0", name="ck_run_cost_limit"),
        CheckConstraint("cost_actual_usd >= 0", name="ck_run_cost_actual"),
        Index("idx_agent_runs_tenant_status_updated", "tenant_id", "status", "updated_at"),
        Index("idx_agent_runs_principal_created", "tenant_id", "principal_id", "created_at"),
    )

    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    tenant_id: Mapped[str] = mapped_column(Text)
    principal_id: Mapped[str] = mapped_column(Text)
    use_case: Mapped[str] = mapped_column(Text)
    status: Mapped[RunStatus] = mapped_column(RUN_STATUS, default=RunStatus.RECEIVED)
    risk: Mapped[RiskLevel] = mapped_column(RISK_LEVEL)
    contract_schema_version: Mapped[str] = mapped_column(Text)
    contract_json: Mapped[dict[str, Any]] = mapped_column(JSONB)
    current_plan_version: Mapped[int] = mapped_column(Integer, default=0)
    workflow_id: Mapped[str] = mapped_column(Text, unique=True)
    workflow_run_id: Mapped[str | None] = mapped_column(Text)
    idempotency_key: Mapped[str] = mapped_column(Text)
    request_hash: Mapped[str] = mapped_column(Text)
    cost_limit_usd: Mapped[Decimal] = mapped_column(Numeric(14, 6))
    cost_actual_usd: Mapped[Decimal] = mapped_column(Numeric(14, 6), default=Decimal(0))
    token_input: Mapped[int] = mapped_column(BigInteger, default=0)
    token_output: Mapped[int] = mapped_column(BigInteger, default=0)
    tool_call_count: Mapped[int] = mapped_column(Integer, default=0)
    deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    cancel_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_code: Mapped[str | None] = mapped_column(Text)
    failure_detail_ref: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    final_artifact_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    version: Mapped[int] = mapped_column(BigInteger, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RunEvent(Base):
    __tablename__ = "run_events"
    __table_args__ = (
        PrimaryKeyConstraint("created_at", "event_id", name="pk_run_events"),
        UniqueConstraint("run_id", "sequence_no", "created_at", name="uq_run_event_sequence"),
        Index("idx_run_events_run_seq", "run_id", "sequence_no"),
        Index("idx_run_events_tenant_time", "tenant_id", "created_at"),
        Index("idx_run_events_type_time", "event_type", "created_at"),
        {"postgresql_partition_by": "RANGE (created_at)"},
    )

    event_id: Mapped[int] = mapped_column(BigInteger, autoincrement=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_runs.run_id", ondelete="RESTRICT")
    )
    tenant_id: Mapped[str] = mapped_column(Text)
    sequence_no: Mapped[int] = mapped_column(BigInteger)
    event_type: Mapped[str] = mapped_column(Text)
    schema_version: Mapped[str] = mapped_column(Text, default="1.0")
    actor_type: Mapped[str] = mapped_column(Text)
    actor_id: Mapped[str | None] = mapped_column(Text)
    task_id: Mapped[str | None] = mapped_column(Text)
    action_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    correlation_id: Mapped[str] = mapped_column(Text)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    payload_hash: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )


class ExecutionPlan(Base):
    __tablename__ = "execution_plans"
    __table_args__ = (
        UniqueConstraint("run_id", "plan_version", name="uq_plan_run_version"),
        CheckConstraint("plan_version > 0", name="ck_plan_version"),
        Index("idx_execution_plans_run", "run_id", "plan_version"),
    )

    plan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_runs.run_id", ondelete="RESTRICT")
    )
    tenant_id: Mapped[str] = mapped_column(Text)
    plan_version: Mapped[int] = mapped_column(Integer)
    schema_version: Mapped[str] = mapped_column(Text)
    plan_json: Mapped[dict[str, Any]] = mapped_column(JSONB)
    plan_hash: Mapped[str] = mapped_column(Text)
    planner_model: Mapped[str] = mapped_column(Text)
    prompt_id: Mapped[str] = mapped_column(Text)
    prompt_version: Mapped[str] = mapped_column(Text)
    validation_status: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )


class TaskExecution(Base):
    __tablename__ = "task_executions"
    __table_args__ = (
        UniqueConstraint("run_id", "plan_version", "task_id", "attempt", name="uq_task_attempt"),
        CheckConstraint("attempt > 0", name="ck_task_attempt"),
        Index("idx_task_exec_run_plan", "run_id", "plan_version", "task_id"),
    )

    task_execution_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_runs.run_id", ondelete="RESTRICT")
    )
    tenant_id: Mapped[str] = mapped_column(Text)
    plan_version: Mapped[int] = mapped_column(Integer)
    task_id: Mapped[str] = mapped_column(Text)
    task_kind: Mapped[str] = mapped_column(Text)
    attempt: Mapped[int] = mapped_column(Integer)
    status: Mapped[TaskStatus] = mapped_column(TASK_STATUS, default=TaskStatus.PENDING)
    model_name: Mapped[str | None] = mapped_column(Text)
    model_settings: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    prompt_id: Mapped[str | None] = mapped_column(Text)
    prompt_version: Mapped[str | None] = mapped_column(Text)
    input_refs: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    output_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    output_artifact_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    error_code: Mapped[str | None] = mapped_column(Text)
    usage_json: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )


class ToolInvocation(Base):
    __tablename__ = "tool_invocations"
    __table_args__ = (
        Index("idx_tool_invocations_run_task", "run_id", "task_id", "created_at"),
        Index("idx_tool_invocations_tool_time", "tool_name", "created_at"),
    )

    invocation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_runs.run_id", ondelete="RESTRICT")
    )
    tenant_id: Mapped[str] = mapped_column(Text)
    plan_version: Mapped[int] = mapped_column(Integer)
    task_id: Mapped[str] = mapped_column(Text)
    tool_name: Mapped[str] = mapped_column(Text)
    tool_version: Mapped[str] = mapped_column(Text)
    effect: Mapped[ToolEffect] = mapped_column(TOOL_EFFECT)
    args_hash: Mapped[str] = mapped_column(Text)
    args_redacted: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    data_scope_hash: Mapped[str] = mapped_column(Text)
    policy_decision_id: Mapped[str] = mapped_column(Text)
    policy_version: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    result_hash: Mapped[str | None] = mapped_column(Text)
    result_artifact_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    error_code: Mapped[str | None] = mapped_column(Text)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    provider_request_id: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PreparedAction(Base):
    __tablename__ = "prepared_actions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_action_tenant_idempotency"),
        UniqueConstraint("action_id", "payload_hash", name="uq_action_payload_hash"),
        CheckConstraint("required_approvals >= 0", name="ck_action_required_approvals"),
        Index("idx_prepared_actions_run", "run_id", "created_at"),
        Index("idx_prepared_actions_pending", "tenant_id", "status", "expires_at"),
    )

    action_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_runs.run_id", ondelete="RESTRICT")
    )
    tenant_id: Mapped[str] = mapped_column(Text)
    principal_id: Mapped[str] = mapped_column(Text)
    action_type: Mapped[str] = mapped_column(Text)
    tool_name: Mapped[str] = mapped_column(Text)
    tool_version: Mapped[str] = mapped_column(Text)
    payload_encrypted: Mapped[bytes] = mapped_column(LargeBinary)
    payload_hash: Mapped[str] = mapped_column(Text)
    preview_json: Mapped[dict[str, Any]] = mapped_column(JSONB)
    risk: Mapped[RiskLevel] = mapped_column(RISK_LEVEL)
    approval_policy: Mapped[str] = mapped_column(Text)
    required_approvals: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[ActionStatus] = mapped_column(ACTION_STATUS)
    idempotency_key: Mapped[str] = mapped_column(Text)
    policy_version: Mapped[str] = mapped_column(Text)
    receipt_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    receipt_artifact_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    verification_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    failure_code: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    committing_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    committed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    version: Mapped[int] = mapped_column(BigInteger, default=0)


class Approval(Base):
    __tablename__ = "approvals"
    __table_args__ = (
        UniqueConstraint("action_id", "actor_id", "payload_hash", name="uq_approval_actor_payload"),
        Index("idx_approvals_action_time", "action_id", "created_at"),
    )

    approval_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    action_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("prepared_actions.action_id", ondelete="RESTRICT")
    )
    tenant_id: Mapped[str] = mapped_column(Text)
    actor_id: Mapped[str] = mapped_column(Text)
    actor_roles: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    auth_strength: Mapped[str] = mapped_column(Text)
    decision: Mapped[ApprovalDecision] = mapped_column(APPROVAL_DECISION)
    payload_hash: Mapped[str] = mapped_column(Text)
    comment: Mapped[str | None] = mapped_column(Text)
    policy_version: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )


class Artifact(Base):
    __tablename__ = "artifacts"
    __table_args__ = (
        UniqueConstraint("tenant_id", "uri", name="uq_artifact_tenant_uri"),
        CheckConstraint("size_bytes >= 0", name="ck_artifact_size"),
        CheckConstraint(
            "lifecycle_status IN ('available', 'delete_pending', 'deleted')",
            name="ck_artifact_lifecycle_status",
        ),
        CheckConstraint("delete_attempts >= 0", name="ck_artifact_delete_attempts"),
        CheckConstraint(
            "legal_hold_status IN ('none', 'on')",
            name="ck_artifact_legal_hold_status",
        ),
        Index("idx_artifacts_run", "run_id", "created_at"),
        Index("idx_artifacts_expiry", "expires_at", "deleted_at"),
        Index("idx_artifacts_delete_queue", "lifecycle_status", "delete_requested_at"),
        Index("idx_artifacts_legal_hold", "tenant_id", "legal_hold_status"),
    )

    artifact_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_runs.run_id", ondelete="RESTRICT")
    )
    tenant_id: Mapped[str] = mapped_column(Text)
    task_id: Mapped[str | None] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(Text)
    uri: Mapped[str] = mapped_column(Text)
    media_type: Mapped[str] = mapped_column(Text)
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(Text)
    classification: Mapped[str] = mapped_column(Text)
    source_json: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_by: Mapped[str] = mapped_column(Text)
    retention_policy: Mapped[str] = mapped_column(Text)
    encryption_key_ref: Mapped[str | None] = mapped_column(Text)
    object_version_id: Mapped[str | None] = mapped_column(Text)
    object_retain_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    legal_hold_status: Mapped[str] = mapped_column(
        Text,
        default="none",
        server_default=text("'none'"),
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lifecycle_status: Mapped[str] = mapped_column(
        Text,
        default="available",
        server_default=text("'available'"),
    )
    delete_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    delete_attempts: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))
    delete_last_error_code: Mapped[str | None] = mapped_column(Text)


class IdempotencyRecord(Base):
    __tablename__ = "idempotency_records"
    __table_args__ = (
        PrimaryKeyConstraint("tenant_id", "scope", "idempotency_key"),
        Index("idx_idempotency_expiry", "expires_at"),
    )

    tenant_id: Mapped[str] = mapped_column(Text)
    scope: Mapped[str] = mapped_column(Text)
    idempotency_key: Mapped[str] = mapped_column(Text)
    request_hash: Mapped[str] = mapped_column(Text)
    resource_type: Mapped[str] = mapped_column(Text)
    resource_id: Mapped[str] = mapped_column(Text)
    response_status: Mapped[int | None] = mapped_column(Integer)
    response_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )


class PromptVersion(Base):
    __tablename__ = "prompt_versions"
    __table_args__ = (
        PrimaryKeyConstraint("prompt_id", "version"),
        CheckConstraint(
            "status IN ('draft','approved','deprecated','disabled')",
            name="ck_prompt_status",
        ),
    )

    prompt_id: Mapped[str] = mapped_column(Text)
    version: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(Text)
    content_sha256: Mapped[str] = mapped_column(Text)
    content_uri: Mapped[str] = mapped_column(Text)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict)
    status: Mapped[str] = mapped_column(Text)
    approved_by: Mapped[str | None] = mapped_column(Text)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )


class ToolCatalogEntry(Base):
    __tablename__ = "tool_catalog"
    __table_args__ = (
        PrimaryKeyConstraint("tenant_id", "tool_name", "version"),
        Index("idx_tool_catalog_capability", "tenant_id", "capability_name", "enabled"),
    )

    tenant_id: Mapped[str] = mapped_column(Text)
    tool_name: Mapped[str] = mapped_column(Text)
    version: Mapped[str] = mapped_column(Text)
    capability_name: Mapped[str] = mapped_column(Text)
    effect: Mapped[ToolEffect] = mapped_column(TOOL_EFFECT)
    risk: Mapped[RiskLevel] = mapped_column(RISK_LEVEL)
    definition_json: Mapped[dict[str, Any]] = mapped_column(JSONB)
    definition_hash: Mapped[str] = mapped_column(Text)
    policy_ref: Mapped[str] = mapped_column(Text)
    adapter_ref: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )


class MemoryRecord(Base):
    __tablename__ = "memory_records"
    __table_args__ = (
        CheckConstraint("confidence BETWEEN 0 AND 1", name="ck_memory_confidence"),
        CheckConstraint("memory_version > 0", name="ck_memory_version_positive"),
        CheckConstraint("length(trim(purpose)) > 0", name="ck_memory_purpose_required"),
        Index(
            "idx_memory_subject_active",
            "tenant_id",
            "subject_type",
            "subject_id",
            "memory_type",
        ),
    )

    memory_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    tenant_id: Mapped[str] = mapped_column(Text)
    subject_type: Mapped[str] = mapped_column(Text)
    subject_id: Mapped[str] = mapped_column(Text)
    memory_type: Mapped[str] = mapped_column(Text)
    content_encrypted: Mapped[bytes] = mapped_column(LargeBinary)
    content_hash: Mapped[str] = mapped_column(Text)
    source_refs: Mapped[list[Any]] = mapped_column(JSONB)
    classification: Mapped[str] = mapped_column(Text)
    confidence: Mapped[Decimal | None] = mapped_column(Numeric(5, 4))
    owner_id: Mapped[str] = mapped_column(Text)
    write_policy: Mapped[str] = mapped_column(Text)
    purpose: Mapped[str] = mapped_column(Text, default="general")
    data_scope: Mapped[dict[str, Any]] = mapped_column(JSONB)
    memory_version: Mapped[int] = mapped_column(Integer, default=1)
    valid_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    superseded_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("memory_records.memory_id")
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )


class OutboxEvent(Base):
    __tablename__ = "outbox_events"
    __table_args__ = (
        UniqueConstraint("aggregate_type", "aggregate_id", "event_key", name="uq_outbox_event_key"),
        CheckConstraint("attempts >= 0", name="ck_outbox_attempts"),
        Index("idx_outbox_pending", "published_at", "available_at"),
    )

    outbox_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    tenant_id: Mapped[str] = mapped_column(Text)
    aggregate_type: Mapped[str] = mapped_column(Text)
    aggregate_id: Mapped[str] = mapped_column(Text)
    event_key: Mapped[str] = mapped_column(Text)
    event_type: Mapped[str] = mapped_column(Text)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    payload_hash: Mapped[str] = mapped_column(Text)
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )


class WebhookEndpoint(Base):
    __tablename__ = "webhook_endpoints"
    __table_args__ = (
        UniqueConstraint("tenant_id", "endpoint_name", name="uq_webhook_endpoint_name"),
    )

    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    tenant_id: Mapped[str] = mapped_column(Text)
    endpoint_name: Mapped[str] = mapped_column(Text)
    url: Mapped[str] = mapped_column(Text)
    event_types: Mapped[list[str]] = mapped_column(ARRAY(Text))
    signing_secret_ref: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )


class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"
    __table_args__ = (
        UniqueConstraint("endpoint_id", "outbox_id", name="uq_webhook_delivery"),
        CheckConstraint("attempts >= 0", name="ck_webhook_attempts"),
        Index("idx_webhook_delivery_pending", "status", "next_attempt_at"),
    )

    delivery_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    tenant_id: Mapped[str] = mapped_column(Text)
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("webhook_endpoints.endpoint_id", ondelete="RESTRICT")
    )
    outbox_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("outbox_events.outbox_id", ondelete="RESTRICT")
    )
    status: Mapped[str] = mapped_column(Text, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    response_status: Mapped[int | None] = mapped_column(Integer)
    response_hash: Mapped[str | None] = mapped_column(Text)
    last_error: Mapped[str | None] = mapped_column(Text)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dead_lettered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )


class CapabilityKillSwitch(Base):
    __tablename__ = "capability_kill_switches"
    __table_args__ = (
        PrimaryKeyConstraint("tenant_id", "capability_name"),
        CheckConstraint("mode IN ('none','writes','all')", name="ck_kill_switch_mode"),
    )

    tenant_id: Mapped[str] = mapped_column(Text)
    capability_name: Mapped[str] = mapped_column(Text)
    mode: Mapped[str] = mapped_column(Text, default="none")
    reason: Mapped[str] = mapped_column(Text)
    changed_by: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )


class MemoryLifecycleEvent(Base):
    __tablename__ = "memory_lifecycle_events"
    __table_args__ = (Index("idx_memory_lifecycle_memory_time", "memory_id", "created_at"),)

    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    memory_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("memory_records.memory_id", ondelete="RESTRICT")
    )
    tenant_id: Mapped[str] = mapped_column(Text)
    event_type: Mapped[str] = mapped_column(Text)
    actor_id: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)
    previous_hash: Mapped[str | None] = mapped_column(Text)
    replacement_memory_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
