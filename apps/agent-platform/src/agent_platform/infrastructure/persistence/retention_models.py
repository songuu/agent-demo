"""Durable policy, legal-hold, retry, and evidence records for data retention."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    PrimaryKeyConstraint,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from agent_platform.infrastructure.persistence.models import Base


class RetentionPolicyVersion(Base):
    """Append-only, owner-bound lifecycle policy."""

    __tablename__ = "retention_policy_versions"
    __table_args__ = (
        PrimaryKeyConstraint("tenant_id", "policy_key", "version"),
        CheckConstraint("version > 0", name="ck_retention_policy_version"),
        CheckConstraint(
            "online_retention_days > 0",
            name="ck_retention_policy_online_days",
        ),
        CheckConstraint(
            "archive_retention_days IS NULL OR "
            "archive_retention_days >= online_retention_days",
            name="ck_retention_policy_archive_days",
        ),
        CheckConstraint(
            "disposition IN ("
            "'archive_then_purge','immutable_archive','hash_only_delete',"
            "'artifact_then_delete','retain'"
            ")",
            name="ck_retention_policy_disposition",
        ),
        Index(
            "idx_retention_policy_lookup",
            "tenant_id",
            "resource_type",
            "classification",
            "enabled",
            "version",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(Text)
    policy_key: Mapped[str] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer)
    resource_type: Mapped[str] = mapped_column(Text)
    classification: Mapped[str] = mapped_column(Text)
    business_requirement: Mapped[str] = mapped_column(Text)
    audit_requirement: Mapped[str] = mapped_column(Text)
    owner_id: Mapped[str] = mapped_column(Text)
    online_retention_days: Mapped[int] = mapped_column(Integer)
    archive_retention_days: Mapped[int | None] = mapped_column(Integer)
    disposition: Mapped[str] = mapped_column(Text)
    immutable_archive: Mapped[bool] = mapped_column(Boolean)
    legal_hold_enabled: Mapped[bool] = mapped_column(Boolean)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    effective_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("now()"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("now()"),
    )


class LegalHold(Base):
    """Mutable projection of a hold; every transition is also append-only."""

    __tablename__ = "legal_holds"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active','released','expired')",
            name="ck_legal_hold_status",
        ),
        CheckConstraint(
            "released_at IS NULL OR released_at >= starts_at",
            name="ck_legal_hold_release_time",
        ),
        CheckConstraint(
            "expires_at IS NULL OR expires_at > starts_at",
            name="ck_legal_hold_expiry_time",
        ),
        Index(
            "idx_legal_hold_active_resource",
            "tenant_id",
            "resource_type",
            "resource_id",
            "status",
            "starts_at",
        ),
    )

    hold_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    tenant_id: Mapped[str] = mapped_column(Text)
    resource_type: Mapped[str] = mapped_column(Text)
    resource_id: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)
    case_reference: Mapped[str] = mapped_column(Text)
    owner_id: Mapped[str] = mapped_column(Text)
    policy_key: Mapped[str] = mapped_column(Text)
    policy_version: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(Text, default="active")
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    released_by: Mapped[str | None] = mapped_column(Text)
    release_reason: Mapped[str | None] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("now()"),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("now()"),
    )


class LegalHoldEvent(Base):
    """Append-only evidence for hold application, release, and expiry."""

    __tablename__ = "legal_hold_events"
    __table_args__ = (
        UniqueConstraint("hold_id", "sequence_no", name="uq_legal_hold_event_sequence"),
        CheckConstraint("sequence_no > 0", name="ck_legal_hold_event_sequence"),
        Index("idx_legal_hold_event_time", "tenant_id", "created_at", "event_id"),
    )

    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    hold_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    tenant_id: Mapped[str] = mapped_column(Text)
    sequence_no: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(Text)
    actor_id: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)
    previous_hash: Mapped[str | None] = mapped_column(Text)
    event_hash: Mapped[str] = mapped_column(Text)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("now()"),
    )


class RetentionJob(Base):
    """Retryable state for one lifecycle operation on one resource."""

    __tablename__ = "retention_jobs"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "resource_type",
            "resource_id",
            "operation",
            "policy_key",
            "policy_version",
            name="uq_retention_job_resource_operation",
        ),
        CheckConstraint(
            "status IN ('pending','in_progress','succeeded','failed','held')",
            name="ck_retention_job_status",
        ),
        CheckConstraint("attempts >= 0", name="ck_retention_job_attempts"),
        Index(
            "idx_retention_job_retry",
            "status",
            "next_attempt_at",
            "created_at",
        ),
    )

    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    tenant_id: Mapped[str] = mapped_column(Text)
    resource_type: Mapped[str] = mapped_column(Text)
    resource_id: Mapped[str] = mapped_column(Text)
    operation: Mapped[str] = mapped_column(Text)
    policy_key: Mapped[str] = mapped_column(Text)
    policy_version: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(Text, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("now()"),
    )
    source_payload_hash: Mapped[str | None] = mapped_column(Text)
    archive_uri: Mapped[str | None] = mapped_column(Text)
    archive_sha256: Mapped[str | None] = mapped_column(Text)
    archive_version_id: Mapped[str | None] = mapped_column(Text)
    object_lock_mode: Mapped[str | None] = mapped_column(Text)
    retain_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(Text)
    last_error_detail: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("now()"),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("now()"),
    )


class RetentionEvidence(Base):
    """Append-only, hash-chained cleanup/archive evidence."""

    __tablename__ = "retention_evidence"
    __table_args__ = (
        UniqueConstraint("job_id", "sequence_no", name="uq_retention_evidence_sequence"),
        CheckConstraint("sequence_no > 0", name="ck_retention_evidence_sequence"),
        Index(
            "idx_retention_evidence_resource",
            "tenant_id",
            "resource_type",
            "resource_id",
            "created_at",
        ),
    )

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    tenant_id: Mapped[str] = mapped_column(Text)
    sequence_no: Mapped[int] = mapped_column(Integer)
    operation: Mapped[str] = mapped_column(Text)
    resource_type: Mapped[str] = mapped_column(Text)
    resource_id: Mapped[str] = mapped_column(Text)
    policy_key: Mapped[str] = mapped_column(Text)
    policy_version: Mapped[int] = mapped_column(Integer)
    legal_hold_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    source_payload_hash: Mapped[str | None] = mapped_column(Text)
    archive_uri: Mapped[str | None] = mapped_column(Text)
    archive_sha256: Mapped[str | None] = mapped_column(Text)
    archive_version_id: Mapped[str | None] = mapped_column(Text)
    object_lock_mode: Mapped[str | None] = mapped_column(Text)
    retain_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    previous_hash: Mapped[str | None] = mapped_column(Text)
    evidence_hash: Mapped[str] = mapped_column(Text)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("now()"),
    )
