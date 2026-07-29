"""Expand-only SQLAlchemy models for production governance adapters."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    PrimaryKeyConstraint,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from agent_platform.infrastructure.persistence.models import Base


class WebhookEndpointSecretState(Base):
    __tablename__ = "webhook_endpoint_secret_state"
    __table_args__ = (
        CheckConstraint("secret_version > 0", name="ck_webhook_secret_version"),
        Index("idx_webhook_secret_state_tenant", "tenant_id", "endpoint_id"),
    )

    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("webhook_endpoints.endpoint_id", ondelete="RESTRICT"),
        primary_key=True,
    )
    tenant_id: Mapped[str] = mapped_column(Text)
    secret_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )


class ScopedKillSwitch(Base):
    __tablename__ = "kill_switches"
    __table_args__ = (
        CheckConstraint(
            "scope IN ('capability','use_case','tenant','environment','global')",
            name="ck_scoped_kill_switch_scope",
        ),
        CheckConstraint(
            "mode IN ('writes','all')",
            name="ck_scoped_kill_switch_mode",
        ),
        Index(
            "idx_kill_switches_active",
            "tenant_partition",
            "scope",
            "scope_id",
            "activated_at",
        ),
    )

    switch_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    tenant_partition: Mapped[str] = mapped_column(Text)
    scope: Mapped[str] = mapped_column(Text)
    scope_id: Mapped[str] = mapped_column(Text)
    mode: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)
    changed_by: Mapped[str] = mapped_column(Text)
    incident_id: Mapped[str] = mapped_column(Text)
    activated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deactivated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deactivated_by: Mapped[str | None] = mapped_column(Text)
    deactivation_reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )


class KillSwitchAuditRow(Base):
    __tablename__ = "kill_switch_audit"
    __table_args__ = (
        PrimaryKeyConstraint("audit_id"),
        Index(
            "idx_kill_switch_audit_time",
            "tenant_partition",
            "created_at",
            "audit_id",
        ),
    )

    audit_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), server_default=text("gen_random_uuid()")
    )
    switch_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("kill_switches.switch_id", ondelete="RESTRICT"),
    )
    tenant_partition: Mapped[str] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text)
    scope: Mapped[str] = mapped_column(Text)
    scope_id: Mapped[str] = mapped_column(Text)
    mode: Mapped[str] = mapped_column(Text)
    changed_by: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)
    incident_id: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
