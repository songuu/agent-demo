"""Additional expand-only projections used by production port adapters."""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    PrimaryKeyConstraint,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from agent_platform.infrastructure.persistence.models import Base


class RunRuntimeSnapshot(Base):
    """JSON projections that do not belong in the normalized execution tables."""

    __tablename__ = "run_runtime_snapshots"
    __table_args__ = (
        CheckConstraint("progress >= 0 AND progress <= 1", name="ck_runtime_progress"),
        Index("idx_run_runtime_snapshots_tenant", "tenant_id", "updated_at"),
    )

    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agent_runs.run_id", ondelete="RESTRICT"),
        primary_key=True,
    )
    tenant_id: Mapped[str] = mapped_column(Text)
    plan_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    outputs_json: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    result_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    progress: Mapped[Decimal] = mapped_column(Numeric(7, 6), default=Decimal(0))
    pause_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )


class CapabilityRecordRow(Base):
    """Tenant override or global capability default."""

    __tablename__ = "capability_records"
    __table_args__ = (
        PrimaryKeyConstraint("tenant_id", "capability_name"),
        Index(
            "idx_capability_records_visible",
            "tenant_id",
            "capability_name",
            "enabled",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(Text)
    capability_name: Mapped[str] = mapped_column(Text)
    version: Mapped[str] = mapped_column(Text)
    effect: Mapped[str] = mapped_column(Text)
    risk: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    disabled_reason: Mapped[str | None] = mapped_column(Text)
    policy_version: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
