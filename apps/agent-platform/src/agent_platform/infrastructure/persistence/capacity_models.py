"""Durable tenant admission reservations and immutable cost ledger mappings."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import CheckConstraint, Date, DateTime, Index, Numeric, PrimaryKeyConstraint, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from agent_platform.infrastructure.persistence.models import Base


class RunCapacityReservation(Base):
    __tablename__ = "run_capacity_reservations"
    __table_args__ = (
        PrimaryKeyConstraint("tenant_id", "reservation_key"),
        CheckConstraint(
            "requested_cost_usd > 0",
            name="ck_capacity_reservation_requested_cost",
        ),
        CheckConstraint(
            "status IN ('active','released','settled','settled_over_budget')",
            name="ck_capacity_reservation_status",
        ),
        CheckConstraint(
            "priority IN ('low','normal','high','critical')",
            name="ck_capacity_reservation_priority",
        ),
        Index(
            "idx_capacity_reservation_tenant_active",
            "tenant_id",
            "status",
            "expires_at",
        ),
        Index("idx_capacity_reservation_run", "tenant_id", "run_id"),
    )

    tenant_id: Mapped[str] = mapped_column(Text)
    reservation_key: Mapped[str] = mapped_column(Text)
    run_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    requested_cost_usd: Mapped[Decimal] = mapped_column(Numeric(18, 6))
    settled_cost_usd: Mapped[Decimal | None] = mapped_column(Numeric(18, 6))
    priority: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, default="active")
    daily_period: Mapped[date] = mapped_column(Date)
    monthly_period: Mapped[date] = mapped_column(Date)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    rate_catalog_id: Mapped[str | None] = mapped_column(Text)
    breakdown: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CostLedgerEntry(Base):
    __tablename__ = "cost_ledger_entries"
    __table_args__ = (
        PrimaryKeyConstraint("tenant_id", "event_id"),
        CheckConstraint("amount_usd >= 0", name="ck_cost_ledger_amount"),
        CheckConstraint(
            "component IN ('model','tool','sandbox','artifact','workflow','observability')",
            name="ck_cost_ledger_component",
        ),
        Index(
            "idx_cost_ledger_tenant_occurred",
            "tenant_id",
            "occurred_at",
        ),
        Index("idx_cost_ledger_run", "tenant_id", "run_id"),
    )

    tenant_id: Mapped[str] = mapped_column(Text)
    event_id: Mapped[str] = mapped_column(Text)
    run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    component: Mapped[str] = mapped_column(Text)
    amount_usd: Mapped[Decimal] = mapped_column(Numeric(18, 6))
    rate_catalog_id: Mapped[str] = mapped_column(Text)
    source_units: Mapped[dict[str, Any]] = mapped_column(JSONB)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
