"""Add durable capacity reservations and an immutable full-cost ledger.

Revision ID: 20260727_0009
Revises: 20260724_0008
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260727_0009"
down_revision: str | None = "20260724_0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "run_capacity_reservations",
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("reservation_key", sa.Text(), nullable=False),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("requested_cost_usd", sa.Numeric(18, 6), nullable=False),
        sa.Column("settled_cost_usd", sa.Numeric(18, 6), nullable=True),
        sa.Column("priority", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default="active"),
        sa.Column("daily_period", sa.Date(), nullable=False),
        sa.Column("monthly_period", sa.Date(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rate_catalog_id", sa.Text(), nullable=True),
        sa.Column("breakdown", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "requested_cost_usd > 0",
            name="ck_capacity_reservation_requested_cost",
        ),
        sa.CheckConstraint(
            "status IN ('active','released','settled','settled_over_budget')",
            name="ck_capacity_reservation_status",
        ),
        sa.CheckConstraint(
            "priority IN ('low','normal','high','critical')",
            name="ck_capacity_reservation_priority",
        ),
        sa.PrimaryKeyConstraint("tenant_id", "reservation_key"),
    )
    op.create_index(
        "idx_capacity_reservation_tenant_active",
        "run_capacity_reservations",
        ["tenant_id", "status", "expires_at"],
    )
    op.create_index(
        "idx_capacity_reservation_run",
        "run_capacity_reservations",
        ["tenant_id", "run_id"],
    )
    op.create_table(
        "cost_ledger_entries",
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("event_id", sa.Text(), nullable=False),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("component", sa.Text(), nullable=False),
        sa.Column("amount_usd", sa.Numeric(18, 6), nullable=False),
        sa.Column("rate_catalog_id", sa.Text(), nullable=False),
        sa.Column("source_units", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint("amount_usd >= 0", name="ck_cost_ledger_amount"),
        sa.CheckConstraint(
            "component IN ('model','tool','sandbox','artifact','workflow','observability')",
            name="ck_cost_ledger_component",
        ),
        sa.PrimaryKeyConstraint("tenant_id", "event_id"),
    )
    op.create_index(
        "idx_cost_ledger_tenant_occurred",
        "cost_ledger_entries",
        ["tenant_id", "occurred_at"],
    )
    op.create_index(
        "idx_cost_ledger_run",
        "cost_ledger_entries",
        ["tenant_id", "run_id"],
    )

    op.execute("ALTER TABLE run_capacity_reservations ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE run_capacity_reservations FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY tenant_isolation_run_capacity_reservations
        ON run_capacity_reservations
        USING (tenant_id = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id = current_setting('app.tenant_id', true))
        """
    )
    op.execute("ALTER TABLE cost_ledger_entries ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE cost_ledger_entries FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY tenant_isolation_cost_ledger_entries
        ON cost_ledger_entries
        USING (tenant_id = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id = current_setting('app.tenant_id', true))
        """
    )

    op.execute(
        """
        CREATE FUNCTION reject_cost_ledger_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
          RAISE EXCEPTION 'cost ledger entries are append-only'
            USING ERRCODE = '55000';
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER cost_ledger_entries_immutable
        BEFORE UPDATE OR DELETE ON cost_ledger_entries
        FOR EACH ROW EXECUTE FUNCTION reject_cost_ledger_mutation()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS cost_ledger_entries_immutable ON cost_ledger_entries")
    op.execute("DROP FUNCTION IF EXISTS reject_cost_ledger_mutation()")
    op.drop_index("idx_cost_ledger_run", table_name="cost_ledger_entries")
    op.drop_index("idx_cost_ledger_tenant_occurred", table_name="cost_ledger_entries")
    op.drop_table("cost_ledger_entries")
    op.drop_index(
        "idx_capacity_reservation_run",
        table_name="run_capacity_reservations",
    )
    op.drop_index(
        "idx_capacity_reservation_tenant_active",
        table_name="run_capacity_reservations",
    )
    op.drop_table("run_capacity_reservations")
