"""Expand durable projections required by the application repository ports.

Revision ID: 20260724_0002
Revises: 20260724_0001
Create Date: 2026-07-24
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "20260724_0002"
down_revision: str | None = "20260724_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _execute(statement: str) -> None:
    op.execute(statement)


def upgrade() -> None:
    _execute("SET LOCAL lock_timeout = '5s'")
    _execute("SET LOCAL statement_timeout = '120s'")
    _execute(
        """
        CREATE TABLE run_runtime_snapshots (
            run_id uuid PRIMARY KEY
                REFERENCES agent_runs(run_id) ON DELETE RESTRICT,
            tenant_id text NOT NULL,
            plan_json jsonb,
            outputs_json jsonb NOT NULL DEFAULT '{}'::jsonb,
            result_json jsonb,
            progress numeric(7,6) NOT NULL DEFAULT 0
                CHECK (progress >= 0 AND progress <= 1),
            pause_requested boolean NOT NULL DEFAULT false,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    _execute(
        """
        INSERT INTO run_runtime_snapshots(run_id, tenant_id)
        SELECT run_id, tenant_id
        FROM agent_runs
        """
    )
    _execute(
        "CREATE INDEX idx_run_runtime_snapshots_tenant "
        "ON run_runtime_snapshots (tenant_id, updated_at DESC)"
    )
    _execute("ALTER TABLE run_runtime_snapshots ENABLE ROW LEVEL SECURITY")
    _execute("ALTER TABLE run_runtime_snapshots FORCE ROW LEVEL SECURITY")
    _execute(
        """
        CREATE POLICY tenant_isolation_run_runtime_snapshots
        ON run_runtime_snapshots
        USING (tenant_id = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id = current_setting('app.tenant_id', true))
        """
    )

    _execute(
        """
        CREATE TABLE capability_records (
            tenant_id text NOT NULL,
            capability_name text NOT NULL,
            version text NOT NULL,
            effect text NOT NULL,
            risk text NOT NULL,
            enabled boolean NOT NULL DEFAULT true,
            disabled_reason text,
            policy_version text NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (tenant_id, capability_name)
        )
        """
    )
    _execute(
        "CREATE INDEX idx_capability_records_visible "
        "ON capability_records (tenant_id, capability_name, enabled)"
    )
    _execute("ALTER TABLE capability_records ENABLE ROW LEVEL SECURITY")
    _execute("ALTER TABLE capability_records FORCE ROW LEVEL SECURITY")
    # Global defaults are readable by every tenant but writable only from the
    # explicit "*" tenant session used by the bootstrap/migration process.
    _execute(
        """
        CREATE POLICY capability_records_select
        ON capability_records FOR SELECT
        USING (
            tenant_id = current_setting('app.tenant_id', true)
            OR tenant_id = '*'
        )
        """
    )
    _execute(
        """
        CREATE POLICY capability_records_insert
        ON capability_records FOR INSERT
        WITH CHECK (tenant_id = current_setting('app.tenant_id', true))
        """
    )
    _execute(
        """
        CREATE POLICY capability_records_update
        ON capability_records FOR UPDATE
        USING (tenant_id = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id = current_setting('app.tenant_id', true))
        """
    )
    _execute(
        """
        CREATE POLICY capability_records_delete
        ON capability_records FOR DELETE
        USING (tenant_id = current_setting('app.tenant_id', true))
        """
    )


def downgrade() -> None:
    _execute("DROP TABLE IF EXISTS capability_records")
    _execute("DROP TABLE IF EXISTS run_runtime_snapshots")
