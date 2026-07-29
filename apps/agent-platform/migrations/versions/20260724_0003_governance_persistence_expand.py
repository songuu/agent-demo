"""Expand production persistence for governed memory, webhooks, and Kill Switches.

Revision ID: 20260724_0003
Revises: 20260724_0002
Create Date: 2026-07-24
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "20260724_0003"
down_revision: str | None = "20260724_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _execute(statement: str) -> None:
    op.execute(statement)


def upgrade() -> None:
    _execute("SET LOCAL lock_timeout = '5s'")
    _execute("SET LOCAL statement_timeout = '120s'")

    # The reference vault emits a corrected event for the replacement record.
    _execute(
        """
        ALTER TABLE memory_lifecycle_events
        DROP CONSTRAINT IF EXISTS memory_lifecycle_events_event_type_check
        """
    )
    _execute(
        """
        ALTER TABLE memory_lifecycle_events
        ADD CONSTRAINT ck_memory_lifecycle_event_type CHECK (
            event_type IN (
                'created','corrected','validated','superseded','expired','deleted'
            )
        )
        """
    )

    _execute(
        """
        CREATE TABLE webhook_endpoint_secret_state (
            endpoint_id uuid PRIMARY KEY
                REFERENCES webhook_endpoints(endpoint_id) ON DELETE RESTRICT,
            tenant_id text NOT NULL,
            secret_version integer NOT NULL DEFAULT 1
                CHECK (secret_version > 0),
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    _execute(
        """
        INSERT INTO webhook_endpoint_secret_state(
            endpoint_id, tenant_id, secret_version
        )
        SELECT endpoint_id, tenant_id, 1
        FROM webhook_endpoints
        """
    )
    _execute(
        "CREATE INDEX idx_webhook_secret_state_tenant "
        "ON webhook_endpoint_secret_state (tenant_id, endpoint_id)"
    )
    _execute("ALTER TABLE webhook_endpoint_secret_state ENABLE ROW LEVEL SECURITY")
    _execute("ALTER TABLE webhook_endpoint_secret_state FORCE ROW LEVEL SECURITY")
    _execute(
        """
        CREATE POLICY tenant_isolation_webhook_endpoint_secret_state
        ON webhook_endpoint_secret_state
        USING (tenant_id = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id = current_setting('app.tenant_id', true))
        """
    )

    # A cluster role named agent_platform_admin is provisioned outside the
    # application migration. Missing role means fail-closed (false).
    _execute(
        """
        CREATE OR REPLACE FUNCTION app_is_platform_admin()
        RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY INVOKER
        AS $$
            SELECT COALESCE(
                pg_has_role(
                    current_user,
                    to_regrole('agent_platform_admin'),
                    'member'
                ),
                false
            )
        $$
        """
    )
    _execute(
        """
        CREATE TABLE kill_switches (
            switch_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_partition text NOT NULL,
            scope text NOT NULL CHECK (
                scope IN ('capability','use_case','tenant','environment','global')
            ),
            scope_id text NOT NULL,
            mode text NOT NULL CHECK (mode IN ('writes','all')),
            reason text NOT NULL,
            changed_by text NOT NULL,
            incident_id text NOT NULL,
            activated_at timestamptz NOT NULL,
            expires_at timestamptz,
            deactivated_at timestamptz,
            deactivated_by text,
            deactivation_reason text,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now(),
            CHECK (expires_at IS NULL OR expires_at > activated_at)
        )
        """
    )
    _execute(
        "CREATE INDEX idx_kill_switches_active "
        "ON kill_switches (tenant_partition, scope, scope_id, activated_at DESC) "
        "WHERE deactivated_at IS NULL"
    )
    _execute(
        """
        CREATE TABLE kill_switch_audit (
            audit_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            switch_id uuid NOT NULL
                REFERENCES kill_switches(switch_id) ON DELETE RESTRICT,
            tenant_partition text NOT NULL,
            action text NOT NULL CHECK (action IN ('activated','deactivated')),
            scope text NOT NULL CHECK (
                scope IN ('capability','use_case','tenant','environment','global')
            ),
            scope_id text NOT NULL,
            mode text NOT NULL CHECK (mode IN ('writes','all')),
            changed_by text NOT NULL,
            reason text NOT NULL,
            incident_id text NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    _execute(
        "CREATE INDEX idx_kill_switch_audit_time "
        "ON kill_switch_audit (tenant_partition, created_at, audit_id)"
    )
    for table in ("kill_switches", "kill_switch_audit"):
        _execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        _execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        _execute(
            f"CREATE POLICY scoped_select_{table} ON {table} FOR SELECT "
            "USING ("
            "tenant_partition = current_setting('app.tenant_id', true) "
            "OR tenant_partition = '*' "
            "OR app_is_platform_admin()"
            ")"
        )
        _execute(
            f"CREATE POLICY scoped_insert_{table} ON {table} FOR INSERT "
            "WITH CHECK ("
            "tenant_partition = current_setting('app.tenant_id', true) "
            "OR app_is_platform_admin()"
            ")"
        )
        _execute(
            f"CREATE POLICY scoped_update_{table} ON {table} FOR UPDATE "
            "USING ("
            "tenant_partition = current_setting('app.tenant_id', true) "
            "OR app_is_platform_admin()"
            ") WITH CHECK ("
            "tenant_partition = current_setting('app.tenant_id', true) "
            "OR app_is_platform_admin()"
            ")"
        )
        _execute(
            f"CREATE POLICY scoped_delete_{table} ON {table} FOR DELETE "
            "USING ("
            "tenant_partition = current_setting('app.tenant_id', true) "
            "OR app_is_platform_admin()"
            ")"
        )


def downgrade() -> None:
    _execute("DROP TABLE IF EXISTS kill_switch_audit")
    _execute("DROP TABLE IF EXISTS kill_switches")
    _execute("DROP FUNCTION IF EXISTS app_is_platform_admin")
    _execute("DROP TABLE IF EXISTS webhook_endpoint_secret_state")
    _execute(
        """
        ALTER TABLE memory_lifecycle_events
        DROP CONSTRAINT IF EXISTS ck_memory_lifecycle_event_type
        """
    )
    _execute(
        """
        ALTER TABLE memory_lifecycle_events
        ADD CONSTRAINT memory_lifecycle_events_event_type_check CHECK (
            event_type IN ('created','validated','superseded','expired','deleted')
        )
        """
    )
