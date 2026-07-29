"""Make immutable audit facts append-only at the database boundary.

Revision ID: 20260724_0005
Revises: 20260724_0004
"""

from __future__ import annotations

from alembic import op

revision = "20260724_0005"
down_revision = "20260724_0004"
branch_labels = None
depends_on = None

IMMUTABLE_TABLES = (
    "run_events",
    "approvals",
    "execution_plans",
    "tool_invocations",
)


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION reject_immutable_audit_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY INVOKER
        AS $$
        BEGIN
            RAISE EXCEPTION '% is append-only; % is forbidden', TG_TABLE_NAME, TG_OP
                USING ERRCODE = '55000';
        END
        $$
        """
    )
    for table in IMMUTABLE_TABLES:
        op.execute(
            f"""
            CREATE TRIGGER trg_{table}_append_only
            BEFORE UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION reject_immutable_audit_mutation()
            """
        )


def downgrade() -> None:
    for table in reversed(IMMUTABLE_TABLES):
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_append_only ON {table}")
    op.execute("DROP FUNCTION IF EXISTS reject_immutable_audit_mutation()")