"""Expand principal-bound Artifact download audit records.

Revision ID: 20260724_0004
Revises: 20260724_0003
Create Date: 2026-07-24
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "20260724_0004"
down_revision: str | None = "20260724_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _execute(statement: str) -> None:
    op.execute(statement)


def upgrade() -> None:
    _execute("SET LOCAL lock_timeout = '5s'")
    _execute("SET LOCAL statement_timeout = '120s'")
    _execute(
        """
        CREATE TABLE artifact_download_audit (
            download_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            artifact_id uuid NOT NULL
                REFERENCES artifacts(artifact_id) ON DELETE RESTRICT,
            tenant_id text NOT NULL,
            principal_id text NOT NULL,
            purpose text NOT NULL,
            expires_at timestamptz NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    _execute(
        "CREATE INDEX idx_artifact_download_audit_artifact "
        "ON artifact_download_audit (tenant_id, artifact_id, created_at DESC)"
    )
    _execute("ALTER TABLE artifact_download_audit ENABLE ROW LEVEL SECURITY")
    _execute("ALTER TABLE artifact_download_audit FORCE ROW LEVEL SECURITY")
    _execute(
        """
        CREATE POLICY tenant_isolation_artifact_download_audit
        ON artifact_download_audit
        USING (tenant_id = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id = current_setting('app.tenant_id', true))
        """
    )


def downgrade() -> None:
    _execute("DROP TABLE IF EXISTS artifact_download_audit")
