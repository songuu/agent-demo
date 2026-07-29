"""Make Artifact object deletion durable and retryable.

Revision ID: 20260724_0007
Revises: 20260724_0006
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "20260724_0007"
down_revision: str | None = "20260724_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _execute(statement: str) -> None:
    op.execute(statement)


def upgrade() -> None:
    _execute("SET LOCAL lock_timeout = '5s'")
    _execute("SET LOCAL statement_timeout = '120s'")
    _execute("ALTER TABLE artifacts ADD COLUMN lifecycle_status text")
    _execute("ALTER TABLE artifacts ADD COLUMN delete_requested_at timestamptz")
    _execute("ALTER TABLE artifacts ADD COLUMN delete_attempts integer")
    _execute("ALTER TABLE artifacts ADD COLUMN delete_last_error_code text")
    _execute(
        """
        UPDATE artifacts
        SET
            lifecycle_status = CASE
                WHEN deleted_at IS NULL THEN 'available'
                ELSE 'deleted'
            END,
            delete_requested_at = deleted_at,
            delete_attempts = CASE
                WHEN deleted_at IS NULL THEN 0
                ELSE 1
            END
        WHERE lifecycle_status IS NULL OR delete_attempts IS NULL
        """
    )
    _execute("ALTER TABLE artifacts ALTER COLUMN lifecycle_status SET NOT NULL")
    _execute("ALTER TABLE artifacts ALTER COLUMN lifecycle_status SET DEFAULT 'available'")
    _execute("ALTER TABLE artifacts ALTER COLUMN delete_attempts SET NOT NULL")
    _execute("ALTER TABLE artifacts ALTER COLUMN delete_attempts SET DEFAULT 0")
    _execute(
        "ALTER TABLE artifacts ADD CONSTRAINT ck_artifact_lifecycle_status "
        "CHECK (lifecycle_status IN ('available', 'delete_pending', 'deleted'))"
    )
    _execute(
        "ALTER TABLE artifacts ADD CONSTRAINT ck_artifact_delete_attempts "
        "CHECK (delete_attempts >= 0)"
    )
    _execute(
        "CREATE INDEX idx_artifacts_delete_queue ON artifacts "
        "(lifecycle_status, delete_requested_at)"
    )


def downgrade() -> None:
    _execute("DROP INDEX IF EXISTS idx_artifacts_delete_queue")
    _execute(
        "ALTER TABLE artifacts DROP CONSTRAINT IF EXISTS ck_artifact_delete_attempts"
    )
    _execute(
        "ALTER TABLE artifacts DROP CONSTRAINT IF EXISTS ck_artifact_lifecycle_status"
    )
    _execute("ALTER TABLE artifacts DROP COLUMN IF EXISTS delete_last_error_code")
    _execute("ALTER TABLE artifacts DROP COLUMN IF EXISTS delete_attempts")
    _execute("ALTER TABLE artifacts DROP COLUMN IF EXISTS delete_requested_at")
    _execute("ALTER TABLE artifacts DROP COLUMN IF EXISTS lifecycle_status")
