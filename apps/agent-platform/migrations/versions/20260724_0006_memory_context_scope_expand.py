"""Persist purpose-bound data scope and correction version for long-term memory.

Revision ID: 20260724_0006
Revises: 20260724_0005
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "20260724_0006"
down_revision: str | None = "20260724_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _execute(statement: str) -> None:
    op.execute(statement)


def upgrade() -> None:
    _execute("SET LOCAL lock_timeout = '5s'")
    _execute("SET LOCAL statement_timeout = '120s'")
    _execute("ALTER TABLE memory_records ADD COLUMN purpose text")
    _execute("ALTER TABLE memory_records ADD COLUMN data_scope jsonb")
    _execute("ALTER TABLE memory_records ADD COLUMN memory_version integer")
    _execute(
        """
        UPDATE memory_records
        SET
            purpose = 'general',
            data_scope = jsonb_build_object(
                'tenant_id', tenant_id,
                'resource_types', jsonb_build_array('memory'),
                'resource_ids', '[]'::jsonb,
                'row_filter', '{}'::jsonb,
                'allowed_fields', '[]'::jsonb,
                'classifications', jsonb_build_array(classification)
            ),
            memory_version = 1
        WHERE purpose IS NULL OR data_scope IS NULL OR memory_version IS NULL
        """
    )
    _execute("ALTER TABLE memory_records ALTER COLUMN purpose SET NOT NULL")
    _execute("ALTER TABLE memory_records ALTER COLUMN purpose SET DEFAULT 'general'")
    _execute("ALTER TABLE memory_records ALTER COLUMN data_scope SET NOT NULL")

    _execute("ALTER TABLE memory_records ALTER COLUMN memory_version SET NOT NULL")
    _execute("ALTER TABLE memory_records ALTER COLUMN memory_version SET DEFAULT 1")
    _execute(
        "ALTER TABLE memory_records ADD CONSTRAINT ck_memory_version_positive "
        "CHECK (memory_version > 0)"
    )
    _execute(
        "ALTER TABLE memory_records ADD CONSTRAINT ck_memory_purpose_required "
        "CHECK (length(trim(purpose)) > 0)"
    )
    _execute(
        "CREATE INDEX idx_memory_context_lookup ON memory_records "
        "(tenant_id, owner_id, purpose, classification, valid_until) "
        "WHERE deleted_at IS NULL AND superseded_by IS NULL"
    )


def downgrade() -> None:
    _execute("DROP INDEX IF EXISTS idx_memory_context_lookup")
    _execute("ALTER TABLE memory_records DROP CONSTRAINT IF EXISTS ck_memory_purpose_required")
    _execute("ALTER TABLE memory_records DROP CONSTRAINT IF EXISTS ck_memory_version_positive")
    _execute("ALTER TABLE memory_records DROP COLUMN IF EXISTS memory_version")
    _execute("ALTER TABLE memory_records DROP COLUMN IF EXISTS data_scope")
    _execute("ALTER TABLE memory_records DROP COLUMN IF EXISTS purpose")
