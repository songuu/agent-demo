"""Add versioned retention policy, legal hold, retry, and cleanup evidence.

Revision ID: 20260724_0008
Revises: 20260724_0007
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "20260724_0008"
down_revision: str | None = "20260724_0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _execute(statement: str) -> None:
    op.execute(statement)


def upgrade() -> None:
    _execute("SET LOCAL lock_timeout = '5s'")
    _execute("SET LOCAL statement_timeout = '120s'")
    _execute("ALTER TABLE artifacts ADD COLUMN object_version_id text")
    _execute("ALTER TABLE artifacts ADD COLUMN object_retain_until timestamptz")
    _execute("ALTER TABLE artifacts ADD COLUMN legal_hold_status text")
    _execute("UPDATE artifacts SET legal_hold_status = 'none' WHERE legal_hold_status IS NULL")
    _execute("ALTER TABLE artifacts ALTER COLUMN legal_hold_status SET NOT NULL")
    _execute("ALTER TABLE artifacts ALTER COLUMN legal_hold_status SET DEFAULT 'none'")
    _execute(
        "ALTER TABLE artifacts ADD CONSTRAINT ck_artifact_legal_hold_status "
        "CHECK (legal_hold_status IN ('none', 'on'))"
    )
    _execute(
        "CREATE INDEX idx_artifacts_legal_hold ON artifacts "
        "(tenant_id, legal_hold_status)"
    )
    _execute(
        """
        CREATE TABLE retention_policy_versions (
            tenant_id text NOT NULL,
            policy_key text NOT NULL,
            version integer NOT NULL CHECK (version > 0),
            resource_type text NOT NULL,
            classification text NOT NULL,
            business_requirement text NOT NULL,
            audit_requirement text NOT NULL,
            owner_id text NOT NULL,
            online_retention_days integer NOT NULL CHECK (online_retention_days > 0),
            archive_retention_days integer,
            disposition text NOT NULL CHECK (
                disposition IN (
                    'archive_then_purge',
                    'immutable_archive',
                    'hash_only_delete',
                    'artifact_then_delete',
                    'retain'
                )
            ),
            immutable_archive boolean NOT NULL,
            legal_hold_enabled boolean NOT NULL,
            enabled boolean NOT NULL DEFAULT true,
            effective_at timestamptz NOT NULL DEFAULT now(),
            created_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (tenant_id, policy_key, version),
            CHECK (
                archive_retention_days IS NULL
                OR archive_retention_days >= online_retention_days
            )
        )
        """
    )
    _execute(
        "CREATE INDEX idx_retention_policy_lookup ON retention_policy_versions "
        "(tenant_id, resource_type, classification, enabled, version DESC)"
    )
    _execute(
        """
        CREATE TABLE legal_holds (
            hold_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id text NOT NULL,
            resource_type text NOT NULL,
            resource_id text NOT NULL,
            reason text NOT NULL,
            case_reference text NOT NULL,
            owner_id text NOT NULL,
            policy_key text NOT NULL,
            policy_version integer NOT NULL CHECK (policy_version > 0),
            status text NOT NULL DEFAULT 'active'
                CHECK (status IN ('active','released','expired')),
            starts_at timestamptz NOT NULL,
            expires_at timestamptz,
            released_at timestamptz,
            released_by text,
            release_reason text,
            version integer NOT NULL DEFAULT 0 CHECK (version >= 0),
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now(),
            CHECK (released_at IS NULL OR released_at >= starts_at),
            CHECK (expires_at IS NULL OR expires_at > starts_at)
        )
        """
    )
    _execute(
        "CREATE INDEX idx_legal_hold_active_resource ON legal_holds "
        "(tenant_id, resource_type, resource_id, status, starts_at)"
    )
    _execute(
        """
        CREATE TABLE legal_hold_events (
            event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            hold_id uuid NOT NULL REFERENCES legal_holds(hold_id) ON DELETE RESTRICT,
            tenant_id text NOT NULL,
            sequence_no integer NOT NULL CHECK (sequence_no > 0),
            event_type text NOT NULL,
            actor_id text NOT NULL,
            reason text NOT NULL,
            previous_hash text,
            event_hash text NOT NULL,
            details jsonb NOT NULL DEFAULT '{}'::jsonb,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (hold_id, sequence_no)
        )
        """
    )
    _execute(
        "CREATE INDEX idx_legal_hold_event_time ON legal_hold_events "
        "(tenant_id, created_at, event_id)"
    )
    _execute(
        """
        CREATE TABLE retention_jobs (
            job_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id text NOT NULL,
            resource_type text NOT NULL,
            resource_id text NOT NULL,
            operation text NOT NULL,
            policy_key text NOT NULL,
            policy_version integer NOT NULL CHECK (policy_version > 0),
            status text NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending','in_progress','succeeded','failed','held')),
            attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
            next_attempt_at timestamptz NOT NULL DEFAULT now(),
            source_payload_hash text,
            archive_uri text,
            archive_sha256 text,
            archive_version_id text,
            object_lock_mode text,
            retain_until timestamptz,
            last_error_code text,
            last_error_detail text,
            started_at timestamptz,
            completed_at timestamptz,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (
                tenant_id,
                resource_type,
                resource_id,
                operation,
                policy_key,
                policy_version
            )
        )
        """
    )
    _execute(
        "CREATE INDEX idx_retention_job_retry ON retention_jobs "
        "(status, next_attempt_at, created_at)"
    )
    _execute(
        """
        CREATE TABLE retention_evidence (
            evidence_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            job_id uuid NOT NULL REFERENCES retention_jobs(job_id) ON DELETE RESTRICT,
            tenant_id text NOT NULL,
            sequence_no integer NOT NULL CHECK (sequence_no > 0),
            operation text NOT NULL,
            resource_type text NOT NULL,
            resource_id text NOT NULL,
            policy_key text NOT NULL,
            policy_version integer NOT NULL CHECK (policy_version > 0),
            legal_hold_id uuid REFERENCES legal_holds(hold_id) ON DELETE RESTRICT,
            source_payload_hash text,
            archive_uri text,
            archive_sha256 text,
            archive_version_id text,
            object_lock_mode text,
            retain_until timestamptz,
            previous_hash text,
            evidence_hash text NOT NULL,
            details jsonb NOT NULL DEFAULT '{}'::jsonb,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (job_id, sequence_no)
        )
        """
    )
    _execute(
        "CREATE INDEX idx_retention_evidence_resource ON retention_evidence "
        "(tenant_id, resource_type, resource_id, created_at)"
    )

    tenant_tables = (
        "retention_policy_versions",
        "legal_holds",
        "legal_hold_events",
        "retention_jobs",
        "retention_evidence",
    )
    for table in tenant_tables:
        _execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        _execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")

    _execute(
        """
        CREATE POLICY tenant_select_retention_policy_versions
        ON retention_policy_versions FOR SELECT
        USING (
            tenant_id = current_setting('app.tenant_id', true)
            OR tenant_id = '__platform__'
        )
        """
    )
    _execute(
        """
        CREATE POLICY tenant_write_retention_policy_versions
        ON retention_policy_versions FOR INSERT
        WITH CHECK (tenant_id = current_setting('app.tenant_id', true))
        """
    )
    for table in ("legal_holds", "legal_hold_events", "retention_jobs", "retention_evidence"):
        _execute(
            f"CREATE POLICY tenant_isolation_{table} ON {table} "
            "USING (tenant_id = current_setting('app.tenant_id', true)) "
            "WITH CHECK (tenant_id = current_setting('app.tenant_id', true))"
        )

    for table in (
        "retention_policy_versions",
        "legal_hold_events",
        "retention_evidence",
    ):
        _execute(
            f"""
            CREATE TRIGGER trg_{table}_append_only
            BEFORE UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION reject_immutable_audit_mutation()
            """
        )

    _execute(
        """
        CREATE OR REPLACE FUNCTION enforce_legal_hold_transition()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY INVOKER
        AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'legal_holds is non-destructive; DELETE is forbidden'
                    USING ERRCODE = '55000';
            END IF;
            IF OLD.status <> 'active' OR NEW.status NOT IN ('released', 'expired') THEN
                RAISE EXCEPTION 'invalid legal hold transition'
                    USING ERRCODE = '55000';
            END IF;
            IF (
                NEW.tenant_id,
                NEW.resource_type,
                NEW.resource_id,
                NEW.reason,
                NEW.case_reference,
                NEW.owner_id,
                NEW.policy_key,
                NEW.policy_version,
                NEW.starts_at,
                NEW.expires_at
            ) IS DISTINCT FROM (
                OLD.tenant_id,
                OLD.resource_type,
                OLD.resource_id,
                OLD.reason,
                OLD.case_reference,
                OLD.owner_id,
                OLD.policy_key,
                OLD.policy_version,
                OLD.starts_at,
                OLD.expires_at
            ) THEN
                RAISE EXCEPTION 'legal hold scope is immutable'
                    USING ERRCODE = '55000';
            END IF;
            IF NEW.version <> OLD.version + 1 THEN
                RAISE EXCEPTION 'legal hold version must advance by one'
                    USING ERRCODE = '55000';
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    _execute(
        """
        CREATE TRIGGER trg_legal_holds_controlled_transition
        BEFORE UPDATE OR DELETE ON legal_holds
        FOR EACH ROW EXECUTE FUNCTION enforce_legal_hold_transition()
        """
    )

    _execute(
        """
        INSERT INTO retention_policy_versions (
            tenant_id,
            policy_key,
            version,
            resource_type,
            classification,
            business_requirement,
            audit_requirement,
            owner_id,
            online_retention_days,
            archive_retention_days,
            disposition,
            immutable_archive,
            legal_hold_enabled
        ) VALUES
        (
            '__platform__',
            'agent-run-default',
            1,
            'agent_run',
            'any',
            'Keep online snapshots for support and approved business reconstruction.',
            'Archive before minimizing mutable snapshots; retain aggregate statistics.',
            'platform-data-governance',
            180,
            365,
            'archive_then_purge',
            true,
            true
        ),
        (
            '__platform__',
            'run-event-audit',
            1,
            'run_event',
            'any',
            'Support tenant export and incident reconstruction.',
            'Preserve an immutable audit stream for at least 365 days.',
            'security-audit',
            365,
            2555,
            'immutable_archive',
            true,
            true
        ),
        (
            '__platform__',
            'model-raw-minimal',
            1,
            'model_raw',
            'any',
            'Raw model content is disabled by default and only retained for bounded diagnosis.',
            'After expiry keep only hashes, usage, errors, and approved fragments.',
            'ai-safety',
            1,
            NULL,
            'hash_only_delete',
            false,
            true
        ),
        (
            '__platform__',
            'tool-raw-short',
            1,
            'tool_raw',
            'any',
            'Keep raw tool results online only for short-lived processing.',
            'Move required evidence to a governed Artifact before raw cleanup.',
            'tool-platform',
            7,
            90,
            'artifact_then_delete',
            false,
            true
        ),
        (
            '__platform__',
            'approval-receipt-record',
            1,
            'approval_receipt',
            'any',
            'Preserve prepared actions, approvals, and receipts as long-lived business records.',
            'Never break the approval and external side-effect audit chain.',
            'business-controls',
            2555,
            3650,
            'retain',
            true,
            true
        )
        """
    )


def downgrade() -> None:
    _execute("DROP TRIGGER IF EXISTS trg_legal_holds_controlled_transition ON legal_holds")
    _execute("DROP FUNCTION IF EXISTS enforce_legal_hold_transition()")
    for table in (
        "retention_evidence",
        "legal_hold_events",
        "retention_policy_versions",
    ):
        _execute(f"DROP TRIGGER IF EXISTS trg_{table}_append_only ON {table}")
    for table in (
        "retention_evidence",
        "retention_jobs",
        "legal_hold_events",
        "legal_holds",
        "retention_policy_versions",
    ):
        _execute(f"DROP TABLE IF EXISTS {table}")
    _execute("DROP INDEX IF EXISTS idx_artifacts_legal_hold")
    _execute("ALTER TABLE artifacts DROP CONSTRAINT IF EXISTS ck_artifact_legal_hold_status")
    _execute("ALTER TABLE artifacts DROP COLUMN IF EXISTS legal_hold_status")
    _execute("ALTER TABLE artifacts DROP COLUMN IF EXISTS object_retain_until")
    _execute("ALTER TABLE artifacts DROP COLUMN IF EXISTS object_version_id")
