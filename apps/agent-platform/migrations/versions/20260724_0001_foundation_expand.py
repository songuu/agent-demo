"""Expand the Agent platform durable data model.

Revision ID: 20260724_0001
Revises:
Create Date: 2026-07-24
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "20260724_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _execute(statement: str) -> None:
    op.execute(statement)


def upgrade() -> None:
    # Bound schema changes so a deployment cannot block production indefinitely.
    _execute("SET LOCAL lock_timeout = '5s'")
    _execute("SET LOCAL statement_timeout = '120s'")
    _execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    _execute("CREATE EXTENSION IF NOT EXISTS citext")
    _execute(
        "CREATE TYPE run_status AS ENUM "
        "('received','classified','planning','authorized','executing','replanning',"
        "'verifying','waiting_approval','paused','committing','compensating',"
        "'completed','failed','cancelled')"
    )
    _execute(
        "CREATE TYPE task_status AS ENUM "
        "('pending','running','succeeded','failed','cancelled','skipped')"
    )
    _execute(
        "CREATE TYPE action_status AS ENUM "
        "('proposed','prepared','pending_approval','approved','rejected','expired',"
        "'committing','unknown','committed','verify_failed','compensating',"
        "'compensated','compensation_failed','cancelled')"
    )
    _execute("CREATE TYPE approval_decision AS ENUM ('approved','rejected')")
    _execute("CREATE TYPE risk_level AS ENUM ('low','medium','high','critical')")
    _execute("CREATE TYPE tool_effect AS ENUM ('read','prepare','commit')")

    _execute(
        """
        CREATE TABLE agent_runs (
            run_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id text NOT NULL,
            principal_id text NOT NULL,
            use_case text NOT NULL,
            status run_status NOT NULL DEFAULT 'received',
            risk risk_level NOT NULL,
            contract_schema_version text NOT NULL,
            contract_json jsonb NOT NULL,
            current_plan_version integer NOT NULL DEFAULT 0
                CHECK (current_plan_version >= 0),
            workflow_id text NOT NULL UNIQUE,
            workflow_run_id text,
            idempotency_key text NOT NULL,
            request_hash text NOT NULL,
            cost_limit_usd numeric(14,6) NOT NULL CHECK (cost_limit_usd > 0),
            cost_actual_usd numeric(14,6) NOT NULL DEFAULT 0
                CHECK (cost_actual_usd >= 0),
            token_input bigint NOT NULL DEFAULT 0 CHECK (token_input >= 0),
            token_output bigint NOT NULL DEFAULT 0 CHECK (token_output >= 0),
            tool_call_count integer NOT NULL DEFAULT 0 CHECK (tool_call_count >= 0),
            deadline_at timestamptz NOT NULL,
            cancel_requested_at timestamptz,
            failure_code text,
            failure_detail_ref uuid,
            final_artifact_id uuid,
            version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now(),
            completed_at timestamptz,
            UNIQUE (tenant_id, idempotency_key)
        )
        """
    )
    _execute(
        "CREATE INDEX idx_agent_runs_tenant_status_updated "
        "ON agent_runs (tenant_id, status, updated_at DESC)"
    )
    _execute(
        "CREATE INDEX idx_agent_runs_principal_created "
        "ON agent_runs (tenant_id, principal_id, created_at DESC)"
    )
    _execute(
        "CREATE INDEX idx_agent_runs_deadline_active ON agent_runs (deadline_at) "
        "WHERE status NOT IN ('completed','failed','cancelled')"
    )

    # PostgreSQL requires a partition key in a partitioned-table uniqueness
    # constraint. A separate counter row supplies global per-Run sequence uniqueness.
    _execute(
        """
        CREATE TABLE run_event_sequences (
            run_id uuid PRIMARY KEY REFERENCES agent_runs(run_id) ON DELETE RESTRICT,
            next_sequence_no bigint NOT NULL DEFAULT 1 CHECK (next_sequence_no > 0)
        )
        """
    )
    _execute(
        """
        CREATE TABLE run_events (
            event_id bigint GENERATED ALWAYS AS IDENTITY,
            run_id uuid NOT NULL REFERENCES agent_runs(run_id) ON DELETE RESTRICT,
            tenant_id text NOT NULL,
            sequence_no bigint NOT NULL CHECK (sequence_no > 0),
            event_type text NOT NULL,
            schema_version text NOT NULL DEFAULT '1.0',
            actor_type text NOT NULL,
            actor_id text,
            task_id text,
            action_id uuid,
            correlation_id text NOT NULL,
            payload jsonb NOT NULL,
            payload_hash text NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (created_at, event_id),
            UNIQUE (run_id, sequence_no, created_at)
        ) PARTITION BY RANGE (created_at)
        """
    )
    _execute("CREATE TABLE run_events_default PARTITION OF run_events DEFAULT")
    _execute("CREATE INDEX idx_run_events_run_seq ON run_events (run_id, sequence_no)")
    _execute("CREATE INDEX idx_run_events_tenant_time ON run_events (tenant_id, created_at DESC)")
    _execute("CREATE INDEX idx_run_events_type_time ON run_events (event_type, created_at DESC)")

    _execute(
        """
        CREATE TABLE execution_plans (
            plan_id uuid PRIMARY KEY,
            run_id uuid NOT NULL REFERENCES agent_runs(run_id) ON DELETE RESTRICT,
            tenant_id text NOT NULL,
            plan_version integer NOT NULL CHECK (plan_version > 0),
            schema_version text NOT NULL,
            plan_json jsonb NOT NULL,
            plan_hash text NOT NULL,
            planner_model text NOT NULL,
            prompt_id text NOT NULL,
            prompt_version text NOT NULL,
            validation_status text NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (run_id, plan_version)
        )
        """
    )
    _execute("CREATE INDEX idx_execution_plans_run ON execution_plans (run_id, plan_version DESC)")
    _execute(
        """
        CREATE TABLE task_executions (
            task_execution_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            run_id uuid NOT NULL REFERENCES agent_runs(run_id) ON DELETE RESTRICT,
            tenant_id text NOT NULL,
            plan_version integer NOT NULL,
            task_id text NOT NULL,
            task_kind text NOT NULL,
            attempt integer NOT NULL CHECK (attempt > 0),
            status task_status NOT NULL DEFAULT 'pending',
            model_name text,
            model_settings jsonb,
            prompt_id text,
            prompt_version text,
            input_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
            output_json jsonb,
            output_artifact_id uuid,
            error_code text,
            usage_json jsonb NOT NULL DEFAULT '{}'::jsonb,
            started_at timestamptz,
            completed_at timestamptz,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (run_id, plan_version, task_id, attempt)
        )
        """
    )
    _execute(
        "CREATE INDEX idx_task_exec_run_plan ON task_executions (run_id, plan_version, task_id)"
    )
    _execute(
        "CREATE INDEX idx_task_exec_active ON task_executions (status, created_at) "
        "WHERE status IN ('pending','running')"
    )

    _execute(
        """
        CREATE TABLE tool_invocations (
            invocation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            run_id uuid NOT NULL REFERENCES agent_runs(run_id) ON DELETE RESTRICT,
            tenant_id text NOT NULL,
            plan_version integer NOT NULL,
            task_id text NOT NULL,
            tool_name text NOT NULL,
            tool_version text NOT NULL,
            effect tool_effect NOT NULL,
            args_hash text NOT NULL,
            args_redacted jsonb NOT NULL DEFAULT '{}'::jsonb,
            data_scope_hash text NOT NULL,
            policy_decision_id text NOT NULL,
            policy_version text NOT NULL,
            status text NOT NULL,
            result_hash text,
            result_artifact_id uuid,
            error_code text,
            latency_ms integer CHECK (latency_ms IS NULL OR latency_ms >= 0),
            provider_request_id text,
            created_at timestamptz NOT NULL DEFAULT now(),
            completed_at timestamptz
        )
        """
    )
    _execute(
        "CREATE INDEX idx_tool_invocations_run_task "
        "ON tool_invocations (run_id, task_id, created_at)"
    )
    _execute(
        "CREATE INDEX idx_tool_invocations_tool_time "
        "ON tool_invocations (tool_name, created_at DESC)"
    )
    _execute(
        """
        CREATE TABLE prepared_actions (
            action_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            run_id uuid NOT NULL REFERENCES agent_runs(run_id) ON DELETE RESTRICT,
            tenant_id text NOT NULL,
            principal_id text NOT NULL,
            action_type text NOT NULL,
            tool_name text NOT NULL,
            tool_version text NOT NULL,
            payload_encrypted bytea NOT NULL,
            payload_hash text NOT NULL,
            preview_json jsonb NOT NULL,
            risk risk_level NOT NULL,
            approval_policy text NOT NULL,
            required_approvals integer NOT NULL DEFAULT 0
                CHECK (required_approvals >= 0),
            status action_status NOT NULL,
            idempotency_key text NOT NULL,
            policy_version text NOT NULL,
            receipt_json jsonb,
            receipt_artifact_id uuid,
            verification_json jsonb,
            failure_code text,
            expires_at timestamptz NOT NULL,
            approved_at timestamptz,
            committing_at timestamptz,
            committed_at timestamptz,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now(),
            version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
            UNIQUE (tenant_id, idempotency_key),
            UNIQUE (action_id, payload_hash)
        )
        """
    )
    _execute("CREATE INDEX idx_prepared_actions_run ON prepared_actions (run_id, created_at)")
    _execute(
        "CREATE INDEX idx_prepared_actions_pending "
        "ON prepared_actions (tenant_id, status, expires_at) "
        "WHERE status IN ('pending_approval','approved','committing','unknown')"
    )
    _execute(
        """
        CREATE TABLE approvals (
            approval_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            action_id uuid NOT NULL
                REFERENCES prepared_actions(action_id) ON DELETE RESTRICT,
            tenant_id text NOT NULL,
            actor_id text NOT NULL,
            actor_roles text[] NOT NULL DEFAULT '{}',
            auth_strength text NOT NULL,
            decision approval_decision NOT NULL,
            payload_hash text NOT NULL,
            comment text,
            policy_version text NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (action_id, actor_id, payload_hash)
        )
        """
    )
    _execute("CREATE INDEX idx_approvals_action_time ON approvals (action_id, created_at)")
    _execute(
        """
        CREATE TABLE artifacts (
            artifact_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            run_id uuid REFERENCES agent_runs(run_id) ON DELETE RESTRICT,
            tenant_id text NOT NULL,
            task_id text,
            kind text NOT NULL,
            uri text NOT NULL,
            media_type text NOT NULL,
            size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
            sha256 text NOT NULL,
            classification text NOT NULL,
            source_json jsonb NOT NULL,
            created_by text NOT NULL,
            retention_policy text NOT NULL,
            encryption_key_ref text,
            expires_at timestamptz,
            created_at timestamptz NOT NULL DEFAULT now(),
            deleted_at timestamptz,
            UNIQUE (tenant_id, uri)
        )
        """
    )
    _execute("CREATE INDEX idx_artifacts_run ON artifacts (run_id, created_at)")
    _execute(
        "CREATE INDEX idx_artifacts_expiry ON artifacts (expires_at) "
        "WHERE expires_at IS NOT NULL AND deleted_at IS NULL"
    )

    _execute(
        """
        CREATE TABLE idempotency_records (
            tenant_id text NOT NULL,
            scope text NOT NULL,
            idempotency_key text NOT NULL,
            request_hash text NOT NULL,
            resource_type text NOT NULL,
            resource_id text NOT NULL,
            response_status integer CHECK (
                response_status IS NULL OR response_status BETWEEN 100 AND 599
            ),
            response_json jsonb,
            expires_at timestamptz NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (tenant_id, scope, idempotency_key)
        )
        """
    )
    _execute("CREATE INDEX idx_idempotency_expiry ON idempotency_records (expires_at)")
    _execute(
        """
        CREATE TABLE prompt_versions (
            prompt_id text NOT NULL,
            version text NOT NULL,
            role text NOT NULL,
            content_sha256 text NOT NULL,
            content_uri text NOT NULL,
            metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
            status text NOT NULL CHECK (
                status IN ('draft','approved','deprecated','disabled')
            ),
            approved_by text,
            approved_at timestamptz,
            created_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (prompt_id, version)
        )
        """
    )
    _execute(
        """
        CREATE TABLE tool_catalog (
            tenant_id text NOT NULL,
            tool_name text NOT NULL,
            version text NOT NULL,
            capability_name text NOT NULL,
            effect tool_effect NOT NULL,
            risk risk_level NOT NULL,
            definition_json jsonb NOT NULL,
            definition_hash text NOT NULL,
            policy_ref text NOT NULL,
            adapter_ref text NOT NULL,
            enabled boolean NOT NULL DEFAULT false,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (tenant_id, tool_name, version)
        )
        """
    )
    _execute(
        "CREATE INDEX idx_tool_catalog_capability "
        "ON tool_catalog (tenant_id, capability_name, enabled)"
    )
    _execute(
        """
        CREATE TABLE memory_records (
            memory_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id text NOT NULL,
            subject_type text NOT NULL,
            subject_id text NOT NULL,
            memory_type text NOT NULL,
            content_encrypted bytea NOT NULL,
            content_hash text NOT NULL,
            source_refs jsonb NOT NULL,
            classification text NOT NULL,
            confidence numeric(5,4) CHECK (confidence BETWEEN 0 AND 1),
            owner_id text NOT NULL,
            write_policy text NOT NULL,
            valid_from timestamptz NOT NULL DEFAULT now(),
            valid_until timestamptz,
            superseded_by uuid REFERENCES memory_records(memory_id),
            deleted_at timestamptz,
            created_at timestamptz NOT NULL DEFAULT now(),
            CHECK (valid_until IS NULL OR valid_until > valid_from)
        )
        """
    )
    _execute(
        "CREATE INDEX idx_memory_subject_active "
        "ON memory_records (tenant_id, subject_type, subject_id, memory_type) "
        "WHERE deleted_at IS NULL"
    )

    _execute(
        """
        CREATE TABLE outbox_events (
            outbox_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id text NOT NULL,
            aggregate_type text NOT NULL,
            aggregate_id text NOT NULL,
            event_key text NOT NULL,
            event_type text NOT NULL,
            payload jsonb NOT NULL,
            payload_hash text NOT NULL,
            available_at timestamptz NOT NULL DEFAULT now(),
            attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
            last_error text,
            published_at timestamptz,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (aggregate_type, aggregate_id, event_key)
        )
        """
    )
    _execute(
        "CREATE INDEX idx_outbox_pending ON outbox_events (available_at) WHERE published_at IS NULL"
    )
    _execute(
        """
        CREATE TABLE webhook_endpoints (
            endpoint_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id text NOT NULL,
            endpoint_name text NOT NULL,
            url text NOT NULL,
            event_types text[] NOT NULL,
            signing_secret_ref text NOT NULL,
            enabled boolean NOT NULL DEFAULT true,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (tenant_id, endpoint_name)
        )
        """
    )
    _execute(
        """
        CREATE TABLE webhook_deliveries (
            delivery_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id text NOT NULL,
            endpoint_id uuid NOT NULL
                REFERENCES webhook_endpoints(endpoint_id) ON DELETE RESTRICT,
            outbox_id uuid NOT NULL
                REFERENCES outbox_events(outbox_id) ON DELETE RESTRICT,
            status text NOT NULL DEFAULT 'pending' CHECK (
                status IN ('pending','delivering','delivered','retry','dead_letter')
            ),
            attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
            response_status integer,
            response_hash text,
            last_error text,
            next_attempt_at timestamptz NOT NULL DEFAULT now(),
            delivered_at timestamptz,
            dead_lettered_at timestamptz,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (endpoint_id, outbox_id)
        )
        """
    )
    _execute(
        "CREATE INDEX idx_webhook_delivery_pending "
        "ON webhook_deliveries (next_attempt_at) "
        "WHERE status IN ('pending','retry')"
    )
    _execute(
        """
        CREATE TABLE capability_kill_switches (
            tenant_id text NOT NULL,
            capability_name text NOT NULL,
            mode text NOT NULL DEFAULT 'none'
                CHECK (mode IN ('none','writes','all')),
            reason text NOT NULL,
            changed_by text NOT NULL,
            expires_at timestamptz,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (tenant_id, capability_name)
        )
        """
    )
    _execute(
        """
        CREATE TABLE memory_lifecycle_events (
            event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            memory_id uuid NOT NULL
                REFERENCES memory_records(memory_id) ON DELETE RESTRICT,
            tenant_id text NOT NULL,
            event_type text NOT NULL CHECK (
                event_type IN ('created','validated','superseded','expired','deleted')
            ),
            actor_id text NOT NULL,
            reason text NOT NULL,
            previous_hash text,
            replacement_memory_id uuid REFERENCES memory_records(memory_id),
            metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
            created_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    _execute(
        "CREATE INDEX idx_memory_lifecycle_memory_time "
        "ON memory_lifecycle_events (memory_id, created_at)"
    )

    # Add cyclic Artifact references only after both sides exist.
    _execute(
        "ALTER TABLE agent_runs ADD CONSTRAINT fk_agent_runs_final_artifact "
        "FOREIGN KEY (final_artifact_id) REFERENCES artifacts(artifact_id)"
    )
    _execute(
        "ALTER TABLE agent_runs ADD CONSTRAINT fk_agent_runs_failure_detail "
        "FOREIGN KEY (failure_detail_ref) REFERENCES artifacts(artifact_id)"
    )
    _execute(
        "ALTER TABLE task_executions ADD CONSTRAINT fk_task_exec_output_artifact "
        "FOREIGN KEY (output_artifact_id) REFERENCES artifacts(artifact_id)"
    )
    _execute(
        "ALTER TABLE tool_invocations ADD CONSTRAINT fk_tool_inv_result_artifact "
        "FOREIGN KEY (result_artifact_id) REFERENCES artifacts(artifact_id)"
    )
    _execute(
        "ALTER TABLE prepared_actions ADD CONSTRAINT fk_action_receipt_artifact "
        "FOREIGN KEY (receipt_artifact_id) REFERENCES artifacts(artifact_id)"
    )

    tenant_tables = (
        "agent_runs",
        "run_events",
        "prepared_actions",
        "artifacts",
        "execution_plans",
        "task_executions",
        "tool_invocations",
        "approvals",
        "idempotency_records",
        "tool_catalog",
        "memory_records",
        "outbox_events",
        "webhook_endpoints",
        "webhook_deliveries",
        "capability_kill_switches",
        "memory_lifecycle_events",
    )
    for table in tenant_tables:
        _execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        _execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        _execute(
            f"CREATE POLICY tenant_isolation_{table} ON {table} "
            "USING (tenant_id = current_setting('app.tenant_id', true)) "
            "WITH CHECK (tenant_id = current_setting('app.tenant_id', true))"
        )

    # Allocate sequence numbers under the agent_runs row lock. This remains
    # deterministic across time partitions and avoids the specification's MAX race.
    _execute(
        """
        CREATE OR REPLACE FUNCTION transition_run(
            p_run_id uuid,
            p_tenant_id text,
            p_expected run_status[],
            p_target run_status,
            p_expected_version bigint,
            p_event_type text,
            p_actor_type text,
            p_actor_id text,
            p_correlation_id text,
            p_payload jsonb,
            p_payload_hash text
        ) RETURNS agent_runs
        LANGUAGE plpgsql
        SECURITY INVOKER
        AS $$
        DECLARE
            v_run agent_runs;
            v_next_seq bigint;
            v_event_key text;
        BEGIN
            UPDATE agent_runs
            SET status = p_target,
                version = version + 1,
                updated_at = now(),
                completed_at = CASE
                    WHEN p_target IN ('completed','failed','cancelled') THEN now()
                    ELSE completed_at
                END
            WHERE run_id = p_run_id
              AND tenant_id = p_tenant_id
              AND status = ANY(p_expected)
              AND version = p_expected_version
            RETURNING * INTO v_run;

            IF NOT FOUND THEN
                RAISE EXCEPTION 'run transition conflict'
                    USING ERRCODE = '40001';
            END IF;

            INSERT INTO run_event_sequences(run_id, next_sequence_no)
            VALUES (p_run_id, 2)
            ON CONFLICT (run_id) DO UPDATE
            SET next_sequence_no = run_event_sequences.next_sequence_no + 1
            RETURNING next_sequence_no - 1 INTO v_next_seq;

            INSERT INTO run_events(
                run_id, tenant_id, sequence_no, event_type, actor_type,
                actor_id, correlation_id, payload, payload_hash
            ) VALUES (
                p_run_id, p_tenant_id, v_next_seq, p_event_type, p_actor_type,
                p_actor_id, p_correlation_id, p_payload, p_payload_hash
            );

            v_event_key := p_correlation_id || ':' || v_next_seq::text;
            INSERT INTO outbox_events(
                tenant_id, aggregate_type, aggregate_id, event_key,
                event_type, payload, payload_hash
            ) VALUES (
                p_tenant_id, 'run', p_run_id::text, v_event_key,
                p_event_type, p_payload, p_payload_hash
            );

            RETURN v_run;
        END
        $$
        """
    )


def downgrade() -> None:
    _execute("DROP FUNCTION IF EXISTS transition_run")
    for table in (
        "memory_lifecycle_events",
        "capability_kill_switches",
        "webhook_deliveries",
        "webhook_endpoints",
        "outbox_events",
        "memory_records",
        "tool_catalog",
        "prompt_versions",
        "idempotency_records",
        "approvals",
        "prepared_actions",
        "tool_invocations",
        "task_executions",
        "execution_plans",
        "run_events",
        "run_event_sequences",
        "artifacts",
        "agent_runs",
    ):
        _execute(f"DROP TABLE IF EXISTS {table} CASCADE")
    for enum_type in (
        "tool_effect",
        "risk_level",
        "approval_decision",
        "action_status",
        "task_status",
        "run_status",
    ):
        _execute(f"DROP TYPE IF EXISTS {enum_type}")
