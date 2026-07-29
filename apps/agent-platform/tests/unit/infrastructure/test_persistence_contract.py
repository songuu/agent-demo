from __future__ import annotations

from sqlalchemy.dialects import postgresql

from agent_platform.infrastructure.persistence.models import (
    ActionStatus,
    AgentRun,
    Base,
    RunStatus,
)
from agent_platform.infrastructure.persistence.repositories import (
    build_transition_statement,
)


def test_foundation_metadata_contains_auditable_platform_tables() -> None:
    expected = {
        "agent_runs",
        "run_events",
        "execution_plans",
        "task_executions",
        "tool_invocations",
        "prepared_actions",
        "approvals",
        "artifacts",
        "idempotency_records",
        "prompt_versions",
        "tool_catalog",
        "memory_records",
        "outbox_events",
        "webhook_endpoints",
        "webhook_deliveries",
        "capability_kill_switches",
        "memory_lifecycle_events",
    }

    assert expected <= set(Base.metadata.tables)


def test_paused_is_an_explicit_controlled_run_status_extension() -> None:
    assert RunStatus.PAUSED.value == "paused"
    assert AgentRun.__table__.c.status.default.arg == RunStatus.RECEIVED


def test_action_status_preserves_unknown_outcome_for_reconciliation() -> None:
    assert ActionStatus.UNKNOWN.value == "unknown"


def test_transition_statement_uses_database_atomic_function() -> None:
    statement = build_transition_statement(
        run_id="00000000-0000-0000-0000-000000000001",
        tenant_id="tenant-a",
        expected=(RunStatus.EXECUTING,),
        target=RunStatus.VERIFYING,
        expected_version=3,
        event_type="run.status_changed",
        actor_type="worker",
        actor_id="worker-1",
        correlation_id="corr-1",
        payload={"schema_version": "1.0"},
        payload_hash="abc",
    )
    rendered = str(statement.compile(dialect=postgresql.dialect()))

    assert "transition_run" in rendered
    assert "p_expected_version" in rendered
