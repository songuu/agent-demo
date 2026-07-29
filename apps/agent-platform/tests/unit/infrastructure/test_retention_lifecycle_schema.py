from __future__ import annotations

from pathlib import Path

from agent_platform.infrastructure.persistence.retention_models import (
    LegalHold,
    LegalHoldEvent,
    RetentionEvidence,
    RetentionJob,
    RetentionPolicyVersion,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def test_retention_schema_models_cover_policy_hold_retry_and_evidence() -> None:
    assert RetentionPolicyVersion.__table__.primary_key.columns.keys() == [
        "tenant_id",
        "policy_key",
        "version",
    ]
    assert {
        "resource_type",
        "classification",
        "business_requirement",
        "audit_requirement",
        "owner_id",
        "online_retention_days",
        "archive_retention_days",
        "disposition",
        "immutable_archive",
        "legal_hold_enabled",
    }.issubset(RetentionPolicyVersion.__table__.columns.keys())
    assert {"resource_type", "resource_id", "owner_id", "status"}.issubset(
        LegalHold.__table__.columns.keys()
    )
    assert {"event_type", "actor_id", "reason", "event_hash"}.issubset(
        LegalHoldEvent.__table__.columns.keys()
    )
    assert {
        "status",
        "attempts",
        "next_attempt_at",
        "archive_uri",
        "archive_sha256",
        "archive_version_id",
        "object_lock_mode",
        "retain_until",
        "last_error_code",
    }.issubset(RetentionJob.__table__.columns.keys())
    assert {
        "operation",
        "policy_key",
        "policy_version",
        "source_payload_hash",
        "previous_hash",
        "evidence_hash",
    }.issubset(RetentionEvidence.__table__.columns.keys())


def test_retention_migration_seeds_architecture_baselines_and_enforces_rls() -> None:
    migration = (
        PROJECT_ROOT / "migrations" / "versions" / "20260724_0008_retention_lifecycle_expand.py"
    ).read_text(encoding="utf-8")

    for table in (
        "retention_policy_versions",
        "legal_holds",
        "legal_hold_events",
        "retention_jobs",
        "retention_evidence",
    ):
        assert f"CREATE TABLE {table}" in migration
        assert f'"{table}",' in migration
    assert 'f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"' in migration
    assert 'f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"' in migration

    assert "CREATE TRIGGER trg_{table}_append_only" in migration
    for immutable_table in (
        "retention_policy_versions",
        "legal_hold_events",
        "retention_evidence",
    ):
        assert f'"{immutable_table}",' in migration
    assert "'agent_run'" in migration
    assert "180" in migration
    assert "'run_event'" in migration
    assert "365" in migration
    assert "'model_raw'" in migration
    assert "'tool_raw'" in migration
    assert "'approval_receipt'" in migration


def test_retention_cli_is_real_worker_wiring() -> None:
    retention_module = (
        PROJECT_ROOT / "src" / "agent_platform" / "infrastructure" / "retention.py"
    ).read_text(encoding="utf-8")
    worker_module = (
        PROJECT_ROOT / "src" / "agent_platform" / "infrastructure" / "retention_worker.py"
    ).read_text(encoding="utf-8")

    assert "RETENTION_ADAPTER_REQUIRED" not in retention_module
    assert "PostgresLifecycleRetention" in worker_module
    assert "S3ImmutableArchiveAdapter" in worker_module
