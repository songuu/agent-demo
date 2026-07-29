from __future__ import annotations

import hashlib
import os
from collections.abc import AsyncIterable, Iterable, Mapping
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import select, text

from agent_platform.domain.hashing import canonical_json
from agent_platform.infrastructure.persistence.models import (
    AgentRun,
    Artifact,
    RiskLevel,
    RunEvent,
    RunStatus,
)
from agent_platform.infrastructure.persistence.retention_models import (
    LegalHold,
    LegalHoldEvent,
    RetentionEvidence,
    RetentionJob,
)
from agent_platform.infrastructure.persistence.session import (
    create_session_factory,
    dispose_session_factory,
)
from agent_platform.infrastructure.retention_lifecycle import (
    ApplyLegalHold,
    ArchiveDescriptor,
    ImmutableArchiveReceipt,
    PostgresLegalHoldService,
    PostgresLifecycleRetention,
)

pytestmark = pytest.mark.integration


class _Archive:
    async def archive_json_lines(
        self,
        descriptor: ArchiveDescriptor,
        rows: Iterable[Mapping[str, Any]] | AsyncIterable[Mapping[str, Any]],
    ) -> ImmutableArchiveReceipt:
        values: list[Mapping[str, Any]] = []
        if isinstance(rows, AsyncIterable):
            async for row in rows:
                values.append(row)
        else:
            values.extend(rows)
        content = canonical_json(
            {
                "descriptor": descriptor,
                "rows": values,
            }
        ).encode()
        digest = hashlib.sha256(content).hexdigest()
        return ImmutableArchiveReceipt(
            tenant_id=descriptor.tenant_id,
            resource_type=descriptor.resource_type,
            resource_id=descriptor.resource_id,
            uri=f"s3://retention-test/{descriptor.resource_type}/{digest}.jsonl",
            sha256=digest,
            version_id=f"version-{digest[:12]}",
            object_lock_mode="COMPLIANCE",
            retain_until=datetime.now(UTC)
            + timedelta(days=descriptor.policy.archive_retention_days or 365),
            content_length=len(content),
            policy_key=descriptor.policy.policy_key,
            policy_version=descriptor.policy.version,
        )

    async def restore_and_verify(self, receipt: ImmutableArchiveReceipt) -> bytes:
        raise NotImplementedError(receipt.uri)


@pytest.mark.asyncio
async def test_lifecycle_migration_and_worker_archive_purge_with_evidence() -> None:
    database_url = os.getenv("AGENT_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("AGENT_TEST_DATABASE_URL is required for PostgreSQL integration tests")
    factory = create_session_factory(database_url)
    tenant_id = f"retention-{uuid4()}"
    run_id = uuid4()
    now = datetime.now(UTC)
    try:
        async with factory() as session:
            policy_count = await session.scalar(
                text(
                    "SELECT count(*) FROM retention_policy_versions "
                    "WHERE tenant_id = '__platform__'"
                )
            )
            rls = await session.scalar(
                text("SELECT relrowsecurity FROM pg_class WHERE relname = 'retention_evidence'")
            )
            append_trigger = await session.scalar(
                text(
                    "SELECT EXISTS (SELECT 1 FROM pg_trigger "
                    "WHERE tgname = 'trg_retention_evidence_append_only')"
                )
            )
        assert policy_count == 5
        assert rls is True
        assert append_trigger is True

        async with factory() as session, session.begin():
            session.add(
                AgentRun(
                    run_id=run_id,
                    tenant_id=tenant_id,
                    principal_id="principal-sensitive",
                    use_case="retention-integration",
                    status=RunStatus.COMPLETED,
                    risk=RiskLevel.LOW,
                    contract_schema_version="TaskContract@1.0",
                    contract_json={"goal": "sensitive goal"},
                    current_plan_version=0,
                    workflow_id=f"workflow-{run_id}",
                    workflow_run_id=f"workflow-run-{run_id}",
                    idempotency_key=f"idempotency-{run_id}",
                    request_hash="a" * 64,
                    cost_limit_usd=Decimal("1"),
                    cost_actual_usd=Decimal("0.25"),
                    token_input=100,
                    token_output=50,
                    tool_call_count=1,
                    deadline_at=now - timedelta(days=499),
                    version=0,
                    created_at=now - timedelta(days=500),
                    updated_at=now - timedelta(days=500),
                    completed_at=now - timedelta(days=500),
                )
            )
            session.add(
                RunEvent(
                    run_id=run_id,
                    tenant_id=tenant_id,
                    sequence_no=1,
                    event_type="run.completed",
                    schema_version="1.0",
                    actor_type="workflow",
                    actor_id="workflow",
                    task_id=None,
                    action_id=None,
                    correlation_id=f"correlation-{run_id}",
                    payload={"status": "completed"},
                    payload_hash="b" * 64,
                    created_at=now - timedelta(days=500),
                )
            )

        report = await PostgresLifecycleRetention(
            session_factory=factory,
            archive=_Archive(),
        ).run_once(now=now, batch_size=100)

        assert report.archived_runs >= 1
        assert report.purged_runs >= 1
        assert report.archived_event_streams >= 1
        assert report.failures == 0

        async with factory() as session:
            run = await session.scalar(
                select(AgentRun).where(
                    AgentRun.run_id == run_id,
                    AgentRun.tenant_id == tenant_id,
                )
            )
            jobs = list(
                (
                    await session.scalars(
                        select(RetentionJob)
                        .where(
                            RetentionJob.tenant_id == tenant_id,
                            RetentionJob.resource_id == str(run_id),
                        )
                        .order_by(RetentionJob.resource_type, RetentionJob.operation)
                    )
                ).all()
            )
            evidence = list(
                (
                    await session.scalars(
                        select(RetentionEvidence).where(
                            RetentionEvidence.tenant_id == tenant_id,
                            RetentionEvidence.resource_id == str(run_id),
                        )
                    )
                ).all()
            )
            event_count = await session.scalar(
                select(text("count(*)"))
                .select_from(RunEvent)
                .where(
                    RunEvent.run_id == run_id,
                    RunEvent.tenant_id == tenant_id,
                )
            )

        assert run is not None
        assert run.contract_schema_version == "RetentionPurged@1.0"
        assert run.contract_json["retention_status"] == "purged"
        assert run.principal_id.startswith("sha256:")
        assert {(job.resource_type, job.operation, job.status) for job in jobs} == {
            ("agent_run", "archive", "succeeded"),
            ("agent_run", "purge", "succeeded"),
            ("run_event", "archive", "succeeded"),
        }
        assert {item.operation for item in evidence} == {"archived", "purged"}
        assert all(item.evidence_hash for item in evidence)
        assert event_count == 1
    finally:
        await dispose_session_factory(factory)


@pytest.mark.asyncio
async def test_artifact_legal_hold_projects_through_rls_and_release_is_auditable() -> None:
    database_url = os.getenv("AGENT_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("AGENT_TEST_DATABASE_URL is required for PostgreSQL integration tests")
    factory = create_session_factory(database_url)
    tenant_id = f"legal-hold-{uuid4()}"
    artifact_id = uuid4()
    now = datetime.now(UTC)
    try:
        async with factory() as session, session.begin():
            session.add(
                Artifact(
                    artifact_id=artifact_id,
                    run_id=None,
                    tenant_id=tenant_id,
                    task_id=None,
                    kind="release-evidence",
                    uri=f"s3://retention-test/{tenant_id}/{artifact_id}",
                    media_type="application/json",
                    size_bytes=2,
                    sha256="c" * 64,
                    classification="restricted",
                    source_json={},
                    created_by="release-controller",
                    retention_policy="release-evidence@1:immutable:365d",
                    encryption_key_ref="kms-test",
                    object_version_id="version-test",
                    object_retain_until=now + timedelta(days=365),
                    legal_hold_status="none",
                    expires_at=now + timedelta(days=365),
                    lifecycle_status="available",
                    delete_attempts=0,
                )
            )

        service = PostgresLegalHoldService(factory)
        hold_id = await service.apply(
            ApplyLegalHold(
                tenant_id=tenant_id,
                resource_type="artifact",
                resource_id=str(artifact_id),
                reason="Regulatory investigation",
                case_reference="case-2026-001",
                owner_id="legal",
                policy_key="release-evidence-default",
                policy_version=1,
                starts_at=now,
            ),
            actor_id="legal-officer-1",
        )

        async with factory() as session:
            held = await session.scalar(select(Artifact).where(Artifact.artifact_id == artifact_id))
            applied = await session.scalar(select(LegalHold).where(LegalHold.hold_id == hold_id))
        assert held is not None and held.legal_hold_status == "on"
        assert applied is not None and applied.status == "active"

        await service.release(
            tenant_id=tenant_id,
            hold_id=hold_id,
            actor_id="legal-officer-2",
            reason="Investigation closed",
            now=now + timedelta(hours=1),
        )

        async with factory() as session:
            released_artifact = await session.scalar(
                select(Artifact).where(Artifact.artifact_id == artifact_id)
            )
            released_hold = await session.scalar(
                select(LegalHold).where(LegalHold.hold_id == hold_id)
            )
            events = list(
                (
                    await session.scalars(
                        select(LegalHoldEvent)
                        .where(LegalHoldEvent.hold_id == hold_id)
                        .order_by(LegalHoldEvent.sequence_no)
                    )
                ).all()
            )
        assert released_artifact is not None
        assert released_artifact.legal_hold_status == "none"
        assert released_hold is not None and released_hold.status == "released"
        assert [event.event_type for event in events] == ["applied", "released"]
        assert events[1].previous_hash == events[0].event_hash
    finally:
        await dispose_session_factory(factory)
