from __future__ import annotations

import asyncio
import copy
import hashlib
import os
import subprocess
import sys
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from prometheus_client import CollectorRegistry
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import create_async_engine
from testcontainers.postgres import PostgresContainer

from agent_platform.application.errors import Conflict, NotFound, PlatformError, UnknownOutcome
from agent_platform.application.records import (
    ActionRecord,
    ArtifactDownload,
    ArtifactRecord,
    AuditEvent,
    CapabilityRecord,
    PlanExecutionRecord,
    RunRecord,
    TaskExecutionRecord,
    ToolInvocationRecord,
)
from agent_platform.application.trajectory_monitor import (
    TrajectoryCandidate,
    TrajectoryGuard,
)
from agent_platform.domain.enums import ActionStatus, RiskLevel, RunStatus, ToolEffect
from agent_platform.domain.hashing import payload_hash
from agent_platform.domain.models import (
    DataScope,
    ExecutionPlan,
    FinalResponse,
    Principal,
    SuccessCriterion,
    TaskContract,
    TaskSpec,
    WorkerOutput,
)
from agent_platform.infrastructure.observability.metrics import PlatformMetrics
from agent_platform.infrastructure.observability.operational_metrics import (
    OperationalMetricsCollector,
)
from agent_platform.infrastructure.persistence.artifact_models import (
    ArtifactDownloadAudit,
)
from agent_platform.infrastructure.persistence.models import (
    Artifact,
    OutboxEvent,
    PreparedAction,
    RunEvent,
    TaskExecution,
    ToolInvocation,
)
from agent_platform.infrastructure.persistence.production_store import (
    AesGcmActionPayloadCipher,
    PostgresPlatformStore,
    PostgresRunRepository,
)
from agent_platform.infrastructure.persistence.session import (
    AsyncSessionFactory,
    create_session_factory,
    dispose_session_factory,
    tenant_session,
)

pytestmark = pytest.mark.integration
PROJECT_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True, slots=True)
class DatabaseUrls:
    admin: str
    application: str


class MemoryContentStore:
    def __init__(self) -> None:
        self.records: dict[tuple[str, UUID], ArtifactRecord] = {}

    async def put(self, artifact: ArtifactRecord) -> ArtifactRecord:
        self.records[(artifact.tenant_id, artifact.artifact_id)] = copy.deepcopy(artifact)
        return copy.deepcopy(artifact)

    async def get(self, artifact_id: UUID, tenant_id: str) -> ArtifactRecord:
        artifact = self.records.get((tenant_id, artifact_id))
        if artifact is None:
            raise NotFound("artifact", str(artifact_id))
        return copy.deepcopy(artifact)

    async def delete(self, artifact_id: UUID, tenant_id: str) -> None:
        if self.records.pop((tenant_id, artifact_id), None) is None:
            raise NotFound("artifact", str(artifact_id))

    def uri_for(self, artifact: ArtifactRecord) -> str:
        run_part = str(artifact.run_id) if artifact.run_id else "unbound"
        return (
            f"s3://test-bucket/test/tenant/{artifact.tenant_id}/"
            f"run/{run_part}/artifacts/{artifact.artifact_id}"
        )

    async def create_download(
        self,
        artifact: ArtifactRecord,
        *,
        principal_id: str,
        tenant_id: str,
        purpose: str,
        expires_in_seconds: int,
    ) -> ArtifactDownload:
        assert principal_id and purpose and artifact.tenant_id == tenant_id
        return ArtifactDownload(
            artifact_id=artifact.artifact_id,
            url=f"https://download.test/{artifact.artifact_id}?signature=fake",
            expires_at=datetime.now(UTC) + timedelta(seconds=expires_in_seconds),
        )


def malware_provenance(content: bytes) -> dict[str, object]:
    return {
        "malware": {
            "request_id": "postgres-scan-request",
            "sha256": hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content),
            "verdict": "clean",
            "engine": "controlled-av",
            "engine_version": "2026.07.24",
            "scanned_at": "2026-07-24T12:00:00+00:00",
            "evidence_id": "postgres-scan-evidence",
        }
    }


async def _provision_application_role(admin_url: str) -> str:
    admin = make_url(admin_url)
    application = admin.set(
        username="agent_store_test",
        password="agent-store-test",
    )
    engine = create_async_engine(admin_url)
    try:
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "CREATE ROLE agent_store_test LOGIN PASSWORD "
                    "'agent-store-test' NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE NOINHERIT NOBYPASSRLS"
                )
            )
            await connection.execute(
                text(f'GRANT CONNECT ON DATABASE "{admin.database}" TO agent_store_test')
            )
            await connection.execute(text("GRANT USAGE ON SCHEMA public TO agent_store_test"))
            await connection.execute(
                text(
                    "GRANT SELECT, INSERT, UPDATE, DELETE "
                    "ON ALL TABLES IN SCHEMA public TO agent_store_test"
                )
            )
            await connection.execute(
                text(
                    "GRANT USAGE, SELECT, UPDATE "
                    "ON ALL SEQUENCES IN SCHEMA public TO agent_store_test"
                )
            )
            await connection.execute(
                text("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO agent_store_test")
            )
    finally:
        await engine.dispose()
    return application.render_as_string(hide_password=False)


@pytest.fixture(scope="module")
def database_urls() -> Iterator[DatabaseUrls]:
    with PostgresContainer("postgres:16-alpine") as postgres:
        admin_url = postgres.get_connection_url(driver="asyncpg")
        environment = dict(os.environ)
        environment["AGENT_DATABASE_URL"] = admin_url
        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=PROJECT_ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        application_url = asyncio.run(_provision_application_role(admin_url))
        yield DatabaseUrls(admin=admin_url, application=application_url)


@pytest.fixture
async def database_factory(
    database_urls: DatabaseUrls,
) -> AsyncIterator[AsyncSessionFactory]:
    factory = create_session_factory(database_urls.application, pool_size=5)
    try:
        yield factory
    finally:
        await dispose_session_factory(factory)


@pytest.fixture
def content_store() -> MemoryContentStore:
    return MemoryContentStore()


@pytest.fixture
def store(
    database_factory: AsyncSessionFactory,
    content_store: MemoryContentStore,
) -> PostgresPlatformStore:
    return PostgresPlatformStore(
        database_factory,
        action_payload_cipher=AesGcmActionPayloadCipher(b"k" * 32),
        artifact_content_store=content_store,
    )


def make_contract(tenant_id: str) -> TaskContract:
    return TaskContract(
        goal="Persist a bounded Agent run",
        success_criteria=[
            SuccessCriterion(
                id="persisted",
                description="The state survives a database round trip",
                verification="environment",
                evidence_required=True,
            )
        ],
        principal=Principal(
            user_id="user-1",
            tenant_id=tenant_id,
            roles=frozenset({"operator"}),
            scopes=frozenset({"email.send"}),
            auth_strength="mfa",
        ),
        data_scope=DataScope(
            tenant_id=tenant_id,
            resource_types=frozenset({"email"}),
        ),
        risk=RiskLevel.HIGH,
        allowed_capabilities=frozenset({"email.prepare"}),
        max_cost_usd=Decimal("5"),
        max_duration_seconds=321,
        max_replans=4,
        external_write_policy="approval",
    )


def make_run(
    *,
    tenant_id: str = "tenant-a",
    idempotency_key: str | None = None,
    request_hash: str = "a" * 64,
) -> RunRecord:
    run_id = uuid4()
    return RunRecord(
        run_id=run_id,
        tenant_id=tenant_id,
        principal_id="user-1",
        contract=make_contract(tenant_id),
        idempotency_key=idempotency_key or f"request-{run_id}",
        request_hash=request_hash,
        workflow_id=f"agent-run-{run_id}",
    )


def make_action(run: RunRecord, *, idempotency_key: str = "action-1") -> ActionRecord:
    return ActionRecord(
        action_id=uuid4(),
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        principal_id=run.principal_id,
        action_type="email.send",
        tool_name="email.prepare",
        tool_version="1.0.0",
        canonical_payload={"subject": "Approved"},
        payload_hash="b" * 64,
        preview={"subject": "Approved"},
        risk=RiskLevel.HIGH,
        approval_policy="human",
        required_approvals=1,
        idempotency_key=idempotency_key,
        policy_version="bundle-1",
        expires_at=datetime(2099, 1, 1, tzinfo=UTC),
    )


@pytest.mark.asyncio
async def test_operational_metrics_snapshot_executes_against_postgres(
    database_urls: DatabaseUrls,
    store: PostgresPlatformStore,
) -> None:
    management_factory = create_session_factory(database_urls.admin, pool_size=2)
    try:
        collector = OperationalMetricsCollector(
            management_factory,
            PlatformMetrics(CollectorRegistry()),
            environment="test",
        )
        empty = await collector._read_postgres_snapshot()
        assert empty.pending_total == 0
        assert empty.missing_notification_count == 0
        assert set(empty.pending_by_risk.values()) == {0}
        assert set(empty.approval_webhook_by_status.values()) == {0}

        run, _ = await store.runs.create_once(
            make_run(idempotency_key=f"operational-metrics-{uuid4()}")
        )
        action = replace(
            make_action(run, idempotency_key=f"operational-action-{uuid4()}"),
            status=ActionStatus.PENDING_APPROVAL,
        )
        _, created, event = await store.actions.create_once_with_event(
            action,
            AuditEvent(
                event_type="action.approval_required",
                payload={
                    "run_id": str(run.run_id),
                    "action_id": str(action.action_id),
                    "payload_hash": action.payload_hash,
                },
                correlation_id="operational-metrics-integration",
                action_id=action.action_id,
            ),
        )
        assert created is True
        assert event is not None

        snapshot = await collector._read_postgres_snapshot()

        assert snapshot.pending_total == 1
        assert snapshot.pending_by_risk["high"] == 1
        assert snapshot.missing_notification_count == 1
        assert snapshot.missing_notification_oldest_age_seconds >= 0
        assert set(snapshot.approval_webhook_by_status.values()) == {0}
    finally:
        await dispose_session_factory(management_factory)


@pytest.mark.asyncio
async def test_run_idempotency_contract_resolution_and_rls_non_disclosure(
    store: PostgresPlatformStore,
) -> None:
    run = make_run(idempotency_key=f"run-idempotency-{uuid4()}")
    stored, created = await store.runs.create_once(run)
    duplicate_input = make_run(idempotency_key=run.idempotency_key)
    duplicate, duplicate_created = await store.runs.create_once(duplicate_input)

    assert created is True
    assert duplicate_created is False
    assert duplicate.run_id == stored.run_id
    assert duplicate.contract == run.contract
    contract = await store.runs.resolve_contract(stored.run_id, stored.tenant_id)
    assert (contract.max_replans, contract.max_duration_seconds) == (4, 321)

    with pytest.raises(NotFound):
        await store.runs.get(stored.run_id, "tenant-b")

    changed = make_run(
        idempotency_key=run.idempotency_key,
        request_hash="c" * 64,
    )
    with pytest.raises(Conflict, match="different request"):
        await store.runs.create_once(changed)


@pytest.mark.asyncio
async def test_run_creation_first_event_and_outbox_are_atomic(
    store: PostgresPlatformStore,
    database_factory: AsyncSessionFactory,
) -> None:
    run = make_run(idempotency_key=f"atomic-create-{uuid4()}")
    stored, created, event = await store.runs.create_once_with_event(
        run,
        "run.status_changed",
        {"from": None, "to": "received"},
        "correlation-create",
    )

    assert created is True
    assert event is not None
    assert event.sequence_no == 1
    duplicate, duplicate_created, duplicate_event = await store.runs.create_once_with_event(
        replace(run, run_id=uuid4()),
        "run.status_changed",
        {"from": None, "to": "received"},
        "correlation-duplicate",
    )
    assert duplicate.run_id == stored.run_id
    assert duplicate_created is False
    assert duplicate_event is None
    assert len(await store.runs.events_after(run.run_id, run.tenant_id, 0)) == 1

    failed = make_run(idempotency_key=f"atomic-create-failure-{uuid4()}")
    with pytest.raises((TypeError, ValueError)):
        await store.runs.create_once_with_event(
            failed,
            "run.status_changed",
            {"not_json": object()},
            "correlation-create-rollback",
        )
    with pytest.raises(NotFound):
        await store.runs.get(failed.run_id, failed.tenant_id)

    async with tenant_session(database_factory, run.tenant_id) as session:
        event_count = await session.scalar(
            select(func.count())
            .select_from(OutboxEvent)
            .where(OutboxEvent.aggregate_id == str(run.run_id))
        )
        failed_event_count = await session.scalar(
            select(func.count())
            .select_from(OutboxEvent)
            .where(OutboxEvent.aggregate_id == str(failed.run_id))
        )
    assert event_count == 1
    assert failed_event_count == 0


@pytest.mark.asyncio
async def test_run_snapshot_event_and_outbox_are_atomic(
    store: PostgresPlatformStore,
    database_factory: AsyncSessionFactory,
) -> None:
    run, _ = await store.runs.create_once(make_run())
    expected_version = run.version
    run.status = RunStatus.EXECUTING
    run.progress = 0.5
    run.plan = ExecutionPlan(
        plan_version=1,
        tasks=[
            TaskSpec(
                id="task-1",
                kind="analysis",
                objective="Verify a typed snapshot round trip",
                output_schema="WorkerOutput@1.0",
                risk=RiskLevel.HIGH,
                estimated_cost_usd=Decimal("1"),
            )
        ],
        final_task_id="task-1",
        expected_total_cost_usd=Decimal("1"),
    )
    run.current_plan_version = 1
    run.outputs["task-1"] = WorkerOutput(summary="durable")
    run.result = FinalResponse(summary="verified")
    run.updated_at = datetime.now(UTC)

    stored, event = await store.runs.save_with_event(
        run,
        expected_version,
        "task.completed",
        {"task_id": "task-1"},
        "correlation-atomic",
    )

    assert stored.version == expected_version + 1
    assert stored.progress == 0.5
    assert isinstance(stored.plan, ExecutionPlan)
    assert stored.plan == run.plan
    assert stored.outputs == {"task-1": WorkerOutput(summary="durable")}
    assert stored.result == FinalResponse(summary="verified")
    assert event.sequence_no == 1
    assert [
        item.sequence_no for item in await store.runs.events_after(run.run_id, run.tenant_id, 0)
    ] == [1]
    async with tenant_session(database_factory, run.tenant_id) as session:
        assert (
            await session.scalar(
                select(func.count())
                .select_from(OutboxEvent)
                .where(OutboxEvent.aggregate_id == str(run.run_id))
            )
            == 1
        )

    stored.progress = 0.9
    stored.updated_at = datetime.now(UTC)
    with pytest.raises((TypeError, ValueError)):
        await store.runs.save_with_event(
            stored,
            stored.version,
            "run.invalid",
            {"not_json": object()},
            "correlation-rollback",
        )

    unchanged = await store.runs.get(run.run_id, run.tenant_id)
    assert unchanged.version == stored.version
    assert unchanged.progress == 0.5
    assert len(await store.runs.events_after(run.run_id, run.tenant_id, 0)) == 1


@pytest.mark.asyncio
async def test_trajectory_pause_replays_after_restart_and_is_atomic(
    store: PostgresPlatformStore,
    database_factory: AsyncSessionFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run, _ = await store.runs.create_once(make_run())
    baseline_version = run.version

    def candidate(args_hash: str) -> TrajectoryCandidate:
        return TrajectoryCandidate(
            boundary="prepare",
            task_id="sec-003",
            operation_name="email.prepare",
            capability="email.prepare",
            args_hash=args_hash,
        )

    first_guard = TrajectoryGuard(store.runs)
    first_check = await first_guard.preflight(
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        candidate=candidate("1" * 64),
        correlation_id="trajectory-first",
    )
    await first_guard.record_outcome(
        first_check,
        status="denied",
        error_code="POLICY_DENIED",
        denial_kind="policy",
    )
    baseline_events = await store.runs.events_after(run.run_id, run.tenant_id, 0)
    assert [event.event_type for event in baseline_events] == [
        "trajectory.candidate",
        "trajectory.decision",
        "trajectory.outcome",
    ]

    original_append = store.runs._append_event_in_session

    async def fail_decision(*args: Any, **kwargs: Any) -> Any:
        if len(args) >= 3 and args[2] == "trajectory.decision":
            raise RuntimeError("injected trajectory decision failure")
        return await original_append(*args, **kwargs)

    with monkeypatch.context() as fault:
        fault.setattr(store.runs, "_append_event_in_session", fail_decision)
        with pytest.raises(RuntimeError, match="injected trajectory decision failure"):
            await TrajectoryGuard(store.runs).preflight(
                run_id=run.run_id,
                tenant_id=run.tenant_id,
                candidate=candidate("2" * 64),
                correlation_id="trajectory-fault",
            )

    restarted_runs = PostgresRunRepository(database_factory)
    recovered = await restarted_runs.get(run.run_id, run.tenant_id)
    assert recovered.status is RunStatus.RECEIVED
    assert recovered.pause_requested is False
    assert recovered.version == baseline_version
    assert await restarted_runs.events_after(run.run_id, run.tenant_id, 0) == baseline_events

    with pytest.raises(PlatformError, match="TRAJECTORY_PAUSED"):
        await TrajectoryGuard(restarted_runs).preflight(
            run_id=run.run_id,
            tenant_id=run.tenant_id,
            candidate=candidate("2" * 64),
            correlation_id="trajectory-restart",
        )

    paused = await PostgresRunRepository(database_factory).get(run.run_id, run.tenant_id)
    assert paused.status is RunStatus.PAUSED
    assert paused.pause_requested is True
    assert paused.paused_from is RunStatus.RECEIVED
    assert paused.version == baseline_version + 1

    events = await restarted_runs.events_after(run.run_id, run.tenant_id, 0)
    assert [event.event_type for event in events] == [
        "trajectory.candidate",
        "trajectory.decision",
        "trajectory.outcome",
        "trajectory.candidate",
        "trajectory.decision",
    ]
    assert events[-1].payload["action"] == "pause"
    assert events[-1].payload["reason_codes"] == ["DENIAL_BYPASS_ATTEMPT"]
    assert events[-1].payload["paused_from"] == "received"
    async with tenant_session(database_factory, run.tenant_id) as session:
        outbox_count = await session.scalar(
            select(func.count())
            .select_from(OutboxEvent)
            .where(OutboxEvent.aggregate_id == str(run.run_id))
        )
    assert outbox_count == 5


@pytest.mark.asyncio
async def test_action_idempotency_row_lock_and_unknown_checkpoint(
    store: PostgresPlatformStore,
    database_factory: AsyncSessionFactory,
) -> None:
    run, _ = await store.runs.create_once(make_run())
    action = make_action(run, idempotency_key=f"action-{uuid4()}")
    stored, created = await store.actions.create_once(action)
    duplicate, duplicate_created = await store.actions.create_once(
        replace(action, action_id=uuid4())
    )

    assert created is True
    assert duplicate_created is False
    assert duplicate.action_id == stored.action_id
    with pytest.raises(NotFound):
        await store.actions.get(stored.action_id, "tenant-b")

    changed = replace(
        action,
        action_id=uuid4(),
        canonical_payload={"subject": "Changed"},
        payload_hash="d" * 64,
    )
    with pytest.raises(Conflict, match="different payload"):
        await store.actions.create_once(changed)

    with pytest.raises(UnknownOutcome):
        async with store.actions.get_for_update(stored.action_id, stored.tenant_id) as locked:
            locked.status = ActionStatus.UNKNOWN
            locked.failure_code = "COMMIT_OUTCOME_UNKNOWN"
            raise UnknownOutcome(str(locked.action_id))

    checkpoint = await store.actions.get(stored.action_id, stored.tenant_id)
    assert checkpoint.status is ActionStatus.UNKNOWN
    assert checkpoint.failure_code == "COMMIT_OUTCOME_UNKNOWN"
    assert checkpoint.version == stored.version + 1

    first_entered = asyncio.Event()
    release_first = asyncio.Event()
    second_entered = asyncio.Event()

    async def first_holder() -> None:
        async with store.actions.get_for_update(stored.action_id, stored.tenant_id):
            first_entered.set()
            await release_first.wait()

    async def second_holder() -> None:
        await first_entered.wait()
        async with store.actions.get_for_update(stored.action_id, stored.tenant_id):
            second_entered.set()

    first_task = asyncio.create_task(first_holder())
    second_task = asyncio.create_task(second_holder())
    await first_entered.wait()
    await asyncio.sleep(0.1)
    assert second_entered.is_set() is False
    release_first.set()
    await asyncio.gather(first_task, second_task)
    assert second_entered.is_set() is True

    async with tenant_session(database_factory, stored.tenant_id) as session:
        encrypted = await session.scalar(
            select(PreparedAction.payload_encrypted).where(
                PreparedAction.action_id == stored.action_id
            )
        )
    assert encrypted is not None
    assert b"Approved" not in encrypted


@pytest.mark.asyncio
async def test_artifact_metadata_and_capability_overrides_are_tenant_scoped(
    store: PostgresPlatformStore,
    content_store: MemoryContentStore,
    database_factory: AsyncSessionFactory,
) -> None:
    run, _ = await store.runs.create_once(make_run())
    await store.capabilities.register(
        "*",
        CapabilityRecord(
            name="email.prepare",
            version="1.0.0",
            effect="prepare",
            risk="high",
        ),
    )
    assert (await store.capabilities.list("tenant-a"))[0].enabled is True
    disabled = await store.capabilities.set_enabled("tenant-a", "email.prepare", False, "incident")
    assert disabled.enabled is False
    assert disabled.disabled_reason == "incident"
    assert (await store.capabilities.list("tenant-b"))[0].enabled is True

    body = b"verified artifact"
    artifact = ArtifactRecord(
        artifact_id=uuid4(),
        tenant_id=run.tenant_id,
        run_id=run.run_id,
        kind="report",
        media_type="text/plain",
        content=body,
        sha256=hashlib.sha256(body).hexdigest(),
        classification="internal",
        created_by=run.principal_id,
        scan_status="malware_clean",
        scan_provenance=malware_provenance(body),
    )
    await store.artifacts.put(artifact)
    round_trip = await store.artifacts.get(artifact.artifact_id, artifact.tenant_id)
    assert round_trip == artifact
    async with tenant_session(database_factory, artifact.tenant_id) as session:
        uri = await session.scalar(
            select(Artifact.uri).where(Artifact.artifact_id == artifact.artifact_id)
        )
        source = await session.scalar(
            select(Artifact.source_json).where(Artifact.artifact_id == artifact.artifact_id)
        )
    assert uri == content_store.uri_for(artifact)
    assert source == {
        "scan_status": "malware_clean",
        "scan_provenance": malware_provenance(body),
    }
    download = await store.artifacts.create_download(
        artifact,
        principal_id=run.principal_id,
        tenant_id=artifact.tenant_id,
        purpose="user-download",
        expires_in_seconds=300,
    )
    assert download.artifact_id == artifact.artifact_id
    assert download.url.startswith("https://download.test/")
    async with tenant_session(database_factory, artifact.tenant_id) as session:
        audit = await session.execute(
            select(
                ArtifactDownloadAudit.principal_id,
                ArtifactDownloadAudit.purpose,
            ).where(ArtifactDownloadAudit.artifact_id == artifact.artifact_id)
        )
        audit_values = audit.one()
    assert tuple(audit_values) == (
        run.principal_id,
        "user-download",
    )
    with pytest.raises(NotFound):
        await store.artifacts.get(artifact.artifact_id, "tenant-b")

    await store.artifacts.delete(artifact.artifact_id, artifact.tenant_id)
    assert (artifact.tenant_id, artifact.artifact_id) not in content_store.records
    with pytest.raises(NotFound):
        await store.artifacts.get(artifact.artifact_id, artifact.tenant_id)

    expired = replace(
        artifact,
        artifact_id=uuid4(),
        expires_at=datetime(2020, 1, 1, tzinfo=UTC),
    )
    await store.artifacts.put(expired)
    with pytest.raises(NotFound):
        await store.artifacts.get(expired.artifact_id, expired.tenant_id)


def make_invocation(
    run: RunRecord,
    *,
    effect: ToolEffect = ToolEffect.PREPARE,
    task_id: str = "task-1",
) -> ToolInvocationRecord:
    now = datetime.now(UTC)
    return ToolInvocationRecord(
        invocation_id=uuid4(),
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        plan_version=1,
        task_id=task_id,
        tool_name="email.prepare",
        tool_version="1.0.0",
        effect=effect,
        args_hash="1" * 64,
        args_redacted={"subject": "[REDACTED]"},
        data_scope_hash="2" * 64,
        policy_decision_id="3" * 64,
        policy_version="bundle-1",
        status="succeeded",
        result_hash="4" * 64,
        latency_ms=7,
        provider_request_id="provider-request-1",
        created_at=now,
        completed_at=now,
    )


@pytest.mark.asyncio
async def test_action_audit_fault_rolls_back_snapshot_invocation_event_and_outbox(
    store: PostgresPlatformStore,
    database_factory: AsyncSessionFactory,
) -> None:
    run, _ = await store.runs.create_once(make_run())
    failed_action = make_action(run, idempotency_key=f"fault-create-{uuid4()}")
    invocation = make_invocation(run)

    with pytest.raises((TypeError, ValueError)):
        await store.actions.create_once_with_event(
            failed_action,
            AuditEvent(
                event_type="action.prepared",
                payload={"not_json": object()},
                correlation_id="correlation-action-create-fault",
                action_id=failed_action.action_id,
            ),
            invocation,
        )

    with pytest.raises(NotFound):
        await store.actions.get(failed_action.action_id, failed_action.tenant_id)
    async with tenant_session(database_factory, run.tenant_id) as session:
        assert (
            await session.scalar(
                select(func.count())
                .select_from(PreparedAction)
                .where(PreparedAction.action_id == failed_action.action_id)
            )
            == 0
        )
        assert (
            await session.scalar(
                select(func.count())
                .select_from(ToolInvocation)
                .where(ToolInvocation.invocation_id == invocation.invocation_id)
            )
            == 0
        )
        assert (
            await session.scalar(
                select(func.count())
                .select_from(OutboxEvent)
                .where(OutboxEvent.aggregate_id == str(run.run_id))
            )
            == 0
        )

    action = make_action(run, idempotency_key=f"fault-update-{uuid4()}")
    stored, _ = await store.actions.create_once(action)
    with pytest.raises((TypeError, ValueError)):
        async with store.actions.transaction(stored.action_id, stored.tenant_id) as transaction:
            transaction.action.status = ActionStatus.APPROVED
            transaction.append_event(
                AuditEvent(
                    event_type="action.approval_recorded",
                    payload={"not_json": object()},
                    correlation_id="correlation-action-update-fault",
                    action_id=stored.action_id,
                )
            )

    unchanged = await store.actions.get(stored.action_id, stored.tenant_id)
    assert unchanged.status is ActionStatus.PREPARED
    assert unchanged.version == stored.version
    assert await store.runs.events_after(run.run_id, run.tenant_id, 0) == ()
    async with tenant_session(database_factory, run.tenant_id) as session:
        assert (
            await session.scalar(
                select(func.count())
                .select_from(OutboxEvent)
                .where(OutboxEvent.aggregate_id == str(run.run_id))
            )
            == 0
        )


@pytest.mark.asyncio
async def test_task_completion_fault_rolls_back_run_snapshot_and_execution_record(
    store: PostgresPlatformStore,
    database_factory: AsyncSessionFactory,
) -> None:
    run, _ = await store.runs.create_once(make_run())
    started_at = datetime.now(UTC)
    execution = TaskExecutionRecord(
        task_execution_id=uuid4(),
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        plan_version=1,
        task_id="task-1",
        task_kind="analysis",
        attempt=1,
        status="running",
        model_name="gpt-5.6-terra",
        model_settings={"reasoning": "medium"},
        prompt_id="worker",
        prompt_version="1.0.0",
        started_at=started_at,
        created_at=started_at,
    )
    await store.audit.start_task(
        execution,
        AuditEvent(
            event_type="task.started",
            payload={"task_execution_id": str(execution.task_execution_id)},
            correlation_id="correlation-task-start",
            task_id=execution.task_id,
        ),
    )

    baseline = await store.runs.get(run.run_id, run.tenant_id)
    expected_version = baseline.version
    baseline.progress = 0.75
    baseline.current_plan_version = 1
    baseline.outputs[execution.task_id] = WorkerOutput(summary="must roll back")
    baseline.updated_at = datetime.now(UTC)
    execution.status = "succeeded"
    execution.output_json = {"summary": "must roll back"}
    execution.completed_at = datetime.now(UTC)

    with pytest.raises((TypeError, ValueError)):
        await store.audit.complete_task_with_run(
            baseline,
            expected_version,
            execution,
            AuditEvent(
                event_type="task.completed",
                payload={"not_json": object()},
                correlation_id="correlation-task-completion-fault",
                task_id=execution.task_id,
            ),
        )

    unchanged = await store.runs.get(run.run_id, run.tenant_id)
    assert unchanged.version == expected_version
    assert unchanged.progress == 0
    assert unchanged.current_plan_version == 0
    assert unchanged.outputs == {}
    events = await store.runs.events_after(run.run_id, run.tenant_id, 0)
    assert [event.event_type for event in events] == ["task.started"]
    async with tenant_session(database_factory, run.tenant_id) as session:
        status = await session.scalar(
            select(TaskExecution.status).where(
                TaskExecution.task_execution_id == execution.task_execution_id
            )
        )
        outbox_count = await session.scalar(
            select(func.count())
            .select_from(OutboxEvent)
            .where(OutboxEvent.aggregate_id == str(run.run_id))
        )
    assert status is not None and status.value == "running"
    assert outbox_count == 1


@pytest.mark.asyncio
async def test_immutable_audit_tables_reject_update_and_delete(
    store: PostgresPlatformStore,
    database_factory: AsyncSessionFactory,
) -> None:
    run = make_run()
    _, _, event = await store.runs.create_once_with_event(
        run,
        "run.created",
        {"run_id": str(run.run_id)},
        "correlation-append-only",
    )
    assert event is not None

    async with tenant_session(database_factory, run.tenant_id) as session:
        trigger_names = set(
            await session.scalars(
                text(
                    "SELECT tgname FROM pg_trigger "
                    "WHERE NOT tgisinternal AND tgname LIKE 'trg_%_append_only'"
                )
            )
        )
    assert {
        "trg_run_events_append_only",
        "trg_approvals_append_only",
        "trg_execution_plans_append_only",
        "trg_tool_invocations_append_only",
    } <= trigger_names

    with pytest.raises(DBAPIError) as update_error:
        async with tenant_session(database_factory, run.tenant_id) as session:
            await session.execute(
                update(RunEvent).where(RunEvent.run_id == run.run_id).values(event_type="tampered")
            )
            await session.commit()
    assert getattr(update_error.value.orig, "sqlstate", None) == "55000"

    with pytest.raises(DBAPIError) as delete_error:
        async with tenant_session(database_factory, run.tenant_id) as session:
            await session.execute(delete(RunEvent).where(RunEvent.run_id == run.run_id))
            await session.commit()
    assert getattr(delete_error.value.orig, "sqlstate", None) == "55000"

    persisted = await store.runs.events_after(run.run_id, run.tenant_id, 0)
    assert len(persisted) == 1
    assert persisted[0].event_type == "run.created"


@pytest.mark.asyncio
async def test_audit_export_reconstructs_full_execution_and_action_provenance(
    store: PostgresPlatformStore,
) -> None:
    run, _ = await store.runs.create_once(make_run())
    task = TaskSpec(
        id="task-1",
        kind="analysis",
        objective="Produce traceable output",
        output_schema="WorkerOutput@1.0",
        risk=RiskLevel.HIGH,
        estimated_cost_usd=Decimal("1"),
    )
    plan = ExecutionPlan(
        plan_version=1,
        tasks=[task],
        final_task_id=task.id,
        expected_total_cost_usd=Decimal("1"),
    )
    plan_json = plan.model_dump(mode="json")
    plan_digest = payload_hash(plan_json)
    expected_version = run.version
    run.plan = plan
    run.current_plan_version = 1
    run.updated_at = datetime.now(UTC)
    run, _ = await store.audit.save_plan_with_run(
        run,
        expected_version,
        PlanExecutionRecord(
            plan_id=plan.plan_id,
            run_id=run.run_id,
            tenant_id=run.tenant_id,
            plan_version=1,
            schema_version=plan.schema_version,
            plan_json=plan_json,
            plan_hash=plan_digest,
            planner_model="gpt-5.6-sol",
            prompt_id="planner",
            prompt_version="1.0.0",
        ),
        AuditEvent(
            event_type="plan.created",
            payload={
                "plan_id": str(plan.plan_id),
                "plan_hash": plan_digest,
                "model_settings": {"reasoning": "high"},
                "prompt_id": "planner",
                "prompt_version": "1.0.0",
            },
            correlation_id="correlation-plan",
            actor_type="runtime",
            actor_id="gpt-5.6-sol",
        ),
    )

    now = datetime.now(UTC)
    execution = TaskExecutionRecord(
        task_execution_id=uuid4(),
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        plan_version=1,
        task_id=task.id,
        task_kind=task.kind,
        attempt=1,
        status="running",
        model_name="gpt-5.6-terra",
        model_settings={"reasoning": "medium"},
        prompt_id="worker",
        prompt_version="1.0.0",
        input_refs=[{"artifact_id": "input-1", "sha256": "5" * 64}],
        started_at=now,
        created_at=now,
    )
    await store.audit.start_task(
        execution,
        AuditEvent(
            event_type="task.started",
            payload={"task_execution_id": str(execution.task_execution_id)},
            correlation_id="correlation-task-start",
            actor_type="runtime",
            actor_id=execution.model_name,
            task_id=task.id,
        ),
    )
    run = await store.runs.get(run.run_id, run.tenant_id)
    expected_version = run.version
    output = WorkerOutput(summary="traceable output")
    run.outputs[task.id] = output
    run.progress = 1
    run.updated_at = datetime.now(UTC)
    execution.status = "succeeded"
    execution.output_json = output.model_dump(mode="json")
    execution.completed_at = datetime.now(UTC)
    run, _ = await store.audit.complete_task_with_run(
        run,
        expected_version,
        execution,
        AuditEvent(
            event_type="task.completed",
            payload={
                "task_execution_id": str(execution.task_execution_id),
                "output_hash": payload_hash(execution.output_json),
            },
            correlation_id="correlation-task-complete",
            actor_type="runtime",
            actor_id=execution.model_name,
            task_id=task.id,
        ),
    )

    artifact_body = b"receipt evidence"
    artifact = ArtifactRecord(
        artifact_id=uuid4(),
        tenant_id=run.tenant_id,
        run_id=run.run_id,
        kind="receipt",
        media_type="application/json",
        content=artifact_body,
        sha256=hashlib.sha256(artifact_body).hexdigest(),
        classification="internal",
        created_by="commit-worker",
        scan_status="malware_clean",
        scan_provenance=malware_provenance(artifact_body),
    )
    await store.artifacts.put(artifact)

    action = make_action(run, idempotency_key=f"audit-export-{uuid4()}")
    prepare_invocation = make_invocation(run)
    _, created, _ = await store.actions.create_once_with_event(
        action,
        AuditEvent(
            event_type="action.prepared",
            payload={
                "action_id": str(action.action_id),
                "tool_invocation_id": str(prepare_invocation.invocation_id),
                "payload_hash": action.payload_hash,
            },
            correlation_id="correlation-action-prepare",
            actor_type="runtime",
            actor_id="gpt-5.6-terra",
            task_id=task.id,
            action_id=action.action_id,
        ),
        prepare_invocation,
    )
    assert created is True

    approval_id = uuid4()
    commit_invocation = make_invocation(
        run,
        effect=ToolEffect.COMMIT,
        task_id="commit",
    )
    receipt = {
        "external_operation_id": "email-1",
        "provider_request_id": "provider-request-1",
        "raw_receipt_artifact_id": str(artifact.artifact_id),
    }
    verification = {
        "passed": True,
        "method": "read_after_write",
        "verified_at": datetime.now(UTC).isoformat(),
    }
    async with store.actions.transaction(action.action_id, action.tenant_id) as transaction:
        transaction.action.approvals.append(
            {
                "approval_id": str(approval_id),
                "actor_id": "approver-1",
                "actor_roles": ["approver"],
                "auth_strength": "mfa",
                "decision": "approved",
                "payload_hash": action.payload_hash,
                "policy_version": action.policy_version,
                "created_at": datetime.now(UTC).isoformat(),
            }
        )
        transaction.action.status = ActionStatus.COMMITTED
        transaction.action.receipt = receipt
        transaction.action.verification = verification
        transaction.append_tool_invocation(commit_invocation)
        transaction.append_event(
            AuditEvent(
                event_type="action.approval_recorded",
                payload={
                    "action_id": str(action.action_id),
                    "approval_id": str(approval_id),
                    "payload_hash": action.payload_hash,
                },
                correlation_id="correlation-action-approval",
                actor_type="human",
                actor_id="approver-1",
                action_id=action.action_id,
            )
        )
        transaction.append_event(
            AuditEvent(
                event_type="action.committed",
                payload={
                    "action_id": str(action.action_id),
                    "tool_invocation_id": str(commit_invocation.invocation_id),
                    "receipt_hash": payload_hash(receipt),
                    "verification_hash": payload_hash(verification),
                },
                correlation_id="correlation-action-commit",
                actor_type="commit-worker",
                actor_id="commit-worker",
                action_id=action.action_id,
            )
        )

    exported = await store.audit.export_run(run.run_id, run.tenant_id)
    assert exported["contract"]["goal"] == run.contract.goal
    assert exported["plans"][0] == {
        **exported["plans"][0],
        "plan_hash": plan_digest,
        "planner_model": "gpt-5.6-sol",
        "prompt_id": "planner",
        "prompt_version": "1.0.0",
    }
    assert exported["task_executions"][0]["model_name"] == "gpt-5.6-terra"
    assert exported["task_executions"][0]["prompt_id"] == "worker"
    assert exported["task_executions"][0]["output"]["summary"] == "traceable output"
    assert {item["effect"] for item in exported["tool_invocations"]} == {
        "prepare",
        "commit",
    }
    exported_action = exported["actions"][0]
    assert exported_action["payload_hash"] == action.payload_hash
    assert exported_action["approvals"][0]["approval_id"] == str(approval_id)
    assert exported_action["approvals"][0]["payload_hash"] == action.payload_hash
    assert exported_action["receipt"] == receipt
    assert exported_action["receipt_artifact_id"] == str(artifact.artifact_id)
    assert exported_action["verification"] == verification
    assert exported["artifacts"][0]["sha256"] == artifact.sha256
    assert exported["artifacts"][0]["created_by"] == "commit-worker"
    committed = next(
        event for event in exported["events"] if event["event_type"] == "action.committed"
    )
    assert committed["action_id"] == str(action.action_id)
    assert committed["payload"]["tool_invocation_id"] == str(commit_invocation.invocation_id)
    assert committed["payload_hash"] == payload_hash(committed["payload"])
