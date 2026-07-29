from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from decimal import Decimal
from types import SimpleNamespace
from typing import Any

import pytest
from temporalio.exceptions import ApplicationError
from tests.unit.workflows.test_activity_lifecycle import (
    _action,
    _activities,
    _output,
    _payload,
    _plan,
    _Runtime,
    _seed_run,
)

from agent_platform.application.dag_scheduler import RuntimeUsage
from agent_platform.application.errors import PlatformError
from agent_platform.application.records import ArtifactRecord
from agent_platform.domain.enums import ActionStatus, RunStatus
from agent_platform.domain.models import WorkerOutput
from agent_platform.workflows.activities import ActivityDependencies, TemporalActivities


@pytest.mark.parametrize("operation", ["reconcile", "compensate"])
@pytest.mark.asyncio
async def test_recovery_activity_failure_settles_run_and_reraises(
    operation: str,
) -> None:
    from agent_platform.infrastructure.memory_store import InMemoryPlatformStore

    store = InMemoryPlatformStore()
    run = await _seed_run(
        store,
        status=RunStatus.COMMITTING,
        key=f"activity-recovery-{operation}",
    )

    class _FailingCommit:
        async def reconcile_unknown(self, **_: Any) -> None:
            raise RuntimeError("reconcile provider unavailable")

        async def compensate(self, **_: Any) -> None:
            raise RuntimeError("compensation provider unavailable")

    activities = _activities(
        store,
        _Runtime(),
        commit_service=_FailingCommit(),
        commit_scopes=frozenset({"business:commit"}),
    )
    payload = _payload(
        run,
        action_id=str(run.run_id),
        requested_by="operator-a",
        reason="rollback failed",
    )
    method = (
        activities.reconcile_action
        if operation == "reconcile"
        else activities.compensate_action
    )

    with pytest.raises(RuntimeError, match="provider unavailable"):
        await method(payload)

    saved = await store.runs.get(run.run_id, run.tenant_id)
    events = await store.runs.events_after(run.run_id, run.tenant_id, 0)
    assert saved.status is RunStatus.FAILED
    assert next(event for event in events if event.event_type == "run.failed").payload[
        "reason_code"
    ] == f"ACTION_RECOVERY_{operation.upper()}_FAILED"


@pytest.mark.asyncio
async def test_recovery_requires_explicit_worker_owned_scopes() -> None:
    from agent_platform.infrastructure.memory_store import InMemoryPlatformStore

    store = InMemoryPlatformStore()
    run = await _seed_run(
        store,
        status=RunStatus.COMMITTING,
        key="activity-recovery-scope",
    )
    activities = _activities(store, _Runtime(), commit_service=object())

    with pytest.raises(ApplicationError) as error:
        await activities.reconcile_action(
            _payload(
                run,
                action_id=str(run.run_id),
                requested_by="operator-a",
            )
        )

    assert error.value.type == "COMMIT_SCOPES_NOT_CONFIGURED"


class _NonAtomicRunRepository:
    def __init__(self, inner: Any, *, conflict_attempts: int = 0) -> None:
        self._inner = inner
        self._remaining_conflicts = conflict_attempts
        self.save_calls = 0

    async def get(self, *args: Any, **kwargs: Any) -> Any:
        return await self._inner.get(*args, **kwargs)

    async def save(self, *args: Any, **kwargs: Any) -> Any:
        self.save_calls += 1
        if self._remaining_conflicts:
            self._remaining_conflicts -= 1
            raise PlatformError(
                "OPTIMISTIC_LOCK_CONFLICT",
                "simulated concurrent budget update",
                retryable=True,
            )
        return await self._inner.save(*args, **kwargs)

    async def append_event(self, *args: Any, **kwargs: Any) -> Any:
        return await self._inner.append_event(*args, **kwargs)


@pytest.mark.asyncio
async def test_budget_warning_fallback_retries_conflicts_and_appends_event() -> None:
    from agent_platform.infrastructure.memory_store import InMemoryPlatformStore

    backing = InMemoryPlatformStore()
    run = await _seed_run(
        backing,
        status=RunStatus.PLANNING,
        key="activity-budget-fallback",
    )
    runs = _NonAtomicRunRepository(backing.runs, conflict_attempts=2)
    store = SimpleNamespace(runs=runs, artifacts=backing.artifacts)
    activities = TemporalActivities(
        ActivityDependencies(
            store=store,
            runtime=object(),
            gateway=object(),
            run_service=object(),
            commit_service=object(),
        )
    )

    await activities._persist_runtime_usage(
        _payload(run),
        RuntimeUsage(
            cost_usd=Decimal("4"),
            input_tokens=100,
            output_tokens=20,
            pricing_catalog_version="catalog-v1",
        ),
    )

    saved = await backing.runs.get(run.run_id, run.tenant_id)
    events = await backing.runs.events_after(run.run_id, run.tenant_id, 0)
    assert runs.save_calls == 3
    assert saved.cost_actual_usd == Decimal("4")
    assert saved.token_input == 100
    assert saved.token_output == 20
    assert next(event for event in events if event.event_type == "budget.warning").payload[
        "pricing_catalog_version"
    ] == "catalog-v1"


@pytest.mark.asyncio
async def test_budget_conflict_on_final_attempt_is_not_hidden() -> None:
    from agent_platform.infrastructure.memory_store import InMemoryPlatformStore

    backing = InMemoryPlatformStore()
    run = await _seed_run(
        backing,
        status=RunStatus.PLANNING,
        key="activity-budget-conflict",
    )
    runs = _NonAtomicRunRepository(backing.runs, conflict_attempts=3)
    activities = TemporalActivities(
        ActivityDependencies(
            store=SimpleNamespace(runs=runs, artifacts=backing.artifacts),
            runtime=object(),
            gateway=object(),
            run_service=object(),
            commit_service=object(),
        )
    )

    with pytest.raises(PlatformError, match="OPTIMISTIC_LOCK_CONFLICT"):
        await activities._persist_runtime_usage(
            _payload(run),
            RuntimeUsage(cost_usd=Decimal("4")),
        )

    assert runs.save_calls == 3


@pytest.mark.asyncio
async def test_final_response_binds_artifact_and_verified_commit_receipt() -> None:
    from agent_platform.infrastructure.memory_store import InMemoryPlatformStore

    store = InMemoryPlatformStore()
    run = await _seed_run(
        store,
        status=RunStatus.VERIFYING,
        key="activity-final-evidence",
    )
    content = b"source-backed final artifact"
    artifact = ArtifactRecord(
        artifact_id=run.run_id,
        tenant_id=run.tenant_id,
        run_id=run.run_id,
        kind="report",
        media_type="text/plain",
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        classification="internal",
        created_by=run.principal_id,
    )
    await store.artifacts.put(artifact)
    metadata = ArtifactRecord(
        artifact_id=artifact.artifact_id,
        tenant_id=artifact.tenant_id,
        run_id=artifact.run_id,
        kind=artifact.kind,
        media_type=artifact.media_type,
        content=b"",
        size_bytes=len(content),
        sha256=artifact.sha256,
        classification=artifact.classification,
        created_by=artifact.created_by,
    )

    class MetadataOnlyArtifactStore:
        def __init__(self) -> None:
            self.metadata_reads = 0

        async def get_metadata(self, artifact_id: object, tenant_id: str) -> ArtifactRecord:
            assert artifact_id == metadata.artifact_id
            assert tenant_id == metadata.tenant_id
            self.metadata_reads += 1
            return metadata

        async def get(self, artifact_id: object, tenant_id: str) -> ArtifactRecord:
            raise AssertionError(f"finalize read Artifact body: {artifact_id} {tenant_id}")

    metadata_store = MetadataOnlyArtifactStore()
    store.artifacts = metadata_store
    action = _action(
        run,
        key="committed-action",
        status=ActionStatus.COMMITTED,
    )
    now = datetime.now(UTC)
    action.receipt = {
        "external_operation_id": "provider-op-1",
        "committed_at": now.isoformat(),
        "result_summary": {"delivered": True},
    }
    action.verification = {
        "passed": True,
        "verified_at": now.isoformat(),
        "method": "provider_readback",
        "details": {"provider_request_id": "request-1"},
    }
    await store.actions.create_once(action)
    activities = _activities(store, _Runtime())
    output = _output().model_copy(update={"artifacts": [artifact.artifact_id]})

    await activities._store_final_response(
        run,
        _plan(),
        {"final": output},
    )

    saved = await store.runs.get(run.run_id, run.tenant_id)
    assert saved.result.artifacts[0].sha256 == artifact.sha256
    assert saved.result.artifacts[0].size_bytes == len(content)
    assert metadata_store.metadata_reads == 1
    assert saved.result.receipts[0].external_operation_id == "provider-op-1"
    assert saved.result.receipts[0].verification.passed is True


@pytest.mark.asyncio
async def test_final_response_rejects_missing_must_criterion_evidence() -> None:
    from agent_platform.infrastructure.memory_store import InMemoryPlatformStore

    store = InMemoryPlatformStore()
    run = await _seed_run(
        store,
        status=RunStatus.VERIFYING,
        key="activity-final-hard-failure",
    )
    activities = _activities(store, _Runtime())

    with pytest.raises(
        PlatformError,
        match="FINAL_RESPONSE_CRITERION_COVERAGE_INCOMPLETE",
    ):
        await activities._store_final_response(
            run,
            _plan(),
            {"final": WorkerOutput(summary="missing criterion verification")},
        )
