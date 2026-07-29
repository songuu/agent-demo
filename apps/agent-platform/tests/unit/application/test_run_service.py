from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal
from typing import Any

import pytest

from agent_platform.api.schemas import (
    BudgetRequest,
    CreateRunRequest,
    RequestedOutput,
    SuccessCriterionRequest,
)
from agent_platform.application.errors import Conflict, PlatformError
from agent_platform.application.records import EventRecord, RunRecord
from agent_platform.application.run_service import RunService
from agent_platform.domain.enums import RunStatus
from agent_platform.domain.models import DataScope, Principal
from agent_platform.infrastructure.memory_store import (
    InMemoryPlatformStore,
    InMemoryRunRepository,
)


class WorkflowSpy:
    def __init__(
        self,
        *,
        start_failures: int = 0,
        signal_failures: dict[str, int] | None = None,
    ) -> None:
        self.started: list[object] = []
        self.start_attempts = 0
        self._start_failures = start_failures
        self._signal_failures = dict(signal_failures or {})
        self.signal_attempts = {"cancel": 0, "pause": 0, "resume": 0}
        self.cancelled: list[object] = []
        self.paused: list[object] = []
        self.resumed: list[object] = []

    async def start(
        self,
        run_id: object,
        tenant_id: str,
        correlation_id: str,
        *,
        contract: object | None = None,
    ) -> None:
        self.start_attempts += 1
        if self._start_failures > 0:
            self._start_failures -= 1
            raise RuntimeError("TEMPORAL_START_UNAVAILABLE")
        self.started.append((run_id, contract))

    def _record_signal_attempt(self, signal: str) -> None:
        self.signal_attempts[signal] += 1
        if self._signal_failures.get(signal, 0) > 0:
            self._signal_failures[signal] -= 1
            raise RuntimeError(f"TEMPORAL_{signal.upper()}_UNAVAILABLE")

    async def cancel(self, run_id: object, tenant_id: str, reason: str) -> None:
        self._record_signal_attempt("cancel")
        self.cancelled.append(run_id)

    async def pause(self, run_id: object, tenant_id: str, reason: str) -> None:
        self._record_signal_attempt("pause")
        self.paused.append(run_id)

    async def resume(self, run_id: object, tenant_id: str) -> None:
        self._record_signal_attempt("resume")
        self.resumed.append(run_id)


class AtomicRunRepositorySpy(InMemoryRunRepository):
    retry_workflow_start_on_duplicate = True

    def __init__(self) -> None:
        super().__init__()
        self.atomic_creates = 0
        self.atomic_saves = 0

    async def create_once_with_event(
        self,
        run: RunRecord,
        event_type: str,
        payload: Mapping[str, Any],
        correlation_id: str,
    ) -> tuple[RunRecord, bool, EventRecord | None]:
        self.atomic_creates += 1
        stored, created = await super().create_once(run)
        event = (
            await super().append_event(
                stored,
                event_type,
                payload,
                correlation_id,
            )
            if created
            else None
        )
        return stored, created, event

    async def save_with_event(
        self,
        run: RunRecord,
        expected_version: int,
        event_type: str,
        payload: Mapping[str, Any],
        correlation_id: str,
    ) -> tuple[RunRecord, EventRecord]:
        self.atomic_saves += 1
        stored = await super().save(run, expected_version)
        event = await super().append_event(
            stored,
            event_type,
            payload,
            correlation_id,
        )
        return stored, event

    async def create_once(self, run: RunRecord) -> tuple[RunRecord, bool]:
        raise AssertionError("legacy create path must not be used")

    async def save(self, run: RunRecord, expected_version: int) -> RunRecord:
        raise AssertionError("legacy save path must not be used")

    async def append_event(
        self,
        run: RunRecord,
        event_type: str,
        payload: Mapping[str, Any],
        correlation_id: str,
    ) -> EventRecord:
        raise AssertionError("legacy append path must not be used")


def principal() -> Principal:
    return Principal(
        user_id="user-1",
        tenant_id="tenant-a",
        roles=frozenset({"analyst"}),
        scopes=frozenset({"runs:create", "knowledge:read"}),
        auth_strength="mfa",
        session_id="session-1",
    )


def request() -> CreateRunRequest:
    return CreateRunRequest(
        goal="Create a source-backed report",
        success_criteria=[
            SuccessCriterionRequest(
                id="sc-1",
                description="Every key claim has evidence",
                severity="must",
            )
        ],
        allowed_capabilities=["knowledge.search", "artifact.create"],
        constraints={"markets": ["SG", "JP"]},
        budget=BudgetRequest(
            max_cost_usd=Decimal("5"),
            max_duration_seconds=300,
            max_tool_calls=7,
        ),
        external_write_policy="deny",
        requested_output=RequestedOutput(format="market_report@1.0"),
    )


def data_scope() -> DataScope:
    return DataScope(
        tenant_id="tenant-a",
        resource_types=frozenset({"knowledge", "artifact"}),
        classifications=frozenset({"internal", "public"}),
    )


@pytest.mark.asyncio
async def test_create_is_request_idempotent_and_starts_workflow_once() -> None:
    store = InMemoryPlatformStore()
    workflow = WorkflowSpy()
    service = RunService(store.runs, store.actions, workflow)

    first, created = await service.create(
        request(),
        principal(),
        data_scope(),
        idempotency_key="request-1",
        correlation_id="corr-1",
    )
    second, duplicate_created = await service.create(
        request(),
        principal(),
        data_scope(),
        idempotency_key="request-1",
        correlation_id="corr-2",
    )

    assert created is True
    assert duplicate_created is False
    assert first.run_id == second.run_id
    assert first.contract.max_tool_calls == 7
    assert workflow.started == [(first.run_id, first.contract)]
    events = await store.runs.events_after(first.run_id, "tenant-a", 0)
    assert [event.event_type for event in events] == ["run.status_changed"]


@pytest.mark.asyncio
async def test_control_signal_retries_converge_without_duplicate_state_events() -> None:
    store = InMemoryPlatformStore()
    workflow = WorkflowSpy(
        signal_failures={"pause": 1, "resume": 1, "cancel": 1},
    )
    service = RunService(store.runs, store.actions, workflow)
    run, _ = await service.create(
        request(),
        principal(),
        data_scope(),
        idempotency_key="signal-retry-1",
        correlation_id="corr-create",
    )
    await service.transition(run.run_id, "tenant-a", RunStatus.CLASSIFIED, "corr-classify")
    await service.transition(run.run_id, "tenant-a", RunStatus.PLANNING, "corr-plan")

    with pytest.raises(PlatformError) as pause_failed:
        await service.pause(run.run_id, principal(), "review", "corr-pause")
    assert pause_failed.value.code == "WORKFLOW_SIGNAL_FAILED"
    assert pause_failed.value.retryable is True
    assert (await store.runs.get(run.run_id, "tenant-a")).status == RunStatus.PAUSED
    paused = await service.pause(run.run_id, principal(), "review", "corr-pause-retry")
    assert paused.status == RunStatus.PAUSED

    with pytest.raises(PlatformError) as resume_failed:
        await service.resume(run.run_id, principal(), "corr-resume")
    assert resume_failed.value.code == "WORKFLOW_SIGNAL_FAILED"
    assert (await store.runs.get(run.run_id, "tenant-a")).status == RunStatus.PLANNING
    resumed = await service.resume(run.run_id, principal(), "corr-resume-retry")
    assert resumed.status == RunStatus.PLANNING

    with pytest.raises(PlatformError) as cancel_failed:
        await service.cancel(run.run_id, principal(), "stop", "corr-cancel")
    assert cancel_failed.value.code == "WORKFLOW_SIGNAL_FAILED"
    assert (await store.runs.get(run.run_id, "tenant-a")).cancellation_requested is True
    cancelled = await service.cancel(
        run.run_id,
        principal(),
        "stop",
        "corr-cancel-retry",
    )
    assert cancelled.cancellation_requested is True
    assert workflow.signal_attempts == {"cancel": 2, "pause": 2, "resume": 2}
    assert workflow.paused == [run.run_id]
    assert workflow.resumed == [run.run_id]
    assert workflow.cancelled == [run.run_id]
    events = await store.runs.events_after(run.run_id, "tenant-a", 0)
    assert [event.event_type for event in events].count("run.cancellation_requested") == 1


@pytest.mark.asyncio
async def test_pause_resume_cancel_follow_explicit_state_machine() -> None:
    store = InMemoryPlatformStore()
    workflow = WorkflowSpy()
    service = RunService(store.runs, store.actions, workflow)
    run, _ = await service.create(
        request(),
        principal(),
        data_scope(),
        idempotency_key="request-1",
        correlation_id="corr-1",
    )
    await service.transition(
        run.run_id,
        "tenant-a",
        RunStatus.CLASSIFIED,
        "corr-1",
    )
    await service.transition(
        run.run_id,
        "tenant-a",
        RunStatus.PLANNING,
        "corr-1",
    )
    paused_during_planning = await service.pause(
        run.run_id, principal(), "human review", "corr-pause"
    )
    assert paused_during_planning.paused_from == RunStatus.PLANNING
    resumed_to_planning = await service.resume(run.run_id, principal(), "corr-resume")
    assert resumed_to_planning.status == RunStatus.PLANNING
    assert resumed_to_planning.paused_from is None
    await service.transition(
        run.run_id,
        "tenant-a",
        RunStatus.AUTHORIZED,
        "corr-1",
    )
    await service.transition(
        run.run_id,
        "tenant-a",
        RunStatus.EXECUTING,
        "corr-1",
    )

    paused = await service.pause(run.run_id, principal(), "human review", "corr-2")
    assert paused.status == RunStatus.PAUSED
    resumed = await service.resume(run.run_id, principal(), "corr-3")
    assert resumed.status == RunStatus.EXECUTING
    cancelled = await service.cancel(run.run_id, principal(), "user request", "corr-4")
    assert cancelled.cancellation_requested is True
    assert workflow.cancelled == [run.run_id]

    with pytest.raises(Conflict):
        await service.resume(run.run_id, principal(), "corr-5")


@pytest.mark.asyncio
async def test_production_repository_atomic_seams_cover_create_transition_and_cancel() -> None:
    store = InMemoryPlatformStore()
    runs = AtomicRunRepositorySpy()
    workflow = WorkflowSpy()
    service = RunService(runs, store.actions, workflow)

    run, created = await service.create(
        request(),
        principal(),
        data_scope(),
        idempotency_key="atomic-request-1",
        correlation_id="corr-create",
    )
    transitioned = await service.transition(
        run.run_id,
        run.tenant_id,
        RunStatus.CLASSIFIED,
        "corr-transition",
    )
    cancelled = await service.cancel(
        run.run_id,
        principal(),
        "operator request",
        "corr-cancel",
    )

    assert created is True
    assert transitioned.status is RunStatus.CLASSIFIED
    assert cancelled.cancellation_requested is True
    assert runs.atomic_creates == 1
    assert runs.atomic_saves == 2
    assert [
        event.event_type for event in await runs.events_after(run.run_id, run.tenant_id, 0)
    ] == [
        "run.status_changed",
        "run.status_changed",
        "run.cancellation_requested",
    ]


@pytest.mark.asyncio
async def test_duplicate_create_recovers_a_failed_production_workflow_start() -> None:
    store = InMemoryPlatformStore()
    runs = AtomicRunRepositorySpy()
    workflow = WorkflowSpy(start_failures=1)
    service = RunService(runs, store.actions, workflow)

    with pytest.raises(RuntimeError, match="TEMPORAL_START_UNAVAILABLE"):
        await service.create(
            request(),
            principal(),
            data_scope(),
            idempotency_key="recover-start-1",
            correlation_id="corr-first",
        )

    recovered, created = await service.create(
        request(),
        principal(),
        data_scope(),
        idempotency_key="recover-start-1",
        correlation_id="corr-retry",
    )

    assert created is False
    assert workflow.start_attempts == 2
    assert workflow.started == [(recovered.run_id, recovered.contract)]
    events = await runs.events_after(recovered.run_id, recovered.tenant_id, 0)
    assert [event.event_type for event in events] == ["run.status_changed"]
