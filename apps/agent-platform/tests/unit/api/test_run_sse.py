from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from types import SimpleNamespace
from typing import cast
from uuid import UUID, uuid4

import pytest
from fastapi import Request
from fastapi.responses import StreamingResponse

from agent_platform.api.dependencies import RequestIdentity
from agent_platform.api.routes_runs import get_events
from agent_platform.application.records import EventRecord, RunRecord
from agent_platform.domain.enums import RunStatus
from agent_platform.domain.models import DataScope, Principal

RUN_ID = uuid4()
TENANT_ID = "tenant-a"


def _run(status: RunStatus) -> RunRecord:
    return RunRecord(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        principal_id="user-a",
        contract=object(),
        idempotency_key="run-idempotency",
        request_hash="request-hash",
        workflow_id=f"run-{RUN_ID}",
        status=status,
    )


def _event(sequence_no: int, event_type: str) -> EventRecord:
    return EventRecord(
        # Deliberately unrelated to the run-local sequence. PostgreSQL event IDs
        # are globally allocated, so exposing this value breaks SSE resume.
        event_id=str(9_000 + sequence_no),
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        sequence_no=sequence_no,
        event_type=event_type,
        payload={"sequence_no": sequence_no},
        correlation_id="correlation-sse",
    )


class StaticRunEvents:
    def __init__(
        self,
        *,
        status: RunStatus,
        events: Sequence[EventRecord],
    ) -> None:
        self.status = status
        self.events = list(events)
        self.after_calls: list[int] = []

    async def get(self, run_id: UUID, tenant_id: str) -> RunRecord:
        assert run_id == RUN_ID
        assert tenant_id == TENANT_ID
        return _run(self.status)

    async def events_after(
        self,
        run_id: UUID,
        tenant_id: str,
        sequence_no: int,
    ) -> Sequence[EventRecord]:
        assert run_id == RUN_ID
        assert tenant_id == TENANT_ID
        self.after_calls.append(sequence_no)
        return tuple(event for event in self.events if event.sequence_no > sequence_no)


class GrowingRunEvents(StaticRunEvents):
    def __init__(self) -> None:
        super().__init__(
            status=RunStatus.EXECUTING,
            events=(_event(1, "run.status_changed"),),
        )
        self._published_terminal = False

    async def events_after(
        self,
        run_id: UUID,
        tenant_id: str,
        sequence_no: int,
    ) -> Sequence[EventRecord]:
        records = await super().events_after(run_id, tenant_id, sequence_no)
        if not self._published_terminal:
            self._published_terminal = True
            self.status = RunStatus.COMPLETED
            self.events.append(_event(2, "run.completed"))
        return records


@dataclass
class FakeRequest:
    repository: StaticRunEvents
    disconnect_after_checks: int | None = None
    disconnect_checks: int = 0

    def __post_init__(self) -> None:
        store = SimpleNamespace(runs=self.repository)
        container = SimpleNamespace(store=store)
        self.app = SimpleNamespace(state=SimpleNamespace(container=container))

    async def is_disconnected(self) -> bool:
        self.disconnect_checks += 1
        return (
            self.disconnect_after_checks is not None
            and self.disconnect_checks > self.disconnect_after_checks
        )


def _identity() -> RequestIdentity:
    principal = Principal(
        user_id="user-a",
        tenant_id=TENANT_ID,
        roles=frozenset({"analyst"}),
        scopes=frozenset({"runs:read"}),
        auth_strength="mfa",
    )
    return RequestIdentity(
        principal=principal,
        data_scope=DataScope(
            tenant_id=TENANT_ID,
            resource_types=frozenset({"knowledge"}),
        ),
    )


async def _response_body(response: StreamingResponse) -> str:
    chunks: list[bytes] = []
    async for chunk in response.body_iterator:
        chunks.append(chunk.encode() if isinstance(chunk, str) else bytes(chunk))
    return b"".join(chunks).decode()


async def _open_stream(
    repository: StaticRunEvents,
    *,
    last_event_id: str | None = None,
    disconnect_after_checks: int | None = None,
) -> tuple[StreamingResponse, FakeRequest]:
    request = FakeRequest(
        repository,
        disconnect_after_checks=disconnect_after_checks,
    )
    response = await get_events(
        RUN_ID,
        cast(Request, request),
        _identity(),
        last_event_id=last_event_id,
        after=None,
    )
    return response, request


def _ids(body: str) -> list[int]:
    return [int(line.removeprefix("id: ")) for line in body.splitlines() if line.startswith("id: ")]


@pytest.mark.asyncio
async def test_sse_uses_run_local_sequence_and_reconnects_without_gap_or_duplicate() -> None:
    repository = StaticRunEvents(
        status=RunStatus.COMPLETED,
        events=(
            _event(1, "run.status_changed"),
            _event(2, "run.completed"),
        ),
    )

    initial, _ = await _open_stream(repository)
    resumed, _ = await _open_stream(repository, last_event_id="1")
    caught_up, _ = await _open_stream(repository, last_event_id="2")

    initial_body = await _response_body(initial)
    resumed_body = await _response_body(resumed)
    caught_up_body = await _response_body(caught_up)

    assert _ids(initial_body) == [1, 2]
    assert _ids(resumed_body) == [2]
    assert _ids(caught_up_body) == []
    assert "id: 9001" not in initial_body
    assert "id: 9002" not in initial_body


@pytest.mark.asyncio
async def test_sse_keeps_polling_and_delivers_terminal_event_added_after_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("agent_platform.api.routes_runs.SSE_POLL_INTERVAL_SECONDS", 0)
    repository = GrowingRunEvents()

    response, _ = await _open_stream(repository)
    body = await _response_body(response)

    assert _ids(body) == [1, 2]
    assert "event: run.completed" in body
    assert repository.after_calls[:2] == [0, 1]


@pytest.mark.asyncio
async def test_sse_emits_heartbeat_until_client_disconnects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("agent_platform.api.routes_runs.SSE_POLL_INTERVAL_SECONDS", 0)
    monkeypatch.setattr("agent_platform.api.routes_runs.SSE_HEARTBEAT_INTERVAL_SECONDS", 0)
    repository = StaticRunEvents(status=RunStatus.EXECUTING, events=())

    response, request = await _open_stream(repository, disconnect_after_checks=1)
    body = await _response_body(response)

    assert body == ": heartbeat\n\n"
    assert request.disconnect_checks == 2
    assert repository.after_calls == [0]
