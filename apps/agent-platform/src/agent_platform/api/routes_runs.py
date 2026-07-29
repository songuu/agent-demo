from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Annotated, Protocol, cast
from uuid import UUID

import orjson
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import StreamingResponse

from agent_platform.api.auth import require_scope
from agent_platform.api.dependencies import RequestIdentity, current_identity
from agent_platform.api.schemas import (
    CancelRunRequest,
    CreateRunRequest,
    PauseRunRequest,
    ResumeRunRequest,
    RunAcceptedResponse,
    RunView,
)
from agent_platform.application.ports import RunRepository
from agent_platform.application.run_service import RunService
from agent_platform.domain.state_machines import RUN_TERMINAL_STATUSES

router = APIRouter(prefix="/v1/runs", tags=["runs"])

SSE_POLL_INTERVAL_SECONDS = 1.0
SSE_HEARTBEAT_INTERVAL_SECONDS = 15.0


class _RunStore(Protocol):
    @property
    def runs(self) -> RunRepository: ...


class _RunContainer(Protocol):
    @property
    def run_service(self) -> RunService: ...

    @property
    def store(self) -> _RunStore: ...


def _container(request: Request) -> _RunContainer:
    return cast(_RunContainer, request.app.state.container)


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=RunAcceptedResponse,
)
async def create_run(
    body: CreateRunRequest,
    response: Response,
    request: Request,
    identity: Annotated[RequestIdentity, Depends(current_identity)],
    idempotency_key: Annotated[
        str,
        Header(min_length=8, max_length=256, alias="Idempotency-Key"),
    ],
) -> RunAcceptedResponse:
    require_scope(identity.principal, "runs:create")
    service = _container(request).run_service
    run, _ = await service.create(
        body,
        identity.principal,
        identity.data_scope,
        idempotency_key=idempotency_key,
        correlation_id=request.state.correlation_id,
    )
    base = f"/v1/runs/{run.run_id}"
    response.headers["Location"] = base
    return RunAcceptedResponse(
        run_id=run.run_id,
        status=run.status.value,
        created_at=run.created_at,
        links={
            "self": base,
            "events": f"{base}/events",
            "actions": f"{base}/actions",
        },
    )


@router.get("/{run_id}", response_model=RunView)
async def get_run(
    run_id: UUID,
    request: Request,
    response: Response,
    identity: Annotated[RequestIdentity, Depends(current_identity)],
    if_none_match: Annotated[str | None, Header(alias="If-None-Match")] = None,
) -> RunView | Response:
    require_scope(identity.principal, "runs:read")
    service = _container(request).run_service
    record = await service.get(run_id, identity.principal)
    etag = f'"run-{record.version}"'
    if if_none_match == etag:
        return Response(
            status_code=status.HTTP_304_NOT_MODIFIED,
            headers={"ETag": etag},
        )
    response.headers["ETag"] = etag
    return RunView.model_validate(await service.snapshot(run_id, identity.principal))


@router.get("/{run_id}/events")
async def get_events(
    run_id: UUID,
    request: Request,
    identity: Annotated[RequestIdentity, Depends(current_identity)],
    last_event_id: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
    after: Annotated[int | None, Query(ge=0)] = None,
) -> StreamingResponse:
    require_scope(identity.principal, "runs:read")
    sequence = after if after is not None else 0
    if last_event_id is not None:
        try:
            sequence = int(last_event_id)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Last-Event-ID must be a run-local event sequence number",
            ) from exc
        if sequence < 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Last-Event-ID must be non-negative",
            )

    runs = _container(request).store.runs
    # Resolve authorization and tenant visibility before starting the response.
    # Exceptions raised after StreamingResponse begins cannot become a proper
    # 4xx response.
    await runs.get(
        run_id,
        identity.principal.tenant_id,
    )

    async def stream() -> AsyncIterator[bytes]:
        cursor = sequence
        last_output_at = asyncio.get_running_loop().time()

        while not await request.is_disconnected():
            records = await runs.events_after(
                run_id,
                identity.principal.tenant_id,
                cursor,
            )
            for event in records:
                # Repository semantics already guarantee `> cursor`; retaining
                # the guard prevents duplicate delivery if an adapter violates
                # that contract during a retry or read-replica transition.
                if event.sequence_no <= cursor:
                    continue
                data = orjson.dumps(
                    {
                        "run_id": str(event.run_id),
                        **event.payload,
                    }
                ).decode()
                yield (
                    f"id: {event.sequence_no}\nevent: {event.event_type}\ndata: {data}\n\n"
                ).encode()
                cursor = event.sequence_no
                last_output_at = asyncio.get_running_loop().time()

            run = await runs.get(run_id, identity.principal.tenant_id)
            if run.status in RUN_TERMINAL_STATUSES:
                terminal_event_type = f"run.{run.status.value}"
                if any(event.event_type == terminal_event_type for event in records):
                    return
                if not records:
                    # The in-memory adapter saves the terminal snapshot and
                    # appends its event in two awaits. Confirm that the durable
                    # terminal event is at or behind the client's cursor before
                    # closing, otherwise the final event could be lost in that
                    # narrow window.
                    history = await runs.events_after(
                        run_id,
                        identity.principal.tenant_id,
                        0,
                    )
                    terminal_sequence = next(
                        (
                            event.sequence_no
                            for event in reversed(history)
                            if event.event_type == terminal_event_type
                        ),
                        None,
                    )
                    if terminal_sequence is not None and terminal_sequence <= cursor:
                        return

            now = asyncio.get_running_loop().time()
            if now - last_output_at >= SSE_HEARTBEAT_INTERVAL_SECONDS:
                yield b": heartbeat\n\n"
                last_output_at = now
            await asyncio.sleep(SSE_POLL_INTERVAL_SECONDS)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/{run_id}:cancel", status_code=status.HTTP_202_ACCEPTED)
async def cancel_run(
    run_id: UUID,
    body: CancelRunRequest,
    request: Request,
    identity: Annotated[RequestIdentity, Depends(current_identity)],
) -> dict[str, str]:
    require_scope(identity.principal, "runs:control")
    run = await _container(request).run_service.cancel(
        run_id,
        identity.principal,
        body.reason,
        request.state.correlation_id,
    )
    return {"run_id": str(run.run_id), "status": "cancellation_requested"}


@router.post("/{run_id}:pause", status_code=status.HTTP_202_ACCEPTED)
async def pause_run(
    run_id: UUID,
    body: PauseRunRequest,
    request: Request,
    identity: Annotated[RequestIdentity, Depends(current_identity)],
) -> dict[str, str]:
    require_scope(identity.principal, "runs:control")
    run = await _container(request).run_service.pause(
        run_id,
        identity.principal,
        body.reason,
        request.state.correlation_id,
    )
    return {"run_id": str(run.run_id), "status": run.status.value}


@router.post("/{run_id}:resume", status_code=status.HTTP_202_ACCEPTED)
async def resume_run(
    run_id: UUID,
    body: ResumeRunRequest,
    request: Request,
    identity: Annotated[RequestIdentity, Depends(current_identity)],
) -> dict[str, str]:
    del body
    require_scope(identity.principal, "runs:control")
    run = await _container(request).run_service.resume(
        run_id,
        identity.principal,
        request.state.correlation_id,
    )
    return {"run_id": str(run.run_id), "status": run.status.value}
