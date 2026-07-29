from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request

from agent_platform.api.auth import require_scope, require_step_up
from agent_platform.api.dependencies import RequestIdentity, current_identity
from agent_platform.api.projections import capability_view
from agent_platform.api.schemas import CapabilityView, DisableCapabilityRequest

router = APIRouter(tags=["capabilities"])


@router.get("/v1/capabilities", response_model=list[CapabilityView])
async def list_capabilities(
    request: Request,
    identity: Annotated[RequestIdentity, Depends(current_identity)],
) -> list[CapabilityView]:
    records = await request.app.state.container.store.capabilities.list(
        identity.principal.tenant_id
    )
    return [capability_view(item) for item in records if item.enabled]


@router.post(
    "/v1/admin/capabilities/{name}:disable",
    response_model=CapabilityView,
)
async def disable_capability(
    name: str,
    body: DisableCapabilityRequest,
    request: Request,
    identity: Annotated[RequestIdentity, Depends(current_identity)],
) -> CapabilityView:
    require_scope(identity.principal, "admin:capabilities")
    require_step_up(identity.principal)
    record = await request.app.state.container.store.capabilities.set_enabled(
        identity.principal.tenant_id, name, False, body.reason
    )
    return capability_view(record)


@router.post(
    "/v1/admin/capabilities/{name}:enable",
    response_model=CapabilityView,
)
async def enable_capability(
    name: str,
    body: DisableCapabilityRequest,
    request: Request,
    identity: Annotated[RequestIdentity, Depends(current_identity)],
) -> CapabilityView:
    require_scope(identity.principal, "admin:capabilities")
    require_step_up(identity.principal)
    record = await request.app.state.container.store.capabilities.set_enabled(
        identity.principal.tenant_id, name, True, body.reason
    )
    return capability_view(record)
