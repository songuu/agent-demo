from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, status

from agent_platform.api.auth import require_scope, require_step_up
from agent_platform.api.dependencies import RequestIdentity, current_identity
from agent_platform.api.projections import action_view
from agent_platform.api.schemas import (
    ActionRecoveryAccepted,
    ActionRecoveryRequest,
    ActionView,
    ApprovalRequest,
    RejectionRequest,
)
from agent_platform.application.errors import Forbidden, PlatformError

router = APIRouter(tags=["actions"])


@router.get("/v1/runs/{run_id}/actions", response_model=list[ActionView])
async def list_actions(
    run_id: UUID,
    request: Request,
    identity: Annotated[RequestIdentity, Depends(current_identity)],
) -> list[ActionView]:
    require_scope(identity.principal, "runs:read")
    await request.app.state.container.store.runs.get(run_id, identity.principal.tenant_id)
    actions = await request.app.state.container.store.actions.list_for_run(
        run_id, identity.principal.tenant_id
    )
    return [action_view(item) for item in actions]


@router.post("/v1/actions/{action_id}:approve", response_model=ActionView)
async def approve_action(
    action_id: UUID,
    body: ApprovalRequest,
    request: Request,
    identity: Annotated[RequestIdentity, Depends(current_identity)],
) -> ActionView:
    require_scope(identity.principal, "actions:approve")
    require_step_up(identity.principal)
    action = await request.app.state.container.action_service.decide(
        action_id,
        tenant_id=identity.principal.tenant_id,
        actor_id=identity.principal.user_id,
        actor_roles=identity.principal.roles,
        auth_strength=identity.principal.auth_strength,
        decision="approved",
        expected_payload_hash=body.payload_hash,
        comment=body.comment,
    )
    return action_view(action)


@router.post(
    "/v1/actions/{action_id}:recover",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ActionRecoveryAccepted,
)
async def recover_action(
    action_id: UUID,
    body: ActionRecoveryRequest,
    request: Request,
    identity: Annotated[RequestIdentity, Depends(current_identity)],
) -> ActionRecoveryAccepted:
    require_scope(identity.principal, "actions:recover")
    if (
        "admin" not in identity.principal.roles
        or identity.principal.auth_strength != "phishing_resistant"
    ):
        raise Forbidden(
            "ACTION_RECOVERY_OPERATOR_REQUIRED",
            "Action recovery requires an admin with phishing-resistant authentication",
        )
    action = await request.app.state.container.store.actions.get(
        action_id,
        identity.principal.tenant_id,
    )
    starter = getattr(request.app.state.container, "recovery_workflow", None)
    start_recovery = getattr(starter, "start_action_recovery", None)
    if not callable(start_recovery):
        raise PlatformError(
            "ACTION_RECOVERY_UNAVAILABLE",
            "The transaction recovery workflow is unavailable",
            http_status=503,
            retryable=True,
        )
    workflow_id = await start_recovery(
        run_id=action.run_id,
        action_id=action.action_id,
        tenant_id=identity.principal.tenant_id,
        correlation_id=request.state.correlation_id,
        requested_by=identity.principal.user_id,
        operation=body.operation,
        reason=body.reason,
    )
    return ActionRecoveryAccepted(
        action_id=action.action_id,
        run_id=action.run_id,
        operation=body.operation,
        workflow_id=workflow_id,
    )


@router.post("/v1/actions/{action_id}:reject", response_model=ActionView)
async def reject_action(
    action_id: UUID,
    body: RejectionRequest,
    request: Request,
    identity: Annotated[RequestIdentity, Depends(current_identity)],
) -> ActionView:
    require_scope(identity.principal, "actions:approve")
    require_step_up(identity.principal)
    action = await request.app.state.container.action_service.decide(
        action_id,
        tenant_id=identity.principal.tenant_id,
        actor_id=identity.principal.user_id,
        actor_roles=identity.principal.roles,
        auth_strength=identity.principal.auth_strength,
        decision="rejected",
        expected_payload_hash=body.payload_hash,
        comment=body.reason,
    )
    return action_view(action)
