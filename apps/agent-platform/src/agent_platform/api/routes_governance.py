"""User-governed memory, audit export, Webhooks, and Kill Switch APIs."""

from __future__ import annotations

import base64
from datetime import datetime
from decimal import Decimal
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from agent_platform.api.auth import require_scope, require_step_up
from agent_platform.api.dependencies import RequestIdentity, current_identity
from agent_platform.application.errors import Forbidden
from agent_platform.domain.models import DataScope
from agent_platform.infrastructure.kill_switch import KillSwitchScope
from agent_platform.infrastructure.webhook_registry import WebhookEndpointView

router = APIRouter(tags=["governance"])
Identity = Annotated[RequestIdentity, Depends(current_identity)]


class MemoryWriteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject_type: Literal["user", "project"]
    subject_id: str = Field(min_length=1, max_length=200)
    memory_type: Literal["preference", "project_knowledge", "decision", "constraint"]
    content: str = Field(min_length=1, max_length=32_000)
    classification: Literal["public", "internal", "confidential", "restricted"]
    write_policy: str = Field(min_length=1, max_length=100)
    confirm_write: bool
    confidence: Decimal | None = Field(default=None, ge=0, le=1)
    source_refs: tuple[str, ...] = Field(default=(), max_length=50)
    purpose: str = Field(default="general", min_length=1, max_length=4_000)
    data_scope: DataScope | None = None
    valid_until: datetime | None = None


class MemoryCorrectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str = Field(min_length=1, max_length=32_000)
    reason: str = Field(min_length=1, max_length=1_000)


class ReasonRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=1_000)


class MemoryViewResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    memory_id: UUID
    subject_type: str
    subject_id: str
    memory_type: str
    content: str
    content_hash: str
    classification: str
    owner_id: str
    write_policy: str
    confidence: Decimal | None
    source_refs: tuple[str, ...]
    purpose: str
    data_scope: DataScope
    version: int
    valid_from: datetime
    valid_until: datetime | None


class KillSwitchActivateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope: KillSwitchScope
    scope_id: str = Field(min_length=1, max_length=200)
    mode: Literal["writes", "all"]
    reason: str = Field(min_length=1, max_length=1_000)
    incident_id: str = Field(min_length=1, max_length=200)
    expires_at: datetime | None = None


class KillSwitchResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    switch_id: UUID
    scope: KillSwitchScope
    scope_id: str
    mode: str
    reason: str
    changed_by: str
    incident_id: str
    activated_at: datetime
    expires_at: datetime | None
    deactivated_at: datetime | None


class WebhookRegistrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    endpoint_name: str = Field(min_length=1, max_length=100)
    url: HttpUrl
    event_types: frozenset[str] = Field(min_length=1, max_length=50)


class WebhookEndpointResponse(BaseModel):
    endpoint_id: UUID
    endpoint_name: str
    url: str
    event_types: frozenset[str]
    enabled: bool
    secret_version: int
    signing_secret: str | None = None


def _memory_scope_allowed(requested: DataScope, authorized: DataScope) -> bool:
    if authorized.resource_ids and not requested.resource_ids:
        return False
    if not requested.is_subset_of(authorized):
        return False
    if requested.row_filter != authorized.row_filter:
        return False
    if authorized.allowed_fields and not requested.allowed_fields:
        return False
    return True


def _require_memory_scope(
    requested: DataScope,
    authorized: DataScope,
    *,
    classification: str,
) -> None:
    classifications = {item.value for item in requested.classifications}
    if not _memory_scope_allowed(requested, authorized) or classification not in classifications:
        raise Forbidden(
            "MEMORY_DATA_SCOPE_FORBIDDEN",
            "Memory classification or data scope exceeds the authenticated scope",
        )


@router.post(
    "/v1/memories",
    response_model=MemoryViewResponse,
    status_code=status.HTTP_201_CREATED,
)
async def write_memory(
    body: MemoryWriteRequest,
    request: Request,
    identity: Identity,
) -> MemoryViewResponse:
    require_scope(identity.principal, "memory:write")
    if (
        body.subject_type == "user"
        and body.subject_id != identity.principal.user_id
        and "admin" not in identity.principal.roles
    ):
        raise Forbidden(
            "MEMORY_SUBJECT_PRINCIPAL_MISMATCH",
            "A user memory must belong to the authenticated principal",
        )
    if (
        body.subject_type == "project"
        and identity.data_scope.resource_ids
        and body.subject_id not in identity.data_scope.resource_ids
    ):
        raise Forbidden(
            "MEMORY_SUBJECT_OUTSIDE_DATA_SCOPE",
            "The memory subject is outside the authenticated data scope",
        )
    memory_scope = body.data_scope or identity.data_scope
    _require_memory_scope(
        memory_scope,
        identity.data_scope,
        classification=body.classification,
    )
    record = await request.app.state.container.memory_vault.write(
        tenant_id=identity.principal.tenant_id,
        subject_type=body.subject_type,
        subject_id=body.subject_id,
        memory_type=body.memory_type,
        content=body.content,
        owner_id=identity.principal.user_id,
        classification=body.classification,
        write_policy=body.write_policy,
        approved=body.confirm_write,
        confidence=body.confidence,
        source_refs=body.source_refs,
        purpose=body.purpose,
        data_scope=memory_scope,
        valid_until=body.valid_until,
    )
    views = await request.app.state.container.memory_vault.list_visible(
        identity.principal.tenant_id,
        identity.principal.user_id,
        data_scope=identity.data_scope,
        purpose=body.purpose,
    )
    view = next(item for item in views if item.memory_id == record.memory_id)
    return MemoryViewResponse.model_validate(view)


@router.get("/v1/memories", response_model=list[MemoryViewResponse])
async def list_memories(
    request: Request,
    identity: Identity,
    purpose: str | None = None,
) -> list[MemoryViewResponse]:
    require_scope(identity.principal, "memory:read")
    records = await request.app.state.container.memory_vault.list_visible(
        identity.principal.tenant_id,
        identity.principal.user_id,
        data_scope=identity.data_scope,
        purpose=purpose,
    )
    return [MemoryViewResponse.model_validate(record) for record in records]


@router.post(
    "/v1/memories/{memory_id}:correct",
    response_model=MemoryViewResponse,
)
async def correct_memory(
    memory_id: UUID,
    body: MemoryCorrectionRequest,
    request: Request,
    identity: Identity,
) -> MemoryViewResponse:
    require_scope(identity.principal, "memory:write")
    existing = await request.app.state.container.memory_vault.get(
        memory_id, identity.principal.tenant_id
    )
    if existing.owner_id != identity.principal.user_id and "admin" not in identity.principal.roles:
        raise Forbidden()
    _require_memory_scope(
        existing.data_scope,
        identity.data_scope,
        classification=existing.classification,
    )
    corrected = await request.app.state.container.memory_vault.correct(
        memory_id,
        tenant_id=identity.principal.tenant_id,
        actor_id=identity.principal.user_id,
        content=body.content,
        reason=body.reason,
    )
    views = await request.app.state.container.memory_vault.list_visible(
        identity.principal.tenant_id,
        existing.owner_id,
        data_scope=identity.data_scope,
        purpose=existing.purpose,
    )
    view = next(item for item in views if item.memory_id == corrected.memory_id)
    return MemoryViewResponse.model_validate(view)


@router.post("/v1/memories/{memory_id}:delete", status_code=status.HTTP_204_NO_CONTENT)
async def delete_memory(
    memory_id: UUID,
    body: ReasonRequest,
    request: Request,
    identity: Identity,
) -> None:
    require_scope(identity.principal, "memory:write")
    existing = await request.app.state.container.memory_vault.get(
        memory_id, identity.principal.tenant_id
    )
    if existing.owner_id != identity.principal.user_id and "admin" not in identity.principal.roles:
        raise Forbidden()
    _require_memory_scope(
        existing.data_scope,
        identity.data_scope,
        classification=existing.classification,
    )
    await request.app.state.container.memory_vault.delete(
        memory_id,
        tenant_id=identity.principal.tenant_id,
        actor_id=identity.principal.user_id,
        reason=body.reason,
    )


@router.get("/v1/audit/runs/{run_id}")
async def export_run_audit(
    run_id: UUID,
    request: Request,
    identity: Identity,
) -> dict[str, object]:
    require_scope(identity.principal, "audit:read")
    exported = dict(
        await request.app.state.container.store.audit.export_run(
            run_id,
            identity.principal.tenant_id,
        )
    )
    exported["exported_by"] = identity.principal.user_id
    return exported


@router.post(
    "/v1/admin/kill-switches",
    response_model=KillSwitchResponse,
    status_code=status.HTTP_201_CREATED,
)
async def activate_kill_switch(
    body: KillSwitchActivateRequest,
    request: Request,
    identity: Identity,
) -> KillSwitchResponse:
    require_scope(identity.principal, "admin:kill-switch")
    require_step_up(identity.principal)
    record = await request.app.state.container.kill_switches.activate(
        scope=body.scope,
        scope_id=body.scope_id,
        mode=body.mode,
        reason=body.reason,
        changed_by=identity.principal.user_id,
        incident_id=body.incident_id,
        expires_at=body.expires_at,
    )
    observability = getattr(request.app.state.container, "observability", None)
    if observability is not None:
        observability.record_kill_switch(
            scope=str(getattr(record.scope, "value", record.scope)),
            mode=str(getattr(record.mode, "value", record.mode)),
            active=True,
        )
    return KillSwitchResponse.model_validate(record)


@router.get("/v1/admin/kill-switches", response_model=list[KillSwitchResponse])
async def list_kill_switches(
    request: Request,
    identity: Identity,
) -> list[KillSwitchResponse]:
    require_scope(identity.principal, "admin:kill-switch")
    records = await request.app.state.container.kill_switches.active()
    return [KillSwitchResponse.model_validate(record) for record in records]


@router.post(
    "/v1/admin/kill-switches/{switch_id}:deactivate",
    response_model=KillSwitchResponse,
)
async def deactivate_kill_switch(
    switch_id: UUID,
    body: ReasonRequest,
    request: Request,
    identity: Identity,
) -> KillSwitchResponse:
    require_scope(identity.principal, "admin:kill-switch")
    require_step_up(identity.principal)
    record = await request.app.state.container.kill_switches.deactivate(
        switch_id,
        changed_by=identity.principal.user_id,
        reason=body.reason,
    )
    observability = getattr(request.app.state.container, "observability", None)
    if observability is not None:
        observability.record_kill_switch(
            scope=str(getattr(record.scope, "value", record.scope)),
            mode=str(getattr(record.mode, "value", record.mode)),
            active=False,
        )
    return KillSwitchResponse.model_validate(record)


@router.post(
    "/v1/admin/webhooks",
    response_model=WebhookEndpointResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register_webhook(
    body: WebhookRegistrationRequest,
    request: Request,
    identity: Identity,
) -> WebhookEndpointResponse:
    require_scope(identity.principal, "admin:webhooks")
    require_step_up(identity.principal)
    view, secret = await request.app.state.container.webhook_registry.register(
        tenant_id=identity.principal.tenant_id,
        endpoint_name=body.endpoint_name,
        url=str(body.url),
        event_types=body.event_types,
    )
    return _webhook_response(view, secret=secret or None)


@router.get("/v1/admin/webhooks", response_model=list[WebhookEndpointResponse])
async def list_webhooks(
    request: Request,
    identity: Identity,
) -> list[WebhookEndpointResponse]:
    require_scope(identity.principal, "admin:webhooks")
    records = await request.app.state.container.webhook_registry.list(identity.principal.tenant_id)
    return [_webhook_response(record) for record in records]


@router.post(
    "/v1/admin/webhooks/{endpoint_id}:disable",
    response_model=WebhookEndpointResponse,
)
async def disable_webhook(
    endpoint_id: UUID,
    request: Request,
    identity: Identity,
) -> WebhookEndpointResponse:
    require_scope(identity.principal, "admin:webhooks")
    require_step_up(identity.principal)
    view = await request.app.state.container.webhook_registry.set_enabled(
        endpoint_id,
        identity.principal.tenant_id,
        enabled=False,
    )
    return _webhook_response(view)


@router.post(
    "/v1/admin/webhooks/{endpoint_id}:rotate-secret",
    response_model=WebhookEndpointResponse,
)
async def rotate_webhook_secret(
    endpoint_id: UUID,
    request: Request,
    identity: Identity,
) -> WebhookEndpointResponse:
    require_scope(identity.principal, "admin:webhooks")
    require_step_up(identity.principal)
    view, secret = await request.app.state.container.webhook_registry.rotate_secret(
        endpoint_id,
        identity.principal.tenant_id,
    )
    return _webhook_response(view, secret=secret)


def _webhook_response(
    view: WebhookEndpointView, *, secret: bytes | None = None
) -> WebhookEndpointResponse:
    return WebhookEndpointResponse(
        endpoint_id=view.endpoint_id,
        endpoint_name=view.endpoint_name,
        url=view.url,
        event_types=view.event_types,
        enabled=view.enabled,
        secret_version=view.secret_version,
        signing_secret=(
            base64.urlsafe_b64encode(secret).decode().rstrip("=") if secret is not None else None
        ),
    )
