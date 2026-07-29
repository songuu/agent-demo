from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from agent_platform.api.routes_governance import (
    KillSwitchActivateRequest,
    MemoryCorrectionRequest,
    MemoryWriteRequest,
    ReasonRequest,
    WebhookRegistrationRequest,
    _memory_scope_allowed,
    _require_memory_scope,
    activate_kill_switch,
    correct_memory,
    deactivate_kill_switch,
    delete_memory,
    disable_webhook,
    export_run_audit,
    list_kill_switches,
    list_memories,
    list_webhooks,
    register_webhook,
    rotate_webhook_secret,
    write_memory,
)
from agent_platform.application.errors import Forbidden
from agent_platform.domain.enums import DataClassification
from agent_platform.domain.models import DataScope, Principal
from agent_platform.infrastructure.kill_switch import KillSwitchRecord, KillSwitchScope
from agent_platform.infrastructure.webhook_registry import WebhookEndpointView


def _scope(
    *,
    resource_ids: frozenset[str] = frozenset(),
    allowed_fields: frozenset[str] = frozenset(),
) -> DataScope:
    return DataScope(
        tenant_id="tenant-a",
        resource_types=frozenset({"memory", "knowledge"}),
        resource_ids=resource_ids,
        classifications=frozenset({DataClassification.INTERNAL, DataClassification.CONFIDENTIAL}),
        allowed_fields=allowed_fields,
    )


def _identity(
    *,
    user_id: str = "operator-1",
    roles: frozenset[str] = frozenset({"admin"}),
    data_scope: DataScope | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        principal=Principal(
            user_id=user_id,
            tenant_id="tenant-a",
            scopes=frozenset(
                {
                    "memory:read",
                    "memory:write",
                    "audit:read",
                    "admin:kill-switch",
                    "admin:webhooks",
                }
            ),
            roles=roles,
            auth_strength="phishing_resistant",
        ),
        data_scope=data_scope or _scope(),
    )


def _memory_view(
    *,
    memory_id: UUID | None = None,
    owner_id: str = "operator-1",
    data_scope: DataScope | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        memory_id=memory_id or uuid4(),
        subject_type="user",
        subject_id=owner_id,
        memory_type="preference",
        content="Use verified sources",
        content_hash="a" * 64,
        classification="internal",
        owner_id=owner_id,
        write_policy="explicit-confirmation",
        confidence=Decimal("0.95"),
        source_refs=("artifact:one",),
        purpose="release",
        data_scope=data_scope or _scope(),
        version=1,
        valid_from=datetime.now(UTC),
        valid_until=None,
    )


class _MemoryVault:
    def __init__(self, view: SimpleNamespace) -> None:
        self.view = view
        self.calls: list[tuple[str, dict[str, object]]] = []

    async def write(self, **kwargs: object) -> SimpleNamespace:
        self.calls.append(("write", kwargs))
        return self.view

    async def list_visible(self, *args: object, **kwargs: object) -> tuple[SimpleNamespace, ...]:
        self.calls.append(("list_visible", {"args": args, **kwargs}))
        return (self.view,)

    async def get(self, memory_id: UUID, tenant_id: str) -> SimpleNamespace:
        self.calls.append(("get", {"memory_id": memory_id, "tenant_id": tenant_id}))
        return self.view

    async def correct(self, memory_id: UUID, **kwargs: object) -> SimpleNamespace:
        self.calls.append(("correct", {"memory_id": memory_id, **kwargs}))
        return self.view

    async def delete(self, memory_id: UUID, **kwargs: object) -> None:
        self.calls.append(("delete", {"memory_id": memory_id, **kwargs}))


class _AuditStore:
    async def export_run(self, run_id: UUID, tenant_id: str) -> dict[str, object]:
        return {"run_id": str(run_id), "tenant_id": tenant_id, "events": []}


class _Observability:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, bool]] = []

    def record_kill_switch(self, *, scope: str, mode: str, active: bool) -> None:
        self.calls.append((scope, mode, active))


class _KillSwitches:
    def __init__(self) -> None:
        self.record = KillSwitchRecord(
            switch_id=uuid4(),
            scope=KillSwitchScope.TENANT,
            scope_id="tenant-a",
            mode="writes",
            reason="incident containment",
            changed_by="operator-1",
            incident_id="INC-42",
            activated_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        self.calls: list[tuple[str, dict[str, object]]] = []

    async def activate(self, **kwargs: object) -> KillSwitchRecord:
        self.calls.append(("activate", kwargs))
        return self.record

    async def active(self) -> tuple[KillSwitchRecord, ...]:
        self.calls.append(("active", {}))
        return (self.record,)

    async def deactivate(self, switch_id: UUID, **kwargs: object) -> KillSwitchRecord:
        self.calls.append(("deactivate", {"switch_id": switch_id, **kwargs}))
        self.record.deactivated_at = datetime.now(UTC)
        return self.record


class _WebhookRegistry:
    def __init__(self) -> None:
        self.view = WebhookEndpointView(
            endpoint_id=uuid4(),
            tenant_id="tenant-a",
            endpoint_name="audit-sink",
            url="https://hooks.example.test/audit",
            event_types=frozenset({"run.completed"}),
            enabled=True,
            secret_version=1,
        )
        self.calls: list[tuple[str, dict[str, object]]] = []

    async def register(self, **kwargs: object) -> tuple[WebhookEndpointView, bytes]:
        self.calls.append(("register", kwargs))
        return self.view, b"governed-secret"

    async def list(self, tenant_id: str) -> tuple[WebhookEndpointView, ...]:
        self.calls.append(("list", {"tenant_id": tenant_id}))
        return (self.view,)

    async def set_enabled(
        self,
        endpoint_id: UUID,
        tenant_id: str,
        *,
        enabled: bool,
    ) -> WebhookEndpointView:
        self.calls.append(
            (
                "set_enabled",
                {
                    "endpoint_id": endpoint_id,
                    "tenant_id": tenant_id,
                    "enabled": enabled,
                },
            )
        )
        return replace(self.view, enabled=enabled)

    async def rotate_secret(
        self,
        endpoint_id: UUID,
        tenant_id: str,
    ) -> tuple[WebhookEndpointView, bytes]:
        self.calls.append(
            (
                "rotate_secret",
                {"endpoint_id": endpoint_id, "tenant_id": tenant_id},
            )
        )
        return (
            replace(self.view, secret_version=2),
            b"rotated-secret",
        )


def _request(
    *,
    memory_vault: object | None = None,
    kill_switches: object | None = None,
    webhook_registry: object | None = None,
    observability: object | None = None,
) -> SimpleNamespace:
    container = SimpleNamespace(
        memory_vault=memory_vault,
        kill_switches=kill_switches,
        webhook_registry=webhook_registry,
        observability=observability,
        store=SimpleNamespace(audit=_AuditStore()),
    )
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(container=container)))


def test_memory_scope_rejects_implicit_broadening_and_row_filter_drift() -> None:
    authorized = _scope(
        resource_ids=frozenset({"project-a"}),
        allowed_fields=frozenset({"title"}),
    )

    assert _memory_scope_allowed(authorized, authorized) is True
    assert _memory_scope_allowed(_scope(), authorized) is False
    assert (
        _memory_scope_allowed(
            authorized.model_copy(update={"row_filter": "owner_id = 'other'"}),
            authorized,
        )
        is False
    )
    assert (
        _memory_scope_allowed(
            authorized.model_copy(update={"allowed_fields": frozenset()}),
            authorized,
        )
        is False
    )
    with pytest.raises(Forbidden, match="MEMORY_DATA_SCOPE_FORBIDDEN"):
        _require_memory_scope(
            authorized,
            authorized,
            classification="restricted",
        )


@pytest.mark.asyncio
async def test_memory_routes_write_list_correct_and_delete_bound_owner_data() -> None:
    view = _memory_view()
    vault = _MemoryVault(view)
    request = _request(memory_vault=vault)
    identity = _identity()

    written = await write_memory(
        MemoryWriteRequest(
            subject_type="user",
            subject_id="operator-1",
            memory_type="preference",
            content="Use verified sources",
            classification="internal",
            write_policy="explicit-confirmation",
            confirm_write=True,
            confidence=Decimal("0.95"),
            source_refs=("artifact:one",),
            purpose="release",
        ),
        request,
        identity,
    )
    listed = await list_memories(request, identity, purpose="release")
    corrected = await correct_memory(
        view.memory_id,
        MemoryCorrectionRequest(content="Use two verified sources", reason="clarify"),
        request,
        identity,
    )
    deleted = await delete_memory(
        view.memory_id,
        ReasonRequest(reason="user request"),
        request,
        identity,
    )

    assert written.memory_id == corrected.memory_id == view.memory_id
    assert [item.memory_id for item in listed] == [view.memory_id]
    assert deleted is None
    assert [name for name, _ in vault.calls] == [
        "write",
        "list_visible",
        "list_visible",
        "get",
        "correct",
        "list_visible",
        "get",
        "delete",
    ]


@pytest.mark.asyncio
async def test_memory_routes_fail_closed_for_subject_and_owner_mismatch() -> None:
    view = _memory_view(owner_id="another-user")
    vault = _MemoryVault(view)
    request = _request(memory_vault=vault)
    non_admin = _identity(roles=frozenset())

    with pytest.raises(Forbidden, match="MEMORY_SUBJECT_PRINCIPAL_MISMATCH"):
        await write_memory(
            MemoryWriteRequest(
                subject_type="user",
                subject_id="another-user",
                memory_type="preference",
                content="untrusted",
                classification="internal",
                write_policy="explicit-confirmation",
                confirm_write=True,
            ),
            request,
            non_admin,
        )
    with pytest.raises(Forbidden):
        await correct_memory(
            view.memory_id,
            MemoryCorrectionRequest(content="overwrite", reason="unauthorized"),
            request,
            non_admin,
        )
    with pytest.raises(Forbidden):
        await delete_memory(
            view.memory_id,
            ReasonRequest(reason="unauthorized"),
            request,
            non_admin,
        )


@pytest.mark.asyncio
async def test_project_memory_cannot_escape_authenticated_resource_ids() -> None:
    identity = _identity(data_scope=_scope(resource_ids=frozenset({"project-a"})))

    with pytest.raises(Forbidden, match="MEMORY_SUBJECT_OUTSIDE_DATA_SCOPE"):
        await write_memory(
            MemoryWriteRequest(
                subject_type="project",
                subject_id="project-b",
                memory_type="project_knowledge",
                content="cross-project",
                classification="internal",
                write_policy="explicit-confirmation",
                confirm_write=True,
            ),
            _request(memory_vault=_MemoryVault(_memory_view())),
            identity,
        )


@pytest.mark.asyncio
async def test_audit_and_kill_switch_routes_bind_actor_and_emit_state_metrics() -> None:
    switches = _KillSwitches()
    observability = _Observability()
    request = _request(kill_switches=switches, observability=observability)
    identity = _identity()
    run_id = uuid4()

    audit = await export_run_audit(run_id, request, identity)
    activated = await activate_kill_switch(
        KillSwitchActivateRequest(
            scope=KillSwitchScope.TENANT,
            scope_id="tenant-a",
            mode="writes",
            reason="incident containment",
            incident_id="INC-42",
        ),
        request,
        identity,
    )
    active = await list_kill_switches(request, identity)
    deactivated = await deactivate_kill_switch(
        switches.record.switch_id,
        ReasonRequest(reason="incident resolved"),
        request,
        identity,
    )

    assert audit["exported_by"] == "operator-1"
    assert activated.switch_id == deactivated.switch_id == switches.record.switch_id
    assert [item.switch_id for item in active] == [switches.record.switch_id]
    assert switches.calls[0][1]["changed_by"] == "operator-1"
    assert observability.calls == [
        ("tenant", "writes", True),
        ("tenant", "writes", False),
    ]


@pytest.mark.asyncio
async def test_webhook_routes_expose_secret_only_on_register_and_rotation() -> None:
    registry = _WebhookRegistry()
    request = _request(webhook_registry=registry)
    identity = _identity()

    registered = await register_webhook(
        WebhookRegistrationRequest(
            endpoint_name="audit-sink",
            url="https://hooks.example.test/audit",
            event_types=frozenset({"run.completed"}),
        ),
        request,
        identity,
    )
    listed = await list_webhooks(request, identity)
    disabled = await disable_webhook(registry.view.endpoint_id, request, identity)
    rotated = await rotate_webhook_secret(registry.view.endpoint_id, request, identity)

    assert registered.signing_secret == "Z292ZXJuZWQtc2VjcmV0"
    assert listed[0].signing_secret is None
    assert disabled.enabled is False
    assert rotated.secret_version == 2
    assert rotated.signing_secret == "cm90YXRlZC1zZWNyZXQ"
