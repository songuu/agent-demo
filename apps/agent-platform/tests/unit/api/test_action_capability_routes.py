from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from agent_platform.api.routes_actions import (
    approve_action,
    list_actions,
    recover_action,
    reject_action,
)
from agent_platform.api.routes_capabilities import (
    disable_capability,
    enable_capability,
    list_capabilities,
)
from agent_platform.api.schemas import (
    ActionRecoveryRequest,
    ApprovalRequest,
    DisableCapabilityRequest,
    RejectionRequest,
)
from agent_platform.application.errors import Forbidden, PlatformError
from agent_platform.application.records import ActionRecord, CapabilityRecord
from agent_platform.domain.enums import ActionStatus, RiskLevel
from agent_platform.domain.models import Principal


def _principal(
    *,
    scopes: frozenset[str] = frozenset(
        {"runs:read", "actions:approve", "actions:recover", "admin:capabilities"}
    ),
    roles: frozenset[str] = frozenset({"admin", "approver"}),
    auth_strength: str = "phishing_resistant",
) -> Principal:
    return Principal(
        user_id="operator-1",
        tenant_id="tenant-a",
        scopes=scopes,
        roles=roles,
        auth_strength=auth_strength,
    )


def _identity(**principal_updates: object) -> SimpleNamespace:
    return SimpleNamespace(principal=_principal(**principal_updates))


def _action() -> ActionRecord:
    return ActionRecord(
        action_id=uuid4(),
        run_id=uuid4(),
        tenant_id="tenant-a",
        principal_id="requester-1",
        action_type="email.prepare",
        tool_name="email.prepare",
        tool_version="1.0.0",
        canonical_payload={"subject": "bounded"},
        payload_hash="a" * 64,
        preview={"subject": "bounded"},
        risk=RiskLevel.HIGH,
        approval_policy="single-approver",
        required_approvals=1,
        idempotency_key="action-1",
        policy_version="policy-1",
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        status=ActionStatus.PENDING_APPROVAL,
    )


class _ActionStore:
    def __init__(self, action: ActionRecord) -> None:
        self.action = action
        self.run_gets: list[tuple[UUID, str]] = []
        self.action_gets: list[tuple[UUID, str]] = []

    async def get_run(self, run_id: UUID, tenant_id: str) -> object:
        self.run_gets.append((run_id, tenant_id))
        return object()

    async def get_action(self, action_id: UUID, tenant_id: str) -> ActionRecord:
        self.action_gets.append((action_id, tenant_id))
        return self.action

    async def list_for_run(self, run_id: UUID, tenant_id: str) -> tuple[ActionRecord, ...]:
        self.action_gets.append((self.action.action_id, tenant_id))
        assert run_id == self.action.run_id
        return (self.action,)


class _ActionService:
    def __init__(self, action: ActionRecord) -> None:
        self.action = action
        self.calls: list[tuple[UUID, dict[str, object]]] = []

    async def decide(self, action_id: UUID, **kwargs: object) -> ActionRecord:
        self.calls.append((action_id, kwargs))
        return self.action


class _RecoveryWorkflow:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    async def start_action_recovery(self, **kwargs: object) -> str:
        self.calls.append(kwargs)
        return "action-recovery/tenant-a/action-1"


def _action_request(
    action: ActionRecord,
    *,
    recovery_workflow: object | None = None,
) -> tuple[SimpleNamespace, _ActionStore, _ActionService]:
    store = _ActionStore(action)
    service = _ActionService(action)
    container = SimpleNamespace(
        store=SimpleNamespace(
            runs=SimpleNamespace(get=store.get_run),
            actions=SimpleNamespace(
                get=store.get_action,
                list_for_run=store.list_for_run,
            ),
        ),
        action_service=service,
    )
    if recovery_workflow is not None:
        container.recovery_workflow = recovery_workflow
    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(container=container)),
        state=SimpleNamespace(correlation_id="correlation-1"),
    )
    return request, store, service


@pytest.mark.asyncio
async def test_action_routes_list_approve_and_reject_with_bound_identity() -> None:
    action = _action()
    request, store, service = _action_request(action)
    identity = _identity()

    listed = await list_actions(action.run_id, request, identity)
    approved = await approve_action(
        action.action_id,
        ApprovalRequest(payload_hash=action.payload_hash, comment="reviewed"),
        request,
        identity,
    )
    rejected = await reject_action(
        action.action_id,
        RejectionRequest(payload_hash=action.payload_hash, reason="unsafe"),
        request,
        identity,
    )

    assert [item.action_id for item in listed] == [action.action_id]
    assert approved.action_id == rejected.action_id == action.action_id
    assert store.run_gets == [(action.run_id, "tenant-a")]
    assert [call[1]["decision"] for call in service.calls] == ["approved", "rejected"]
    assert all(call[1]["actor_id"] == "operator-1" for call in service.calls)


@pytest.mark.asyncio
async def test_action_recovery_starts_exact_tenant_bound_workflow() -> None:
    action = _action()
    recovery = _RecoveryWorkflow()
    request, store, _ = _action_request(action, recovery_workflow=recovery)

    accepted = await recover_action(
        action.action_id,
        ActionRecoveryRequest(operation="compensate", reason="provider drift"),
        request,
        _identity(),
    )

    assert accepted.action_id == action.action_id
    assert accepted.run_id == action.run_id
    assert accepted.workflow_id == "action-recovery/tenant-a/action-1"
    assert store.action_gets == [(action.action_id, "tenant-a")]
    assert recovery.calls == [
        {
            "run_id": action.run_id,
            "action_id": action.action_id,
            "tenant_id": "tenant-a",
            "correlation_id": "correlation-1",
            "requested_by": "operator-1",
            "operation": "compensate",
            "reason": "provider drift",
        }
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("identity", "expected_code"),
    (
        (_identity(roles=frozenset({"approver"})), "ACTION_RECOVERY_OPERATOR_REQUIRED"),
        (_identity(auth_strength="mfa"), "ACTION_RECOVERY_OPERATOR_REQUIRED"),
    ),
)
async def test_action_recovery_requires_admin_and_phishing_resistant_auth(
    identity: SimpleNamespace,
    expected_code: str,
) -> None:
    action = _action()
    request, _, _ = _action_request(action, recovery_workflow=_RecoveryWorkflow())

    with pytest.raises(Forbidden) as caught:
        await recover_action(
            action.action_id,
            ActionRecoveryRequest(operation="reconcile"),
            request,
            identity,
        )

    assert caught.value.code == expected_code


@pytest.mark.asyncio
async def test_action_recovery_fails_closed_without_durable_workflow() -> None:
    action = _action()
    request, _, _ = _action_request(action)

    with pytest.raises(PlatformError) as caught:
        await recover_action(
            action.action_id,
            ActionRecoveryRequest(operation="reconcile"),
            request,
            _identity(),
        )

    assert caught.value.code == "ACTION_RECOVERY_UNAVAILABLE"
    assert caught.value.retryable is True


class _CapabilityStore:
    def __init__(self) -> None:
        self.enabled = CapabilityRecord(
            name="knowledge.search",
            version="1.0.0",
            effect="read",
            risk="low",
        )
        self.disabled = CapabilityRecord(
            name="email.prepare",
            version="1.0.0",
            effect="prepare",
            risk="high",
            enabled=False,
            disabled_reason="incident",
        )
        self.calls: list[tuple[str, str, bool, str]] = []

    async def list(self, tenant_id: str) -> tuple[CapabilityRecord, ...]:
        assert tenant_id == "tenant-a"
        return self.enabled, self.disabled

    async def set_enabled(
        self,
        tenant_id: str,
        name: str,
        enabled: bool,
        reason: str,
    ) -> CapabilityRecord:
        self.calls.append((tenant_id, name, enabled, reason))
        return CapabilityRecord(
            name=name,
            version="1.0.0",
            effect="read",
            risk="low",
            enabled=enabled,
            disabled_reason=None if enabled else reason,
        )


@pytest.mark.asyncio
async def test_capability_routes_filter_disabled_and_bind_admin_mutations() -> None:
    store = _CapabilityStore()
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                container=SimpleNamespace(
                    store=SimpleNamespace(capabilities=store),
                )
            )
        )
    )
    identity = _identity()
    body = DisableCapabilityRequest(reason="operator decision")

    listed = await list_capabilities(request, identity)
    disabled = await disable_capability("knowledge.search", body, request, identity)
    enabled = await enable_capability("knowledge.search", body, request, identity)

    assert [item.name for item in listed] == ["knowledge.search"]
    assert disabled.enabled is False
    assert enabled.enabled is True
    assert store.calls == [
        ("tenant-a", "knowledge.search", False, "operator decision"),
        ("tenant-a", "knowledge.search", True, "operator decision"),
    ]
