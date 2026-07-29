from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from agent_platform.application.action_service import ActionService
from agent_platform.application.commit_service import CommitService
from agent_platform.application.errors import (
    Forbidden,
    PlatformError,
    StaleActionHash,
    UnknownOutcome,
)
from agent_platform.application.records import ActionRecord, RunRecord
from agent_platform.domain.enums import ActionStatus, RiskLevel, ToolEffect
from agent_platform.domain.hashing import payload_hash
from agent_platform.infrastructure.credentials import EphemeralCredentialBroker
from agent_platform.infrastructure.kill_switch import (
    KillSwitchRegistry,
    KillSwitchScope,
)
from agent_platform.infrastructure.memory_store import InMemoryPlatformStore
from agent_platform.tools.models import PolicyDecision, RegisteredTool, ToolDefinition
from agent_platform.tools.registry import ToolRegistry


class WorkflowSpy:
    def __init__(self, *, notify_failures: int = 0) -> None:
        self.decisions: list[tuple[object, str]] = []
        self.notify_attempts = 0
        self._notify_failures = notify_failures

    async def notify_action(
        self,
        action_id: object,
        tenant_id: str,
        decision: str,
    ) -> None:
        assert tenant_id == "tenant-a"
        self.notify_attempts += 1
        if self._notify_failures > 0:
            self._notify_failures -= 1
            raise RuntimeError("TEMPORAL_SIGNAL_UNAVAILABLE")
        self.decisions.append((action_id, decision))


class AllowPolicy:
    async def authorize_action(self, request: object) -> PolicyDecision:
        return PolicyDecision(
            allowed=True,
            reason_codes=(),
            approval_required=False,
            policy_version="test-1",
            credential_scopes=frozenset({"email:commit"}),
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
            required_approvals=0,
        )


class CommitAdapter:
    def __init__(self, *, unknown: bool = False) -> None:
        self.unknown = unknown
        self.commits = 0
        self.lookup_result: object | None = None
        self.verify_passed = True

    async def read(self, args: object, credential: object) -> object:
        raise AssertionError("write adapter read should not be called")

    async def preview(self, args: object, credential: object) -> object:
        return {"preview": args}

    async def lookup_by_idempotency_key(self, key: str, credential: object) -> object | None:
        return self.lookup_result

    async def commit(self, payload: object, credential: object, key: str) -> object:
        self.commits += 1
        if self.unknown:
            raise UnknownOutcome("action-unknown", provider_request_id="provider-1")
        return {
            "external_operation_id": f"email-{self.commits}",
            "committed_at": datetime.now(UTC).isoformat(),
            "idempotency_key": key,
        }

    async def verify(self, action: object, receipt: object, credential: object) -> object:
        return {
            "passed": self.verify_passed,
            "verified_at": datetime.now(UTC).isoformat(),
            "method": "read_after_write",
        }

    async def compensate(self, action: object, receipt: object, credential: object) -> object:
        return {"compensated": True}


def tool(adapter: CommitAdapter) -> RegisteredTool:
    return RegisteredTool(
        ToolDefinition(
            name="email.prepare",
            version="1.0.0",
            description="Prepare and commit a sandbox email",
            capability_name="email.prepare",
            effect=ToolEffect.PREPARE,
            input_schema={
                "type": "object",
                "properties": {"subject": {"type": "string"}},
                "required": ["subject"],
                "additionalProperties": False,
            },
            output_schema={"type": "object"},
            risk=RiskLevel.HIGH,
            required_scopes=frozenset({"email:commit"}),
            timeout_seconds=5,
            max_result_bytes=1000,
            idempotency="business_key",
            approval_policy="human",
            adapter_ref="sandbox_email",
        ),
        adapter,
    )


async def seeded_action(
    store: InMemoryPlatformStore,
    *,
    required_approvals: int = 1,
) -> tuple[RunRecord, ActionRecord]:
    run_id = uuid4()
    run, _ = await store.runs.create_once(
        RunRecord(
            run_id=run_id,
            tenant_id="tenant-a",
            principal_id="requester",
            contract=SimpleNamespace(
                constraints={"use_case": "notification"},
                requested_output=SimpleNamespace(schema_name="notification@1.0"),
            ),
            idempotency_key="request-1",
            request_hash="hash",
            workflow_id=f"run-{run_id}",
        )
    )
    action, _ = await store.actions.create_once(
        ActionRecord(
            action_id=uuid4(),
            run_id=run.run_id,
            tenant_id=run.tenant_id,
            principal_id=run.principal_id,
            action_type="email.prepare",
            tool_name="email.prepare",
            tool_version="1.0.0",
            canonical_payload={"subject": "Approved"},
            payload_hash=payload_hash({"subject": "Approved"}),
            preview={"subject": "Approved"},
            risk=RiskLevel.HIGH,
            approval_policy="human",
            required_approvals=required_approvals,
            idempotency_key="business-1",
            policy_version="test-1",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            status=ActionStatus.PENDING_APPROVAL,
        )
    )
    return run, action


@pytest.mark.asyncio
async def test_stale_hash_requester_approval_and_weak_auth_are_rejected() -> None:
    store = InMemoryPlatformStore()
    _, action = await seeded_action(store)
    service = ActionService(store.actions, WorkflowSpy())

    with pytest.raises(StaleActionHash):
        await service.decide(
            action.action_id,
            tenant_id="tenant-a",
            actor_id="approver",
            actor_roles=frozenset({"approver"}),
            auth_strength="mfa",
            decision="approved",
            expected_payload_hash="old",
            comment=None,
        )
    with pytest.raises(Forbidden, match="separation"):
        await service.decide(
            action.action_id,
            tenant_id="tenant-a",
            actor_id="requester",
            actor_roles=frozenset({"approver"}),
            auth_strength="mfa",
            decision="approved",
            expected_payload_hash=action.payload_hash,
            comment=None,
        )
    with pytest.raises(Forbidden, match="step-up"):
        await service.decide(
            action.action_id,
            tenant_id="tenant-a",
            actor_id="approver",
            actor_roles=frozenset({"approver"}),
            auth_strength="password",
            decision="approved",
            expected_payload_hash=action.payload_hash,
            comment=None,
        )


@pytest.mark.asyncio
async def test_approval_retry_resignals_without_duplicate_approval() -> None:
    store = InMemoryPlatformStore()
    run, action = await seeded_action(store)
    workflow = WorkflowSpy(notify_failures=1)
    service = ActionService(store.actions, workflow)
    decision = {
        "tenant_id": "tenant-a",
        "actor_id": "approver-1",
        "actor_roles": frozenset({"approver"}),
        "auth_strength": "mfa",
        "decision": "approved",
        "expected_payload_hash": action.payload_hash,
        "comment": "reviewed",
    }

    with pytest.raises(PlatformError) as failed:
        await service.decide(action.action_id, **decision)

    assert failed.value.code == "WORKFLOW_SIGNAL_FAILED"
    assert failed.value.retryable is True
    persisted = await store.actions.get(action.action_id, "tenant-a")
    assert persisted.status == ActionStatus.APPROVED
    assert len(persisted.approvals) == 1

    retried = await service.decide(action.action_id, **decision)

    assert retried.status == ActionStatus.APPROVED
    assert len(retried.approvals) == 1
    assert workflow.notify_attempts == 2
    assert workflow.decisions == [(action.action_id, "approved")]
    events = await store.runs.events_after(run.run_id, run.tenant_id, 0)
    assert [event.event_type for event in events] == ["action.approval_recorded"]
    assert events[0].action_id == action.action_id
    assert events[0].payload["approval_id"] == persisted.approvals[0]["approval_id"]
    assert events[0].payload["payload_hash"] == action.payload_hash


@pytest.mark.asyncio
async def test_two_person_approval_is_counted_by_distinct_actor() -> None:
    store = InMemoryPlatformStore()
    _, action = await seeded_action(store, required_approvals=2)
    workflow = WorkflowSpy()
    service = ActionService(store.actions, workflow)
    first = await service.decide(
        action.action_id,
        tenant_id="tenant-a",
        actor_id="approver-1",
        actor_roles=frozenset({"approver"}),
        auth_strength="mfa",
        decision="approved",
        expected_payload_hash=action.payload_hash,
        comment=None,
    )
    assert first.status == ActionStatus.PENDING_APPROVAL
    second = await service.decide(
        action.action_id,
        tenant_id="tenant-a",
        actor_id="approver-2",
        actor_roles=frozenset({"approver"}),
        auth_strength="phishing_resistant",
        decision="approved",
        expected_payload_hash=action.payload_hash,
        comment="reviewed",
    )
    assert second.status == ActionStatus.APPROVED
    assert workflow.decisions == [(action.action_id, "approved")]


@pytest.mark.asyncio
async def test_unknown_outcome_is_persisted_and_never_blindly_retried() -> None:
    store = InMemoryPlatformStore()
    _, action = await seeded_action(store)
    async with store.actions.get_for_update(action.action_id, action.tenant_id) as locked:
        locked.status = ActionStatus.APPROVED
    adapter = CommitAdapter(unknown=True)
    registry = ToolRegistry()
    registry.register(tool(adapter), expose_to_agent=True)
    service = CommitService(
        store.actions,
        store.runs,
        registry,
        AllowPolicy(),
        EphemeralCredentialBroker(),
    )

    with pytest.raises(UnknownOutcome):
        await service.commit(
            tenant_id="tenant-a",
            principal_id="commit-worker",
            principal_scopes=frozenset({"email:commit"}),
            action_id=action.action_id,
            correlation_id="corr-1",
        )
    assert adapter.commits == 1
    assert (await store.actions.get(action.action_id, "tenant-a")).status == ActionStatus.UNKNOWN

    with pytest.raises(UnknownOutcome):
        await service.commit(
            tenant_id="tenant-a",
            principal_id="commit-worker",
            principal_scopes=frozenset({"email:commit"}),
            action_id=action.action_id,
            correlation_id="corr-2",
        )
    assert adapter.commits == 1


@pytest.mark.asyncio
async def test_commit_rechecks_hierarchical_kill_switch_before_side_effect() -> None:
    store = InMemoryPlatformStore()
    _, action = await seeded_action(store)
    async with store.actions.get_for_update(action.action_id, action.tenant_id) as locked:
        locked.status = ActionStatus.APPROVED
    adapter = CommitAdapter()
    registry = ToolRegistry()
    registry.register(tool(adapter), expose_to_agent=True)
    kill_switches = KillSwitchRegistry(environment="test")
    await kill_switches.activate(
        scope=KillSwitchScope.TENANT,
        scope_id="tenant-a",
        mode="writes",
        reason="containment",
        changed_by="operator",
        incident_id="INC-COMMIT",
    )
    service = CommitService(
        store.actions,
        store.runs,
        registry,
        AllowPolicy(),
        EphemeralCredentialBroker(),
        kill_switches=kill_switches,
    )

    with pytest.raises(PlatformError) as blocked:
        await service.commit(
            tenant_id="tenant-a",
            principal_id="commit-worker",
            principal_scopes=frozenset({"email:commit"}),
            action_id=action.action_id,
            correlation_id="corr-kill",
        )

    assert blocked.value.code == "TENANT_KILL_SWITCH_ACTIVE"
    assert adapter.commits == 0
    persisted = await store.actions.get(action.action_id, "tenant-a")
    assert persisted.status == ActionStatus.APPROVED


@pytest.mark.asyncio
async def test_commit_lookup_suppresses_duplicate_and_requires_read_after_write() -> None:
    store = InMemoryPlatformStore()
    run, action = await seeded_action(store)
    async with store.actions.get_for_update(action.action_id, action.tenant_id) as locked:
        locked.status = ActionStatus.APPROVED
    adapter = CommitAdapter()
    adapter.lookup_result = {
        "external_operation_id": "existing",
        "idempotency_key": action.idempotency_key,
    }
    registry = ToolRegistry()
    registry.register(tool(adapter), expose_to_agent=True)
    service = CommitService(
        store.actions,
        store.runs,
        registry,
        AllowPolicy(),
        EphemeralCredentialBroker(),
    )

    receipt = await service.commit(
        tenant_id="tenant-a",
        principal_id="commit-worker",
        principal_scopes=frozenset({"email:commit"}),
        action_id=action.action_id,
        correlation_id="corr-1",
    )

    assert receipt["external_operation_id"] == "existing"
    assert adapter.commits == 0
    assert (await store.actions.get(action.action_id, "tenant-a")).status == ActionStatus.COMMITTED
    events = await store.runs.events_after(run.run_id, run.tenant_id, 0)
    committed = next(event for event in events if event.event_type == "action.committed")
    assert committed.action_id == action.action_id
    assert committed.payload["receipt_hash"]
    assert committed.payload["verification_hash"]
    invocation_id = committed.payload["tool_invocation_id"]
    invocation = next(
        value for value in store.audit._tools.values() if str(value.invocation_id) == invocation_id
    )
    assert invocation.effect is ToolEffect.COMMIT
    assert invocation.result_hash == committed.payload["receipt_hash"]
