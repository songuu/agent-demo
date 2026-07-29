from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from agent_platform.application.commit_service import CommitService
from agent_platform.application.errors import Conflict, StaleActionHash, UnknownOutcome
from agent_platform.application.records import ActionRecord, RunRecord
from agent_platform.domain.enums import ActionStatus, RiskLevel, ToolEffect
from agent_platform.domain.hashing import payload_hash
from agent_platform.infrastructure.credentials import EphemeralCredentialBroker
from agent_platform.infrastructure.memory_store import InMemoryPlatformStore
from agent_platform.tools.models import PolicyDecision, RegisteredTool, ToolDefinition
from agent_platform.tools.registry import ToolRegistry


@pytest.mark.asyncio
async def test_commit_timeout_becomes_durable_unknown_and_is_not_retried() -> None:
    service, store, action, adapter = await _service(_SlowAdapter())

    with pytest.raises(UnknownOutcome):
        await service.commit(
            tenant_id=action.tenant_id,
            principal_id="commit-worker",
            principal_scopes=frozenset({"email:commit"}),
            action_id=action.action_id,
            correlation_id="commit-timeout-1",
        )

    assert adapter.commit_calls == 1
    assert (await store.actions.get(action.action_id, action.tenant_id)).status == (
        ActionStatus.UNKNOWN
    )
    with pytest.raises(UnknownOutcome):
        await service.commit(
            tenant_id=action.tenant_id,
            principal_id="commit-worker",
            principal_scopes=frozenset({"email:commit"}),
            action_id=action.action_id,
            correlation_id="commit-timeout-2",
        )
    assert adapter.commit_calls == 1


@pytest.mark.asyncio
async def test_commit_provider_error_becomes_durable_unknown_and_is_not_retried() -> None:
    adapter = _Adapter()
    adapter.commit_error = RuntimeError("provider disconnected after accepting request")
    service, store, action, _ = await _service(adapter)

    with pytest.raises(UnknownOutcome) as failed:
        await service.commit(
            tenant_id=action.tenant_id,
            principal_id="commit-worker",
            principal_scopes=frozenset({"email:commit"}),
            action_id=action.action_id,
            correlation_id="commit-provider-error-1",
        )

    assert failed.value.__cause__ is adapter.commit_error
    persisted = await store.actions.get(action.action_id, action.tenant_id)
    assert persisted.status == ActionStatus.UNKNOWN
    assert persisted.failure_code == "COMMIT_OUTCOME_UNKNOWN"
    assert adapter.commit_calls == 1

    with pytest.raises(UnknownOutcome):
        await service.commit(
            tenant_id=action.tenant_id,
            principal_id="commit-worker",
            principal_scopes=frozenset({"email:commit"}),
            action_id=action.action_id,
            correlation_id="commit-provider-error-2",
        )
    assert adapter.commit_calls == 1


@pytest.mark.asyncio
async def test_verify_error_persists_receipt_as_unknown_for_reconciliation() -> None:
    adapter = _Adapter()
    adapter.verify_error = RuntimeError("provider read path unavailable")
    service, store, action, _ = await _service(adapter)

    with pytest.raises(UnknownOutcome) as failed:
        await service.commit(
            tenant_id=action.tenant_id,
            principal_id="commit-worker",
            principal_scopes=frozenset({"email:commit"}),
            action_id=action.action_id,
            correlation_id="commit-verify-error-1",
        )

    assert failed.value.__cause__ is adapter.verify_error
    persisted = await store.actions.get(action.action_id, action.tenant_id)
    assert persisted.status == ActionStatus.UNKNOWN
    assert persisted.failure_code == "SIDE_EFFECT_VERIFICATION_UNKNOWN"
    assert persisted.receipt is not None
    assert persisted.receipt["external_operation_id"] == "email-1"


@pytest.mark.asyncio
async def test_commit_recomputes_payload_hash_before_side_effect() -> None:
    service, store, action, adapter = await _service(_Adapter())
    async with store.actions.get_for_update(action.action_id, action.tenant_id) as locked:
        locked.canonical_payload["subject"] = "tampered after approval"

    with pytest.raises(StaleActionHash):
        await service.commit(
            tenant_id=action.tenant_id,
            principal_id="commit-worker",
            principal_scopes=frozenset({"email:commit"}),
            action_id=action.action_id,
            correlation_id="commit-hash-1",
        )

    assert adapter.commit_calls == 0


@pytest.mark.asyncio
async def test_verify_failure_can_be_compensated_with_audited_state() -> None:
    adapter = _Adapter()
    adapter.verify_passed = False
    service, store, action, _ = await _service(adapter)

    with pytest.raises(Exception, match="SIDE_EFFECT_VERIFICATION_FAILED"):
        await service.commit(
            tenant_id=action.tenant_id,
            principal_id="commit-worker",
            principal_scopes=frozenset({"email:commit"}),
            action_id=action.action_id,
            correlation_id="commit-verify-1",
        )
    failed = await store.actions.get(action.action_id, action.tenant_id)
    assert failed.status == ActionStatus.VERIFY_FAILED

    result = await service.compensate(
        tenant_id=action.tenant_id,
        principal_id="commit-worker",
        principal_scopes=frozenset({"email:commit"}),
        action_id=action.action_id,
        correlation_id="commit-compensate-1",
        reason="Read-after-write verification failed.",
    )

    assert result["compensated"] is True
    assert adapter.compensate_calls == 1
    compensated = await store.actions.get(action.action_id, action.tenant_id)
    assert compensated.status == ActionStatus.COMPENSATED


@pytest.mark.asyncio
async def test_reconcile_unknown_absent_returns_action_to_approved_and_audits() -> None:
    service, store, action, adapter = await _service(_Adapter())
    async with store.actions.get_for_update(action.action_id, action.tenant_id) as locked:
        locked.status = ActionStatus.UNKNOWN
        locked.failure_code = "COMMIT_OUTCOME_UNKNOWN"

    result = await service.reconcile_unknown(
        tenant_id=action.tenant_id,
        principal_id="commit-worker",
        principal_scopes=frozenset({"email:commit"}),
        action_id=action.action_id,
        correlation_id="reconcile-absent-1",
    )

    assert result is None
    assert adapter.commit_calls == 0
    reconciled = await store.actions.get(action.action_id, action.tenant_id)
    assert reconciled.status == ActionStatus.APPROVED
    assert reconciled.failure_code is None
    events = await store.runs.events_after(action.run_id, action.tenant_id, 0)
    assert events[-1].event_type == "action.reconciled"
    assert events[-1].payload["outcome"] == "confirmed_absent"
    assert events[-1].correlation_id == "reconcile-absent-1"


@pytest.mark.asyncio
async def test_reconcile_unknown_existing_effect_becomes_committed_and_audits() -> None:
    adapter = _Adapter()
    adapter.lookup_result = {
        "external_operation_id": "email-existing",
        "committed_at": datetime.now(UTC).isoformat(),
        "idempotency_key": "email-business-key",
    }
    service, store, action, _ = await _service(adapter)
    async with store.actions.get_for_update(action.action_id, action.tenant_id) as locked:
        locked.status = ActionStatus.UNKNOWN
        locked.failure_code = "COMMIT_OUTCOME_UNKNOWN"

    receipt = await service.reconcile_unknown(
        tenant_id=action.tenant_id,
        principal_id="commit-worker",
        principal_scopes=frozenset({"email:commit"}),
        action_id=action.action_id,
        correlation_id="reconcile-existing-1",
    )

    assert receipt == adapter.lookup_result
    reconciled = await store.actions.get(action.action_id, action.tenant_id)
    assert reconciled.status == ActionStatus.COMMITTED
    assert reconciled.receipt == adapter.lookup_result
    assert reconciled.failure_code is None
    events = await store.runs.events_after(action.run_id, action.tenant_id, 0)
    assert events[-1].event_type == "action.reconciled"
    assert events[-1].payload["outcome"] == "committed"


@pytest.mark.asyncio
async def test_reconcile_unknown_existing_unverified_effect_is_recoverable() -> None:
    adapter = _Adapter()
    adapter.lookup_result = {
        "external_operation_id": "email-existing",
        "committed_at": datetime.now(UTC).isoformat(),
    }
    adapter.verify_passed = False
    service, store, action, _ = await _service(adapter)
    async with store.actions.get_for_update(action.action_id, action.tenant_id) as locked:
        locked.status = ActionStatus.UNKNOWN

    result = await service.reconcile_unknown(
        tenant_id=action.tenant_id,
        principal_id="commit-worker",
        principal_scopes=frozenset({"email:commit"}),
        action_id=action.action_id,
        correlation_id="reconcile-unverified-1",
    )

    assert result is None
    reconciled = await store.actions.get(action.action_id, action.tenant_id)
    assert reconciled.status == ActionStatus.VERIFY_FAILED
    assert reconciled.receipt == adapter.lookup_result
    events = await store.runs.events_after(action.run_id, action.tenant_id, 0)
    assert events[-1].payload["outcome"] == "verify_failed"


@pytest.mark.asyncio
async def test_reconcile_unknown_absent_rejects_expired_or_changed_action() -> None:
    service, store, action, _ = await _service(_Adapter())
    async with store.actions.get_for_update(action.action_id, action.tenant_id) as locked:
        locked.status = ActionStatus.UNKNOWN
        locked.expires_at = datetime.now(UTC) - timedelta(seconds=1)

    with pytest.raises(Conflict, match="ACTION_EXPIRED"):
        await service.reconcile_unknown(
            tenant_id=action.tenant_id,
            principal_id="commit-worker",
            principal_scopes=frozenset({"email:commit"}),
            action_id=action.action_id,
            correlation_id="reconcile-expired-1",
        )
    assert (
        await store.actions.get(action.action_id, action.tenant_id)
    ).status == ActionStatus.EXPIRED

    service, store, action, _ = await _service(_Adapter())
    async with store.actions.get_for_update(action.action_id, action.tenant_id) as locked:
        locked.status = ActionStatus.UNKNOWN
        locked.canonical_payload["subject"] = "changed"

    with pytest.raises(StaleActionHash):
        await service.reconcile_unknown(
            tenant_id=action.tenant_id,
            principal_id="commit-worker",
            principal_scopes=frozenset({"email:commit"}),
            action_id=action.action_id,
            correlation_id="reconcile-stale-1",
        )
    assert (
        await store.actions.get(action.action_id, action.tenant_id)
    ).status == ActionStatus.UNKNOWN


async def _service(
    adapter: _Adapter,
) -> tuple[CommitService, InMemoryPlatformStore, ActionRecord, _Adapter]:
    store = InMemoryPlatformStore()
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
            idempotency_key="run-key",
            request_hash="run-hash",
            workflow_id=f"agent-run-{run_id}",
        )
    )
    canonical_payload = {"subject": "Approved"}
    action, _ = await store.actions.create_once(
        ActionRecord(
            action_id=uuid4(),
            run_id=run.run_id,
            tenant_id=run.tenant_id,
            principal_id=run.principal_id,
            action_type="email.prepare",
            tool_name="email.prepare",
            tool_version="1.0.0",
            canonical_payload=canonical_payload,
            payload_hash=payload_hash(canonical_payload),
            preview=canonical_payload,
            risk=RiskLevel.HIGH,
            approval_policy="human",
            required_approvals=1,
            idempotency_key="email-business-key",
            policy_version="test-1",
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
            status=ActionStatus.APPROVED,
        )
    )
    registry = ToolRegistry()
    registry.register(
        RegisteredTool(
            ToolDefinition(
                name="email.prepare",
                version="1.0.0",
                description="Sandbox email prepare/commit.",
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
                timeout_seconds=1,
                max_result_bytes=1000,
                idempotency="business_key",
                approval_policy="human",
                adapter_ref="sandbox_email",
            ),
            adapter,
        ),
        expose_to_agent=True,
    )
    service = CommitService(
        store.actions,
        store.runs,
        registry,
        _AllowPolicy(),
        EphemeralCredentialBroker(),
    )
    return service, store, action, adapter


class _AllowPolicy:
    async def authorize_action(self, request: object) -> PolicyDecision:
        del request
        return PolicyDecision(
            allowed=True,
            reason_codes=(),
            approval_required=False,
            policy_version="test-1",
            credential_scopes=frozenset({"email:commit"}),
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
            required_approvals=0,
        )


class _Adapter:
    def __init__(self) -> None:
        self.commit_calls = 0
        self.compensate_calls = 0
        self.verify_passed = True
        self.lookup_result: object | None = None
        self.commit_error: Exception | None = None
        self.verify_error: Exception | None = None

    async def read(self, args: object, credential: object) -> object:
        raise AssertionError("not a read adapter")

    async def preview(self, args: object, credential: object) -> object:
        return {"preview": args}

    async def lookup_by_idempotency_key(self, key: str, credential: object) -> object | None:
        return self.lookup_result

    async def commit(self, payload: object, credential: object, key: str) -> object:
        self.commit_calls += 1
        if self.commit_error is not None:
            raise self.commit_error
        return {
            "external_operation_id": "email-1",
            "committed_at": datetime.now(UTC).isoformat(),
            "idempotency_key": key,
        }

    async def verify(self, action: object, receipt: object, credential: object) -> object:
        if self.verify_error is not None:
            raise self.verify_error
        return {
            "passed": self.verify_passed,
            "verified_at": datetime.now(UTC).isoformat(),
            "method": "read_after_write",
        }

    async def compensate(self, action: object, receipt: object, credential: object) -> object:
        self.compensate_calls += 1
        return {"compensated": True}


class _SlowAdapter(_Adapter):
    async def commit(self, payload: object, credential: object, key: str) -> object:
        self.commit_calls += 1
        await asyncio.sleep(2)
        return await super().commit(payload, credential, key)
