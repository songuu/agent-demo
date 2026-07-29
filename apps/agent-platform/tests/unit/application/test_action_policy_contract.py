from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from agent_platform.application.action_service import ActionService
from agent_platform.application.commit_service import CommitService
from agent_platform.application.errors import Forbidden
from agent_platform.application.records import ActionRecord, RunRecord
from agent_platform.domain.enums import ActionStatus, RiskLevel
from agent_platform.domain.hashing import payload_hash
from agent_platform.infrastructure.memory_store import InMemoryPlatformStore


def test_commit_policy_request_contains_the_complete_opa_context() -> None:
    payload = {"subject": "approved"}
    action = ActionRecord(
        action_id=uuid4(),
        run_id=uuid4(),
        tenant_id="tenant-a",
        principal_id="requester",
        action_type="email.prepare",
        tool_name="email.prepare",
        tool_version="1.0.0",
        canonical_payload=payload,
        payload_hash=payload_hash(payload),
        preview=payload,
        risk=RiskLevel.CRITICAL,
        approval_policy="two-person",
        required_approvals=2,
        idempotency_key="email-1",
        policy_version="policy-1",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
        status=ActionStatus.APPROVED,
        approvals=[
            {
                "actor_id": "approver-1",
                "auth_strength": "phishing_resistant",
                "decision": "approved",
                "payload_hash": payload_hash(payload),
            },
            {
                "actor_id": "approver-2",
                "auth_strength": "phishing_resistant",
                "decision": "approved",
                "payload_hash": payload_hash(payload),
            },
        ],
    )

    request = CommitService._policy_request(
        action,
        tenant_id="tenant-a",
        principal_id="commit-worker",
        principal_scopes=frozenset({"email:commit"}),
        phase="commit",
    )

    assert request["phase"] == "commit"
    assert request["caller"] == "commit-worker"
    assert request["tool"]["effect"] == "commit"
    assert request["principal"]["auth_strength"] == "phishing_resistant"
    assert request["action"]["required_approvals"] == 2
    assert request["action"]["risk"] == "critical"
    assert request["action"]["expires_at"].endswith("+00:00")
    assert request["approval"]["payload_hash"] == action.payload_hash
    assert len(request["approvals"]) == 2
    assert request["kill_switch"] == {"mode": "none"}


@pytest.mark.asyncio
async def test_critical_action_requires_phishing_resistant_approval() -> None:
    store = InMemoryPlatformStore()
    run, _ = await store.runs.create_once(
        RunRecord(
            run_id=uuid4(),
            tenant_id="tenant-a",
            principal_id="requester",
            contract=SimpleNamespace(),
            idempotency_key="run-1",
            request_hash="request-hash",
            workflow_id="agent-run-1",
        )
    )
    payload = {"subject": "critical"}
    action, _ = await store.actions.create_once(
        ActionRecord(
            action_id=uuid4(),
            run_id=run.run_id,
            tenant_id=run.tenant_id,
            principal_id=run.principal_id,
            action_type="email.prepare",
            tool_name="email.prepare",
            tool_version="1.0.0",
            canonical_payload=payload,
            payload_hash=payload_hash(payload),
            preview=payload,
            risk=RiskLevel.CRITICAL,
            approval_policy="two-person",
            required_approvals=2,
            idempotency_key="email-1",
            policy_version="policy-1",
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
            status=ActionStatus.PENDING_APPROVAL,
        )
    )
    service = ActionService(store.actions, _WorkflowSpy())

    with pytest.raises(Forbidden, match="STEP_UP_AUTH_REQUIRED"):
        await service.decide(
            action.action_id,
            tenant_id=action.tenant_id,
            actor_id="approver-1",
            actor_roles=frozenset({"approver"}),
            auth_strength="mfa",
            decision="approved",
            expected_payload_hash=action.payload_hash,
            comment=None,
        )

    unchanged = await store.actions.get(action.action_id, action.tenant_id)
    assert unchanged.status == ActionStatus.PENDING_APPROVAL
    assert unchanged.approvals == []

    accepted = await service.decide(
        action.action_id,
        tenant_id=action.tenant_id,
        actor_id="approver-1",
        actor_roles=frozenset({"approver"}),
        auth_strength="phishing_resistant",
        decision="approved",
        expected_payload_hash=action.payload_hash,
        comment=None,
    )
    assert accepted.status == ActionStatus.PENDING_APPROVAL
    assert len(accepted.approvals) == 1


class _WorkflowSpy:
    async def notify_action(
        self,
        action_id: object,
        tenant_id: str,
        decision: str,
    ) -> None:
        raise AssertionError(f"approval should not complete: {action_id=} {tenant_id=} {decision=}")
