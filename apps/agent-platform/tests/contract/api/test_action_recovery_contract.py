from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import httpx
import pytest

from agent_platform.api.app import create_app
from agent_platform.application.records import ActionRecord, RunRecord
from agent_platform.config import Settings
from agent_platform.container import build_container
from agent_platform.domain.enums import ActionStatus, RiskLevel
from agent_platform.domain.hashing import payload_hash


class _RecoveryStarter:
    def __init__(self) -> None:
        self.command: dict[str, Any] | None = None

    async def start_action_recovery(self, **command: Any) -> str:
        self.command = command
        return "action-recovery-workflow-1"


def _headers(*, auth_strength: str = "phishing_resistant") -> dict[str, str]:
    return {
        "X-Agent-Tenant": "tenant-a",
        "X-Agent-User": "operator-a",
        "X-Agent-Roles": "admin",
        "X-Agent-Scopes": "actions:recover",
        "X-Agent-Auth-Strength": auth_strength,
        "X-Correlation-ID": "recovery-api-1",
    }


@pytest.mark.asyncio
async def test_recovery_api_submits_only_a_secret_free_temporal_command() -> None:
    settings = Settings(environment="test", auth_disabled=True)
    container = await build_container(settings)
    starter = _RecoveryStarter()
    container.recovery_workflow = starter
    action = await _stored_unknown_action(container)
    app = create_app(settings, container=container)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        response = await client.post(
            f"/v1/actions/{action.action_id}:recover",
            headers=_headers(),
            json={"operation": "reconcile"},
        )
    await container.aclose()

    assert response.status_code == 202
    assert response.json() == {
        "action_id": str(action.action_id),
        "run_id": str(action.run_id),
        "operation": "reconcile",
        "workflow_id": "action-recovery-workflow-1",
        "status": "accepted",
    }
    assert starter.command == {
        "run_id": action.run_id,
        "action_id": action.action_id,
        "tenant_id": "tenant-a",
        "correlation_id": "recovery-api-1",
        "requested_by": "operator-a",
        "operation": "reconcile",
        "reason": None,
    }
    assert not {
        "credential",
        "credentials",
        "secret",
        "token",
        "api_key",
    } & set(starter.command)


@pytest.mark.asyncio
async def test_recovery_api_requires_phishing_resistant_admin_and_reason() -> None:
    settings = Settings(environment="test", auth_disabled=True)
    container = await build_container(settings)
    starter = _RecoveryStarter()
    container.recovery_workflow = starter
    action = await _stored_unknown_action(container)
    app = create_app(settings, container=container)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        weak_auth = await client.post(
            f"/v1/actions/{action.action_id}:recover",
            headers=_headers(auth_strength="mfa"),
            json={"operation": "reconcile"},
        )
        missing_reason = await client.post(
            f"/v1/actions/{action.action_id}:recover",
            headers=_headers(),
            json={"operation": "compensate"},
        )
    await container.aclose()

    assert weak_auth.status_code == 403
    assert weak_auth.json()["error"]["code"] == "ACTION_RECOVERY_OPERATOR_REQUIRED"
    assert missing_reason.status_code == 422
    assert starter.command is None


async def _stored_unknown_action(container: Any) -> ActionRecord:
    run_id = uuid4()
    run, _ = await container.store.runs.create_once(
        RunRecord(
            run_id=run_id,
            tenant_id="tenant-a",
            principal_id="requester-a",
            contract=SimpleNamespace(),
            idempotency_key="recovery-api-run",
            request_hash="request-hash",
            workflow_id=f"agent-run-{run_id}",
        )
    )
    canonical_payload = {"subject": "Approved"}
    action, _ = await container.store.actions.create_once(
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
            status=ActionStatus.UNKNOWN,
        )
    )
    return action
