from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest

from agent_platform.workflows import recovery_workflow as workflow_module
from agent_platform.workflows.recovery_workflow import (
    ActionRecoveryWorkflow,
    StartActionRecoveryCommand,
)


def _command(operation: str, *, reason: str | None = None) -> StartActionRecoveryCommand:
    return StartActionRecoveryCommand(
        run_id=str(uuid4()),
        action_id=str(uuid4()),
        tenant_id="tenant-a",
        correlation_id="recovery-corr",
        requested_by="operator-a",
        operation=operation,
        reason=reason,
    )


@pytest.mark.parametrize(
    ("operation", "activity_name"),
    [
        ("reconcile", "transaction.reconcile_action"),
        ("compensate", "transaction.compensate_action"),
    ],
)
@pytest.mark.asyncio
async def test_recovery_workflow_routes_operation_and_returns_bound_identity(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    activity_name: str,
) -> None:
    calls: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    command = _command(
        operation,
        reason="operator rollback" if operation == "compensate" else None,
    )

    async def execute_activity(
        name: str,
        payload: dict[str, Any],
        **options: Any,
    ) -> dict[str, Any]:
        calls.append((name, payload, options))
        return {"action_status": "compensated"}

    monkeypatch.setattr(workflow_module.workflow, "execute_activity", execute_activity)
    recovery = ActionRecoveryWorkflow()
    assert recovery.summary() == {"phase": "received"}

    result = await recovery.run(command)

    assert recovery.summary() == {"phase": "completed"}
    assert result["status"] == "completed"
    assert result["operation"] == operation
    assert result["run_id"] == command.run_id
    assert result["action_id"] == command.action_id
    name, payload, options = calls[0]
    assert name == activity_name
    assert payload["tenant_id"] == command.tenant_id
    assert payload["requested_by"] == command.requested_by
    assert payload["reason"] == command.reason
    assert options["activity_id"] == f"{operation}-{command.action_id}"
    assert options["retry_policy"].maximum_attempts == 1


@pytest.mark.parametrize(
    "field",
    ["run_id", "action_id", "tenant_id", "correlation_id", "requested_by"],
)
def test_recovery_command_requires_each_identity(field: str) -> None:
    values: dict[str, Any] = {
        "run_id": str(uuid4()),
        "action_id": str(uuid4()),
        "tenant_id": "tenant-a",
        "correlation_id": "recovery-corr",
        "requested_by": "operator-a",
        "operation": "reconcile",
    }
    values[field] = " "

    with pytest.raises(ValueError, match="ACTION_RECOVERY_IDENTIFIERS_REQUIRED"):
        StartActionRecoveryCommand(**values)
