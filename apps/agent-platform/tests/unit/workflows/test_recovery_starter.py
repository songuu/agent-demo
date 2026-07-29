from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest

from agent_platform.workflows.recovery_workflow import (
    ActionRecoveryWorkflow,
    StartActionRecoveryCommand,
)
from agent_platform.workflows.temporal_starter import TemporalWorkflowStarter


class _Client:
    def __init__(self) -> None:
        self.calls: list[tuple[object, object, dict[str, Any]]] = []

    async def start_workflow(
        self,
        workflow: object,
        command: object,
        **kwargs: Any,
    ) -> None:
        self.calls.append((workflow, command, kwargs))


@pytest.mark.asyncio
async def test_api_starter_routes_secret_free_recovery_to_commit_queue() -> None:
    client = _Client()
    starter = TemporalWorkflowStarter(
        client=client,  # type: ignore[arg-type]
        task_queue="agent-runs",
        commit_task_queue="agent-commits",
    )
    run_id = uuid4()
    action_id = uuid4()

    workflow_id = await starter.start_action_recovery(
        run_id=run_id,
        action_id=action_id,
        tenant_id="tenant-a",
        correlation_id="corr-recovery-1",
        requested_by="admin-a",
        operation="reconcile",
    )

    workflow, command, options = client.calls[0]
    assert workflow == ActionRecoveryWorkflow.run
    assert isinstance(command, StartActionRecoveryCommand)
    assert command.run_id == str(run_id)
    assert command.action_id == str(action_id)
    assert command.requested_by == "admin-a"
    assert not hasattr(command, "credential")
    assert not hasattr(command, "secret")
    assert options["task_queue"] == "agent-commits"
    assert options["id"] == workflow_id


@pytest.mark.asyncio
async def test_recovery_start_is_idempotent_for_same_correlation() -> None:
    client = _Client()
    starter = TemporalWorkflowStarter(
        client=client,  # type: ignore[arg-type]
        task_queue="agent-runs",
        commit_task_queue="agent-commits",
    )
    args = {
        "run_id": uuid4(),
        "action_id": uuid4(),
        "tenant_id": "tenant-a",
        "correlation_id": "corr-recovery-idempotent",
        "requested_by": "admin-a",
        "operation": "compensate",
        "reason": "approved rollback",
    }

    first = await starter.start_action_recovery(**args)
    second = await starter.start_action_recovery(**args)

    assert first == second
    assert client.calls[0][2]["id"] == client.calls[1][2]["id"]
