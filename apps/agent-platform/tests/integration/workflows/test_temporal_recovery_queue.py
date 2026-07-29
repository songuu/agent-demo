from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from agent_platform.workflows.recovery_workflow import (
    ActionRecoveryWorkflow,
    StartActionRecoveryCommand,
)

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_recovery_workflow_runs_secret_free_operations_on_commit_queue() -> None:
    try:
        environment = await WorkflowEnvironment.start_time_skipping()
    except RuntimeError as exc:
        pytest.skip(f"Temporal time-skipping server unavailable: {exc}")

    received: list[tuple[str, dict[str, Any]]] = []

    @activity.defn(name="transaction.reconcile_action")
    async def reconcile(payload: dict[str, Any]) -> dict[str, Any]:
        received.append(("reconcile", payload))
        return {"action_status": "approved"}

    @activity.defn(name="transaction.compensate_action")
    async def compensate(payload: dict[str, Any]) -> dict[str, Any]:
        received.append(("compensate", payload))
        return {"action_status": "compensated"}

    commit_queue = f"test-agent-recovery-{uuid4()}"
    run_id = str(uuid4())
    action_id = str(uuid4())
    try:
        async with Worker(
            environment.client,
            task_queue=commit_queue,
            workflows=[ActionRecoveryWorkflow],
            activities=[reconcile, compensate],
        ):
            reconciled = await environment.client.execute_workflow(
                ActionRecoveryWorkflow.run,
                StartActionRecoveryCommand(
                    run_id=run_id,
                    action_id=action_id,
                    tenant_id="tenant-a",
                    correlation_id="corr-reconcile",
                    requested_by="admin-a",
                    operation="reconcile",
                ),
                id=f"action-recovery-{uuid4()}",
                task_queue=commit_queue,
            )
            compensated = await environment.client.execute_workflow(
                ActionRecoveryWorkflow.run,
                StartActionRecoveryCommand(
                    run_id=run_id,
                    action_id=action_id,
                    tenant_id="tenant-a",
                    correlation_id="corr-compensate",
                    requested_by="admin-a",
                    operation="compensate",
                    reason="operator approved rollback",
                ),
                id=f"action-recovery-{uuid4()}",
                task_queue=commit_queue,
            )

        assert reconciled["action_status"] == "approved"
        assert compensated["action_status"] == "compensated"
        assert [operation for operation, _ in received] == [
            "reconcile",
            "compensate",
        ]
        for _, payload in received:
            assert "credential" not in payload
            assert "secret" not in payload
            assert "principal_scopes" not in payload
    finally:
        await environment.shutdown()
