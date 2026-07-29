from __future__ import annotations

from collections.abc import Callable
from typing import Any
from uuid import uuid4

import pytest
from temporalio import activity
from temporalio.exceptions import ApplicationError
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from agent_platform.workflows.temporal_workflow import AgentRunWorkflow, StartRunCommand

pytestmark = pytest.mark.integration


def named_activity(name: str, result: Any) -> Callable[[dict[str, Any]], Any]:
    async def implementation(_: dict[str, Any]) -> Any:
        return result

    return activity.defn(name=name)(implementation)


@pytest.mark.asyncio
async def test_commit_failure_persists_run_failure_instead_of_staying_committing() -> None:
    try:
        environment = await WorkflowEnvironment.start_time_skipping()
    except RuntimeError as exc:
        pytest.skip(f"Temporal time-skipping server unavailable: {exc}")

    plan = {
        "plan_version": 1,
        "tasks": [
            {
                "id": "task-a",
                "depends_on": [],
                "timeout_seconds": 30,
            }
        ],
        "final_task_id": "task-a",
    }
    action_id = str(uuid4())
    run_id = str(uuid4())
    failure_payloads: list[dict[str, Any]] = []

    @activity.defn(name="agent.commit_action")
    async def commit(_: dict[str, Any]) -> dict[str, Any]:
        raise ApplicationError(
            "provider outcome requires reconciliation",
            type="COMMIT_OUTCOME_UNKNOWN",
            non_retryable=True,
        )

    @activity.defn(name="agent.fail_run")
    async def fail_run(payload: dict[str, Any]) -> dict[str, Any]:
        failure_payloads.append(payload)
        return {"status": "failed"}

    agent_activities = [
        named_activity("agent.classify_contract", {}),
        named_activity("agent.create_plan", plan),
        named_activity("agent.authorize_plan", {}),
        named_activity("agent.mark_executing", {}),
        named_activity("agent.execute_task", {"summary": "done"}),
        named_activity("agent.verify_run", {"verdict": "pass"}),
        named_activity(
            "agent.list_actions",
            [{"action_id": action_id, "status": "approved"}],
        ),
        named_activity("agent.mark_waiting_approval", {}),
        named_activity("agent.finalize_run", {}),
        named_activity("agent.cancel_run", {}),
        fail_run,
        named_activity("agent.expire_actions", {}),
    ]
    agent_queue = f"test-agent-runs-{uuid4()}"
    commit_queue = f"test-agent-commits-{uuid4()}"
    try:
        async with (
            Worker(
                environment.client,
                task_queue=agent_queue,
                workflows=[AgentRunWorkflow],
                activities=agent_activities,
            ),
            Worker(
                environment.client,
                task_queue=commit_queue,
                activities=[commit],
            ),
        ):
            result = await environment.client.execute_workflow(
                AgentRunWorkflow.run,
                StartRunCommand(
                    run_id=run_id,
                    tenant_id="tenant-a",
                    correlation_id="corr-commit-failure",
                    commit_task_queue=commit_queue,
                ),
                id=f"agent-run-{uuid4()}",
                task_queue=agent_queue,
            )

        assert result["status"] == "failed"
        assert result["reason"] == "COMMIT_OUTCOME_UNKNOWN"
        assert failure_payloads == [
            {
                "run_id": run_id,
                "tenant_id": "tenant-a",
                "correlation_id": "corr-commit-failure",
                "reason": "COMMIT_OUTCOME_UNKNOWN",
            }
        ]
    finally:
        await environment.shutdown()
