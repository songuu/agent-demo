from __future__ import annotations

from collections.abc import Callable
from typing import Any
from uuid import uuid4

import pytest
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from agent_platform.workflows.temporal_workflow import AgentRunWorkflow, StartRunCommand

pytestmark = pytest.mark.integration


def named_activity(name: str, result: Any) -> Callable[[dict[str, Any]], Any]:
    async def implementation(_: dict[str, Any]) -> Any:
        return result

    return activity.defn(name=name)(implementation)


@pytest.mark.asyncio
async def test_commit_activity_runs_only_on_the_configured_commit_queue() -> None:
    try:
        environment = await WorkflowEnvironment.start_time_skipping()
    except RuntimeError as exc:
        pytest.skip(f"Temporal time-skipping server unavailable: {exc}")

    action_id = str(uuid4())
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
    commit_calls = 0

    @activity.defn(name="agent.commit_action")
    async def commit(_: dict[str, Any]) -> dict[str, Any]:
        nonlocal commit_calls
        commit_calls += 1
        return {"external_operation_id": "external-1"}

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
        named_activity("agent.fail_run", {}),
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
                    run_id=str(uuid4()),
                    tenant_id="tenant-a",
                    correlation_id="corr-commit-queue",
                    commit_task_queue=commit_queue,
                ),
                id=f"agent-run-{uuid4()}",
                task_queue=agent_queue,
            )

        assert result["status"] == "completed"
        assert commit_calls == 1
    finally:
        await environment.shutdown()
