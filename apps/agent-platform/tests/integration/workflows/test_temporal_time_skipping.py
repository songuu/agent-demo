from __future__ import annotations

from collections.abc import Callable
from typing import Any
from uuid import uuid4

import pytest
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Replayer, Worker

from agent_platform.workflows.temporal_workflow import (
    AgentRunWorkflow,
    StartRunCommand,
)

pytestmark = pytest.mark.integration


def named_activity(name: str, result: Any) -> Callable[[dict[str, Any]], Any]:
    async def implementation(_: dict[str, Any]) -> Any:
        return result

    return activity.defn(name=name)(implementation)


@pytest.mark.asyncio
async def test_time_skipping_executes_tasks_replans_once_and_finalizes() -> None:
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
    verifier_calls = 0

    @activity.defn(name="agent.verify_run")
    async def verify(_: dict[str, Any]) -> dict[str, Any]:
        nonlocal verifier_calls
        verifier_calls += 1
        if verifier_calls == 1:
            return {"verdict": "revise", "repair_instructions": ["retry"]}
        return {"verdict": "pass"}

    activities = [
        named_activity("agent.classify_contract", {}),
        named_activity("agent.create_plan", plan),
        named_activity("agent.authorize_plan", {}),
        named_activity("agent.mark_executing", {}),
        named_activity("agent.execute_task", {"summary": "done"}),
        verify,
        named_activity("agent.revise_plan", {**plan, "plan_version": 2}),
        named_activity("agent.list_actions", []),
        named_activity("agent.finalize_run", {}),
        named_activity("agent.cancel_run", {}),
        named_activity("agent.fail_run", {}),
        named_activity("agent.expire_actions", {}),
        named_activity("agent.mark_waiting_approval", {}),
        named_activity("agent.commit_action", {}),
    ]
    task_queue = f"test-agent-run-{uuid4()}"
    try:
        async with Worker(
            environment.client,
            task_queue=task_queue,
            workflows=[AgentRunWorkflow],
            activities=activities,
        ):
            handle = await environment.client.start_workflow(
                AgentRunWorkflow.run,
                StartRunCommand(
                    run_id=str(uuid4()),
                    tenant_id="tenant-a",
                    correlation_id="corr-1",
                    max_replans=1,
                ),
                id=f"agent-run-{uuid4()}",
                task_queue=task_queue,
            )
            result = await handle.result()
            history = await handle.fetch_history()
            replay = await Replayer(workflows=[AgentRunWorkflow]).replay_workflow(history)

        assert result["status"] == "completed"
        assert result["replan_count"] == 1
        assert verifier_calls == 2
        assert replay.replay_failure is None
    finally:
        await environment.shutdown()


@pytest.mark.asyncio
async def test_unresolved_verifier_escalation_never_commits_or_finalizes() -> None:
    try:
        environment = await WorkflowEnvironment.start_time_skipping()
    except RuntimeError as exc:
        pytest.skip(f"Temporal time-skipping server unavailable: {exc}")

    plan = {
        "plan_version": 1,
        "tasks": [{"id": "task-a", "depends_on": [], "timeout_seconds": 30}],
        "final_task_id": "task-a",
    }
    calls: list[str] = []

    def recording_activity(name: str, result: Any) -> Callable[[dict[str, Any]], Any]:
        async def implementation(_: dict[str, Any]) -> Any:
            calls.append(name)
            return result

        return activity.defn(name=name)(implementation)

    activities = [
        recording_activity("agent.classify_contract", {}),
        recording_activity("agent.create_plan", plan),
        recording_activity("agent.authorize_plan", {}),
        recording_activity("agent.mark_executing", {}),
        recording_activity("agent.execute_task", {"summary": "done"}),
        recording_activity("agent.verify_run", {"verdict": "escalate"}),
        recording_activity("agent.revise_plan", plan),
        recording_activity("agent.list_actions", []),
        recording_activity("agent.finalize_run", {}),
        recording_activity("agent.cancel_run", {}),
        recording_activity("agent.fail_run", {}),
        recording_activity("agent.expire_actions", {}),
        recording_activity("agent.mark_waiting_approval", {}),
        recording_activity("agent.commit_action", {}),
    ]
    task_queue = f"test-agent-escalation-{uuid4()}"
    try:
        async with Worker(
            environment.client,
            task_queue=task_queue,
            workflows=[AgentRunWorkflow],
            activities=activities,
        ):
            result = await environment.client.execute_workflow(
                AgentRunWorkflow.run,
                StartRunCommand(
                    run_id=str(uuid4()),
                    tenant_id="tenant-a",
                    correlation_id="corr-escalation",
                ),
                id=f"agent-run-{uuid4()}",
                task_queue=task_queue,
            )

        assert result["status"] == "failed"
        assert result["reason"] == "VERIFICATION_ESCALATION_UNRESOLVED"
        assert "agent.fail_run" in calls
        assert "agent.list_actions" not in calls
        assert "agent.commit_action" not in calls
        assert "agent.finalize_run" not in calls
    finally:
        await environment.shutdown()
