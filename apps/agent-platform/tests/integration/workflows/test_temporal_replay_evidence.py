from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any
from uuid import uuid4

import pytest
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from agent_platform.workflows.temporal_workflow import AgentRunWorkflow, StartRunCommand
from tests.integration.workflows.history_evidence import persist_history

pytestmark = pytest.mark.integration


def _activity(name: str, result: Any) -> Callable[[dict[str, Any]], Any]:
    async def implementation(_: dict[str, Any]) -> Any:
        return result

    return activity.defn(name=name)(implementation)


@pytest.mark.asyncio
async def test_exports_multiple_real_agent_histories_for_release_replay() -> None:
    try:
        environment = await WorkflowEnvironment.start_time_skipping()
    except RuntimeError as exc:
        pytest.skip(f"Temporal time-skipping server unavailable: {exc}")

    plan = {
        "plan_version": 1,
        "tasks": [{"id": "task-a", "depends_on": [], "timeout_seconds": 30}],
        "final_task_id": "task-a",
    }
    activities = [
        _activity("agent.classify_contract", {}),
        _activity("agent.create_plan", plan),
        _activity("agent.authorize_plan", {}),
        _activity("agent.mark_executing", {}),
        _activity("agent.execute_task", {"summary": "done"}),
        _activity("agent.verify_run", {"verdict": "pass"}),
        _activity("agent.revise_plan", plan),
        _activity("agent.list_actions", []),
        _activity("agent.finalize_run", {}),
        _activity("agent.cancel_run", {}),
        _activity("agent.fail_run", {}),
        _activity("agent.expire_actions", {}),
        _activity("agent.mark_waiting_approval", {}),
        _activity("agent.commit_action", {}),
    ]
    task_queue = f"test-replay-evidence-{uuid4()}"
    exported = []
    try:
        async with Worker(
            environment.client,
            task_queue=task_queue,
            workflows=[AgentRunWorkflow],
            activities=activities,
        ):
            for case_number in range(2):
                handle = await environment.client.start_workflow(
                    AgentRunWorkflow.run,
                    StartRunCommand(
                        run_id=str(uuid4()),
                        tenant_id="tenant-replay",
                        correlation_id=f"replay-evidence-{case_number}",
                    ),
                    id=f"agent-replay-evidence-{uuid4()}",
                    task_queue=task_queue,
                )
                result = await handle.result()
                history = await handle.fetch_history()
                exported.append(persist_history(history, workflow_type="AgentRunWorkflow"))
                assert result["status"] == "completed"
    finally:
        await environment.shutdown()

    if "AGENT_WORKFLOW_HISTORY_DIR" in os.environ:
        assert all(path is not None and path.is_file() for path in exported)
