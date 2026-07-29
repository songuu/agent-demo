from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
from temporalio import activity
from temporalio.exceptions import ApplicationError
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Replayer, Worker

from agent_platform.workflows.temporal_workflow import AgentRunWorkflow, StartRunCommand

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_budget_exhaustion_marks_run_failed_without_starting_another_step() -> None:
    try:
        environment = await WorkflowEnvironment.start_time_skipping()
    except RuntimeError as exc:
        pytest.skip(f"Temporal time-skipping server unavailable: {exc}")

    @activity.defn(name="agent.classify_contract")
    async def classify(_: dict[str, Any]) -> dict[str, Any]:
        return {"status": "classified"}

    model_calls = 0

    @activity.defn(name="agent.create_plan")
    async def create_plan(_: dict[str, Any]) -> dict[str, Any]:
        nonlocal model_calls
        model_calls += 1
        raise ApplicationError(
            "actual cost reached the hard limit",
            type="BUDGET_EXHAUSTED",
            non_retryable=True,
        )

    failures: list[dict[str, Any]] = []

    @activity.defn(name="agent.fail_run")
    async def fail_run(payload: dict[str, Any]) -> dict[str, Any]:
        failures.append(payload)
        return {"status": "failed"}

    task_queue = f"test-budget-stop-{uuid4()}"
    run_id = str(uuid4())
    try:
        async with Worker(
            environment.client,
            task_queue=task_queue,
            workflows=[AgentRunWorkflow],
            activities=[classify, create_plan, fail_run],
        ):
            handle = await environment.client.start_workflow(
                AgentRunWorkflow.run,
                StartRunCommand(
                    run_id=run_id,
                    tenant_id="tenant-a",
                    correlation_id="corr-1",
                ),
                id=f"agent-run-{uuid4()}",
                task_queue=task_queue,
            )
            result = await handle.result()
            history = await handle.fetch_history()
            replay = await Replayer(workflows=[AgentRunWorkflow]).replay_workflow(history)

        assert result["status"] == "failed"
        assert result["reason"] == "BUDGET_EXHAUSTED"
        assert model_calls == 1
        assert failures == [
            {
                "run_id": run_id,
                "tenant_id": "tenant-a",
                "correlation_id": "corr-1",
                "reason": "BUDGET_EXHAUSTED",
            }
        ]
        assert replay.replay_failure is None
    finally:
        await environment.shutdown()
