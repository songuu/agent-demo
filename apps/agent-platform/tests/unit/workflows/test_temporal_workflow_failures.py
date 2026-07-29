from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from temporalio.exceptions import ActivityError, ApplicationError

from agent_platform.workflows import temporal_workflow as workflow_module
from agent_platform.workflows.temporal_workflow import AgentRunWorkflow, StartRunCommand


def _command() -> StartRunCommand:
    return StartRunCommand(
        run_id="run-1",
        tenant_id="tenant-a",
        correlation_id="corr-1",
        max_duration_seconds=120,
    )


def _activity_error(error_type: str) -> ActivityError:
    error = ActivityError(
        "activity failed",
        scheduled_event_id=1,
        started_event_id=2,
        identity="worker-1",
        activity_type="test",
        activity_id="activity-1",
        retry_state=None,
    )
    error.__cause__ = ApplicationError("typed failure", type=error_type)
    return error


@pytest.mark.asyncio
async def test_budget_activity_failure_marks_run_failed_without_rethrowing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    async def fail_steps(command: StartRunCommand) -> dict[str, Any]:
        del command
        raise _activity_error("BUDGET_EXHAUSTED")

    async def execute_activity(
        name: str,
        payload: dict[str, Any],
        **_: Any,
    ) -> dict[str, Any]:
        calls.append((name, payload))
        return {}

    agent_run = AgentRunWorkflow()
    monkeypatch.setattr(agent_run, "_run_steps", fail_steps)
    monkeypatch.setattr(workflow_module.workflow, "execute_activity", execute_activity)

    result = await agent_run.run(_command())

    assert result["status"] == "failed"
    assert result["reason"] == "BUDGET_EXHAUSTED"
    assert calls == [
        (
            "agent.fail_run",
            {
                "run_id": "run-1",
                "tenant_id": "tenant-a",
                "correlation_id": "corr-1",
                "reason": "BUDGET_EXHAUSTED",
            },
        )
    ]


@pytest.mark.asyncio
async def test_non_budget_activity_failure_is_rethrown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fail_steps(command: StartRunCommand) -> dict[str, Any]:
        del command
        raise _activity_error("MODEL_PROVIDER_UNAVAILABLE")

    agent_run = AgentRunWorkflow()
    monkeypatch.setattr(agent_run, "_run_steps", fail_steps)

    with pytest.raises(ActivityError):
        await agent_run.run(_command())


@pytest.mark.asyncio
async def test_approved_action_is_committed_on_isolated_queue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    plan = {
        "plan_version": 1,
        "tasks": [{"id": "final", "depends_on": [], "max_tool_calls": 0}],
    }

    async def execute_activity(
        name: str,
        payload: dict[str, Any],
        **options: Any,
    ) -> Any:
        calls.append((name, payload, options))
        if name == "agent.create_plan":
            return plan
        if name == "agent.execute_task":
            return {"summary": "ready"}
        if name == "agent.verify_run":
            return {"verdict": "pass"}
        if name == "agent.list_actions":
            return [{"action_id": "action-2", "status": "approved"}]
        return {}

    monkeypatch.setattr(workflow_module.workflow, "patched", lambda _: True)
    monkeypatch.setattr(workflow_module.workflow, "execute_activity", execute_activity)
    monkeypatch.setattr(
        workflow_module.workflow,
        "now",
        lambda: datetime(2026, 7, 24, tzinfo=UTC),
    )

    result = await AgentRunWorkflow().run(_command())

    commit = next(call for call in calls if call[0] == "agent.commit_action")
    assert result["status"] == "completed"
    assert commit[1]["action_id"] == "action-2"
    assert commit[2]["task_queue"] == "agent-commits"
    assert commit[2]["activity_id"] == "commit-action-2"
    assert commit[2]["retry_policy"].maximum_attempts == 1


@pytest.mark.asyncio
async def test_commit_failure_persists_exact_activity_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = {
        "plan_version": 1,
        "tasks": [{"id": "final", "depends_on": [], "max_tool_calls": 0}],
    }
    failures: list[str] = []

    async def execute_activity(
        name: str,
        payload: dict[str, Any],
        **_: Any,
    ) -> Any:
        if name == "agent.create_plan":
            return plan
        if name == "agent.execute_task":
            return {"summary": "ready"}
        if name == "agent.verify_run":
            return {"verdict": "pass"}
        if name == "agent.list_actions":
            return [{"action_id": "action-3", "status": "approved"}]
        if name == "agent.commit_action":
            raise _activity_error("COMMIT_RESULT_UNKNOWN")
        if name == "agent.fail_run":
            failures.append(str(payload["reason"]))
        return {}

    monkeypatch.setattr(workflow_module.workflow, "patched", lambda _: True)
    monkeypatch.setattr(workflow_module.workflow, "execute_activity", execute_activity)
    monkeypatch.setattr(
        workflow_module.workflow,
        "now",
        lambda: datetime(2026, 7, 24, tzinfo=UTC),
    )

    result = await AgentRunWorkflow().run(_command())

    assert result["status"] == "failed"
    assert result["reason"] == "COMMIT_RESULT_UNKNOWN"
    assert failures == ["COMMIT_RESULT_UNKNOWN"]


@pytest.mark.asyncio
async def test_pending_approval_signal_unblocks_and_rejection_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, Any]]] = []
    agent_run = AgentRunWorkflow()

    async def execute_activity(
        name: str,
        payload: dict[str, Any],
        **_: Any,
    ) -> dict[str, Any]:
        calls.append((name, payload))
        return {}

    async def reject(predicate: Any, **_: Any) -> None:
        await agent_run.decide_action("action-4", "REJECTED")
        assert predicate() is True

    monkeypatch.setattr(workflow_module.workflow, "execute_activity", execute_activity)
    monkeypatch.setattr(workflow_module.workflow, "wait_condition", reject)
    monkeypatch.setattr(
        workflow_module.workflow,
        "now",
        lambda: datetime(2026, 7, 24, tzinfo=UTC),
    )

    approved = await agent_run._await_approvals(
        _command(),
        [{"action_id": "action-4", "status": "pending_approval"}],
    )

    assert approved is False
    assert calls[-1][0] == "agent.fail_run"
    assert calls[-1][1]["reason"] == "ACTION_REJECTED"


@pytest.mark.asyncio
async def test_cancelled_plan_batch_stops_before_dependent_task(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent_run = AgentRunWorkflow()
    calls: list[str] = []

    async def execute_activity(
        name: str,
        payload: dict[str, Any],
        **_: Any,
    ) -> dict[str, Any]:
        calls.append(str(payload["task"]["id"]))
        agent_run.cancel_requested = True
        return {"summary": name}

    monkeypatch.setattr(workflow_module.workflow, "execute_activity", execute_activity)

    outputs = await agent_run._execute_plan(
        _command(),
        {
            "plan_version": 1,
            "tasks": [
                {"id": "first", "depends_on": [], "max_tool_calls": 0},
                {"id": "second", "depends_on": ["first"], "max_tool_calls": 0},
            ],
        },
    )

    assert calls == ["first"]
    assert outputs == {"first": {"summary": "agent.execute_task"}}
