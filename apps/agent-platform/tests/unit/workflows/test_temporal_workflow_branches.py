from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from temporalio.exceptions import ApplicationError

from agent_platform.workflows import temporal_workflow as workflow_module
from agent_platform.workflows.temporal_workflow import AgentRunWorkflow, StartRunCommand


def _command(**overrides: Any) -> StartRunCommand:
    values: dict[str, Any] = {
        "run_id": "run-1",
        "tenant_id": "tenant-a",
        "correlation_id": "corr-1",
        "max_duration_seconds": 120,
    }
    values.update(overrides)
    return StartRunCommand(**values)


@pytest.mark.parametrize("status", ["rejected", "expired", "cancelled"])
@pytest.mark.asyncio
async def test_existing_terminal_non_approved_action_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    status: str,
) -> None:
    activity_calls: list[tuple[str, dict[str, Any]]] = []

    async def execute_activity(
        name: str,
        payload: dict[str, Any],
        **_: Any,
    ) -> dict[str, Any]:
        activity_calls.append((name, payload))
        return {}

    monkeypatch.setattr(workflow_module.workflow, "execute_activity", execute_activity)
    monkeypatch.setattr(
        workflow_module.workflow,
        "now",
        lambda: datetime(2026, 7, 24, tzinfo=UTC),
    )
    agent_run = AgentRunWorkflow()

    approved = await agent_run._await_approvals(
        _command(),
        [{"action_id": "action-1", "status": status}],
    )

    assert approved is False
    assert agent_run.phase == "failed"
    fail_payload = next(payload for name, payload in activity_calls if name == "agent.fail_run")
    assert fail_payload["reason"] == "ACTION_NOT_APPROVED"


@pytest.mark.asyncio
async def test_existing_approved_action_passes_without_waiting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    activity_names: list[str] = []

    async def execute_activity(
        name: str,
        payload: dict[str, Any],
        **_: Any,
    ) -> dict[str, Any]:
        del payload
        activity_names.append(name)
        return {}

    async def fail_if_waited(*_: Any, **__: Any) -> None:
        raise AssertionError("an already-approved action must not wait for a signal")

    monkeypatch.setattr(workflow_module.workflow, "execute_activity", execute_activity)
    monkeypatch.setattr(workflow_module.workflow, "wait_condition", fail_if_waited)
    monkeypatch.setattr(
        workflow_module.workflow,
        "now",
        lambda: datetime(2026, 7, 24, tzinfo=UTC),
    )
    agent_run = AgentRunWorkflow()

    approved = await agent_run._await_approvals(
        _command(),
        [{"action_id": "action-1", "status": "approved"}],
    )

    assert approved is True
    assert agent_run.approval_decisions == {"action-1": "approved"}
    assert activity_names == ["agent.mark_waiting_approval"]


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"run_id": ""}, "IDENTIFIERS_REQUIRED"),
        ({"tenant_id": ""}, "IDENTIFIERS_REQUIRED"),
        ({"correlation_id": ""}, "IDENTIFIERS_REQUIRED"),
        ({"commit_task_queue": " "}, "IDENTIFIERS_REQUIRED"),
        ({"max_replans": -1}, "MAX_REPLANS_INVALID"),
        ({"max_replans": 6}, "MAX_REPLANS_INVALID"),
        ({"max_duration_seconds": 4}, "DURATION_INVALID"),
        ({"max_duration_seconds": 86_401}, "DURATION_INVALID"),
        ({"max_tool_calls": 10_001}, "TOOL_BUDGET_INVALID"),
        ({"approval_timeout_seconds": 0}, "APPROVAL_TIMEOUT_INVALID"),
        ({"approval_timeout_seconds": 86_401}, "APPROVAL_TIMEOUT_INVALID"),
    ],
)
def test_start_command_rejects_invalid_bounds(
    overrides: dict[str, Any],
    error: str,
) -> None:
    with pytest.raises(ValueError, match=error):
        _command(**overrides)


@pytest.mark.asyncio
@pytest.mark.parametrize("decision", ["maybe", "expired"])
async def test_invalid_approval_signal_is_ignored(decision: str) -> None:
    agent_run = AgentRunWorkflow()

    await agent_run.decide_action("action-1", decision)

    assert agent_run.approval_decisions == {}


@pytest.mark.asyncio
async def test_execute_plan_runs_dependency_batches_with_bounded_activity_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, Any], dict[str, Any]]] = []

    async def execute_activity(
        name: str,
        payload: dict[str, Any],
        **options: Any,
    ) -> dict[str, Any]:
        calls.append((name, payload, options))
        return {"summary": str(payload["task"]["id"])}

    monkeypatch.setattr(workflow_module.workflow, "execute_activity", execute_activity)
    plan = {
        "plan_version": 3,
        "tasks": [
            {
                "id": "collect",
                "depends_on": [],
                "timeout_seconds": 12,
                "max_tool_calls": 1,
            },
            {
                "id": "synthesize",
                "depends_on": ["collect"],
                "timeout_seconds": 20,
                "max_tool_calls": 1,
            },
        ],
    }

    outputs = await AgentRunWorkflow()._execute_plan(_command(), plan)

    assert outputs == {
        "collect": {"summary": "collect"},
        "synthesize": {"summary": "synthesize"},
    }
    assert calls[1][1]["dependencies"] == {
        "collect": {"summary": "collect"},
    }
    assert calls[0][2]["activity_id"] == "task-3-collect"
    assert calls[1][2]["activity_id"] == "task-3-synthesize"
    assert calls[0][2]["heartbeat_timeout"] == timedelta(seconds=15)


@pytest.mark.parametrize(
    ("plan", "error"),
    [
        ({"plan_version": 1, "tasks": []}, "TEMPORAL_PLAN_HAS_NO_TASKS"),
        (
            {
                "plan_version": 1,
                "tasks": [
                    {
                        "id": "too-expensive",
                        "depends_on": [],
                        "max_tool_calls": 101,
                    }
                ],
            },
            "BUDGET_EXHAUSTED",
        ),
        (
            {
                "plan_version": 1,
                "tasks": [
                    {
                        "id": "left",
                        "depends_on": ["right"],
                        "max_tool_calls": 0,
                    },
                    {
                        "id": "right",
                        "depends_on": ["left"],
                        "max_tool_calls": 0,
                    },
                ],
            },
            "TEMPORAL_PLAN_DEPENDENCY_CYCLE",
        ),
    ],
)
@pytest.mark.asyncio
async def test_execute_plan_rejects_invalid_or_unbounded_dags(
    plan: dict[str, Any],
    error: str,
) -> None:
    with pytest.raises(ValueError, match=error):
        await AgentRunWorkflow()._execute_plan(
            _command(max_tool_calls=100),
            plan,
        )


@pytest.mark.asyncio
async def test_successful_run_replays_patch_and_finalizes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    plan = {
        "plan_version": 1,
        "tasks": [
            {
                "id": "final",
                "depends_on": [],
                "timeout_seconds": 30,
                "max_tool_calls": 1,
            }
        ],
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
            return {"summary": "done"}
        if name == "agent.verify_run":
            return {"verdict": "pass"}
        if name == "agent.list_actions":
            return []
        return {}

    monkeypatch.setattr(workflow_module.workflow, "patched", lambda _: True)
    monkeypatch.setattr(workflow_module.workflow, "execute_activity", execute_activity)

    result = await AgentRunWorkflow().run(_command())

    assert result == {
        "status": "completed",
        "run_id": "run-1",
        "replan_count": 0,
        "workflow_version": workflow_module.WORKFLOW_PATCH_ID,
    }
    assert [name for name, _, _ in calls] == [
        "agent.classify_contract",
        "agent.create_plan",
        "agent.authorize_plan",
        "agent.mark_executing",
        "agent.execute_task",
        "agent.verify_run",
        "agent.list_actions",
        "agent.finalize_run",
    ]


@pytest.mark.asyncio
async def test_revise_is_bounded_and_fails_after_max_replans(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = {
        "plan_version": 1,
        "tasks": [{"id": "final", "depends_on": [], "max_tool_calls": 0}],
    }
    fail_reasons: list[str] = []

    async def execute_activity(
        name: str,
        payload: dict[str, Any],
        **_: Any,
    ) -> Any:
        if name == "agent.create_plan":
            return plan
        if name == "agent.execute_task":
            return {"summary": "incomplete"}
        if name == "agent.verify_run":
            return {"verdict": "revise"}
        if name == "agent.revise_plan":
            return {**plan, "plan_version": 2}
        if name == "agent.fail_run":
            fail_reasons.append(str(payload["reason"]))
        return {}

    monkeypatch.setattr(workflow_module.workflow, "patched", lambda _: False)
    monkeypatch.setattr(workflow_module.workflow, "execute_activity", execute_activity)

    result = await AgentRunWorkflow().run(_command(max_replans=1))

    assert result == {
        "status": "failed",
        "reason": "MAX_REPLANS_EXHAUSTED",
        "replan_count": 1,
        "workflow_version": "legacy",
    }
    assert fail_reasons == ["MAX_REPLANS_EXHAUSTED"]


@pytest.mark.asyncio
async def test_non_pass_verification_fails_without_finalizing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = {
        "plan_version": 1,
        "tasks": [{"id": "final", "depends_on": [], "max_tool_calls": 0}],
    }
    names: list[str] = []

    async def execute_activity(
        name: str,
        payload: dict[str, Any],
        **_: Any,
    ) -> Any:
        del payload
        names.append(name)
        if name == "agent.create_plan":
            return plan
        if name == "agent.execute_task":
            return {"summary": "unsafe"}
        if name == "agent.verify_run":
            return {"verdict": "escalate"}
        return {}

    monkeypatch.setattr(workflow_module.workflow, "patched", lambda _: True)
    monkeypatch.setattr(workflow_module.workflow, "execute_activity", execute_activity)

    result = await AgentRunWorkflow().run(_command())

    assert result["reason"] == "VERIFICATION_ESCALATION_UNRESOLVED"
    assert "agent.fail_run" in names
    assert "agent.finalize_run" not in names


@pytest.mark.asyncio
async def test_approval_timeout_expires_actions_and_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    activity_names: list[str] = []

    async def execute_activity(
        name: str,
        payload: dict[str, Any],
        **_: Any,
    ) -> dict[str, Any]:
        del payload
        activity_names.append(name)
        if name == "agent.expire_actions":
            return {
                "expired": 1,
                "statuses": {"action-1": "expired"},
            }
        return {}

    async def timeout(*_: Any, **__: Any) -> None:
        raise TimeoutError

    monkeypatch.setattr(workflow_module.workflow, "execute_activity", execute_activity)
    monkeypatch.setattr(
        workflow_module.workflow,
        "now",
        lambda: datetime(2026, 7, 24, tzinfo=UTC),
    )
    monkeypatch.setattr(workflow_module.workflow, "wait_condition", timeout)

    result = await AgentRunWorkflow()._await_approvals(
        _command(approval_timeout_seconds=1),
        [{"action_id": "action-1", "status": "pending_approval"}],
    )

    assert result is False
    assert activity_names == [
        "agent.mark_waiting_approval",
        "agent.expire_actions",
        "agent.fail_run",
    ]


@pytest.mark.asyncio
async def test_approval_winning_the_timeout_race_remains_committable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    activity_names: list[str] = []

    async def execute_activity(
        name: str,
        payload: dict[str, Any],
        **_: Any,
    ) -> dict[str, Any]:
        del payload
        activity_names.append(name)
        if name == "agent.expire_actions":
            return {
                "expired": 0,
                "statuses": {"action-1": "approved"},
            }
        return {}

    async def timeout(*_: Any, **__: Any) -> None:
        raise TimeoutError

    monkeypatch.setattr(workflow_module.workflow, "execute_activity", execute_activity)
    monkeypatch.setattr(
        workflow_module.workflow,
        "now",
        lambda: datetime(2026, 7, 24, tzinfo=UTC),
    )
    monkeypatch.setattr(workflow_module.workflow, "wait_condition", timeout)

    agent_run = AgentRunWorkflow()
    result = await agent_run._await_approvals(
        _command(approval_timeout_seconds=1),
        [{"action_id": "action-1", "status": "pending_approval"}],
    )

    assert result is True
    assert agent_run.approval_decisions == {"action-1": "approved"}
    assert activity_names == [
        "agent.mark_waiting_approval",
        "agent.expire_actions",
    ]


@pytest.mark.asyncio
async def test_control_gate_cancels_before_or_after_pause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reasons: list[str] = []

    async def execute_activity(
        name: str,
        payload: dict[str, Any],
        **_: Any,
    ) -> dict[str, Any]:
        assert name == "agent.cancel_run"
        reasons.append(str(payload["reason"]))
        return {}

    async def resume_as_cancelled(predicate: Any, **_: Any) -> None:
        paused.cancel_requested = True
        assert predicate() is True

    monkeypatch.setattr(workflow_module.workflow, "execute_activity", execute_activity)

    immediate = AgentRunWorkflow()
    await immediate.cancel("")
    assert await immediate._control_gate(_command()) is False

    paused = AgentRunWorkflow()
    await paused.pause("")
    monkeypatch.setattr(workflow_module.workflow, "wait_condition", resume_as_cancelled)
    assert await paused._control_gate(_command()) is False

    assert reasons == ["cancel requested", "RUN_CANCELLED"]


def test_activity_failure_reason_walks_nested_causes_and_falls_back() -> None:
    nested = RuntimeError("outer")
    nested.__cause__ = ApplicationError("budget", type="BUDGET_EXHAUSTED")

    assert (
        AgentRunWorkflow._activity_failure_reason(nested, fallback="FAILED") == "BUDGET_EXHAUSTED"
    )
    assert (
        AgentRunWorkflow._activity_failure_reason(
            RuntimeError("no typed cause"),
            fallback="FAILED",
        )
        == "FAILED"
    )
