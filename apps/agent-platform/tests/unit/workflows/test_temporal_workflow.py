from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from agent_platform.workflows.temporal_starter import TemporalWorkflowStarter
from agent_platform.workflows.temporal_workflow import (
    COMMIT_RETRY_POLICY,
    STANDARD_RETRY_POLICY,
    AgentRunWorkflow,
    StartRunCommand,
)


@pytest.mark.asyncio
async def test_signals_and_query_expose_durable_control_state() -> None:
    agent_run = AgentRunWorkflow()

    await agent_run.pause("operator review")
    await agent_run.decide_action("action-1", "approved")
    paused = agent_run.summary()

    assert paused["paused"] is True
    assert paused["pause_reason"] == "operator review"
    assert paused["approval_decisions"] == {"action-1": "approved"}

    await agent_run.resume()
    await agent_run.cancel("user requested")
    cancelled = agent_run.summary()

    assert cancelled["paused"] is False
    assert cancelled["cancel_requested"] is True
    assert cancelled["cancel_reason"] == "user requested"


def test_start_command_rejects_invalid_tool_budget() -> None:
    with pytest.raises(ValueError, match="TOOL_BUDGET_INVALID"):
        StartRunCommand(
            run_id="run-1",
            tenant_id="tenant-a",
            correlation_id="corr-1",
            max_tool_calls=-1,
        )


def test_retry_policies_bound_probabilistic_work_and_never_retry_commit() -> None:
    assert STANDARD_RETRY_POLICY.maximum_attempts == 3
    assert COMMIT_RETRY_POLICY.maximum_attempts == 1


class FakeHandle:
    def __init__(self) -> None:
        self.signals: list[tuple[object, tuple[object, ...]]] = []

    async def signal(
        self,
        signal: object,
        *args: object,
        **kwargs: object,
    ) -> None:
        keyword_args = tuple(kwargs.get("args", ()))
        self.signals.append((signal, args or keyword_args))


class FakeClient:
    def __init__(self) -> None:
        self.started: list[tuple[object, object, dict[str, object]]] = []
        self.handles: dict[str, FakeHandle] = {}

    async def start_workflow(
        self, workflow: object, command: object, **options: object
    ) -> FakeHandle:
        self.started.append((workflow, command, options))
        handle = FakeHandle()
        self.handles[str(options["id"])] = handle
        return handle

    def get_workflow_handle(self, workflow_id: str) -> FakeHandle:
        return self.handles.setdefault(workflow_id, FakeHandle())


@pytest.mark.asyncio
async def test_starter_uses_stable_workflow_id_and_routes_signals() -> None:
    client = FakeClient()
    action_id = uuid4()
    run_id = uuid4()

    async def workflow_for_action(candidate: object, tenant_id: str) -> str:
        assert candidate == action_id
        assert tenant_id == "tenant-a"
        return f"agent-run-{run_id}"

    starter = TemporalWorkflowStarter(
        client=client,  # type: ignore[arg-type]
        task_queue="agent-runs",
        action_workflow_resolver=workflow_for_action,
    )

    await starter.start(
        run_id,
        "tenant-a",
        "corr-1",
        contract=SimpleNamespace(
            max_replans=1,
            max_duration_seconds=321,
            max_tool_calls=7,
        ),
    )
    await starter.pause(run_id, "tenant-a", "maintenance")
    await starter.resume(run_id, "tenant-a")
    await starter.cancel(run_id, "tenant-a", "stop")
    await starter.notify_action(action_id, "tenant-a", "approved")

    _, command, options = client.started[0]
    assert isinstance(command, StartRunCommand)
    assert command.max_replans == 1
    assert command.max_duration_seconds == 321
    assert command.max_tool_calls == 7
    assert options["id"] == f"agent-run-{run_id}"
    assert options["task_queue"] == "agent-runs"
    assert len(client.handles[f"agent-run-{run_id}"].signals) == 4
