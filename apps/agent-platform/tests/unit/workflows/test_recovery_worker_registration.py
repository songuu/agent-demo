from __future__ import annotations

from typing import Any

from agent_platform.workflows import worker as worker_module
from agent_platform.workflows.activities import ActivityDependencies
from agent_platform.workflows.recovery_workflow import ActionRecoveryWorkflow
from agent_platform.workflows.temporal_workflow import AgentRunWorkflow


def test_recovery_workflow_is_registered_only_by_commit_worker(
    monkeypatch: Any,
) -> None:
    registrations: list[dict[str, Any]] = []

    class _Worker:
        def __init__(self, client: object, **kwargs: Any) -> None:
            del client
            registrations.append(kwargs)

    monkeypatch.setattr(worker_module, "Worker", _Worker)
    dependencies = ActivityDependencies(None, None, None, None, None)

    worker_module.build_agent_worker(
        client=object(),  # type: ignore[arg-type]
        task_queue="agent-runs",
        dependencies=dependencies,
    )
    worker_module.build_commit_worker(
        client=object(),  # type: ignore[arg-type]
        task_queue="agent-commits",
        dependencies=dependencies,
    )

    assert registrations[0]["workflows"] == [AgentRunWorkflow]
    assert registrations[1]["workflows"] == [ActionRecoveryWorkflow]
    assert ActionRecoveryWorkflow not in registrations[0]["workflows"]
