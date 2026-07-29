from __future__ import annotations

from typing import Any

from agent_platform.workflows import worker as worker_module
from agent_platform.workflows.activities import ActivityDependencies


def test_temporal_workers_apply_the_configured_activity_limit(
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
        max_concurrent_activities=17,
    )
    worker_module.build_commit_worker(
        client=object(),  # type: ignore[arg-type]
        task_queue="agent-commits",
        dependencies=dependencies,
        max_concurrent_activities=3,
    )

    assert registrations[0]["max_concurrent_activities"] == 17
    assert registrations[1]["max_concurrent_activities"] == 3
