from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest
from temporalio.worker import ActivityInboundInterceptor, ExecuteActivityInput

from agent_platform.infrastructure.observability.temporal_interceptors import (
    TemporalCapacityInterceptor,
)


class _Observer:
    def __init__(self) -> None:
        self.samples: list[tuple[str, float]] = []
        self.activities: list[tuple[str, str, float]] = []

    def record_capacity(self, *, resource: str, utilization_ratio: float) -> None:
        self.samples.append((resource, utilization_ratio))

    def record_activity(
        self,
        *,
        activity: str,
        status: str,
        duration_seconds: float,
    ) -> None:
        self.activities.append((activity, status, duration_seconds))


class _Activity(ActivityInboundInterceptor):
    def __init__(self, *, error: bool = False) -> None:
        self.error = error

    async def execute_activity(self, input: ExecuteActivityInput) -> Any:
        del input
        if self.error:
            raise RuntimeError("activity failed")
        return {"ok": True}


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [False, True])
async def test_capacity_interceptor_observes_entry_and_exit(error: bool) -> None:
    observer = _Observer()
    interceptor = TemporalCapacityInterceptor(
        observer,
        resource="agent-worker:activity",
        max_concurrent_activities=4,
    ).intercept_activity(_Activity(error=error))

    if error:
        with pytest.raises(RuntimeError, match="activity failed"):
            await interceptor.execute_activity(
                cast(ExecuteActivityInput, SimpleNamespace(fn=_Activity.execute_activity))
            )
    else:
        assert await interceptor.execute_activity(
            cast(ExecuteActivityInput, SimpleNamespace(fn=_Activity.execute_activity))
        ) == {"ok": True}

    assert observer.samples == [
        ("agent-worker:activity", 0.25),
        ("agent-worker:activity", 0.0),
    ]
    assert len(observer.activities) == 1
    activity_name, status, duration = observer.activities[0]
    assert activity_name == "execute_activity"
    assert status == ("failed" if error else "completed")
    assert duration >= 0


def test_capacity_interceptor_rejects_zero_capacity() -> None:
    with pytest.raises(ValueError, match="TEMPORAL_ACTIVITY_CAPACITY_INVALID"):
        TemporalCapacityInterceptor(
            _Observer(),
            resource="agent-worker:activity",
            max_concurrent_activities=0,
        )
