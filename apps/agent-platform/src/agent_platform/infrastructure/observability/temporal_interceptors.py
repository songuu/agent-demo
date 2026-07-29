from __future__ import annotations

from time import perf_counter
from typing import Any, Protocol

from temporalio.worker import (
    ActivityInboundInterceptor,
    ExecuteActivityInput,
    Interceptor,
)


class CapacityObserver(Protocol):
    def record_capacity(self, *, resource: str, utilization_ratio: float) -> None: ...

    def record_activity(
        self,
        *,
        activity: str,
        status: str,
        duration_seconds: float,
    ) -> None: ...


class TemporalCapacityInterceptor(Interceptor):
    """Observe real Activity-slot utilization at the worker execution boundary."""

    def __init__(
        self,
        observability: CapacityObserver,
        *,
        resource: str,
        max_concurrent_activities: int,
    ) -> None:
        if max_concurrent_activities < 1:
            raise ValueError("TEMPORAL_ACTIVITY_CAPACITY_INVALID")
        self._observability = observability
        self._resource = resource
        self._capacity = max_concurrent_activities
        self._active = 0

    def intercept_activity(
        self,
        next: ActivityInboundInterceptor,
    ) -> ActivityInboundInterceptor:
        return _CapacityActivityInboundInterceptor(next, self)

    def _entered(self) -> None:
        self._active += 1
        self._observe()

    def _exited(self) -> None:
        self._active = max(self._active - 1, 0)
        self._observe()

    def _observe(self) -> None:
        self._observability.record_capacity(
            resource=self._resource,
            utilization_ratio=self._active / self._capacity,
        )


class _CapacityActivityInboundInterceptor(ActivityInboundInterceptor):
    def __init__(
        self,
        next: ActivityInboundInterceptor,
        capacity: TemporalCapacityInterceptor,
    ) -> None:
        super().__init__(next)
        self._capacity = capacity

    async def execute_activity(self, input: ExecuteActivityInput) -> Any:
        self._capacity._entered()
        started = perf_counter()
        status = "failed"
        try:
            result = await self.next.execute_activity(input)
            status = "completed"
            return result
        finally:
            definition = getattr(input.fn, "__temporal_activity_definition", None)
            activity_name = getattr(definition, "name", None) or input.fn.__name__
            self._capacity._observability.record_activity(
                activity=activity_name,
                status=status,
                duration_seconds=perf_counter() - started,
            )
            self._capacity._exited()
