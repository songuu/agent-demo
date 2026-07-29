from __future__ import annotations

from types import SimpleNamespace

import pytest
from google.protobuf.duration_pb2 import Duration
from prometheus_client import CollectorRegistry, generate_latest

from agent_platform.infrastructure.observability.metrics import PlatformMetrics
from agent_platform.infrastructure.observability.runtime import RuntimeObservability
from agent_platform.infrastructure.observability.temporal_metrics import (
    record_temporal_queue_metrics,
)


class _WorkflowService:
    def __init__(self) -> None:
        self.requests: list[object] = []

    async def describe_task_queue(self, request: object) -> object:
        self.requests.append(request)
        age = Duration(seconds=9)
        return SimpleNamespace(
            stats=SimpleNamespace(
                approximate_backlog_count=4,
                approximate_backlog_age=age,
            )
        )


@pytest.mark.asyncio
async def test_temporal_queue_metrics_use_describe_task_queue_stats() -> None:
    registry = CollectorRegistry()
    telemetry = RuntimeObservability(PlatformMetrics(registry), environment="test")
    service = _WorkflowService()

    await record_temporal_queue_metrics(
        SimpleNamespace(workflow_service=service),
        namespace="agent-platform-test",
        task_queues=("agent-runs",),
        observability=telemetry,
    )

    assert len(service.requests) == 2
    output = generate_latest(registry).decode()
    assert ('agent_queue_backlog{environment="test",queue="agent-runs:workflow"} 4.0') in output
    assert (
        'agent_queue_oldest_age_seconds{environment="test",queue="agent-runs:activity"} 9.0'
    ) in output
