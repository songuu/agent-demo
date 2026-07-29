from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from temporalio.api.enums.v1 import TaskQueueType
from temporalio.api.taskqueue.v1 import TaskQueue
from temporalio.api.workflowservice.v1 import DescribeTaskQueueRequest

from agent_platform.infrastructure.observability.runtime import RuntimeObservability


async def record_temporal_queue_metrics(
    client: Any,
    *,
    namespace: str,
    task_queues: Iterable[str],
    observability: RuntimeObservability,
) -> None:
    """Read Temporal's queue stats rather than inferring backlog from Run state."""

    for task_queue in sorted(set(task_queues)):
        for queue_kind, queue_type in (
            ("workflow", TaskQueueType.TASK_QUEUE_TYPE_WORKFLOW),
            ("activity", TaskQueueType.TASK_QUEUE_TYPE_ACTIVITY),
        ):
            response = await client.workflow_service.describe_task_queue(
                DescribeTaskQueueRequest(
                    namespace=namespace,
                    task_queue=TaskQueue(name=task_queue),
                    task_queue_type=queue_type,
                    report_stats=True,
                )
            )
            stats = response.stats
            oldest_age = stats.approximate_backlog_age.ToTimedelta().total_seconds()
            observability.record_queue_state(
                queue=f"{task_queue}:{queue_kind}",
                backlog=max(int(stats.approximate_backlog_count), 0),
                oldest_age_seconds=max(oldest_age, 0.0),
            )
