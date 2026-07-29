"""Role-specific Temporal workers with process and queue isolation."""

from __future__ import annotations

import asyncio
import os
import sys
import traceback
from collections.abc import Callable, Coroutine, Mapping, Sequence
from datetime import timedelta
from typing import Any, Protocol

from opentelemetry.trace import Tracer
from prometheus_client import CollectorRegistry
from temporalio.client import Client
from temporalio.contrib.opentelemetry import TracingInterceptor
from temporalio.worker import Interceptor, Worker

from agent_platform.config import Settings
from agent_platform.infrastructure.observability.temporal_interceptors import (
    TemporalCapacityInterceptor,
)
from agent_platform.infrastructure.observability.tracing import configure_tracing
from agent_platform.workflows.activities import (
    ActivityDependencies,
    TemporalActivities,
)
from agent_platform.workflows.health_server import WorkerHealthServer
from agent_platform.workflows.recovery_workflow import ActionRecoveryWorkflow
from agent_platform.workflows.temporal_workflow import AgentRunWorkflow


class WorkerProcessResources(Protocol):
    dependencies: ActivityDependencies
    metrics_registry: CollectorRegistry

    async def healthcheck(self) -> Mapping[str, str]: ...
    async def aclose(self) -> None: ...


async def connect_client(settings: Settings, *, tracer: Tracer | None = None) -> Client:
    api_key = settings.temporal_api_key.get_secret_value() or None
    return await Client.connect(
        settings.temporal_address,
        namespace=settings.temporal_namespace,
        api_key=api_key,
        tls=settings.temporal_tls,
        interceptors=(TracingInterceptor(tracer),),
    )


def agent_activity_handlers(dependencies: ActivityDependencies) -> Sequence[Any]:
    bridge = TemporalActivities(dependencies)
    return (
        bridge.classify_contract,
        bridge.create_plan,
        bridge.authorize_plan,
        bridge.mark_executing,
        bridge.execute_task,
        bridge.verify_run,
        bridge.revise_plan,
        bridge.list_actions,
        bridge.mark_waiting_approval,
        bridge.expire_actions,
        bridge.finalize_run,
        bridge.cancel_run,
        bridge.fail_run,
    )


def commit_activity_handlers(dependencies: ActivityDependencies) -> Sequence[Any]:
    bridge = TemporalActivities(dependencies)
    return (
        bridge.commit_action,
        bridge.reconcile_action,
        bridge.compensate_action,
    )


def build_agent_worker(
    *,
    client: Client,
    task_queue: str,
    dependencies: ActivityDependencies,
    build_id: str | None = None,
    max_concurrent_activities: int = 20,
) -> Worker:
    return Worker(
        client,
        task_queue=task_queue,
        workflows=[AgentRunWorkflow],
        activities=agent_activity_handlers(dependencies),
        max_concurrent_activities=max_concurrent_activities,
        interceptors=_capacity_interceptors(
            dependencies,
            resource="agent-worker:activity",
            max_concurrent_activities=max_concurrent_activities,
        ),
        graceful_shutdown_timeout=timedelta(seconds=30),
        **_versioning_options(build_id),
    )


def build_commit_worker(
    *,
    client: Client,
    task_queue: str,
    dependencies: ActivityDependencies,
    build_id: str | None = None,
    max_concurrent_activities: int = 20,
) -> Worker:
    return Worker(
        client,
        task_queue=task_queue,
        workflows=[ActionRecoveryWorkflow],
        activities=commit_activity_handlers(dependencies),
        max_concurrent_activities=max_concurrent_activities,
        interceptors=_capacity_interceptors(
            dependencies,
            resource="commit-worker:activity",
            max_concurrent_activities=max_concurrent_activities,
        ),
        graceful_shutdown_timeout=timedelta(seconds=60),
        **_versioning_options(build_id),
    )


def _capacity_interceptors(
    dependencies: ActivityDependencies,
    *,
    resource: str,
    max_concurrent_activities: int,
) -> tuple[Interceptor, ...]:
    if dependencies.observability is None:
        return ()
    return (
        TemporalCapacityInterceptor(
            dependencies.observability,
            resource=resource,
            max_concurrent_activities=max_concurrent_activities,
        ),
    )


def _versioning_options(build_id: str | None) -> dict[str, Any]:
    if build_id and build_id != "development":
        return {"build_id": build_id, "use_worker_versioning": True}
    return {}


async def run_agent_worker(
    settings: Settings,
    client: Client,
    resources: WorkerProcessResources,
) -> None:
    worker = build_agent_worker(
        client=client,
        task_queue=settings.temporal_task_queue,
        dependencies=resources.dependencies,
        build_id=(
            settings.release_git_sha if settings.temporal_worker_versioning_enabled else None
        ),
        max_concurrent_activities=settings.max_concurrent_activities,
    )
    await _run_with_health(settings, worker, resources)


async def run_commit_worker(
    settings: Settings,
    client: Client,
    resources: WorkerProcessResources,
) -> None:
    worker = build_commit_worker(
        client=client,
        task_queue=settings.temporal_commit_task_queue,
        dependencies=resources.dependencies,
        build_id=(
            settings.release_git_sha if settings.temporal_worker_versioning_enabled else None
        ),
        max_concurrent_activities=settings.max_concurrent_activities,
    )
    await _run_with_health(settings, worker, resources)


async def _run_with_health(
    settings: Settings,
    worker: Worker,
    resources: WorkerProcessResources,
) -> None:
    health = WorkerHealthServer(
        dependency_check=resources.healthcheck,
        registry=resources.metrics_registry,
        health_port=settings.worker_health_port,
        metrics_port=settings.worker_metrics_port,
    )
    await health.start()
    run_task = asyncio.create_task(worker.run())
    try:
        # Worker.is_running changes only after the SDK's namespace validation.
        # Keep readiness false until that validation has actually completed.
        while not worker.is_running:
            done, _ = await asyncio.wait({run_task}, timeout=0.1)
            if done:
                await run_task
                raise RuntimeError("TEMPORAL_WORKER_STOPPED_BEFORE_START")
        health.ready = True
        await run_task
    finally:
        health.ready = False
        await health.aclose()
        await resources.aclose()


async def _agent_main() -> None:
    settings = Settings(process_role="agent-worker")
    trace_provider = configure_tracing(
        service_name=f"{settings.service_name}-agent-worker",
        environment=settings.environment,
        endpoint=settings.otlp_endpoint,
        capture_content=settings.trace_content_capture,
        set_global=False,
    )
    try:
        client = await connect_client(
            settings,
            tracer=trace_provider.get_tracer("agent_platform.temporal"),
        )
        from agent_platform.bootstrap import build_agent_worker_process

        resources = await build_agent_worker_process(
            settings,
            client,
            configured_trace_provider=trace_provider,
        )
    except Exception:
        trace_provider.shutdown()
        raise
    await run_agent_worker(settings, client, resources)


async def _commit_main() -> None:
    settings = Settings(process_role="commit-worker")
    trace_provider = configure_tracing(
        service_name=f"{settings.service_name}-commit-worker",
        environment=settings.environment,
        endpoint=settings.otlp_endpoint,
        capture_content=settings.trace_content_capture,
        set_global=False,
    )
    try:
        client = await connect_client(
            settings,
            tracer=trace_provider.get_tracer("agent_platform.temporal"),
        )
        from agent_platform.bootstrap import build_commit_worker_process

        resources = await build_commit_worker_process(
            settings,
            client,
            configured_trace_provider=trace_provider,
        )
    except Exception:
        trace_provider.shutdown()
        raise
    await run_commit_worker(settings, client, resources)


def agent_main() -> None:
    _run_worker_entrypoint(_agent_main)


def commit_main() -> None:
    _run_worker_entrypoint(_commit_main)


def _run_worker_entrypoint(
    main: Callable[[], Coroutine[Any, Any, None]],
) -> None:
    try:
        asyncio.run(main())
    except Exception:
        traceback.print_exc()
        sys.stderr.flush()
        # Temporal's native bridge can keep executor threads alive after
        # validation errors. Resources are already closed by the async runner;
        # exit immediately so the container restart policy can recover.
        os._exit(1)


if __name__ == "__main__":
    raise SystemExit(
        "Use agent-platform-agent-worker or agent-platform-commit-worker; "
        "the generic worker entrypoint is intentionally unavailable."
    )
