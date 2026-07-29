from __future__ import annotations

import asyncio
import socket

import pytest
from prometheus_client import CollectorRegistry, Counter

from agent_platform.workflows.activities import ActivityDependencies
from agent_platform.workflows.health_server import WorkerHealthServer
from agent_platform.workflows.worker import (
    agent_activity_handlers,
    commit_activity_handlers,
)


def _activity_names(handlers: object) -> set[str]:
    names: set[str] = set()
    for handler in handlers:  # type: ignore[union-attr]
        definition = getattr(handler, "__temporal_activity_definition")
        names.add(str(definition.name))
    return names


def test_agent_and_commit_workers_have_disjoint_activity_registries() -> None:
    dependencies = ActivityDependencies(None, None, None, None, None)

    agent_names = _activity_names(agent_activity_handlers(dependencies))
    commit_names = _activity_names(commit_activity_handlers(dependencies))

    assert "agent.execute_task" in agent_names
    assert "agent.commit_action" not in agent_names
    assert commit_names == {
        "agent.commit_action",
        "transaction.reconcile_action",
        "transaction.compensate_action",
    }
    assert agent_names.isdisjoint(commit_names)


@pytest.mark.asyncio
async def test_worker_health_server_separates_liveness_readiness_and_metrics() -> None:
    health_port = _free_port()
    metrics_port = _free_port()
    while metrics_port == health_port:
        metrics_port = _free_port()
    registry = CollectorRegistry()
    Counter("worker_test_total", "Worker test counter.", registry=registry).inc()

    async def dependencies() -> dict[str, str]:
        return {"database": "ok", "temporal": "ok"}

    server = WorkerHealthServer(
        dependency_check=dependencies,
        registry=registry,
        host="127.0.0.1",
        health_port=health_port,
        metrics_port=metrics_port,
    )
    await server.start()
    try:
        live = await _get(health_port, "/health")
        unavailable = await _get(health_port, "/ready")
        server.ready = True
        ready = await _get(health_port, "/ready")
        metrics = await _get(metrics_port, "/metrics")
    finally:
        await server.aclose()

    assert live.startswith("HTTP/1.1 200 OK")
    assert unavailable.startswith("HTTP/1.1 503 Service Unavailable")
    assert '"ready":false' in unavailable
    assert ready.startswith("HTTP/1.1 200 OK")
    assert '"ready":true' in ready
    assert metrics.startswith("HTTP/1.1 200 OK")
    assert "worker_test_total 1.0" in metrics


async def _get(port: int, path: str) -> str:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".encode())
    await writer.drain()
    payload = await reader.read()
    writer.close()
    await writer.wait_closed()
    return payload.decode()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])
