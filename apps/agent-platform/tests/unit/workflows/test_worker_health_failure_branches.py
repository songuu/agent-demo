from __future__ import annotations

from collections.abc import Awaitable, Coroutine
from types import SimpleNamespace
from typing import Any, cast

import pytest
from prometheus_client import CollectorRegistry
from temporalio.contrib.opentelemetry import TracingInterceptor

from agent_platform import bootstrap as bootstrap_module
from agent_platform.workflows import health_server as health_server_module
from agent_platform.workflows import worker as worker_module
from agent_platform.workflows.health_server import WorkerHealthServer


class _Reader:
    def __init__(self, request_line: bytes) -> None:
        self._request_line = request_line

    async def readline(self) -> bytes:
        return self._request_line


class _Writer:
    def __init__(self) -> None:
        self.payload = bytearray()
        self.drained = False
        self.closed = False
        self.waited = False

    def write(self, payload: bytes) -> None:
        self.payload.extend(payload)

    async def drain(self) -> None:
        self.drained = True

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        self.waited = True


class _Server:
    def __init__(self) -> None:
        self.closed = False
        self.waited = False

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        self.waited = True


async def _healthy_dependencies() -> dict[str, str]:
    return {"database": "ok"}


@pytest.mark.parametrize(
    ("health_port", "metrics_port", "message"),
    [
        (0, 9464, "WORKER_HEALTH_PORT_INVALID"),
        (8081, 65_536, "WORKER_HEALTH_PORT_INVALID"),
        (8081, 8081, "WORKER_HEALTH_PORTS_MUST_DIFFER"),
    ],
)
def test_worker_health_server_rejects_invalid_ports(
    health_port: int,
    metrics_port: int,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        WorkerHealthServer(
            dependency_check=_healthy_dependencies,
            registry=CollectorRegistry(),
            health_port=health_port,
            metrics_port=metrics_port,
        )


@pytest.mark.asyncio
async def test_worker_health_start_closes_liveness_server_when_metrics_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    health_server = _Server()
    calls = 0

    async def start_server(*args: object, **kwargs: object) -> _Server:
        nonlocal calls
        del args, kwargs
        calls += 1
        if calls == 2:
            raise RuntimeError("metrics bind failed")
        return health_server

    monkeypatch.setattr(health_server_module.asyncio, "start_server", start_server)
    server = WorkerHealthServer(
        dependency_check=_healthy_dependencies,
        registry=CollectorRegistry(),
    )

    with pytest.raises(RuntimeError, match="metrics bind failed"):
        await server.start()

    assert health_server.closed is True
    assert health_server.waited is True
    assert server._health_server is None


@pytest.mark.asyncio
async def test_worker_health_close_handles_started_and_unstarted_servers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    servers = [_Server(), _Server()]

    async def start_server(*args: object, **kwargs: object) -> _Server:
        del args, kwargs
        return servers.pop(0)

    monkeypatch.setattr(health_server_module.asyncio, "start_server", start_server)
    server = WorkerHealthServer(
        dependency_check=_healthy_dependencies,
        registry=CollectorRegistry(),
    )

    await server.aclose()
    await server.start()
    active_servers = [
        cast(_Server, server._health_server),
        cast(_Server, server._metrics_server),
    ]
    server.ready = True
    await server.aclose()

    assert server.ready is False
    assert all(item.closed and item.waited for item in active_servers)
    assert server._health_server is None
    assert server._metrics_server is None


@pytest.mark.asyncio
async def test_worker_health_routes_fail_closed_for_dependency_and_unknown_paths() -> None:
    async def unavailable_dependencies() -> dict[str, str]:
        raise RuntimeError("database unavailable")

    server = WorkerHealthServer(
        dependency_check=unavailable_dependencies,
        registry=CollectorRegistry(),
    )
    server.ready = True
    ready_writer = _Writer()
    missing_health_writer = _Writer()
    missing_metrics_writer = _Writer()

    await server._handle_health(
        cast(Any, _Reader(b"GET /ready HTTP/1.1\r\n")),
        cast(Any, ready_writer),
    )
    await server._handle_health(
        cast(Any, _Reader(b"GET /missing HTTP/1.1\r\n")),
        cast(Any, missing_health_writer),
    )
    await server._handle_metrics(
        cast(Any, _Reader(b"GET /missing HTTP/1.1\r\n")),
        cast(Any, missing_metrics_writer),
    )

    assert b"HTTP/1.1 503 Service Unavailable" in ready_writer.payload
    assert b'"dependencies":{"dependencies":"error"}' in ready_writer.payload
    assert b"HTTP/1.1 404 Not Found" in missing_health_writer.payload
    assert b"HTTP/1.1 404 Not Found" in missing_metrics_writer.payload
    assert all(
        writer.drained and writer.closed and writer.waited
        for writer in (ready_writer, missing_health_writer, missing_metrics_writer)
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("request_line", "expected"),
    [
        (b"GET /health?verbose=1 HTTP/1.1\r\n", "/health"),
        (b"POST /health HTTP/1.1\r\n", ""),
        (b"GET /health\r\n", ""),
        (b"x" * 4_097, ""),
    ],
)
async def test_request_path_validates_the_bounded_get_request_line(
    request_line: bytes,
    expected: str,
) -> None:
    assert await WorkerHealthServer._request_path(cast(Any, _Reader(request_line))) == expected


@pytest.mark.asyncio
async def test_request_path_returns_empty_on_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def timeout(
        awaitable: Awaitable[bytes],
        *,
        timeout: float,
    ) -> Coroutine[Any, Any, bytes]:
        del timeout
        cast(Coroutine[Any, Any, bytes], awaitable).close()

        async def raise_timeout() -> bytes:
            raise TimeoutError

        return raise_timeout()

    monkeypatch.setattr(health_server_module.asyncio, "wait_for", timeout)

    assert (
        await WorkerHealthServer._request_path(cast(Any, _Reader(b"GET /health HTTP/1.1\r\n")))
        == ""
    )


@pytest.mark.asyncio
async def test_connect_client_forwards_temporal_connection_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connected = object()
    observed: dict[str, object] = {}

    async def connect(address: str, **kwargs: object) -> object:
        observed["address"] = address
        observed.update(kwargs)
        return connected

    class _Secret:
        def get_secret_value(self) -> str:
            return ""

    monkeypatch.setattr(worker_module.Client, "connect", connect)
    settings = SimpleNamespace(
        temporal_api_key=_Secret(),
        temporal_address="temporal.example:7233",
        temporal_namespace="tenant",
        temporal_tls=True,
    )

    result = await worker_module.connect_client(cast(Any, settings))

    assert result is connected
    interceptors = observed.pop("interceptors")
    assert isinstance(interceptors, tuple)
    assert len(interceptors) == 1
    assert isinstance(interceptors[0], TracingInterceptor)
    assert observed == {
        "address": "temporal.example:7233",
        "namespace": "tenant",
        "api_key": None,
        "tls": True,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("runner_name", "builder_name", "queue_name"),
    [
        ("run_agent_worker", "build_agent_worker", "agent-queue"),
        ("run_commit_worker", "build_commit_worker", "commit-queue"),
    ],
)
async def test_worker_runners_forward_queue_version_and_limits(
    monkeypatch: pytest.MonkeyPatch,
    runner_name: str,
    builder_name: str,
    queue_name: str,
) -> None:
    built_worker = object()
    resources = SimpleNamespace(dependencies=object())
    client = object()
    builder_calls: list[dict[str, object]] = []
    health_calls: list[tuple[object, object, object]] = []

    def build_worker(**kwargs: object) -> object:
        builder_calls.append(kwargs)
        return built_worker

    async def run_with_health(
        settings: object,
        worker: object,
        worker_resources: object,
    ) -> None:
        health_calls.append((settings, worker, worker_resources))

    monkeypatch.setattr(worker_module, builder_name, build_worker)
    monkeypatch.setattr(worker_module, "_run_with_health", run_with_health)
    settings = SimpleNamespace(
        temporal_task_queue="agent-queue",
        temporal_commit_task_queue="commit-queue",
        release_git_sha="abc123",
        max_concurrent_activities=9,
    )
    runner = cast(Any, getattr(worker_module, runner_name))

    await runner(settings, client, resources)

    assert builder_calls == [
        {
            "client": client,
            "task_queue": queue_name,
            "dependencies": resources.dependencies,
            "build_id": "abc123",
            "max_concurrent_activities": 9,
        }
    ]
    assert health_calls == [(settings, built_worker, resources)]


@pytest.mark.asyncio
async def test_run_with_health_always_closes_health_and_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class _Health:
        def __init__(self, **kwargs: object) -> None:
            events.append(f"init:{kwargs['health_port']}:{kwargs['metrics_port']}")
            self.ready = False

        async def start(self) -> None:
            events.append("health.start")

        async def aclose(self) -> None:
            events.append(f"health.close:{self.ready}")

    class _Worker:
        async def run(self) -> None:
            events.append("worker.run")
            raise RuntimeError("worker failed")

    class _Resources:
        dependencies = object()
        metrics_registry = CollectorRegistry()

        async def healthcheck(self) -> dict[str, str]:
            return {"database": "ok"}

        async def aclose(self) -> None:
            events.append("resources.close")

    monkeypatch.setattr(worker_module, "WorkerHealthServer", _Health)
    settings = SimpleNamespace(worker_health_port=8088, worker_metrics_port=9471)

    with pytest.raises(RuntimeError, match="worker failed"):
        await worker_module._run_with_health(
            cast(Any, settings),
            cast(Any, _Worker()),
            cast(Any, _Resources()),
        )

    assert events == [
        "init:8088:9471",
        "health.start",
        "worker.run",
        "health.close:False",
        "resources.close",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("main_name", "builder_name", "role", "runner_name"),
    [
        (
            "_agent_main",
            "build_agent_worker_process",
            "agent-worker",
            "run_agent_worker",
        ),
        (
            "_commit_main",
            "build_commit_worker_process",
            "commit-worker",
            "run_commit_worker",
        ),
    ],
)
async def test_worker_async_entrypoints_build_role_specific_resources(
    monkeypatch: pytest.MonkeyPatch,
    main_name: str,
    builder_name: str,
    role: str,
    runner_name: str,
) -> None:
    settings = SimpleNamespace(
        service_name="agent-platform",
        environment="test",
        otlp_endpoint=None,
        trace_content_capture=False,
    )
    client = object()
    resources = object()
    trace_token = object()
    trace_provider = SimpleNamespace(
        get_tracer=lambda name: trace_token,
        shutdown=lambda: None,
    )
    observed: list[tuple[object, object, object]] = []

    def settings_factory(*, process_role: str) -> object:
        assert process_role == role
        return settings

    def build_trace_provider(**kwargs: object) -> object:
        assert kwargs["service_name"] == f"agent-platform-{role}"
        return trace_provider

    async def connect(candidate: object, *, tracer: object) -> object:
        assert candidate is settings
        assert tracer is trace_token
        return client

    async def build(
        candidate: object,
        connected: object,
        *,
        configured_trace_provider: object,
    ) -> object:
        assert candidate is settings
        assert connected is client
        assert configured_trace_provider is trace_provider
        return resources

    async def run(
        candidate: object,
        connected: object,
        process_resources: object,
    ) -> None:
        observed.append((candidate, connected, process_resources))

    monkeypatch.setattr(worker_module, "Settings", settings_factory)
    monkeypatch.setattr(worker_module, "configure_tracing", build_trace_provider)
    monkeypatch.setattr(worker_module, "connect_client", connect)
    monkeypatch.setattr(bootstrap_module, builder_name, build)
    monkeypatch.setattr(worker_module, runner_name, run)

    await cast(Any, getattr(worker_module, main_name))()

    assert observed == [(settings, client, resources)]


@pytest.mark.parametrize(
    ("entrypoint", "async_entrypoint"),
    [("agent_main", "_agent_main"), ("commit_main", "_commit_main")],
)
def test_sync_worker_entrypoints_delegate_to_asyncio(
    monkeypatch: pytest.MonkeyPatch,
    entrypoint: str,
    async_entrypoint: str,
) -> None:
    observed: list[str] = []

    async def run_worker() -> None:
        observed.append("worker")

    def run(coroutine: Coroutine[Any, Any, None]) -> None:
        observed.append("asyncio")
        coroutine.close()

    monkeypatch.setattr(worker_module, async_entrypoint, run_worker)
    monkeypatch.setattr(worker_module.asyncio, "run", run)

    cast(Any, getattr(worker_module, entrypoint))()

    assert observed == ["asyncio"]
