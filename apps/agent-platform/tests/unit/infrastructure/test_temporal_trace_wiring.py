from __future__ import annotations

import json
from io import StringIO
from types import SimpleNamespace
from typing import cast

import pytest
from fastapi import FastAPI
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from prometheus_client import CollectorRegistry
from starlette.testclient import TestClient
from temporalio.contrib.opentelemetry import TracingInterceptor

from agent_platform import bootstrap
from agent_platform.api.middleware import SecurityEnvelopeMiddleware
from agent_platform.config import Settings
from agent_platform.infrastructure.observability.logging import configure_logging
from agent_platform.infrastructure.observability.metrics import PlatformMetrics
from agent_platform.infrastructure.observability.runtime import RuntimeObservability
from agent_platform.infrastructure.observability.tracing import configure_tracing
from agent_platform.workflows import worker as worker_module
from agent_platform.workflows.temporal_starter import TemporalWorkflowStarter


class _Secret:
    def get_secret_value(self) -> str:
        return ""


@pytest.mark.asyncio
async def test_api_and_worker_temporal_clients_register_official_tracing_interceptor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[dict[str, object]] = []

    async def connect(address: str, **kwargs: object) -> object:
        observed.append({"address": address, **kwargs})
        return object()

    monkeypatch.setattr(bootstrap.Client, "connect", connect)
    monkeypatch.setattr(worker_module.Client, "connect", connect)
    provider = configure_tracing(
        service_name="trace-wiring-test",
        environment="test",
        endpoint=None,
        set_global=False,
    )
    tracer = provider.get_tracer("trace-wiring-test")
    settings = SimpleNamespace(
        temporal_api_key=_Secret(),
        temporal_address="temporal.example:7233",
        temporal_namespace="tenant",
        temporal_tls=True,
    )

    await bootstrap._connect_temporal(cast(Settings, settings), tracer=tracer)
    await worker_module.connect_client(cast(Settings, settings), tracer=tracer)
    await TemporalWorkflowStarter.connect(
        address="temporal.example:7233",
        namespace="tenant",
        task_queue="agent-runs",
        tracer=tracer,
    )

    assert len(observed) == 3
    for connection in observed:
        interceptors = connection["interceptors"]
        assert isinstance(interceptors, tuple)
        assert len(interceptors) == 1
        interceptor = interceptors[0]
        assert isinstance(interceptor, TracingInterceptor)
        assert interceptor.header_key == "_tracer-data"
        assert interceptor.tracer is tracer
    provider.shutdown()


def test_api_middleware_extracts_incoming_traceparent_and_logs_trace_ids() -> None:
    provider = configure_tracing(
        service_name="api-trace-test",
        environment="test",
        endpoint=None,
        set_global=False,
    )
    exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    stream = StringIO()
    configure_logging(json_logs=True, stream=stream, cache_logger=False)
    observability = RuntimeObservability(
        PlatformMetrics(CollectorRegistry()),
        environment="test",
        tracer=provider.get_tracer("api-trace-test"),
    )

    app = FastAPI()
    app.state.container = SimpleNamespace(
        observability=observability,
        quota_limiter=None,
        settings=SimpleNamespace(environment="test", quota_backend="memory"),
    )
    app.add_middleware(SecurityEnvelopeMiddleware, max_request_bytes=1024)

    @app.get("/trace-probe")
    async def trace_probe() -> dict[str, bool]:
        observability.record_activity(
            activity="trace.probe",
            status="completed",
            duration_seconds=0.001,
        )
        return {"ok": True}

    trace_id = "1" * 32
    parent_span_id = "2" * 16
    with TestClient(app) as client:
        response = client.get(
            "/trace-probe",
            headers={"traceparent": f"00-{trace_id}-{parent_span_id}-01"},
        )

    assert response.status_code == 200
    span = next(item for item in exporter.get_finished_spans() if item.name == "agent.api.request")
    assert f"{span.context.trace_id:032x}" == trace_id
    assert span.parent is not None
    assert f"{span.parent.span_id:016x}" == parent_span_id
    assert span.attributes["http.route"] == "/trace-probe"
    event = json.loads(stream.getvalue())
    assert event["trace_id"] == trace_id
    assert len(event["span_id"]) == 16
    provider.shutdown()
