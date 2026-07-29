from __future__ import annotations

import pytest
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from prometheus_client import CollectorRegistry

from agent_platform.infrastructure.observability.metrics import PlatformMetrics
from agent_platform.infrastructure.observability.runtime import RuntimeObservability
from agent_platform.infrastructure.observability.tracing import configure_tracing


class _FailingLogger:
    def info(self, event: str, **event_fields: object) -> object:
        del event, event_fields
        raise OSError("LOG_SINK_UNAVAILABLE")


def test_runtime_trace_keeps_run_correlation_but_excludes_raw_tenant_and_content() -> None:
    provider = configure_tracing(
        service_name="agent-platform-test",
        environment="test",
        endpoint=None,
        set_global=False,
    )
    exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    telemetry = RuntimeObservability(
        PlatformMetrics(CollectorRegistry()),
        environment="test",
        logger=_FailingLogger(),
        tracer=provider.get_tracer("ops01-test"),
    )

    with telemetry.span(
        "agent.tool.call",
        {
            "tool": "knowledge.search",
            "effect": "read",
            "tenant_id": "tenant-must-not-appear",
            "run_id": "run-correlation-1",
            "tenant_id_hash": telemetry.tenant_hash("tenant-must-not-appear"),
        },
    ):
        telemetry.record_tool(
            tool="knowledge.search",
            version="1.0.0",
            effect="read",
            status="success",
            duration_seconds=0.1,
        )

    with pytest.raises(RuntimeError, match="secret model content"):
        with telemetry.span(
            "agent.model.request",
            {"role": "planner", "model": "gpt-5.6-sol"},
        ):
            raise RuntimeError("secret model content")

    spans = exporter.get_finished_spans()
    assert len(spans) == 2
    span = next(item for item in spans if item.name == "agent.tool.call")
    assert span.attributes["tool"] == "knowledge.search"
    assert "tenant_id" not in span.attributes
    assert span.attributes["run_id"] == "run-correlation-1"
    assert str(span.attributes["tenant_id_hash"]).startswith("sha256:")
    assert len(span.events) == 1
    event_attributes = span.events[0].attributes
    assert event_attributes is not None
    assert "tenant_id" not in event_attributes
    assert "run_id" not in event_attributes
    assert "prompt" not in event_attributes
    failed_span = next(item for item in spans if item.name == "agent.model.request")
    assert failed_span.events == ()
    assert "secret model content" not in str(failed_span.attributes)
