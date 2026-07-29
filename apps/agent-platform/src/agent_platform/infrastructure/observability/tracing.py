from __future__ import annotations

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor


def configure_tracing(
    *,
    service_name: str,
    environment: str,
    endpoint: str | None,
    capture_content: bool = False,
    set_global: bool = True,
) -> TracerProvider:
    provider = TracerProvider(
        resource=Resource.create(
            {
                "service.name": service_name,
                "deployment.environment.name": environment,
                "agent.telemetry.content_capture": ("enabled" if capture_content else "disabled"),
            }
        )
    )
    if endpoint:
        provider.add_span_processor(
            BatchSpanProcessor(
                OTLPSpanExporter(endpoint=endpoint, insecure=endpoint.startswith("http://"))
            )
        )
    if set_global:
        trace.set_tracer_provider(provider)
    return provider
