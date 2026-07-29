from __future__ import annotations

import json
from io import StringIO

from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from prometheus_client import CollectorRegistry, generate_latest

from agent_platform.infrastructure.observability.logging import configure_logging
from agent_platform.infrastructure.observability.metrics import PlatformMetrics
from agent_platform.infrastructure.observability.runtime import RuntimeObservability
from agent_platform.infrastructure.observability.tracing import configure_tracing


class _EventLogger:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, object]]] = []

    def info(self, event: str, **event_fields: object) -> None:
        self.events.append((event, event_fields))


def test_operational_metrics_cover_documented_dashboard_dimensions() -> None:
    registry = CollectorRegistry()
    metrics = PlatformMetrics(registry)
    telemetry = RuntimeObservability(metrics, environment="test")

    telemetry.record_run_accept(outcome="accepted")
    telemetry.record_model(
        role="worker",
        model="gpt-5.6-sol",
        status="success",
        duration_seconds=0.4,
        input_tokens=100,
        output_tokens=20,
        cached_input_tokens=80,
        cost_usd=0.012,
        use_case="knowledge-report",
        tenant_tier="standard",
    )
    telemetry.record_model_upgrade(
        role="worker",
        from_model="gpt-5.6-terra",
        to_model="gpt-5.6-sol",
        reason="retry",
    )
    telemetry.record_tool(
        tool="knowledge.search",
        version="1.0.0",
        effect="read",
        status="success",
        duration_seconds=0.2,
        result_bytes=12_345,
    )
    telemetry.record_activity(
        activity="task.execute",
        status="completed",
        duration_seconds=0.5,
    )
    telemetry.record_queue_state(
        queue="agent-runs:activity",
        backlog=3,
        oldest_age_seconds=7.5,
    )
    telemetry.record_dependency_health({"postgres": "ok", "temporal": "error:Unavailable"})
    telemetry.record_capacity(resource="agent-worker", utilization_ratio=0.75)
    telemetry.record_mcp_server(
        server="crm-search",
        healthy=True,
        result_bytes=321,
    )
    telemetry.record_security_event(
        category="prompt_injection",
        severity="sev2",
        outcome="blocked",
    )
    telemetry.record_kill_switch(scope="capability", mode="block", active=True)

    output = generate_latest(registry).decode()
    expected_samples = (
        'agent_run_accept_requests_total{environment="test",outcome="accepted"} 1.0',
        'agent_model_latency_seconds_count{environment="test",model="gpt-5.6-sol",'
        'role="worker",status="success"} 1.0',
        'agent_model_cache_total{environment="test",model="gpt-5.6-sol",'
        'role="worker",status="hit"} 1.0',
        'agent_cost_usd_total{environment="test",model="gpt-5.6-sol",'
        'tenant_tier="standard",use_case="knowledge-report"} 0.012',
        'agent_model_upgrades_total{environment="test",from_model="gpt-5.6-terra",'
        'reason="retry",role="worker",to_model="gpt-5.6-sol"} 1.0',
        'agent_tool_result_bytes_count{environment="test",status="success",'
        'tool="knowledge.search"} 1.0',
        'agent_activity_executions_total{activity="task.execute",environment="test",'
        'status="completed"} 1.0',
        'agent_queue_backlog{environment="test",queue="agent-runs:activity"} 3.0',
        'agent_dependency_health{dependency="postgres",environment="test"} 1.0',
        'agent_dependency_health{dependency="temporal",environment="test"} 0.0',
        'agent_capacity_utilization_ratio{environment="test",resource="agent-worker"} 0.75',
        'agent_mcp_server_health{environment="test",server="crm-search"} 1.0',
        'agent_security_events_total{category="prompt_injection",environment="test",'
        'outcome="blocked",severity="sev2"} 1.0',
        'agent_kill_switch_state{environment="test",mode="block",scope="capability"} 1.0',
    )
    for sample in expected_samples:
        assert sample in output


def test_trace_and_log_events_keep_correlation_chain_but_hash_tenant() -> None:
    provider = configure_tracing(
        service_name="agent-platform-test",
        environment="test",
        endpoint=None,
        set_global=False,
    )
    exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    logger = _EventLogger()
    telemetry = RuntimeObservability(
        PlatformMetrics(CollectorRegistry()),
        environment="test",
        logger=logger,
        tracer=provider.get_tracer("observability-chain-test"),
    )
    tenant_hash = telemetry.tenant_hash("tenant-sensitive")

    with telemetry.span(
        "tool.invoke",
        {
            "correlation_id": "correlation-123",
            "run_id": "run-123",
            "workflow_id": "agent-run-123",
            "plan_id": "plan-123",
            "plan_version": 2,
            "task_id": "market-jp",
            "attempt": 1,
            "tool_invocation_id": "invocation-123",
            "action_id": "action-123",
            "tenant_id_hash": tenant_hash,
            "tenant_id": "tenant-sensitive",
        },
    ):
        telemetry.record_tool(
            tool="knowledge.search",
            version="1.0.0",
            effect="read",
            status="success",
            duration_seconds=0.1,
            result_bytes=42,
        )

    span = exporter.get_finished_spans()[0]
    assert span.attributes["correlation_id"] == "correlation-123"
    assert span.attributes["run_id"] == "run-123"
    assert span.attributes["workflow_id"] == "agent-run-123"
    assert span.attributes["task_id"] == "market-jp"
    assert span.attributes["tool_invocation_id"] == "invocation-123"
    assert span.attributes["action_id"] == "action-123"
    assert span.attributes["tenant_id_hash"] == tenant_hash
    assert "tenant_id" not in span.attributes
    assert "tenant-sensitive" not in str(logger.events)
    assert tenant_hash.startswith("sha256:")


def test_structured_log_merges_the_privacy_safe_correlation_chain() -> None:
    stream = StringIO()
    configure_logging(json_logs=True, stream=stream, cache_logger=False)
    telemetry = RuntimeObservability(
        PlatformMetrics(CollectorRegistry()),
        environment="test",
    )

    with telemetry.span(
        "task.execute",
        {
            "correlation_id": "correlation-log-1",
            "run_id": "run-log-1",
            "plan_version": 3,
            "task_id": "task-log-1",
            "tenant_id_hash": telemetry.tenant_hash("tenant-never-log-raw"),
        },
    ):
        telemetry.record_activity(
            activity="task.execute",
            status="completed",
            duration_seconds=0.1,
        )

    event = json.loads(stream.getvalue())
    assert event["log_schema_version"] == "1.0"
    assert event["service"] == "agent-platform"
    assert event["environment"] == "test"
    assert event["correlation_id"] == "correlation-log-1"
    assert event["run_id"] == "run-log-1"
    assert event["plan_version"] == 3
    assert event["task_id"] == "task-log-1"
    assert event["tenant_id_hash"].startswith("sha256:")
    assert "tenant-never-log-raw" not in stream.getvalue()


def test_budget_utilization_is_a_distribution_not_last_value() -> None:
    registry = CollectorRegistry()
    metrics = PlatformMetrics(registry)
    telemetry = RuntimeObservability(metrics, environment="test")

    for cost in (0.1, 0.9):
        telemetry.record_run_terminal(
            use_case="knowledge-report",
            risk="low",
            status="completed",
            duration_seconds=1,
            cost_usd=cost,
            cost_budget_usd=1,
            tool_calls=0,
            tool_call_budget=1,
            duration_budget_seconds=10,
            tenant_tier="standard",
        )

    output = generate_latest(registry).decode()
    assert (
        'agent_budget_utilization_ratio_count{budget_type="cost",environment="test",'
        'tenant_tier="standard",use_case="knowledge-report"} 2.0'
    ) in output
    assert (
        'agent_budget_utilization_ratio_sum{budget_type="cost",environment="test",'
        'tenant_tier="standard",use_case="knowledge-report"} 1.0'
    ) in output
