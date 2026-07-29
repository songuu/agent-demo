from __future__ import annotations

from io import StringIO

import structlog
from opentelemetry.sdk.trace import TracerProvider
from prometheus_client import CollectorRegistry, generate_latest

from agent_platform.infrastructure.observability.logging import configure_logging
from agent_platform.infrastructure.observability.metrics import PlatformMetrics
from agent_platform.infrastructure.observability.runtime import RuntimeObservability
from agent_platform.infrastructure.observability.tracing import configure_tracing


def test_runtime_observability_records_required_low_cardinality_signals() -> None:
    registry = CollectorRegistry()
    telemetry = RuntimeObservability(
        PlatformMetrics(registry),
        environment="test",
    )

    telemetry.record_run_received(
        use_case="knowledge-report",
        risk="medium",
        tenant_tier="standard",
    )
    telemetry.record_run_terminal(
        use_case="knowledge-report",
        risk="medium",
        status="completed",
        duration_seconds=1.25,
        cost_usd=0.25,
        cost_budget_usd=1.0,
        tool_calls=2,
        tool_call_budget=10,
        duration_budget_seconds=5,
        tenant_tier="standard",
        model="unknown",
    )
    telemetry.record_task(
        kind="analysis",
        model="gpt-5.6-sol",
        status="completed",
        duration_seconds=0.3,
    )
    telemetry.record_model(
        role="planner",
        model="gpt-5.6-sol",
        status="success",
        duration_seconds=0.2,
        input_tokens=12,
        output_tokens=4,
        cached_input_tokens=8,
        cost_usd=0.25,
        use_case="knowledge-report",
        tenant_tier="standard",
    )
    telemetry.record_tool(
        tool="knowledge.search",
        version="1.0.0",
        effect="read",
        status="success",
        duration_seconds=0.1,
    )
    telemetry.record_policy(
        phase="execute",
        allowed=False,
        reason_codes=("DATA_SCOPE_DENIED",),
    )
    telemetry.record_action(action_type="email.prepare", risk="high", status="prepared")
    telemetry.record_approval(
        policy="two-person",
        decision="approved",
        duration_seconds=3.0,
    )
    telemetry.record_verification_failure(
        verifier="side_effect",
        reason="SIDE_EFFECT_VERIFICATION_FAILED",
    )
    telemetry.record_trajectory_alert(
        severity="warning",
        reason="repeated_action",
    )

    output = generate_latest(registry).decode()
    assert (
        'agent_runs_total{environment="test",risk="medium",'
        'status="received",tenant_tier="standard",use_case="knowledge-report"} 1.0'
    ) in output
    assert (
        'agent_runs_total{environment="test",risk="medium",'
        'status="completed",tenant_tier="standard",use_case="knowledge-report"} 1.0'
    ) in output
    assert (
        'agent_task_duration_seconds_count{environment="test",kind="analysis",'
        'model="gpt-5.6-sol",status="completed"} 1.0'
    ) in output
    assert (
        'agent_model_tokens_total{direction="input",environment="test",'
        'model="gpt-5.6-sol",role="planner"} 12.0'
    ) in output
    assert (
        'agent_cost_usd_total{environment="test",model="gpt-5.6-sol",'
        'tenant_tier="standard",use_case="knowledge-report"} 0.25'
    ) in output
    assert (
        'agent_tool_calls_total{effect="read",environment="test",'
        'status="success",tool="knowledge.search",version="1.0.0"} 1.0'
    ) in output
    assert (
        'agent_approvals_duration_seconds_count{decision="approved",environment="test",'
        'policy="two-person"} 1.0'
    ) in output
    assert (
        'agent_verification_failures_total{environment="test",'
        'reason="SIDE_EFFECT_VERIFICATION_FAILED",verifier="side_effect"} 1.0'
    ) in output
    assert (
        'agent_trajectory_alerts_total{environment="test",reason="repeated_action",'
        'severity="warning"} 1.0'
    ) in output
    assert "tenant" not in {
        label for collector in telemetry.metrics.collectors for label in collector._labelnames
    }


def test_logging_configuration_redacts_content_and_is_reconfigurable() -> None:
    stream = StringIO()
    configure_logging(json_logs=True, stream=stream, cache_logger=False)

    structlog.get_logger().info(
        "model.completed",
        prompt="private prompt",
        goal="private business goal",
        nested={
            "authorization": "Bearer secret",
            "query": "private search query",
            "safe": "visible",
        },
    )

    rendered = stream.getvalue()
    assert "private prompt" not in rendered
    assert "private business goal" not in rendered
    assert "private search query" not in rendered
    assert "Bearer secret" not in rendered
    assert "[CONTENT_OMITTED]" in rendered
    assert "[REDACTED]" in rendered
    assert "visible" in rendered


def test_tracing_configuration_is_testable_and_content_capture_defaults_off() -> None:
    provider = configure_tracing(
        service_name="agent-platform-test",
        environment="test",
        endpoint=None,
        set_global=False,
    )

    assert isinstance(provider, TracerProvider)
    attributes = provider.resource.attributes
    assert attributes["service.name"] == "agent-platform-test"
    assert attributes["deployment.environment.name"] == "test"
    assert attributes["agent.telemetry.content_capture"] == "disabled"
