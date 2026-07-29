from __future__ import annotations

from prometheus_client import CollectorRegistry

from agent_platform.infrastructure.observability.logging import redact_event
from agent_platform.infrastructure.observability.metrics import PlatformMetrics


def test_all_required_metrics_are_registered_without_high_cardinality_labels() -> None:
    registry = CollectorRegistry()
    metrics = PlatformMetrics(registry)
    names = {family.name for family in registry.collect()}
    required = {
        "agent_runs",
        "agent_run_duration_seconds",
        "agent_task_duration_seconds",
        "agent_model_requests",
        "agent_model_tokens",
        "agent_cost_usd",
        "agent_tool_calls",
        "agent_tool_latency_seconds",
        "agent_policy_decisions",
        "agent_actions",
        "agent_approvals_duration_seconds",
        "agent_verification_failures",
        "agent_trajectory_alerts",
        "agent_budget_utilization_ratio",
    }
    assert required <= names
    for metric in metrics.collectors:
        label_names = set(metric._labelnames)
        assert not label_names & {"run_id", "user_id", "url", "prompt", "error_message"}


def test_logs_redact_secrets_headers_and_personal_content_recursively() -> None:
    event = {
        "event": "tool.failed",
        "authorization": "Bearer secret",
        "nested": {
            "cookie": "session=secret",
            "openai_api_key": "sk-secret",
            "safe": "visible",
        },
        "prompt": "private model content",
    }
    redacted = redact_event(None, "error", event)
    assert redacted["authorization"] == "[REDACTED]"
    assert redacted["nested"]["cookie"] == "[REDACTED]"
    assert redacted["nested"]["openai_api_key"] == "[REDACTED]"
    assert redacted["nested"]["safe"] == "visible"
    assert redacted["prompt"] == "[CONTENT_OMITTED]"
