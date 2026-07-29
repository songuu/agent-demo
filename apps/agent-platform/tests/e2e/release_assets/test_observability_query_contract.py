from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

PLATFORM_ROOT = Path(__file__).parents[3]
RULES_PATH = PLATFORM_ROOT / "deploy" / "observability" / "prometheus-rules.yaml"
DASHBOARD_ROOT = PLATFORM_ROOT / "deploy" / "observability" / "dashboards"
AGENT_METRIC = re.compile(r"\b(?:agent_[a-zA-Z0-9_:]*|agent:[a-zA-Z0-9_:]*)\b")

RAW_METRICS = {
    "agent_runs_total",
    "agent_run_accept_requests_total",
    "agent_run_duration_seconds_bucket",
    "agent_task_duration_seconds_bucket",
    "agent_activity_executions_total",
    "agent_activity_duration_seconds_bucket",
    "agent_model_requests_total",
    "agent_model_tokens_total",
    "agent_model_latency_seconds_bucket",
    "agent_model_cache_total",
    "agent_model_upgrades_total",
    "agent_cost_usd_total",
    "agent_platform_cost_usd_total",
    "agent_success_cost_usd_bucket",
    "agent_tenant_budget_utilization_ratio_bucket",
    "agent_tool_calls_total",
    "agent_tool_latency_seconds_bucket",
    "agent_tool_result_bytes_bucket",
    "agent_mcp_server_health",
    "agent_mcp_result_bytes_bucket",
    "agent_policy_decisions_total",
    "agent_actions_total",
    "agent_approvals_duration_seconds_bucket",
    "agent_pending_approvals",
    "agent_pending_approval_oldest_age_seconds",
    "agent_pending_approval_overdue_cleanup_lag_seconds",
    "agent_outbox_events_current",
    "agent_webhook_deliveries_current",
    "agent_approval_webhook_deliveries_current",
    "agent_pending_approval_notifications_missing",
    "agent_pending_approval_notification_oldest_missing_age_seconds",
    "agent_approval_notification_latency_seconds",
    "agent_approval_notification_samples",
    "agent_operational_metrics_collector_up",
    "agent_operational_metrics_last_success_timestamp_seconds",
    "agent_verification_failures_total",
    "agent_trajectory_alerts_total",
    "agent_budget_utilization_ratio_bucket",
    "agent_queue_backlog",
    "agent_queue_oldest_age_seconds",
    "agent_dependency_health",
    "agent_capacity_utilization_ratio",
    "agent_security_events_total",
    "agent_kill_switch_state",
}
FORBIDDEN_UNWIRED_SERIES = {
    "agent_business_qualified_ratio",
    "agent_evidence_coverage_ratio",
}


def _rules() -> tuple[dict[str, str], list[str]]:
    document = yaml.safe_load(RULES_PATH.read_text(encoding="utf-8"))
    rules = [rule for group in document["spec"]["groups"] for rule in group["rules"]]
    recordings = {str(rule["record"]): str(rule["expr"]) for rule in rules if "record" in rule}
    expressions = [str(rule["expr"]) for rule in rules]
    return recordings, expressions


def _dashboard_expressions() -> list[str]:
    expressions: list[str] = []
    for path in sorted(DASHBOARD_ROOT.glob("*.json")):
        dashboard: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        expressions.extend(
            str(target["expr"])
            for panel in dashboard["panels"]
            for target in panel.get("targets", ())
        )
    return expressions


def test_recording_rules_group_by_labels_that_exist_on_the_source_metric() -> None:
    recordings, _ = _rules()

    assert "sum by (le, kind, model)" in recordings["agent:task_duration:p95"]
    assert (
        "sum by (environment, model, use_case, tenant_tier)" in recordings["agent:cost_usd:rate1h"]
    )
    assert (
        "sum by (environment, component, use_case, tenant_tier)"
        in recordings["agent:platform_cost_usd:rate1h"]
    )
    assert "agent_platform_cost_usd_total" in recordings["agent:cost_per_success:usd1h"]
    assert "sum by (le, policy, decision)" in recordings["agent:approval_duration:p95"]
    assert "sum by (verifier, reason)" in recordings["agent:verification_failure:rate5m"]
    assert (
        "sum by (le, use_case, tenant_tier, budget_type)"
        in recordings["agent:budget_utilization:p95"]
    )
    assert "agent_budget_utilization_ratio_bucket" in recordings["agent:budget_utilization:p95"]
    assert "sum by (severity, reason)" in recordings["agent:trajectory_alert:rate5m"]


def test_rules_and_dashboards_only_query_wired_agent_series() -> None:
    recordings, rule_expressions = _rules()
    dashboard_expressions = _dashboard_expressions()
    available = RAW_METRICS | set(recordings)

    for expression in [*rule_expressions, *dashboard_expressions]:
        referenced = set(AGENT_METRIC.findall(expression))
        assert referenced <= available, (
            f"PromQL references unavailable Agent series: {sorted(referenced - available)}"
        )
        assert not referenced & FORBIDDEN_UNWIRED_SERIES

    assert all(
        "temporal_workflow_task_schedule_to_start_latency_bucket" not in expression
        for expression in dashboard_expressions
    )
