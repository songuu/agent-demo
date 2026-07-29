from __future__ import annotations

import json
from pathlib import Path

import yaml

PLATFORM_ROOT = Path(__file__).parents[3]
RULES_PATH = PLATFORM_ROOT / "deploy" / "observability" / "prometheus-rules.yaml"
DASHBOARD_ROOT = PLATFORM_ROOT / "deploy" / "observability" / "dashboards"
DEPLOY_SCRIPT = PLATFORM_ROOT / "deploy" / "ci" / "deploy_observability_assets.sh"


def _expressions() -> dict[str, str]:
    document = yaml.safe_load(RULES_PATH.read_text(encoding="utf-8"))
    rules = [rule for group in document["spec"]["groups"] for rule in group["rules"]]
    return {str(rule.get("record") or rule.get("alert")): str(rule["expr"]) for rule in rules}


def test_recording_and_alert_rules_use_emitted_operational_series() -> None:
    expressions = _expressions()

    assert (
        'agent_run_accept_requests_total{outcome="accepted"}'
        in expressions["agent:run_accept_availability:ratio5m"]
    )
    assert (
        "agent_run_accept_requests_total[5m]"
        in expressions["agent:run_accept_availability:ratio5m"]
    )
    assert "agent_budget_utilization_ratio_bucket" in expressions["agent:budget_utilization:p95"]
    assert "agent_queue_backlog" in expressions["AgentQueueBacklog"]
    assert "agent_dependency_health" in expressions["AgentCriticalDependencyUnavailable"]
    assert 'category="duplicate_side_effect"' in expressions["AgentDuplicateSideEffect"]
    assert 'outcome="confirmed"' in expressions["AgentDuplicateSideEffect"]
    assert 'category="cross_tenant_data_exposure"' in expressions["AgentCrossTenantLeakSuspected"]
    assert 'outcome="confirmed"' in expressions["AgentCrossTenantLeakSuspected"]


def test_six_dashboards_cover_the_documented_operational_surfaces() -> None:
    required_series = {
        "executive.json": {
            "agent_run_accept_requests_total",
            "agent:platform_cost_usd:rate1h",
            "agent_trajectory_alerts_total",
        },
        "operations.json": {
            "agent_queue_backlog",
            "agent_activity_executions_total",
            "agent_dependency_health",
            "agent_capacity_utilization_ratio",
        },
        "model.json": {
            "agent_model_latency_seconds_bucket",
            "agent_model_upgrades_total",
            "agent_model_cache_total",
        },
        "tools.json": {
            "agent_tool_result_bytes_bucket",
            "agent_mcp_server_health",
        },
        "actions.json": {
            "agent_actions_total",
            "agent_verification_failures_total",
        },
        "safety.json": {
            "agent_security_events_total",
            "agent_kill_switch_state",
            "agent_trajectory_alerts_total",
        },
    }

    for name, series in required_series.items():
        dashboard = json.loads((DASHBOARD_ROOT / name).read_text(encoding="utf-8"))
        expressions = " ".join(
            str(target["expr"])
            for panel in dashboard["panels"]
            for target in panel.get("targets", ())
        )
        assert len(dashboard["panels"]) >= 5
        assert series <= {item for item in series if item in expressions}


def test_deployer_checks_scrape_query_trace_and_alert_routing_readbacks() -> None:
    script = DEPLOY_SCRIPT.read_text(encoding="utf-8")

    for required in (
        "/api/v1/targets",
        "/api/v1/query",
        "/api/v1/rules",
        "/api/v1/alertmanagers",
        "/api/v2/status",
        "/v1/traces",
        "/api/traces/",
        "synthetic_trace_roundtrip",
        "scrape_target_up",
        "prometheus_active_alertmanager",
        "route_receiver_config_present",
        "/api/dashboards/uid/",
        "grafana_runtime_api_readback",
        "synthetic_alert_submitted",
        "alertmanager_api_readback",
        "receiver_delivery_verified",
        "immutable_receipt_readback",
    ):
        assert required in script


def test_dashboard_runtime_contract_has_six_stable_uid_title_pairs() -> None:
    expected = {
        "agent-platform-actions": "Agent Platform - Actions",
        "agent-platform-executive": "Agent Platform - Executive",
        "agent-platform-model": "Agent Platform - Model",
        "agent-platform-operations": "Agent Platform - Operations",
        "agent-platform-safety": "Agent Platform - Safety",
        "agent-platform-tools": "Agent Platform - Tools",
    }

    actual = {}
    for dashboard_path in sorted(DASHBOARD_ROOT.glob("*.json")):
        dashboard = json.loads(dashboard_path.read_text(encoding="utf-8"))
        actual[str(dashboard["uid"])] = str(dashboard["title"])

    assert actual == expected


def test_approval_operational_rules_are_replica_safe_and_fail_closed() -> None:
    expressions = _expressions()

    assert expressions["agent:pending_approvals:max"].startswith("max by (environment, risk)")
    assert expressions["agent:pending_approval_oldest_age:max"].startswith("max by (environment)")
    assert expressions["agent:approval_notification_latency:p95"].startswith("max by (environment)")
    assert 'quantile="0.95"' in expressions["agent:approval_notification_latency:p95"]
    assert expressions["agent:approval_notification_samples:max"].startswith("max by (environment)")
    assert expressions["agent:approval_webhook_deliveries:max"].startswith(
        "max by (environment, status)"
    )
    assert expressions["agent:pending_approval_notifications_missing:max"].startswith(
        "max by (environment)"
    )
    assert expressions["agent:pending_approval_notification_oldest_missing_age:max"].startswith(
        "max by (environment)"
    )
    assert (
        "agent:approval_notification_latency:p95 > 30"
        in expressions["AgentApprovalNotificationLatency"]
    )
    assert (
        "agent:pending_approval_notifications_missing:max > 0"
        in expressions["AgentApprovalNotificationMissing"]
    )
    assert (
        "agent:pending_approval_notification_oldest_missing_age:max > 30"
        in expressions["AgentApprovalNotificationMissing"]
    )
    assert (
        'agent:approval_webhook_deliveries:max{status=~"retry|dead_letter"} > 0'
        in expressions["AgentApprovalDeliveryBacklog"]
    )
    assert (
        "agent:approval_notification_samples:max"
        not in expressions["AgentApprovalNotificationMissing"]
    )
    assert "agent_operational_metrics_collector_up" in expressions["AgentOperationalMetricsStale"]
    assert (
        "agent_operational_metrics_last_success_timestamp_seconds"
        in expressions["AgentOperationalMetricsStale"]
    )
