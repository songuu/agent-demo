from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

_RATIO_BUCKETS = (0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0, 1.25, 1.5, 2.0, 5.0)
_COST_BUCKETS = (0.0, 0.001, 0.01, 0.1, 1.0, 5.0, 10.0, 50.0, 100.0, 1000.0)
_RESULT_SIZE_BUCKETS = (
    0,
    1_024,
    4_096,
    16_384,
    65_536,
    262_144,
    1_048_576,
    10_000_000,
    50_000_000,
)


class PlatformMetrics:
    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        self.agent_runs_total = Counter(
            "agent_runs_total",
            "Runs accepted and completed by outcome.",
            ("environment", "use_case", "risk", "status", "tenant_tier"),
            registry=self.registry,
        )
        self.agent_run_accept_requests_total = Counter(
            "agent_run_accept_requests_total",
            "Structurally and policy-valid run creation requests by platform outcome.",
            ("environment", "outcome"),
            registry=self.registry,
        )
        self.agent_run_duration_seconds = Histogram(
            "agent_run_duration_seconds",
            "End-to-end run duration.",
            ("environment", "use_case", "risk", "status"),
            registry=self.registry,
        )
        self.agent_task_duration_seconds = Histogram(
            "agent_task_duration_seconds",
            "Task execution duration.",
            ("environment", "kind", "model", "status"),
            registry=self.registry,
        )
        self.agent_model_requests_total = Counter(
            "agent_model_requests_total",
            "Model requests by logical role and outcome.",
            ("environment", "role", "model", "status"),
            registry=self.registry,
        )
        self.agent_model_tokens_total = Counter(
            "agent_model_tokens_total",
            "Model tokens by logical role and direction.",
            ("environment", "role", "model", "direction"),
            registry=self.registry,
        )
        self.agent_model_latency_seconds = Histogram(
            "agent_model_latency_seconds",
            "End-to-end model provider latency.",
            ("environment", "role", "model", "status"),
            registry=self.registry,
        )
        self.agent_model_cache_total = Counter(
            "agent_model_cache_total",
            "Model request cache outcome inferred from provider usage.",
            ("environment", "role", "model", "status"),
            registry=self.registry,
        )
        self.agent_model_upgrades_total = Counter(
            "agent_model_upgrades_total",
            "Model routing upgrades caused by a bounded retry or policy decision.",
            ("environment", "role", "from_model", "to_model", "reason"),
            registry=self.registry,
        )
        self.agent_cost_usd_total = Counter(
            "agent_cost_usd_total",
            "Estimated model cost in USD.",
            ("environment", "model", "use_case", "tenant_tier"),
            registry=self.registry,
        )
        self.agent_platform_cost_usd_total = Counter(
            "agent_platform_cost_usd_total",
            "Reconciled platform cost in USD by stable cost component.",
            ("environment", "component", "use_case", "tenant_tier"),
            registry=self.registry,
        )
        self.agent_tenant_budget_utilization_ratio = Histogram(
            "agent_tenant_budget_utilization_ratio",
            "Tenant daily and monthly budget utilization at Run settlement.",
            ("environment", "period", "control_level", "tenant_tier"),
            buckets=_RATIO_BUCKETS,
            registry=self.registry,
        )
        self.agent_success_cost_usd = Histogram(
            "agent_success_cost_usd",
            "Reconciled full-platform cost for successful Runs.",
            ("environment", "use_case", "tenant_tier"),
            buckets=_COST_BUCKETS,
            registry=self.registry,
        )
        self.agent_tool_calls_total = Counter(
            "agent_tool_calls_total",
            "Tool calls by stable tool and status.",
            ("environment", "tool", "version", "effect", "status"),
            registry=self.registry,
        )
        self.agent_tool_latency_seconds = Histogram(
            "agent_tool_latency_seconds",
            "Tool latency by stable tool name and status.",
            ("environment", "tool", "status"),
            registry=self.registry,
        )
        self.agent_tool_result_bytes = Histogram(
            "agent_tool_result_bytes",
            "Normalized tool result size before inline or Artifact delivery.",
            ("environment", "tool", "status"),
            buckets=_RESULT_SIZE_BUCKETS,
            registry=self.registry,
        )
        self.agent_mcp_server_health = Gauge(
            "agent_mcp_server_health",
            "Most recent managed MCP server probe result (1 healthy, 0 unhealthy).",
            ("environment", "server"),
            registry=self.registry,
        )
        self.agent_mcp_result_bytes = Histogram(
            "agent_mcp_result_bytes",
            "Normalized result size returned by a managed MCP server.",
            ("environment", "server"),
            buckets=_RESULT_SIZE_BUCKETS,
            registry=self.registry,
        )
        self.agent_policy_decisions_total = Counter(
            "agent_policy_decisions_total",
            "Policy decisions by phase and decision.",
            ("environment", "phase", "decision", "reason_code"),
            registry=self.registry,
        )
        self.agent_actions_total = Counter(
            "agent_actions_total",
            "Prepared and committed actions.",
            ("environment", "action_type", "risk", "status"),
            registry=self.registry,
        )
        self.agent_approvals_duration_seconds = Histogram(
            "agent_approvals_duration_seconds",
            "Approval wait duration.",
            ("environment", "policy", "decision"),
            registry=self.registry,
        )
        self.agent_pending_approvals = Gauge(
            "agent_pending_approvals",
            "Current pending approvals sampled from the durable database.",
            ("environment", "risk"),
            registry=self.registry,
        )
        self.agent_pending_approval_oldest_age_seconds = Gauge(
            "agent_pending_approval_oldest_age_seconds",
            "Age of the oldest currently pending approval.",
            ("environment",),
            registry=self.registry,
        )
        self.agent_pending_approval_overdue_cleanup_lag_seconds = Gauge(
            "agent_pending_approval_overdue_cleanup_lag_seconds",
            "Maximum expiry cleanup lag among overdue pending approvals.",
            ("environment",),
            registry=self.registry,
        )
        self.agent_outbox_events_current = Gauge(
            "agent_outbox_events_current",
            "Current unpublished Outbox events by retry state.",
            ("environment", "state"),
            registry=self.registry,
        )
        self.agent_webhook_deliveries_current = Gauge(
            "agent_webhook_deliveries_current",
            "Current webhook deliveries by durable delivery status.",
            ("environment", "status"),
            registry=self.registry,
        )
        self.agent_approval_webhook_deliveries_current = Gauge(
            "agent_approval_webhook_deliveries_current",
            "Current approval webhook deliveries by durable delivery status.",
            ("environment", "status"),
            registry=self.registry,
        )
        self.agent_pending_approval_notifications_missing = Gauge(
            "agent_pending_approval_notifications_missing",
            "Current pending approvals without any delivered approval notification.",
            ("environment",),
            registry=self.registry,
        )
        self.agent_pending_approval_notification_oldest_missing_age_seconds = Gauge(
            "agent_pending_approval_notification_oldest_missing_age_seconds",
            "Age of the oldest pending approval without a delivered notification.",
            ("environment",),
            registry=self.registry,
        )
        self.agent_approval_notification_latency_seconds = Gauge(
            "agent_approval_notification_latency_seconds",
            "Database-derived approval notification latency quantiles for the active window.",
            ("environment", "quantile"),
            registry=self.registry,
        )
        self.agent_approval_notification_samples = Gauge(
            "agent_approval_notification_samples",
            "Delivered approval notification samples in the active database window.",
            ("environment",),
            registry=self.registry,
        )
        self.agent_operational_metrics_collector_up = Gauge(
            "agent_operational_metrics_collector_up",
            "Whether the latest operational database metric refresh succeeded.",
            ("environment",),
            registry=self.registry,
        )
        self.agent_operational_metrics_last_success_timestamp_seconds = Gauge(
            "agent_operational_metrics_last_success_timestamp_seconds",
            "Unix timestamp of the latest successful operational database metric refresh.",
            ("environment",),
            registry=self.registry,
        )
        self.agent_verification_failures_total = Counter(
            "agent_verification_failures_total",
            "Deterministic, environment, or model verification failures.",
            ("environment", "verifier", "reason"),
            registry=self.registry,
        )
        self.agent_trajectory_alerts_total = Counter(
            "agent_trajectory_alerts_total",
            "Trajectory control alerts.",
            ("environment", "severity", "reason"),
            registry=self.registry,
        )
        self.agent_budget_utilization_ratio = Histogram(
            "agent_budget_utilization_ratio",
            "Per-run budget utilization distribution.",
            ("environment", "use_case", "tenant_tier", "budget_type"),
            buckets=_RATIO_BUCKETS,
            registry=self.registry,
        )
        self.agent_activity_executions_total = Counter(
            "agent_activity_executions_total",
            "Temporal Activity executions by stable activity name and outcome.",
            ("environment", "activity", "status"),
            registry=self.registry,
        )
        self.agent_activity_duration_seconds = Histogram(
            "agent_activity_duration_seconds",
            "Temporal Activity execution duration.",
            ("environment", "activity", "status"),
            registry=self.registry,
        )
        self.agent_queue_backlog = Gauge(
            "agent_queue_backlog",
            "Approximate number of pending tasks in a managed task queue.",
            ("environment", "queue"),
            registry=self.registry,
        )
        self.agent_queue_oldest_age_seconds = Gauge(
            "agent_queue_oldest_age_seconds",
            "Approximate age of the oldest pending task.",
            ("environment", "queue"),
            registry=self.registry,
        )
        self.agent_dependency_health = Gauge(
            "agent_dependency_health",
            "Most recent dependency probe result (1 healthy, 0 unhealthy).",
            ("environment", "dependency"),
            registry=self.registry,
        )
        self.agent_capacity_utilization_ratio = Gauge(
            "agent_capacity_utilization_ratio",
            "Current bounded capacity utilization by resource class.",
            ("environment", "resource"),
            registry=self.registry,
        )
        self.agent_security_events_total = Counter(
            "agent_security_events_total",
            "Confirmed or blocked security events by stable category.",
            ("environment", "category", "severity", "outcome"),
            registry=self.registry,
        )
        self.agent_kill_switch_state = Gauge(
            "agent_kill_switch_state",
            "Last observed kill-switch state (1 active, 0 inactive).",
            ("environment", "scope", "mode"),
            registry=self.registry,
        )
        self.collectors = (
            self.agent_runs_total,
            self.agent_run_accept_requests_total,
            self.agent_run_duration_seconds,
            self.agent_task_duration_seconds,
            self.agent_model_requests_total,
            self.agent_model_tokens_total,
            self.agent_model_latency_seconds,
            self.agent_model_cache_total,
            self.agent_model_upgrades_total,
            self.agent_cost_usd_total,
            self.agent_platform_cost_usd_total,
            self.agent_tenant_budget_utilization_ratio,
            self.agent_success_cost_usd,
            self.agent_tool_calls_total,
            self.agent_tool_latency_seconds,
            self.agent_tool_result_bytes,
            self.agent_mcp_server_health,
            self.agent_mcp_result_bytes,
            self.agent_policy_decisions_total,
            self.agent_actions_total,
            self.agent_approvals_duration_seconds,
            self.agent_pending_approvals,
            self.agent_pending_approval_oldest_age_seconds,
            self.agent_pending_approval_overdue_cleanup_lag_seconds,
            self.agent_outbox_events_current,
            self.agent_webhook_deliveries_current,
            self.agent_approval_notification_latency_seconds,
            self.agent_approval_notification_samples,
            self.agent_operational_metrics_collector_up,
            self.agent_operational_metrics_last_success_timestamp_seconds,
            self.agent_verification_failures_total,
            self.agent_trajectory_alerts_total,
            self.agent_budget_utilization_ratio,
            self.agent_activity_executions_total,
            self.agent_activity_duration_seconds,
            self.agent_queue_backlog,
            self.agent_queue_oldest_age_seconds,
            self.agent_dependency_health,
            self.agent_capacity_utilization_ratio,
            self.agent_security_events_total,
            self.agent_kill_switch_state,
        )
