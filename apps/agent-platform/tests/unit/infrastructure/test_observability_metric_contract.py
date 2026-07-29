from __future__ import annotations

import pytest
from prometheus_client import CollectorRegistry

from agent_platform.infrastructure.observability.metrics import PlatformMetrics


@pytest.mark.parametrize(
    ("attribute", "metric_type", "label_names"),
    (
        (
            "agent_runs_total",
            "counter",
            ("environment", "use_case", "risk", "status", "tenant_tier"),
        ),
        (
            "agent_run_duration_seconds",
            "histogram",
            ("environment", "use_case", "risk", "status"),
        ),
        (
            "agent_task_duration_seconds",
            "histogram",
            ("environment", "kind", "model", "status"),
        ),
        (
            "agent_cost_usd_total",
            "counter",
            ("environment", "model", "use_case", "tenant_tier"),
        ),
        (
            "agent_approvals_duration_seconds",
            "histogram",
            ("environment", "policy", "decision"),
        ),
        (
            "agent_verification_failures_total",
            "counter",
            ("environment", "verifier", "reason"),
        ),
        (
            "agent_trajectory_alerts_total",
            "counter",
            ("environment", "severity", "reason"),
        ),
        (
            "agent_budget_utilization_ratio",
            "histogram",
            ("environment", "use_case", "tenant_tier", "budget_type"),
        ),
    ),
)
def test_metric_type_and_label_schema_match_the_observability_contract(
    attribute: str,
    metric_type: str,
    label_names: tuple[str, ...],
) -> None:
    metrics = PlatformMetrics(CollectorRegistry())
    metric = getattr(metrics, attribute)

    assert metric._type == metric_type
    assert tuple(metric._labelnames) == label_names


def test_prometheus_sample_shapes_distinguish_histograms_counters_and_gauges() -> None:
    registry = CollectorRegistry()
    metrics = PlatformMetrics(registry)

    metrics.agent_task_duration_seconds.labels(
        environment="test",
        kind="analysis",
        model="gpt-5.6-sol",
        status="completed",
    ).observe(0.1)
    metrics.agent_trajectory_alerts_total.labels(
        environment="test",
        severity="warning",
        reason="repeated_action",
    ).inc()
    metrics.agent_budget_utilization_ratio.labels(
        environment="test",
        use_case="knowledge-report",
        tenant_tier="standard",
        budget_type="cost",
    ).observe(0.5)

    sample_names = {
        sample.name for metric_family in registry.collect() for sample in metric_family.samples
    }
    assert "agent_task_duration_seconds_bucket" in sample_names
    assert "agent_task_duration_seconds_sum" in sample_names
    assert "agent_trajectory_alerts_total" in sample_names
    assert "agent_budget_utilization_ratio_bucket" in sample_names
    assert "agent_budget_utilization_ratio_sum" in sample_names
