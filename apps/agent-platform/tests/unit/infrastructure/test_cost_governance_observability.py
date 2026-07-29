from __future__ import annotations

from decimal import Decimal

from prometheus_client import CollectorRegistry, generate_latest

from agent_platform.infrastructure.observability.metrics import PlatformMetrics
from agent_platform.infrastructure.observability.runtime import RuntimeObservability


def test_full_cost_and_tenant_budget_metrics_are_low_cardinality() -> None:
    registry = CollectorRegistry()
    metrics = PlatformMetrics(registry)
    observability = RuntimeObservability(metrics, environment="prod")

    observability.record_cost_settlement(
        components={
            "model": Decimal("1.1"),
            "tool": Decimal("0.2"),
            "sandbox": Decimal("0.3"),
            "artifact": Decimal("0.4"),
            "workflow": Decimal("0.01"),
            "observability": Decimal("0.02"),
        },
        daily_utilization=Decimal("0.81"),
        monthly_utilization=Decimal("0.53"),
        control_level="restrict",
        use_case="knowledge-report",
        tenant_tier="standard",
        succeeded=True,
    )

    assert tuple(metrics.agent_platform_cost_usd_total._labelnames) == (
        "environment",
        "component",
        "use_case",
        "tenant_tier",
    )
    assert tuple(metrics.agent_tenant_budget_utilization_ratio._labelnames) == (
        "environment",
        "period",
        "control_level",
        "tenant_tier",
    )
    output = generate_latest(registry).decode()
    assert (
        'agent_platform_cost_usd_total{component="sandbox",environment="prod",'
        'tenant_tier="standard",use_case="knowledge-report"} 0.3'
    ) in output
    assert (
        'agent_tenant_budget_utilization_ratio_count{control_level="restrict",'
        'environment="prod",period="daily",tenant_tier="standard"} 1.0'
    ) in output
    assert (
        'agent_success_cost_usd_count{environment="prod",tenant_tier="standard",'
        'use_case="knowledge-report"} 1.0'
    ) in output
    assert all("tenant_id" not in collector._labelnames for collector in metrics.collectors)
