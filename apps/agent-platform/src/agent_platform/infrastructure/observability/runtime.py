from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from decimal import Decimal
from hashlib import sha256
from typing import Protocol, cast

import structlog
from opentelemetry import trace
from opentelemetry.trace import Span, Tracer

from agent_platform.infrastructure.observability.metrics import PlatformMetrics


class EventLogger(Protocol):
    def info(self, event: str, **event_fields: object) -> object: ...


_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9_.:/-]{1,128}$")
_TENANT_TIERS = frozenset({"free", "standard", "enterprise", "internal", "unknown"})
_COST_COMPONENTS = ("model", "tool", "sandbox", "artifact", "workflow", "observability")
_BUDGET_CONTROL_LEVELS = frozenset({"normal", "midpoint", "restrict", "critical_only", "stop"})
_TRACE_ATTRIBUTE_KEYS = frozenset(
    {
        "action_id",
        "action_type",
        "activity",
        "attempt",
        "active",
        "backlog",
        "cached_input_tokens",
        "category",
        "correlation_id",
        "cost_usd",
        "dependency",
        "from_model",
        "decision",
        "duration_seconds",
        "effect",
        "environment",
        "http_method",
        "http_route",
        "plan_id",
        "plan_version",
        "input_tokens",
        "kind",
        "model",
        "phase",
        "policy",
        "reason_code",
        "reason",
        "risk",
        "run_id",
        "severity",
        "role",
        "status",
        "task_id",
        "tenant_id_hash",
        "tool_invocation_id",
        "workflow_id",
        "workflow_run_id",
        "task_kind",
        "tenant_tier",
        "tool",
        "tool_calls",
        "use_case",
        "verification_type",
        "verifier",
        "oldest_age_seconds",
        "output_tokens",
        "outcome",
        "queue",
        "result_bytes",
        "server",
        "to_model",
        "utilization_ratio",
        "version",
    }
)


class RuntimeObservability:
    """Privacy-safe runtime telemetry facade.

    Identity and content never become metric labels. Correlation-chain identifiers
    are allowed only in structured logs and traces, while tenant identity is hashed
    before it reaches a shared observability backend.
    """

    def __init__(
        self,
        metrics: PlatformMetrics,
        *,
        environment: str,
        logger: EventLogger | None = None,
        tracer: Tracer | None = None,
    ) -> None:
        self.metrics = metrics
        self.environment = self._label(environment)
        self._logger = logger or cast(
            EventLogger,
            structlog.get_logger("agent_platform.runtime"),
        )
        self._tracer = tracer or trace.get_tracer("agent_platform.runtime")

    @contextmanager
    def span(
        self,
        name: str,
        attributes: Mapping[str, str | int | float | bool] | None = None,
    ) -> Iterator[Span]:
        safe_attributes = {
            key: self._label(value) if isinstance(value, str) else value
            for key, value in (attributes or {}).items()
            if key in _TRACE_ATTRIBUTE_KEYS
        }
        safe_attributes.setdefault("environment", self.environment)
        with self._tracer.start_as_current_span(
            name,
            attributes=safe_attributes,
            record_exception=False,
            set_status_on_exception=False,
        ) as current:
            log_context = dict(safe_attributes)
            span_context = current.get_span_context()
            if span_context.is_valid:
                log_context["trace_id"] = f"{span_context.trace_id:032x}"
                log_context["span_id"] = f"{span_context.span_id:016x}"
            with structlog.contextvars.bound_contextvars(**log_context):
                yield current

    @staticmethod
    def tenant_hash(tenant_id: str) -> str:
        normalized = tenant_id.strip()
        if not normalized:
            raise ValueError("TENANT_ID_REQUIRED_FOR_OBSERVABILITY_HASH")
        return f"sha256:{sha256(normalized.encode('utf-8')).hexdigest()}"

    def record_run_accept(self, *, outcome: str) -> None:
        labels = {
            "environment": self.environment,
            "outcome": self._label(outcome),
        }
        self.metrics.agent_run_accept_requests_total.labels(**labels).inc()
        self._emit("run.accept", **labels)

    def record_run_received(
        self,
        *,
        use_case: str,
        risk: str,
        tenant_tier: str = "unknown",
    ) -> None:
        labels = {
            "environment": self.environment,
            "use_case": self._label(use_case),
            "risk": self._label(risk),
            "status": "received",
            "tenant_tier": self._tenant_tier(tenant_tier),
        }
        self.metrics.agent_runs_total.labels(**labels).inc()
        self._emit("run.received", **labels)

    def record_run_terminal(
        self,
        *,
        use_case: str,
        risk: str,
        status: str,
        duration_seconds: float,
        cost_usd: Decimal | float,
        cost_budget_usd: Decimal | float,
        tool_calls: int,
        tool_call_budget: int,
        duration_budget_seconds: int,
        tenant_tier: str = "unknown",
        model: str = "unknown",
    ) -> None:
        use_case_label = self._label(use_case)
        risk_label = self._label(risk)
        status_label = self._label(status)
        tier_label = self._tenant_tier(tenant_tier)
        model_label = self._label(model)
        duration = max(float(duration_seconds), 0.0)
        cost = max(float(cost_usd), 0.0)
        self.metrics.agent_runs_total.labels(
            self.environment,
            use_case_label,
            risk_label,
            status_label,
            tier_label,
        ).inc()
        self.metrics.agent_run_duration_seconds.labels(
            self.environment,
            use_case_label,
            risk_label,
            status_label,
        ).observe(duration)
        if cost > 0 and model_label != "unknown":
            self.metrics.agent_cost_usd_total.labels(
                self.environment,
                model_label,
                use_case_label,
                tier_label,
            ).inc(cost)
        self._set_budget_ratio(
            use_case=use_case_label,
            tenant_tier=tier_label,
            budget_type="cost",
            used=cost,
            limit=float(cost_budget_usd),
        )
        self._set_budget_ratio(
            use_case=use_case_label,
            tenant_tier=tier_label,
            budget_type="tool_calls",
            used=float(max(tool_calls, 0)),
            limit=float(max(tool_call_budget, 0)),
        )
        self._set_budget_ratio(
            use_case=use_case_label,
            tenant_tier=tier_label,
            budget_type="duration",
            used=duration,
            limit=float(max(duration_budget_seconds, 0)),
        )
        self._emit(
            "run.terminal",
            environment=self.environment,
            use_case=use_case_label,
            risk=risk_label,
            status=status_label,
            tenant_tier=tier_label,
            model=model_label,
            duration_seconds=duration,
            cost_usd=cost,
            tool_calls=max(tool_calls, 0),
        )

    def record_cost_settlement(
        self,
        *,
        components: Mapping[object, Decimal | float],
        daily_utilization: Decimal | float,
        monthly_utilization: Decimal | float,
        control_level: str,
        use_case: str,
        tenant_tier: str,
        succeeded: bool,
    ) -> None:
        use_case_label = self._label(use_case)
        tier_label = self._tenant_tier(tenant_tier)
        level_label = control_level if control_level in _BUDGET_CONTROL_LEVELS else "unknown"
        normalized = {
            self._label(component): max(float(amount), 0.0)
            for component, amount in components.items()
        }
        total = 0.0
        for component in _COST_COMPONENTS:
            amount = normalized.get(component, 0.0)
            total += amount
            if amount > 0:
                self.metrics.agent_platform_cost_usd_total.labels(
                    self.environment,
                    component,
                    use_case_label,
                    tier_label,
                ).inc(amount)
        for period, utilization in (
            ("daily", daily_utilization),
            ("monthly", monthly_utilization),
        ):
            self.metrics.agent_tenant_budget_utilization_ratio.labels(
                self.environment,
                period,
                level_label,
                tier_label,
            ).observe(max(float(utilization), 0.0))
        if succeeded:
            self.metrics.agent_success_cost_usd.labels(
                self.environment,
                use_case_label,
                tier_label,
            ).observe(total)
        self._emit(
            "cost.reconciled",
            environment=self.environment,
            use_case=use_case_label,
            tenant_tier=tier_label,
            cost_usd=total,
            utilization_ratio=max(
                float(daily_utilization),
                float(monthly_utilization),
            ),
        )

    def record_task(
        self,
        *,
        kind: str,
        model: str,
        status: str,
        duration_seconds: float,
    ) -> None:
        labels = {
            "environment": self.environment,
            "kind": self._label(kind),
            "model": self._label(model),
            "status": self._label(status),
        }
        duration = max(duration_seconds, 0.0)
        self.metrics.agent_task_duration_seconds.labels(**labels).observe(duration)
        self._emit("task.completed", **labels, duration_seconds=duration)

    def record_model(
        self,
        *,
        role: str,
        model: str,
        status: str,
        duration_seconds: float,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cached_input_tokens: int = 0,
        cost_usd: Decimal | float = 0,
        use_case: str = "unknown",
        tenant_tier: str = "unknown",
    ) -> None:
        labels = {
            "environment": self.environment,
            "role": self._label(role),
            "model": self._label(model),
            "status": self._label(status),
        }
        duration = max(duration_seconds, 0.0)
        cached_tokens = max(cached_input_tokens, 0)
        cost = max(float(cost_usd), 0.0)
        self.metrics.agent_model_requests_total.labels(**labels).inc()
        self.metrics.agent_model_latency_seconds.labels(**labels).observe(duration)
        for direction, tokens in (("input", input_tokens), ("output", output_tokens)):
            if tokens > 0:
                self.metrics.agent_model_tokens_total.labels(
                    self.environment,
                    labels["role"],
                    labels["model"],
                    direction,
                ).inc(tokens)
        self.metrics.agent_model_cache_total.labels(
            self.environment,
            labels["role"],
            labels["model"],
            "hit" if cached_tokens > 0 else "miss",
        ).inc()
        if cost > 0:
            self.metrics.agent_cost_usd_total.labels(
                self.environment,
                labels["model"],
                self._label(use_case),
                self._tenant_tier(tenant_tier),
            ).inc(cost)
        self._emit(
            "model.completed",
            **labels,
            duration_seconds=duration,
            input_tokens=max(input_tokens, 0),
            output_tokens=max(output_tokens, 0),
            cached_input_tokens=cached_tokens,
            cost_usd=cost,
        )

    def record_model_upgrade(
        self,
        *,
        role: str,
        from_model: str,
        to_model: str,
        reason: str,
    ) -> None:
        labels = {
            "environment": self.environment,
            "role": self._label(role),
            "from_model": self._label(from_model),
            "to_model": self._label(to_model),
            "reason": self._label(reason),
        }
        self.metrics.agent_model_upgrades_total.labels(**labels).inc()
        self._emit("model.upgraded", **labels)

    def record_tool(
        self,
        *,
        tool: str,
        version: str,
        effect: str,
        status: str,
        duration_seconds: float,
        result_bytes: int = 0,
    ) -> None:
        labels = {
            "environment": self.environment,
            "tool": self._label(tool),
            "version": self._label(version),
            "effect": self._label(effect),
            "status": self._label(status),
        }
        duration = max(duration_seconds, 0.0)
        normalized_result_bytes = max(result_bytes, 0)
        self.metrics.agent_tool_calls_total.labels(**labels).inc()
        self.metrics.agent_tool_latency_seconds.labels(
            self.environment,
            labels["tool"],
            labels["status"],
        ).observe(duration)
        self.metrics.agent_tool_result_bytes.labels(
            self.environment,
            labels["tool"],
            labels["status"],
        ).observe(normalized_result_bytes)
        self._emit(
            "tool.completed",
            **labels,
            duration_seconds=duration,
            result_bytes=normalized_result_bytes,
        )

    def record_policy(
        self,
        *,
        phase: str,
        allowed: bool,
        reason_codes: tuple[str, ...],
    ) -> None:
        decision = "allow" if allowed else "deny"
        reason_code = self._label(
            sorted(reason_codes)[0] if reason_codes else ("allowed" if allowed else "unspecified")
        )
        labels = {
            "environment": self.environment,
            "phase": self._label(phase),
            "decision": decision,
            "reason_code": reason_code,
        }
        self.metrics.agent_policy_decisions_total.labels(**labels).inc()
        self._emit("policy.decision", **labels)

    def record_action(self, *, action_type: str, risk: str, status: str) -> None:
        labels = {
            "environment": self.environment,
            "action_type": self._label(action_type),
            "risk": self._label(risk),
            "status": self._label(status),
        }
        self.metrics.agent_actions_total.labels(**labels).inc()
        self._emit("action.status", **labels)

    def record_approval(
        self,
        *,
        policy: str,
        decision: str,
        duration_seconds: float,
    ) -> None:
        labels = {
            "environment": self.environment,
            "policy": self._label(policy),
            "decision": self._label(decision),
        }
        self.metrics.agent_approvals_duration_seconds.labels(**labels).observe(
            max(duration_seconds, 0.0)
        )
        self._emit(
            "approval.decision",
            **labels,
            duration_seconds=max(duration_seconds, 0.0),
        )

    def record_verification_failure(
        self,
        *,
        verifier: str,
        reason: str,
    ) -> None:
        labels = {
            "environment": self.environment,
            "verifier": self._label(verifier),
            "reason": self._label(reason),
        }
        self.metrics.agent_verification_failures_total.labels(**labels).inc()
        self._emit("verification.failed", **labels)

    def record_trajectory_alert(self, *, severity: str, reason: str) -> None:
        labels = {
            "environment": self.environment,
            "severity": self._label(severity),
            "reason": self._label(reason),
        }
        self.metrics.agent_trajectory_alerts_total.labels(**labels).inc()
        self._emit("trajectory.alert", **labels)

    def record_activity(
        self,
        *,
        activity: str,
        status: str,
        duration_seconds: float,
    ) -> None:
        labels = {
            "environment": self.environment,
            "activity": self._label(activity),
            "status": self._label(status),
        }
        duration = max(duration_seconds, 0.0)
        self.metrics.agent_activity_executions_total.labels(**labels).inc()
        self.metrics.agent_activity_duration_seconds.labels(**labels).observe(duration)
        self._emit("activity.completed", **labels, duration_seconds=duration)

    def record_queue_state(
        self,
        *,
        queue: str,
        backlog: int,
        oldest_age_seconds: float,
    ) -> None:
        labels = (self.environment, self._label(queue))
        self.metrics.agent_queue_backlog.labels(*labels).set(max(backlog, 0))
        self.metrics.agent_queue_oldest_age_seconds.labels(*labels).set(
            max(oldest_age_seconds, 0.0)
        )
        self._emit(
            "queue.observed",
            environment=self.environment,
            queue=labels[1],
            backlog=max(backlog, 0),
            oldest_age_seconds=max(oldest_age_seconds, 0.0),
        )

    def record_dependency_health(self, statuses: Mapping[str, str]) -> None:
        for dependency, status in statuses.items():
            dependency_label = self._label(dependency)
            healthy = status == "ok"
            self.metrics.agent_dependency_health.labels(
                self.environment,
                dependency_label,
            ).set(1 if healthy else 0)
            self._emit(
                "dependency.health",
                environment=self.environment,
                dependency=dependency_label,
                status="ok" if healthy else "error",
            )

    def record_capacity(self, *, resource: str, utilization_ratio: float) -> None:
        resource_label = self._label(resource)
        ratio = min(max(utilization_ratio, 0.0), 1.0)
        self.metrics.agent_capacity_utilization_ratio.labels(
            self.environment,
            resource_label,
        ).set(ratio)
        self._emit(
            "capacity.observed",
            environment=self.environment,
            resource=resource_label,
            utilization_ratio=ratio,
        )

    def record_mcp_server(
        self,
        *,
        server: str,
        healthy: bool,
        result_bytes: int = 0,
    ) -> None:
        server_label = self._label(server)
        self.metrics.agent_mcp_server_health.labels(
            self.environment,
            server_label,
        ).set(1 if healthy else 0)
        if result_bytes > 0:
            self.metrics.agent_mcp_result_bytes.labels(
                self.environment,
                server_label,
            ).observe(result_bytes)
        self._emit(
            "mcp.health",
            environment=self.environment,
            server=server_label,
            status="ok" if healthy else "error",
            result_bytes=max(result_bytes, 0),
        )

    def record_security_event(
        self,
        *,
        category: str,
        severity: str,
        outcome: str,
    ) -> None:
        labels = {
            "environment": self.environment,
            "category": self._label(category),
            "severity": self._label(severity),
            "outcome": self._label(outcome),
        }
        self.metrics.agent_security_events_total.labels(**labels).inc()
        self._emit("security.event", **labels)

    def record_kill_switch(self, *, scope: str, mode: str, active: bool) -> None:
        labels = {
            "environment": self.environment,
            "scope": self._label(scope),
            "mode": self._label(mode),
        }
        self.metrics.agent_kill_switch_state.labels(**labels).set(1 if active else 0)
        self._emit("kill_switch.changed", **labels, active=active)

    def _set_budget_ratio(
        self,
        *,
        use_case: str,
        tenant_tier: str,
        budget_type: str,
        used: float,
        limit: float,
    ) -> None:
        ratio = 0.0 if limit <= 0 and used <= 0 else 1.0 if limit <= 0 else used / limit
        self.metrics.agent_budget_utilization_ratio.labels(
            self.environment,
            use_case,
            tenant_tier,
            budget_type,
        ).observe(max(ratio, 0.0))

    def _emit(self, event: str, **fields: object) -> None:
        current_span = trace.get_current_span()
        if current_span.is_recording():
            attributes: dict[str, str | bool | int | float] = {}
            for key, value in fields.items():
                if key in _TRACE_ATTRIBUTE_KEYS and isinstance(value, (str, bool, int, float)):
                    attributes[key] = value
            current_span.add_event(event, attributes=attributes)
        try:
            self._logger.info(event, **fields)
        except Exception:
            # Telemetry transport failures must not alter the business outcome.
            return

    @staticmethod
    def _label(value: object) -> str:
        candidate = str(value).strip()
        return candidate if _LABEL_PATTERN.fullmatch(candidate) else "other"

    @staticmethod
    def _tenant_tier(value: str) -> str:
        candidate = value.strip().lower()
        return candidate if candidate in _TENANT_TIERS else "unknown"
