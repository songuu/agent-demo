from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from agent_platform.domain.enums import RiskLevel


@dataclass(frozen=True, slots=True)
class ModelRoute:
    model: str
    reasoning: dict[str, str]
    max_output_tokens: int
    parallel_tool_calls: bool


class ModelPolicy:
    def __init__(self, allowlist: tuple[str, ...]) -> None:
        self._allowlist = frozenset(allowlist)

    def validate_model(self, model: str) -> str:
        if model not in self._allowlist:
            raise ValueError(f"MODEL_NOT_ALLOWED: {model}")
        return model

    def route(
        self,
        role: str,
        risk: RiskLevel,
        retry_count: int,
        complexity: float,
        remaining_budget: Decimal,
    ) -> ModelRoute:
        del complexity
        if remaining_budget <= 0:
            raise ValueError("BUDGET_EXHAUSTED")
        if role in {"planner", "verifier"} and risk in {
            RiskLevel.HIGH,
            RiskLevel.CRITICAL,
        }:
            route = ModelRoute(
                "gpt-5.6-sol",
                {"mode": "pro", "effort": "high"},
                32_000,
                False,
            )
        elif role in {"planner", "verifier"}:
            route = ModelRoute(
                "gpt-5.6-sol", {"effort": "medium"}, 20_000, False
            )
        elif role == "classifier":
            route = ModelRoute("gpt-5.6-luna", {"effort": "low"}, 4_000, False)
        elif role == "worker" and retry_count == 0 and risk != RiskLevel.CRITICAL:
            route = ModelRoute("gpt-5.6-terra", {"effort": "medium"}, 16_000, True)
        else:
            route = ModelRoute("gpt-5.6-sol", {"effort": "high"}, 24_000, False)
        self.validate_model(route.model)
        return route
