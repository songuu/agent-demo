from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def evaluate(policy: dict[str, Any], results: dict[str, Any]) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []

    def minimum(metric: str, policy_key: str) -> None:
        actual = float(results[metric])
        expected = float(policy[policy_key])
        if actual < expected:
            violations.append({"metric": metric, "expected": f">={expected}", "actual": actual})

    def maximum(metric: str, policy_key: str) -> None:
        actual = float(results[metric])
        expected = float(policy[policy_key])
        if actual > expected:
            violations.append({"metric": metric, "expected": f"<={expected}", "actual": actual})

    minimum("hard_gates_pass_rate", "hard_gates_pass_rate_min")
    minimum("golden_success_rate", "golden_absolute_success_rate_min")
    minimum("evidence_coverage", "evidence_coverage_min")
    minimum("must_criterion_verification_coverage", "must_criterion_verification_coverage_min")
    minimum("tool_selection_accuracy", "tool_selection_accuracy_min")
    minimum("high_risk_human_review_samples", "high_risk_human_review_samples_min")
    maximum("high_risk_tool_misselections", "high_risk_tool_misselections_max")
    maximum("average_cost_regression", "average_cost_regression_max")
    maximum("p95_latency_regression", "p95_latency_regression_max")
    maximum("major_human_review_findings", "major_human_review_findings_max")

    allowed_drop = float(policy["golden_max_drop_from_production"])
    baseline = float(results["production_golden_success_rate"])
    current = float(results["golden_success_rate"])
    if current < baseline - allowed_drop:
        violations.append(
            {
                "metric": "golden_success_rate_drop",
                "expected": f">={baseline - allowed_drop}",
                "actual": current,
            }
        )

    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate Agent platform release gates")
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--results", required=True, type=Path)
    args = parser.parse_args()

    violations = evaluate(_load(args.policy), _load(args.results))
    report = {
        "schema_version": "1.0",
        "decision": "block" if violations else "pass",
        "violations": violations,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 2 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
