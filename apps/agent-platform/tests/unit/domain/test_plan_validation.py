from __future__ import annotations

import sys
import unittest
from decimal import Decimal
from pathlib import Path

from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).parents[3] / "src"))

from agent_platform.domain import (
    DataClassification,
    DataScope,
    ExecutionPlan,
    Principal,
    RiskLevel,
    SuccessCriterion,
    TaskContract,
    TaskSpec,
    validate_plan_against_contract,
)
from agent_platform.domain.errors import DomainInvariantError


def make_contract(**overrides: object) -> TaskContract:
    values: dict[str, object] = {
        "goal": "Complete the bounded task",
        "success_criteria": [
            SuccessCriterion(
                id="must-1",
                description="Result passes deterministic validation",
                verification="schema",
            )
        ],
        "principal": Principal(
            user_id="user-1",
            tenant_id="tenant-1",
            auth_strength="mfa",
        ),
        "data_scope": DataScope(
            tenant_id="tenant-1",
            resource_types={"knowledge"},
            classifications={DataClassification.INTERNAL},
        ),
        "risk": RiskLevel.HIGH,
        "allowed_capabilities": {"knowledge.search", "artifact.create"},
        "max_cost_usd": Decimal("4.00"),
        "max_duration_seconds": 300,
        "max_parallelism": 2,
        "max_replans": 2,
    }
    values.update(overrides)
    return TaskContract(**values)


def task(
    task_id: str,
    *,
    depends_on: list[str] | None = None,
    capabilities: list[str] | None = None,
    cost: str = "1.00",
    timeout: int = 60,
    risk: RiskLevel = RiskLevel.HIGH,
) -> TaskSpec:
    return TaskSpec(
        id=task_id,
        kind="analysis",
        objective=f"Execute {task_id}",
        depends_on=depends_on or [],
        capability_names=capabilities or [],
        output_schema="Result@1.0",
        risk=risk,
        timeout_seconds=timeout,
        estimated_cost_usd=Decimal(cost),
    )


class DagShapeTests(unittest.TestCase):
    def test_duplicate_ids_are_rejected(self) -> None:
        with self.assertRaises(ValidationError) as caught:
            ExecutionPlan(
                plan_version=1,
                tasks=[task("same"), task("same")],
                final_task_id="same",
                expected_total_cost_usd=Decimal("2.00"),
            )
        self.assertIn("PLAN_DUPLICATE_TASK_ID", str(caught.exception))

    def test_unknown_dependencies_are_rejected_with_task_context(self) -> None:
        with self.assertRaises(ValidationError) as caught:
            ExecutionPlan(
                plan_version=1,
                tasks=[task("final", depends_on=["missing"])],
                final_task_id="final",
                expected_total_cost_usd=Decimal("1.00"),
            )
        message = str(caught.exception)
        self.assertIn("PLAN_UNKNOWN_DEPENDENCY", message)
        self.assertIn("final", message)
        self.assertIn("missing", message)

    def test_cycles_are_rejected_with_cycle_path(self) -> None:
        with self.assertRaises(ValidationError) as caught:
            ExecutionPlan(
                plan_version=1,
                tasks=[
                    task("a", depends_on=["c"]),
                    task("b", depends_on=["a"]),
                    task("c", depends_on=["b"]),
                ],
                final_task_id="c",
                expected_total_cost_usd=Decimal("3.00"),
            )
        self.assertIn("PLAN_DEPENDENCY_CYCLE", str(caught.exception))
        self.assertIn("a", str(caught.exception))

    def test_final_task_must_exist_and_be_a_sink(self) -> None:
        with self.assertRaises(ValidationError) as missing:
            ExecutionPlan(
                plan_version=1,
                tasks=[task("a")],
                final_task_id="missing",
                expected_total_cost_usd=Decimal("1.00"),
            )
        self.assertIn("PLAN_FINAL_TASK_MISSING", str(missing.exception))

        with self.assertRaises(ValidationError) as not_sink:
            ExecutionPlan(
                plan_version=1,
                tasks=[task("a"), task("b", depends_on=["a"])],
                final_task_id="a",
                expected_total_cost_usd=Decimal("2.00"),
            )
        self.assertIn("PLAN_FINAL_TASK_NOT_SINK", str(not_sink.exception))

    def test_declared_cost_must_equal_task_cost_sum(self) -> None:
        with self.assertRaises(ValidationError) as caught:
            ExecutionPlan(
                plan_version=1,
                tasks=[task("a", cost="1.25")],
                final_task_id="a",
                expected_total_cost_usd=Decimal("1.00"),
            )
        self.assertIn("PLAN_COST_MISMATCH", str(caught.exception))


class ContractPlanValidationTests(unittest.TestCase):
    def test_valid_bounded_plan_passes(self) -> None:
        plan = ExecutionPlan(
            plan_version=1,
            tasks=[
                task("research-a", capabilities=["knowledge.search"], risk=RiskLevel.MEDIUM),
                task("research-b", capabilities=["knowledge.search"], risk=RiskLevel.MEDIUM),
                task(
                    "final",
                    depends_on=["research-a", "research-b"],
                    capabilities=["artifact.create"],
                    risk=RiskLevel.HIGH,
                ),
            ],
            final_task_id="final",
            expected_total_cost_usd=Decimal("3.00"),
        )
        validate_plan_against_contract(plan, make_contract())

    def test_unknown_or_unapproved_capability_is_denied(self) -> None:
        plan = ExecutionPlan(
            plan_version=1,
            tasks=[task("final", capabilities=["network.http"])],
            final_task_id="final",
            expected_total_cost_usd=Decimal("1.00"),
        )
        with self.assertRaises(DomainInvariantError) as caught:
            validate_plan_against_contract(
                plan,
                make_contract(),
                known_capabilities={"knowledge.search", "artifact.create"},
            )
        self.assertEqual(caught.exception.code, "PLAN_CAPABILITY_NOT_ALLOWED")
        self.assertEqual(caught.exception.context["task_id"], "final")
        self.assertEqual(caught.exception.context["capability"], "network.http")

    def test_plan_budget_and_critical_path_are_hard_limits(self) -> None:
        over_budget = ExecutionPlan(
            plan_version=1,
            tasks=[
                task("a", cost="2.50"),
                task("final", depends_on=["a"], cost="2.00"),
            ],
            final_task_id="final",
            expected_total_cost_usd=Decimal("4.50"),
        )
        with self.assertRaises(DomainInvariantError) as budget:
            validate_plan_against_contract(over_budget, make_contract())
        self.assertEqual(budget.exception.code, "BUDGET_EXHAUSTED")

        over_time = ExecutionPlan(
            plan_version=1,
            tasks=[
                task("a", timeout=180),
                task("final", depends_on=["a"], timeout=180),
            ],
            final_task_id="final",
            expected_total_cost_usd=Decimal("2.00"),
        )
        with self.assertRaises(DomainInvariantError) as duration:
            validate_plan_against_contract(over_time, make_contract())
        self.assertEqual(duration.exception.code, "PLAN_DURATION_EXCEEDED")
        self.assertEqual(duration.exception.context["critical_path_seconds"], 360)

    def test_parallel_frontier_cannot_exceed_contract_limit(self) -> None:
        plan = ExecutionPlan(
            plan_version=1,
            tasks=[
                task("a", risk=RiskLevel.MEDIUM),
                task("b", risk=RiskLevel.MEDIUM),
                task("c", risk=RiskLevel.MEDIUM),
                task("final", depends_on=["a", "b", "c"]),
            ],
            final_task_id="final",
            expected_total_cost_usd=Decimal("4.00"),
        )
        with self.assertRaises(DomainInvariantError) as caught:
            validate_plan_against_contract(plan, make_contract(max_parallelism=2))
        self.assertEqual(caught.exception.code, "PLAN_PARALLELISM_EXCEEDED")
        self.assertEqual(caught.exception.context["parallel_width"], 3)

    def test_plan_cannot_downgrade_overall_or_final_risk(self) -> None:
        plan = ExecutionPlan(
            plan_version=1,
            tasks=[task("final", risk=RiskLevel.MEDIUM)],
            final_task_id="final",
            expected_total_cost_usd=Decimal("1.00"),
        )
        with self.assertRaises(DomainInvariantError) as caught:
            validate_plan_against_contract(plan, make_contract(risk=RiskLevel.HIGH))
        self.assertEqual(caught.exception.code, "PLAN_RISK_DOWNGRADE")


if __name__ == "__main__":
    unittest.main()
