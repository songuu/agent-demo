from __future__ import annotations

import asyncio
from dataclasses import dataclass
from decimal import Decimal
from types import SimpleNamespace

import pytest

from agent_platform.application.dag_scheduler import (
    BudgetLedger,
    CancellationToken,
    DagScheduler,
    SchedulerContext,
)
from agent_platform.application.errors import PlatformError
from agent_platform.domain.enums import RiskLevel


@dataclass
class Task:
    id: str
    depends_on: list[str]
    estimated_cost_usd: Decimal = Decimal("1")
    timeout_seconds: int = 2
    max_tool_calls: int = 3
    risk: RiskLevel = RiskLevel.MEDIUM


class Runtime:
    def __init__(self) -> None:
        self.started: list[str] = []
        self.active = 0
        self.max_active = 0

    async def execute_task(
        self, context: object, task: Task, dependencies: dict[str, object]
    ) -> object:
        self.started.append(task.id)
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        await asyncio.sleep(0.01)
        self.active -= 1
        return {"task_id": task.id, "dependencies": sorted(dependencies)}


class Checkpoint:
    def __init__(self) -> None:
        self.saved: list[str] = []

    async def task_completed(self, task_id: str, output: object) -> None:
        self.saved.append(task_id)


@pytest.mark.asyncio
async def test_dag_executes_ready_frontiers_with_bounded_parallelism() -> None:
    runtime = Runtime()
    checkpoint = Checkpoint()
    plan = SimpleNamespace(
        tasks=[
            Task("a", []),
            Task("b", []),
            Task("final", ["a", "b"]),
        ]
    )
    context = SchedulerContext(
        contract=SimpleNamespace(max_parallelism=2),
        budget=BudgetLedger(
            max_cost_usd=Decimal("5"),
            max_tool_calls=10,
            deadline_monotonic=asyncio.get_running_loop().time() + 10,
        ),
        cancel_token=CancellationToken(),
        checkpoint=checkpoint,
        runtime_context=SimpleNamespace(),
    )

    outputs = await DagScheduler(runtime).execute(context, plan)

    assert set(outputs) == {"a", "b", "final"}
    assert runtime.max_active == 2
    assert runtime.started.index("final") > runtime.started.index("a")
    assert runtime.started.index("final") > runtime.started.index("b")
    assert set(checkpoint.saved) == set(outputs)


@pytest.mark.asyncio
async def test_budget_is_checked_before_new_task_and_cancellation_is_immediate() -> None:
    runtime = Runtime()
    plan = SimpleNamespace(tasks=[Task("a", [], estimated_cost_usd=Decimal("2"))])
    cancelled = CancellationToken()
    cancelled.cancel("kill-switch")
    context = SchedulerContext(
        contract=SimpleNamespace(max_parallelism=1),
        budget=BudgetLedger(
            max_cost_usd=Decimal("1"),
            max_tool_calls=1,
            deadline_monotonic=asyncio.get_running_loop().time() + 10,
        ),
        cancel_token=cancelled,
        checkpoint=Checkpoint(),
        runtime_context=SimpleNamespace(),
    )

    with pytest.raises(PlatformError) as caught:
        await DagScheduler(runtime).execute(context, plan)
    assert caught.value.code == "RUN_CANCELLED"
    assert runtime.started == []


@pytest.mark.asyncio
async def test_deadline_has_a_distinct_stable_error_code() -> None:
    ledger = BudgetLedger(
        max_cost_usd=Decimal("10"),
        max_tool_calls=10,
        deadline_monotonic=asyncio.get_running_loop().time() - 1,
    )

    with pytest.raises(PlatformError) as expired:
        ledger.assert_can_start(Task("late", []))

    assert expired.value.code == "DEADLINE_EXCEEDED"
    assert expired.value.http_status == 408


def test_budget_thresholds_are_deterministic() -> None:
    ledger = BudgetLedger(
        max_cost_usd=Decimal("10"),
        max_tool_calls=10,
        deadline_monotonic=100,
    )
    ledger.record_cost(Decimal("5"))
    assert ledger.utilization == Decimal("0.5")
    assert ledger.control_level == "midpoint"
    ledger.record_cost(Decimal("3"))
    assert ledger.control_level == "restrict"
    ledger.record_cost(Decimal("1.5"))
    assert ledger.control_level == "critical_only"
    with pytest.raises(PlatformError, match="hard budget"):
        ledger.record_cost(Decimal("0.5"))
