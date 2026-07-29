from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from agent_platform.application.errors import PlatformError


class CancellationToken:
    def __init__(self) -> None:
        self._cancelled = False
        self._reason = ""

    def cancel(self, reason: str) -> None:
        self._cancelled = True
        self._reason = reason

    def raise_if_cancelled(self) -> None:
        if self._cancelled:
            raise PlatformError(
                "RUN_CANCELLED",
                f"Run was cancelled: {self._reason}",
                http_status=409,
            )


@dataclass(slots=True)
class RuntimeUsage:
    """Actual billable usage produced by one bounded runtime Activity."""

    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: Decimal = Decimal("0")
    tool_calls: int = 0
    pricing_catalog_version: str | None = None

    @property
    def is_empty(self) -> bool:
        return (
            self.input_tokens == 0
            and self.output_tokens == 0
            and self.cost_usd == 0
            and self.tool_calls == 0
        )


@dataclass(slots=True)
class BudgetLedger:
    max_cost_usd: Decimal
    max_tool_calls: int
    deadline_monotonic: float
    cost_usd: Decimal = Decimal("0")
    tool_calls: int = 0
    usage: RuntimeUsage = field(default_factory=RuntimeUsage)

    @classmethod
    def for_runtime(
        cls,
        *,
        max_cost_usd: Decimal,
        max_tool_calls: int,
        remaining_seconds: float,
        cost_usd: Decimal = Decimal("0"),
        tool_calls: int = 0,
    ) -> BudgetLedger:
        try:
            now = asyncio.get_running_loop().time()
        except RuntimeError:
            now = 0.0
        return cls(
            max_cost_usd=max_cost_usd,
            max_tool_calls=max_tool_calls,
            deadline_monotonic=now + max(remaining_seconds, 0.0),
            cost_usd=cost_usd,
            tool_calls=tool_calls,
        )

    @property
    def utilization(self) -> Decimal:
        cost_utilization = self.cost_usd / self.max_cost_usd
        tool_utilization = (
            Decimal(self.tool_calls) / Decimal(self.max_tool_calls)
            if self.max_tool_calls > 0
            else (Decimal("1") if self.tool_calls > 0 else Decimal("0"))
        )
        return max(cost_utilization, tool_utilization)

    @property
    def control_level(self) -> str:
        if self.utilization >= Decimal("1"):
            return "stop"
        if self.utilization >= Decimal("0.95"):
            return "critical_only"
        if self.utilization >= Decimal("0.8"):
            return "restrict"
        if self.utilization >= Decimal("0.5"):
            return "midpoint"
        return "normal"

    def record_cost(self, amount: Decimal) -> None:
        if amount < 0:
            raise ValueError("BUDGET_NEGATIVE_COST")
        self.cost_usd += amount
        if self.cost_usd >= self.max_cost_usd:
            raise PlatformError(
                "BUDGET_EXHAUSTED",
                "Run reached its hard budget",
                http_status=409,
            )

    def assert_can_invoke(self, invocation: str) -> None:
        if invocation not in {"model", "tool"}:
            raise ValueError("BUDGET_INVOCATION_KIND_INVALID")
        loop = asyncio.get_running_loop()
        if loop.time() >= self.deadline_monotonic:
            raise PlatformError(
                "DEADLINE_EXCEEDED",
                "Run deadline was exhausted before the next external call",
                retryable=False,
                http_status=408,
            )
        if self.cost_usd >= self.max_cost_usd or self.utilization >= Decimal("1"):
            raise PlatformError(
                "BUDGET_EXHAUSTED",
                "Run reached its hard budget before the next external call",
                http_status=409,
                context={
                    "invocation": invocation,
                    "cost_usd": str(self.cost_usd),
                    "max_cost_usd": str(self.max_cost_usd),
                    "tool_calls": self.tool_calls,
                    "max_tool_calls": self.max_tool_calls,
                },
            )
        if invocation == "tool" and self.tool_calls >= self.max_tool_calls:
            raise PlatformError(
                "BUDGET_EXHAUSTED",
                "Run reached its hard tool-call budget",
                http_status=409,
                context={
                    "tool_calls": self.tool_calls,
                    "max_tool_calls": self.max_tool_calls,
                },
            )

    def record_model_usage(
        self,
        *,
        input_tokens: int,
        output_tokens: int,
        cost_usd: Decimal,
        pricing_catalog_version: str,
    ) -> None:
        if input_tokens < 0 or output_tokens < 0 or cost_usd < 0:
            raise ValueError("BUDGET_USAGE_NEGATIVE")
        existing_version = self.usage.pricing_catalog_version
        if existing_version is not None and existing_version != pricing_catalog_version:
            raise ValueError("BUDGET_PRICING_VERSION_CHANGED_DURING_ACTIVITY")
        self.cost_usd += cost_usd
        self.usage.input_tokens += input_tokens
        self.usage.output_tokens += output_tokens
        self.usage.cost_usd += cost_usd
        self.usage.pricing_catalog_version = pricing_catalog_version

    def record_tool_call(self) -> None:
        self.assert_can_invoke("tool")
        self.tool_calls += 1
        self.usage.tool_calls += 1

    def assert_can_start(self, task: Any) -> None:
        loop = asyncio.get_running_loop()
        if loop.time() >= self.deadline_monotonic:
            raise PlatformError(
                "DEADLINE_EXCEEDED",
                "Run deadline was exhausted",
                retryable=False,
                http_status=408,
            )
        projected = self.cost_usd + Decimal(task.estimated_cost_usd)
        if projected > self.max_cost_usd:
            raise PlatformError(
                "BUDGET_EXHAUSTED",
                "Task would exceed the run cost budget",
                context={
                    "task_id": task.id,
                    "projected_cost_usd": str(projected),
                    "max_cost_usd": str(self.max_cost_usd),
                },
            )
        if self.tool_calls + int(task.max_tool_calls) > self.max_tool_calls:
            raise PlatformError(
                "BUDGET_EXHAUSTED",
                "Task would exceed the tool-call budget",
                context={"task_id": task.id},
            )

    def record_task(self, task: Any) -> None:
        self.cost_usd += Decimal(task.estimated_cost_usd)
        self.tool_calls += int(task.max_tool_calls)

    def remaining_seconds(self) -> float:
        return max(0.0, self.deadline_monotonic - asyncio.get_running_loop().time())


@dataclass(slots=True)
class SchedulerContext:
    contract: Any
    budget: BudgetLedger
    cancel_token: CancellationToken
    checkpoint: Any
    runtime_context: Any


class DagScheduler:
    def __init__(self, runtime: Any) -> None:
        self._runtime = runtime

    async def execute(
        self,
        context: SchedulerContext,
        plan: Any,
        completed: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        by_id = {task.id: task for task in plan.tasks}
        results = dict(completed or {})
        pending = set(by_id) - set(results)
        semaphore = asyncio.Semaphore(context.contract.max_parallelism)

        async def run_one(task: Any) -> tuple[str, Any]:
            dependencies = {dep: results[dep] for dep in task.depends_on}
            async with semaphore:
                context.cancel_token.raise_if_cancelled()
                context.budget.assert_can_start(task)
                timeout = min(float(task.timeout_seconds), context.budget.remaining_seconds())
                if timeout <= 0:
                    raise PlatformError(
                        "DEADLINE_EXCEEDED",
                        "No run deadline remains",
                        retryable=False,
                        http_status=408,
                    )
                task_started = getattr(context.checkpoint, "task_started", None)
                if callable(task_started):
                    await task_started(task, dependencies)
                try:
                    async with asyncio.timeout(timeout):
                        output = await self._runtime.execute_task(
                            context.runtime_context, task, dependencies
                        )
                except TimeoutError as exc:
                    failure = PlatformError(
                        "TASK_TIMEOUT",
                        f"Task {task.id} exceeded its bounded timeout",
                        retryable=True,
                    )
                    task_failed = getattr(context.checkpoint, "task_failed", None)
                    if callable(task_failed):
                        await task_failed(task, failure)
                    raise failure from exc
                except Exception as exc:
                    task_failed = getattr(context.checkpoint, "task_failed", None)
                    if callable(task_failed):
                        await task_failed(task, exc)
                    raise
                context.budget.record_task(task)
                return task.id, output

        while pending:
            context.cancel_token.raise_if_cancelled()
            ready = [
                by_id[task_id]
                for task_id in sorted(pending)
                if set(by_id[task_id].depends_on) <= set(results)
            ]
            if not ready:
                raise PlatformError(
                    "INVALID_CONTRACT",
                    "Execution plan has no runnable task",
                    context={"pending": sorted(pending)},
                )
            batch = await asyncio.gather(*(run_one(task) for task in ready))
            for task_id, output in batch:
                results[task_id] = output
                pending.remove(task_id)
                await context.checkpoint.task_completed(task_id, output)
        return results
