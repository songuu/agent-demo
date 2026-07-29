from __future__ import annotations

import asyncio
from typing import Any

import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.domain.enums import RiskLevel, ToolEffect
from agent_platform.tools.models import ToolContext, ToolDefinition
from agent_platform.tools.programmatic import (
    ProgrammaticCall,
    ProgrammaticLimits,
    ProgrammaticPlan,
    ProgrammaticReadExecutor,
)


def definition(
    name: str = "knowledge.search",
    *,
    effect: ToolEffect = ToolEffect.READ,
) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        version="1.0.0",
        description="Bounded test tool",
        capability_name=name,
        effect=effect,
        input_schema={
            "type": "object",
            "properties": {
                "size": {"type": "integer", "minimum": 0, "maximum": 10_000},
                "delay": {"type": "number", "minimum": 0, "maximum": 1},
            },
            "additionalProperties": False,
        },
        output_schema={"type": "object"},
        risk=RiskLevel.LOW,
        timeout_seconds=10,
        max_result_bytes=10_000,
        idempotency="none",
        approval_policy="none",
        adapter_ref="test",
    )


def context() -> ToolContext:
    from uuid import uuid4

    return ToolContext(
        run_id=uuid4(),
        task_id="research-a",
        plan_version=1,
        tenant_id="tenant-a",
        principal_id="user-a",
        principal_scopes=frozenset({"knowledge:read"}),
        allowed_capabilities=frozenset({"knowledge.search"}),
        data_scope={"tenant_id": "tenant-a"},
        correlation_id="corr-a",
    )


def plan(*waves: tuple[ProgrammaticCall, ...]) -> ProgrammaticPlan:
    return ProgrammaticPlan(waves=waves)


@pytest.mark.asyncio
async def test_programmatic_executor_enforces_read_effect_and_task_capability() -> None:
    definitions = {
        "knowledge.search": definition(),
        "email.prepare": definition("email.prepare", effect=ToolEffect.PREPARE),
    }

    async def resolve(name: str, tenant_id: str) -> ToolDefinition:
        assert tenant_id == "tenant-a"
        return definitions[name]

    async def invoke(tool: ToolDefinition, args: dict[str, Any]) -> Any:
        return {"tool": tool.name, "args": args}

    executor = ProgrammaticReadExecutor(resolve, invoke)
    with pytest.raises(PlatformError, match="PTC_READ_EFFECT_REQUIRED"):
        await executor.execute(
            plan((ProgrammaticCall(call_id="c1", tool_name="email.prepare"),)),
            context(),
        )
    with pytest.raises(PlatformError, match="PTC_CAPABILITY_DENIED"):
        await executor.execute(
            plan((ProgrammaticCall(call_id="c1", tool_name="other.search"),)),
            context(),
        )


@pytest.mark.asyncio
async def test_programmatic_executor_hard_limits_calls_loops_and_output() -> None:
    async def resolve(name: str, tenant_id: str) -> ToolDefinition:
        return definition(name)

    async def invoke(tool: ToolDefinition, args: dict[str, Any]) -> Any:
        return {"content": "x" * int(args.get("size", 1))}

    executor = ProgrammaticReadExecutor(
        resolve,
        invoke,
        limits=ProgrammaticLimits(
            max_calls=2,
            max_loops=1,
            max_concurrency=1,
            max_duration_seconds=1,
            max_output_bytes=20,
        ),
    )
    with pytest.raises(PlatformError, match="PTC_CALL_LIMIT_EXCEEDED"):
        await executor.execute(
            plan(
                (
                    ProgrammaticCall(call_id="c1", tool_name="knowledge.search"),
                    ProgrammaticCall(call_id="c2", tool_name="knowledge.search"),
                    ProgrammaticCall(call_id="c3", tool_name="knowledge.search"),
                )
            ),
            context(),
        )
    with pytest.raises(PlatformError, match="PTC_LOOP_LIMIT_EXCEEDED"):
        await executor.execute(
            plan(
                (ProgrammaticCall(call_id="c1", tool_name="knowledge.search"),),
                (ProgrammaticCall(call_id="c2", tool_name="knowledge.search"),),
            ),
            context(),
        )
    with pytest.raises(PlatformError, match="PTC_OUTPUT_LIMIT_EXCEEDED"):
        await executor.execute(
            plan(
                (
                    ProgrammaticCall(
                        call_id="c1",
                        tool_name="knowledge.search",
                        args={"size": 100},
                    ),
                )
            ),
            context(),
        )


@pytest.mark.asyncio
async def test_programmatic_executor_bounds_concurrency_and_duration() -> None:
    active = 0
    observed = 0

    async def resolve(name: str, tenant_id: str) -> ToolDefinition:
        return definition(name)

    async def invoke(tool: ToolDefinition, args: dict[str, Any]) -> Any:
        nonlocal active, observed
        active += 1
        observed = max(observed, active)
        try:
            await asyncio.sleep(float(args.get("delay", 0.01)))
            return {"ok": True}
        finally:
            active -= 1

    calls = tuple(
        ProgrammaticCall(
            call_id=f"c{index}",
            tool_name="knowledge.search",
            args={"delay": 0.01},
        )
        for index in range(4)
    )
    executor = ProgrammaticReadExecutor(
        resolve,
        invoke,
        limits=ProgrammaticLimits(
            max_calls=4,
            max_loops=1,
            max_concurrency=2,
            max_duration_seconds=1,
            max_output_bytes=1_000,
        ),
    )
    result = await executor.execute(plan(calls), context())
    assert result.call_count == 4
    assert observed == 2

    timeout_executor = ProgrammaticReadExecutor(
        resolve,
        invoke,
        limits=ProgrammaticLimits(
            max_calls=1,
            max_loops=1,
            max_concurrency=1,
            max_duration_seconds=0.01,
            max_output_bytes=1_000,
        ),
    )
    with pytest.raises(PlatformError, match="PTC_DURATION_EXCEEDED"):
        await timeout_executor.execute(
            plan(
                (
                    ProgrammaticCall(
                        call_id="slow",
                        tool_name="knowledge.search",
                        args={"delay": 0.1},
                    ),
                )
            ),
            context(),
        )
