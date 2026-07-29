from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError

from agent_platform.application.errors import PlatformError
from agent_platform.application.reliability import RetryPolicy, bounded_retry
from agent_platform.infrastructure.cache import SafeCache
from agent_platform.tools.programmatic import (
    ProgrammaticCall,
    ProgrammaticLimits,
    ProgrammaticPlan,
    ProgrammaticReadExecutor,
)

from .test_cache import key
from .test_programmatic import context, definition


@pytest.mark.asyncio
async def test_retry_jitter_never_exceeds_hard_delay_cap() -> None:
    with pytest.raises(ValidationError, match="RETRY_DELAY_ORDER_INVALID"):
        RetryPolicy(base_delay_seconds=2, max_delay_seconds=1)

    attempts = 0
    delays: list[float] = []

    async def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise PlatformError("DEPENDENCY_FAILURE", "retry", retryable=True)
        return "ok"

    async def record_sleep(delay: float) -> None:
        delays.append(delay)

    assert (
        await bounded_retry(
            operation,
            RetryPolicy(
                max_attempts=2,
                base_delay_seconds=1,
                max_delay_seconds=1,
                jitter_ratio=1,
            ),
            sleep=record_sleep,
            jitter=lambda: 1,
        )
        == "ok"
    )
    assert delays == [1]


@pytest.mark.asyncio
async def test_cache_rejects_action_shaped_values_even_under_read_kind() -> None:
    with pytest.raises(PlatformError, match="CACHE_SENSITIVE_VALUE_FORBIDDEN"):
        await SafeCache().put(
            key(),
            tenant_id="tenant-a",
            kind="read_result",
            value={"action_id": "action-1", "status": "approved"},
            ttl_seconds=30,
        )


@pytest.mark.asyncio
async def test_programmatic_tool_resolution_is_inside_total_deadline() -> None:
    async def resolve(name: str, tenant_id: str):
        await asyncio.sleep(0.1)
        return definition()

    async def invoke(tool, args):
        return {}

    executor = ProgrammaticReadExecutor(
        resolve,
        invoke,
        limits=ProgrammaticLimits(max_duration_seconds=0.01),
    )
    with pytest.raises(PlatformError, match="PTC_DURATION_EXCEEDED"):
        await executor.execute(
            ProgrammaticPlan(
                waves=(
                    (
                        ProgrammaticCall(
                            call_id="c1",
                            tool_name="knowledge.search",
                        ),
                    ),
                )
            ),
            context(),
        )
