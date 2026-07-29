from __future__ import annotations

import asyncio

import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.application.reliability import (
    BackpressureGate,
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitOpenError,
    CircuitState,
    RetryPolicy,
    bounded_retry,
)


@pytest.mark.asyncio
async def test_retry_is_bounded_and_respects_retryable_classification() -> None:
    attempts = 0
    delays: list[float] = []

    async def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise PlatformError("DEPENDENCY_FAILURE", "temporary", retryable=True)
        return "ok"

    async def record_sleep(delay: float) -> None:
        delays.append(delay)

    result = await bounded_retry(
        operation,
        RetryPolicy(
            max_attempts=3,
            base_delay_seconds=0.01,
            max_delay_seconds=0.02,
            total_timeout_seconds=1,
            jitter_ratio=0,
        ),
        sleep=record_sleep,
    )
    assert result == "ok"
    assert attempts == 3
    assert delays == [0.01, 0.02]

    attempts = 0

    async def denied() -> None:
        nonlocal attempts
        attempts += 1
        raise PlatformError("FORBIDDEN", "no retry", retryable=False)

    with pytest.raises(PlatformError, match="FORBIDDEN"):
        await bounded_retry(denied, RetryPolicy(max_attempts=5))
    assert attempts == 1


@pytest.mark.asyncio
async def test_circuit_breaker_opens_then_allows_one_half_open_probe() -> None:
    now = [0.0]
    breaker = CircuitBreaker(
        CircuitBreakerConfig(failure_threshold=2, recovery_timeout_seconds=5),
        clock=lambda: now[0],
    )

    async def fail() -> None:
        raise PlatformError("DEPENDENCY_FAILURE", "down", retryable=True)

    for _ in range(2):
        with pytest.raises(PlatformError, match="DEPENDENCY_FAILURE"):
            await breaker.call(fail)
    assert breaker.state is CircuitState.OPEN
    with pytest.raises(CircuitOpenError, match="CIRCUIT_OPEN"):
        await breaker.call(fail)

    now[0] = 5.0

    async def recover() -> str:
        return "healthy"

    assert await breaker.call(recover) == "healthy"
    assert breaker.state is CircuitState.CLOSED


@pytest.mark.asyncio
async def test_backpressure_bounds_active_and_queued_work() -> None:
    gate = BackpressureGate(
        max_in_flight=1,
        max_queued=1,
        queue_timeout_seconds=1,
    )
    release = asyncio.Event()
    first_entered = asyncio.Event()

    async def hold_first() -> None:
        async with gate.slot():
            first_entered.set()
            await release.wait()

    async def wait_second() -> None:
        async with gate.slot():
            return

    first = asyncio.create_task(hold_first())
    await first_entered.wait()
    second = asyncio.create_task(wait_second())
    await asyncio.sleep(0)
    with pytest.raises(PlatformError, match="BACKPRESSURE_REJECTED"):
        async with gate.slot():
            pass
    release.set()
    await asyncio.gather(first, second)
