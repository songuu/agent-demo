from __future__ import annotations

import asyncio

import pytest

from agent_platform.agents.model_reliability import (
    ModelReliabilityConfig,
    ModelReliabilityRegistry,
)
from agent_platform.application.errors import PlatformError
from agent_platform.application.reliability import CircuitState


@pytest.mark.asyncio
async def test_model_backpressure_rejects_before_provider_and_does_not_open_circuit() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    provider_calls = 0
    reliability = ModelReliabilityRegistry(
        ModelReliabilityConfig(
            max_in_flight=1,
            max_queued=0,
            queue_timeout_seconds=0.1,
            circuit_failure_threshold=1,
        )
    )

    async def provider() -> str:
        nonlocal provider_calls
        provider_calls += 1
        entered.set()
        await release.wait()
        return "ok"

    first = asyncio.create_task(reliability.call("project-a", "gpt-5.6-sol", provider))
    await entered.wait()
    with pytest.raises(PlatformError, match="BACKPRESSURE_REJECTED"):
        await reliability.call("project-a", "gpt-5.6-sol", provider)
    release.set()

    assert await first == "ok"
    assert provider_calls == 1
    assert reliability.circuit_state("project-a", "gpt-5.6-sol") is CircuitState.CLOSED


@pytest.mark.asyncio
async def test_model_circuit_isolated_by_project_and_model() -> None:
    provider_calls = 0
    reliability = ModelReliabilityRegistry(
        ModelReliabilityConfig(
            circuit_failure_threshold=2,
            circuit_recovery_timeout_seconds=60,
        )
    )

    async def failing_provider() -> str:
        nonlocal provider_calls
        provider_calls += 1
        raise OSError("provider unavailable")

    for _ in range(2):
        with pytest.raises(OSError, match="provider unavailable"):
            await reliability.call("project-a", "gpt-5.6-sol", failing_provider)

    with pytest.raises(PlatformError, match="CIRCUIT_OPEN"):
        await reliability.call("project-a", "gpt-5.6-sol", failing_provider)

    async def healthy_provider() -> str:
        return "ok"

    assert await reliability.call("project-a", "gpt-5.6-terra", healthy_provider) == "ok"
    assert await reliability.call("project-b", "gpt-5.6-sol", healthy_provider) == "ok"
    assert provider_calls == 2
    assert reliability.circuit_state("project-a", "gpt-5.6-sol") is CircuitState.OPEN
    assert reliability.circuit_state("project-a", "gpt-5.6-terra") is CircuitState.CLOSED
    assert reliability.circuit_state("project-b", "gpt-5.6-sol") is CircuitState.CLOSED


@pytest.mark.asyncio
async def test_model_reliability_rejects_unbounded_or_blank_keys() -> None:
    reliability = ModelReliabilityRegistry(max_keys=1)

    async def operation() -> str:
        return "ok"

    assert await reliability.call("project-a", "gpt-5.6-sol", operation) == "ok"
    with pytest.raises(PlatformError, match="MODEL_RELIABILITY_KEY_LIMIT"):
        await reliability.call("project-a", "gpt-5.6-terra", operation)
    with pytest.raises(PlatformError, match="MODEL_RELIABILITY_KEY_INVALID"):
        await reliability.call("", "gpt-5.6-sol", operation)
