from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from agent_platform.agents.model_reliability import (
    ModelReliabilityConfig,
    ModelReliabilityRegistry,
)


class _SharedControl:
    def __init__(self) -> None:
        self.scopes: list[str] = []

    async def call(
        self,
        scope: str,
        operation: Callable[[], Awaitable[Any]],
        **kwargs: object,
    ) -> Any:
        self.scopes.append(scope)
        return await operation()


@pytest.mark.asyncio
async def test_production_model_reliability_delegates_to_cross_pod_control() -> None:
    shared = _SharedControl()
    registry = ModelReliabilityRegistry(
        ModelReliabilityConfig(max_in_flight=3, max_queued=4),
        shared_control=shared,
    )

    result = await registry.call(
        "project-a",
        "gpt-5.6-sol",
        _ok,
    )

    assert result == "ok"
    assert shared.scopes == ["model:project-a:gpt-5.6-sol"]
    assert registry.circuit_state("project-a", "gpt-5.6-sol") is None


async def _ok() -> str:
    return "ok"
