"""Per-model and per-project circuit breaking with bounded admission."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field

from agent_platform.application.errors import PlatformError
from agent_platform.application.reliability import (
    BackpressureGate,
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
    SharedReliabilityControl,
)


class ModelReliabilityConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_in_flight: int = Field(default=20, ge=1, le=1_000)
    max_queued: int = Field(default=100, ge=0, le=10_000)
    queue_timeout_seconds: float = Field(default=5, gt=0, le=300)
    circuit_failure_threshold: int = Field(default=5, ge=1, le=100)
    circuit_recovery_timeout_seconds: float = Field(default=30, gt=0, le=3_600)


@dataclass(frozen=True, slots=True)
class _ModelControls:
    circuit: CircuitBreaker
    backpressure: BackpressureGate


class ModelReliabilityRegistry:
    """Isolate provider failures and queues for each explicit project/model pair."""

    def __init__(
        self,
        config: ModelReliabilityConfig | None = None,
        *,
        max_keys: int = 100,
        shared_control: SharedReliabilityControl | None = None,
    ) -> None:
        if max_keys < 1 or max_keys > 10_000:
            raise ValueError("MODEL_RELIABILITY_KEY_LIMIT_INVALID")
        self._config = config or ModelReliabilityConfig()
        self._max_keys = max_keys
        self._shared_control = shared_control
        self._controls: dict[tuple[str, str], _ModelControls] = {}
        self._lock = asyncio.Lock()

    async def call[T](
        self,
        project_id: str,
        model: str,
        operation: Callable[[], Awaitable[T]],
    ) -> T:
        key = self._key(project_id, model)
        if self._shared_control is not None:
            return await self._shared_control.call(
                f"model:{key[0]}:{key[1]}",
                operation,
            )
        controls = await self._controls_for(project_id, model)
        # Admission failures are local pressure signals and must not poison the
        # upstream provider circuit.
        async with controls.backpressure.slot():
            return await controls.circuit.call(operation)

    def circuit_state(self, project_id: str, model: str) -> CircuitState | None:
        key = self._key(project_id, model)
        controls = self._controls.get(key)
        return None if controls is None else controls.circuit.state

    async def _controls_for(self, project_id: str, model: str) -> _ModelControls:
        key = self._key(project_id, model)
        controls = self._controls.get(key)
        if controls is not None:
            return controls
        async with self._lock:
            controls = self._controls.get(key)
            if controls is not None:
                return controls
            if len(self._controls) >= self._max_keys:
                raise PlatformError(
                    "MODEL_RELIABILITY_KEY_LIMIT",
                    "Model reliability key capacity is exhausted",
                    retryable=False,
                    http_status=503,
                )
            controls = _ModelControls(
                circuit=CircuitBreaker(
                    CircuitBreakerConfig(
                        failure_threshold=self._config.circuit_failure_threshold,
                        recovery_timeout_seconds=(self._config.circuit_recovery_timeout_seconds),
                    )
                ),
                backpressure=BackpressureGate(
                    max_in_flight=self._config.max_in_flight,
                    max_queued=self._config.max_queued,
                    queue_timeout_seconds=self._config.queue_timeout_seconds,
                ),
            )
            self._controls[key] = controls
            return controls

    @staticmethod
    def _key(project_id: str, model: str) -> tuple[str, str]:
        normalized_project = project_id.strip()
        normalized_model = model.strip()
        if (
            not normalized_project
            or len(normalized_project) > 256
            or not normalized_model
            or len(normalized_model) > 256
        ):
            raise PlatformError(
                "MODEL_RELIABILITY_KEY_INVALID",
                "Model reliability requires bounded project and model identifiers",
                retryable=False,
                http_status=500,
            )
        return normalized_project, normalized_model
