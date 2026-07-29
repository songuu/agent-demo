"""Bounded retry, circuit breaking, and backpressure primitives."""

from __future__ import annotations

import asyncio
import secrets
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agent_platform.application.errors import PlatformError

_SYSTEM_RANDOM = secrets.SystemRandom()


class SharedReliabilityControl(Protocol):
    """Cross-replica concurrency and circuit control without infrastructure coupling."""

    async def call[T](
        self,
        scope: str,
        operation: Callable[[], Awaitable[T]],
        *,
        is_failure: Callable[[Exception], bool] | None = None,
    ) -> T: ...


class RetryPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_attempts: int = Field(default=3, ge=1, le=5)
    base_delay_seconds: float = Field(default=0.1, ge=0, le=5)
    max_delay_seconds: float = Field(default=2, ge=0, le=30)
    total_timeout_seconds: float = Field(default=30, gt=0, le=300)
    jitter_ratio: float = Field(default=0.2, ge=0, le=1)

    @model_validator(mode="after")
    def validate_delay_order(self) -> RetryPolicy:
        if self.base_delay_seconds > self.max_delay_seconds:
            raise ValueError("RETRY_DELAY_ORDER_INVALID: base delay cannot exceed maximum delay")
        return self


async def bounded_retry[T](
    operation: Callable[[], Awaitable[T]],
    policy: RetryPolicy,
    *,
    retry_if: Callable[[Exception], bool] | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    jitter: Callable[[], float] | None = None,
) -> T:
    def default_retry_if(error: Exception) -> bool:
        if isinstance(error, PlatformError):
            return error.retryable
        return isinstance(error, (OSError, TimeoutError))

    classify = retry_if or default_retry_if
    jitter_source = jitter or _SYSTEM_RANDOM.random
    try:
        async with asyncio.timeout(policy.total_timeout_seconds):
            for attempt in range(1, policy.max_attempts + 1):
                try:
                    return await operation()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    if attempt >= policy.max_attempts or not classify(exc):
                        raise
                    delay = min(
                        policy.max_delay_seconds,
                        policy.base_delay_seconds * (2 ** (attempt - 1)),
                    )
                    if policy.jitter_ratio:
                        offset = (min(1, max(0, jitter_source())) * 2) - 1
                        delay = min(
                            policy.max_delay_seconds,
                            max(0, delay * (1 + (offset * policy.jitter_ratio))),
                        )
                    await sleep(delay)
    except TimeoutError as exc:
        raise PlatformError(
            "RETRY_DEADLINE_EXCEEDED",
            "RETRY_DEADLINE_EXCEEDED: retry budget exhausted its deadline",
            retryable=False,
            http_status=504,
        ) from exc
    raise AssertionError("bounded_retry exhausted without returning or raising")


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    failure_threshold: int = Field(default=5, ge=1, le=100)
    recovery_timeout_seconds: float = Field(default=30, gt=0, le=3_600)


class CircuitOpenError(PlatformError):
    def __init__(self) -> None:
        super().__init__(
            "CIRCUIT_OPEN",
            "CIRCUIT_OPEN: dependency circuit is open",
            retryable=True,
            http_status=503,
        )


class CircuitBreaker:
    def __init__(
        self,
        config: CircuitBreakerConfig | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        is_failure: Callable[[Exception], bool] | None = None,
    ) -> None:
        self._config = config or CircuitBreakerConfig()
        self._clock = clock
        self._is_failure = is_failure or self._default_is_failure
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._opened_at: float | None = None
        self._probe_in_flight = False
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        return self._state

    @staticmethod
    def _default_is_failure(error: Exception) -> bool:
        return not isinstance(error, PlatformError) or error.retryable

    async def call[T](self, operation: Callable[[], Awaitable[T]]) -> T:
        is_probe = await self._acquire_permission()
        try:
            result = await operation()
        except asyncio.CancelledError:
            await self._release_probe_without_result(is_probe)
            raise
        except Exception as exc:
            await self._record_failure(is_probe, self._is_failure(exc))
            raise
        await self._record_success()
        return result

    async def _acquire_permission(self) -> bool:
        async with self._lock:
            if self._state is CircuitState.OPEN:
                assert self._opened_at is not None
                if self._clock() - self._opened_at < self._config.recovery_timeout_seconds:
                    raise CircuitOpenError
                self._state = CircuitState.HALF_OPEN
            if self._state is CircuitState.HALF_OPEN:
                if self._probe_in_flight:
                    raise CircuitOpenError
                self._probe_in_flight = True
                return True
            return False

    async def _record_failure(self, is_probe: bool, counts: bool) -> None:
        async with self._lock:
            if is_probe:
                self._probe_in_flight = False
            if not counts:
                return
            self._failure_count += 1
            if is_probe or self._failure_count >= self._config.failure_threshold:
                self._state = CircuitState.OPEN
                self._opened_at = self._clock()

    async def _record_success(self) -> None:
        async with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._opened_at = None
            self._probe_in_flight = False

    async def _release_probe_without_result(self, is_probe: bool) -> None:
        if not is_probe:
            return
        async with self._lock:
            self._probe_in_flight = False


class BackpressureGate:
    def __init__(
        self,
        *,
        max_in_flight: int,
        max_queued: int,
        queue_timeout_seconds: float,
    ) -> None:
        if max_in_flight < 1 or max_queued < 0 or queue_timeout_seconds <= 0:
            raise ValueError("BACKPRESSURE_LIMIT_INVALID: limits must be bounded and positive")
        self._max_in_flight = max_in_flight
        self._max_queued = max_queued
        self._queue_timeout_seconds = queue_timeout_seconds
        self._available = asyncio.Semaphore(max_in_flight)
        self._in_flight = 0
        self._queued = 0
        self._lock = asyncio.Lock()

    @property
    def in_flight(self) -> int:
        return self._in_flight

    @property
    def queued(self) -> int:
        return self._queued

    @asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        queued_registered = False
        counted_in_flight = False
        acquired = False
        try:
            async with self._lock:
                if self._in_flight < self._max_in_flight:
                    self._in_flight += 1
                    counted_in_flight = True
                else:
                    if self._queued >= self._max_queued:
                        raise PlatformError(
                            "BACKPRESSURE_REJECTED",
                            "BACKPRESSURE_REJECTED: queue capacity is exhausted",
                            retryable=True,
                            http_status=503,
                        )
                    self._queued += 1
                    queued_registered = True
            if queued_registered:
                try:
                    async with asyncio.timeout(self._queue_timeout_seconds):
                        await self._available.acquire()
                    acquired = True
                except TimeoutError as exc:
                    raise PlatformError(
                        "BACKPRESSURE_TIMEOUT",
                        "BACKPRESSURE_TIMEOUT: queued work exceeded its deadline",
                        retryable=True,
                        http_status=503,
                    ) from exc
                async with self._lock:
                    self._queued -= 1
                    queued_registered = False
                    self._in_flight += 1
                    counted_in_flight = True
            else:
                await self._available.acquire()
                acquired = True
            yield
        finally:
            if queued_registered:
                async with self._lock:
                    self._queued -= 1
            if acquired:
                self._available.release()
            if counted_in_flight:
                async with self._lock:
                    self._in_flight -= 1
