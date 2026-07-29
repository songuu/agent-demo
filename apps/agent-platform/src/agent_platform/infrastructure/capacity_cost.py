"""Shared capacity controls and auditable full-platform cost reconciliation.

PostgreSQL owns durable Run admission and tenant budget accounting. Redis owns
short-lived model/tool concurrency and circuit state. Temporal remains the
authoritative source for queue backlog and age. Keeping these responsibilities
explicit avoids treating one process-local semaphore or one metrics sample as a
production control.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import math
import re
import secrets
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Protocol, TypeVar, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)
from temporalio.api.enums.v1 import TaskQueueType
from temporalio.api.taskqueue.v1 import TaskQueue
from temporalio.api.workflowservice.v1 import DescribeTaskQueueRequest

from agent_platform.application.errors import PlatformError
from agent_platform.application.records import RunRecord

T = TypeVar("T")
_USD_QUANTUM = Decimal("0.000001")
_GIB = Decimal(1024**3)
_CATALOG_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,127}$")
_SHARED_HASH_TAG = "{shared-control-v1}"
_SYSTEM_RANDOM = secrets.SystemRandom()


class RedisEvalClient(Protocol):
    async def eval(
        self,
        script: str,
        numkeys: int,
        *keys_and_args: object,
    ) -> Any: ...


class QueueProbe(Protocol):
    async def snapshot(self) -> QueueBacklog: ...


class AuditExporter(Protocol):
    async def export_run(
        self,
        run_id: object,
        tenant_id: str,
    ) -> Mapping[str, Any]: ...


class CapacityCostRepository(Protocol):
    async def find_reservation(
        self,
        tenant_id: str,
        reservation_key: str,
    ) -> ReservationView | None: ...

    async def reserve(
        self,
        *,
        tenant_id: str,
        reservation_key: str,
        requested_cost_usd: Decimal,
        priority: RunPriority,
        lease_seconds: int,
        config: CapacityControlConfig,
    ) -> AdmissionDecision: ...

    async def bind_run(
        self,
        *,
        tenant_id: str,
        reservation_key: str,
        run_id: object,
    ) -> None: ...

    async def release(
        self,
        *,
        tenant_id: str,
        reservation_key: str,
        only_if_unbound: bool,
    ) -> None: ...

    async def settle(
        self,
        *,
        tenant_id: str,
        reservation_key: str,
        run_id: object,
        run_limit_usd: Decimal,
        breakdown: CostBreakdown,
        config: CapacityControlConfig,
    ) -> CostSettlement: ...


class QueueBacklog(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    backlog: int = Field(ge=0)
    oldest_age_seconds: float = Field(ge=0)


class RunPriority(StrEnum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class BudgetControlLevel(StrEnum):
    NORMAL = "normal"
    MIDPOINT = "midpoint"
    RESTRICT = "restrict"
    CRITICAL_ONLY = "critical_only"
    STOP = "stop"


class ReservationView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    active: bool
    run_id: str | None = None
    budget_control_level: BudgetControlLevel
    daily_utilization: Decimal = Field(ge=0)
    monthly_utilization: Decimal = Field(ge=0)


class AdmissionDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    newly_reserved: bool
    active_runs: int = Field(ge=0)
    budget_control_level: BudgetControlLevel
    daily_utilization: Decimal = Field(ge=0)
    monthly_utilization: Decimal = Field(ge=0)
    queue_backlog: int = Field(default=0, ge=0)
    queue_oldest_age_seconds: float = Field(default=0, ge=0)


class CostSettlement(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    breakdown: CostBreakdown
    run_limit_exceeded: bool
    tenant_daily_limit_exceeded: bool
    tenant_monthly_limit_exceeded: bool
    budget_control_level: BudgetControlLevel
    daily_utilization: Decimal = Field(ge=0)
    monthly_utilization: Decimal = Field(ge=0)


class CapacityControlConfig(BaseModel):
    """Tenant admission and queue thresholds.

    Daily/monthly values are platform defaults. A future tenant-policy adapter
    may supply stricter values, but can never silently increase these limits.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_max_active_runs: int = Field(default=100, ge=1, le=100_000)
    queue_backlog_soft_limit: int = Field(default=500, ge=1, le=10_000_000)
    queue_oldest_age_soft_limit_seconds: float = Field(default=60, gt=0, le=86_400)
    critical_queue_multiplier: int = Field(default=2, ge=1, le=10)
    reservation_grace_seconds: int = Field(default=300, ge=30, le=3_600)
    tenant_daily_budget_usd: Decimal = Field(
        default=Decimal("1000"),
        gt=0,
        max_digits=18,
        decimal_places=6,
    )
    tenant_monthly_budget_usd: Decimal = Field(
        default=Decimal("20000"),
        gt=0,
        max_digits=18,
        decimal_places=6,
    )
    midpoint_ratio: Decimal = Field(default=Decimal("0.50"), gt=0, lt=1)
    restrict_ratio: Decimal = Field(default=Decimal("0.80"), gt=0, lt=1)
    critical_only_ratio: Decimal = Field(default=Decimal("0.95"), gt=0, lt=1)

    @model_validator(mode="after")
    def validate_thresholds(self) -> CapacityControlConfig:
        if not (self.midpoint_ratio < self.restrict_ratio < self.critical_only_ratio):
            raise ValueError("CAPACITY_BUDGET_THRESHOLDS_INVALID")
        if self.tenant_daily_budget_usd > self.tenant_monthly_budget_usd:
            raise ValueError("CAPACITY_DAILY_BUDGET_EXCEEDS_MONTHLY")
        return self


class SharedReliabilityConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_in_flight: int = Field(default=20, ge=1, le=100_000)
    max_queued: int = Field(default=100, ge=0, le=1_000_000)
    queue_timeout_seconds: float = Field(default=5, gt=0, le=300)
    lease_seconds: float = Field(default=30, gt=1, le=3_600)
    heartbeat_seconds: float = Field(default=10, gt=0, le=1_200)
    circuit_failure_threshold: int = Field(default=5, ge=1, le=1_000)
    circuit_recovery_seconds: float = Field(default=30, gt=0, le=3_600)

    @model_validator(mode="after")
    def validate_lease_heartbeat(self) -> SharedReliabilityConfig:
        if self.heartbeat_seconds >= self.lease_seconds:
            raise ValueError("SHARED_CONTROL_HEARTBEAT_MUST_PRECEDE_LEASE_EXPIRY")
        return self


_ACQUIRE_SLOT_SCRIPT = """
local clock = redis.call("TIME")
local now_ms = (tonumber(clock[1]) * 1000) + math.floor(tonumber(clock[2]) / 1000)
local now_us = (tonumber(clock[1]) * 1000000) + tonumber(clock[2])
local ticket = ARGV[1]
local lease_ms = tonumber(ARGV[2])
local queue_timeout_us = tonumber(ARGV[3])
local max_in_flight = tonumber(ARGV[4])
local max_queued = tonumber(ARGV[5])
redis.call("ZREMRANGEBYSCORE", KEYS[1], "-inf", now_ms)
redis.call("ZREMRANGEBYSCORE", KEYS[2], "-inf", now_us - queue_timeout_us)
if redis.call("ZSCORE", KEYS[1], ticket) then
  return {1, redis.call("ZCARD", KEYS[1]), redis.call("ZCARD", KEYS[2])}
end
local queue_rank = redis.call("ZRANK", KEYS[2], ticket)
local in_flight = tonumber(redis.call("ZCARD", KEYS[1]))
if in_flight < max_in_flight and
   (queue_rank == false or tonumber(queue_rank) == 0) then
  redis.call("ZREM", KEYS[2], ticket)
  redis.call("ZADD", KEYS[1], now_ms + lease_ms, ticket)
  redis.call("PEXPIRE", KEYS[1], lease_ms * 2)
  return {1, in_flight + 1, redis.call("ZCARD", KEYS[2])}
end
if queue_rank == false then
  local queued = tonumber(redis.call("ZCARD", KEYS[2]))
  if queued >= max_queued then
    return {-1, in_flight, queued}
  end
  redis.call("ZADD", KEYS[2], now_us, ticket)
  redis.call("PEXPIRE", KEYS[2], math.ceil(queue_timeout_us / 1000) * 2)
end
return {0, in_flight, redis.call("ZCARD", KEYS[2])}
""".strip()

_RENEW_SLOT_SCRIPT = """
local clock = redis.call("TIME")
local now_ms = (tonumber(clock[1]) * 1000) + math.floor(tonumber(clock[2]) / 1000)
if not redis.call("ZSCORE", KEYS[1], ARGV[1]) then
  return {0}
end
redis.call("ZADD", KEYS[1], now_ms + tonumber(ARGV[2]), ARGV[1])
redis.call("PEXPIRE", KEYS[1], tonumber(ARGV[2]) * 2)
return {1}
""".strip()

_RELEASE_SLOT_SCRIPT = """
local clock = redis.call("TIME")
local now_ms = (tonumber(clock[1]) * 1000) + math.floor(tonumber(clock[2]) / 1000)
redis.call("ZREMRANGEBYSCORE", KEYS[1], "-inf", now_ms)
local removed = redis.call("ZREM", KEYS[1], ARGV[1])
redis.call("ZREM", KEYS[2], ARGV[1])
return {removed}
""".strip()

_CIRCUIT_PERMISSION_SCRIPT = """
local clock = redis.call("TIME")
local now_ms = (tonumber(clock[1]) * 1000) + math.floor(tonumber(clock[2]) / 1000)
local opened_at = tonumber(redis.call("HGET", KEYS[1], "opened_at_ms") or "0")
if opened_at > 0 then
  local recovery_ms = tonumber(ARGV[1])
  local remaining_ms = recovery_ms - (now_ms - opened_at)
  if remaining_ms > 0 then
    return {0, math.ceil(remaining_ms / 1000)}
  end
  local probe = redis.call("SET", KEYS[2], ARGV[2], "NX", "PX", recovery_ms)
  if not probe then
    return {0, math.max(1, math.ceil(recovery_ms / 1000))}
  end
  return {2, 0}
end
return {1, 0}
""".strip()

_CIRCUIT_SUCCESS_SCRIPT = """
local clock = redis.call("TIME")
redis.call("DEL", KEYS[1])
redis.call("DEL", KEYS[2])
return {1}
""".strip()

_CIRCUIT_FAILURE_SCRIPT = """
local clock = redis.call("TIME")
local now_ms = (tonumber(clock[1]) * 1000) + math.floor(tonumber(clock[2]) / 1000)
local threshold = tonumber(ARGV[1])
local recovery_ms = tonumber(ARGV[2])
local is_probe = tonumber(ARGV[3])
local failures = tonumber(redis.call("HINCRBY", KEYS[1], "failures", 1))
if is_probe == 1 or failures >= threshold then
  redis.call("HSET", KEYS[1], "opened_at_ms", now_ms)
end
redis.call("PEXPIRE", KEYS[1], recovery_ms * 10)
redis.call("DEL", KEYS[2])
return {failures}
""".strip()


class RedisSharedReliability:
    """Distributed FIFO-ish admission plus circuit state for one dependency class.

    Slot and queue members are random leases; raw project, model, tool, endpoint,
    tenant, or principal identifiers never enter Redis keys.
    """

    def __init__(
        self,
        client: RedisEvalClient,
        *,
        key_hmac_secret: bytes,
        config: SharedReliabilityConfig | None = None,
        namespace: str = "agent-platform:reliability:v1",
    ) -> None:
        if len(key_hmac_secret) < 32:
            raise ValueError("SHARED_CONTROL_KEY_SECRET_TOO_SHORT")
        if not namespace.strip() or len(namespace) > 128:
            raise ValueError("SHARED_CONTROL_NAMESPACE_INVALID")
        self._client = client
        self._secret = bytes(key_hmac_secret)
        self._config = config or SharedReliabilityConfig()
        self._namespace = namespace.strip()

    async def call(
        self,
        scope: str,
        operation: Callable[[], Awaitable[T]],
        *,
        is_failure: Callable[[Exception], bool] | None = None,
    ) -> T:
        digest = self._scope_digest(scope)
        slots_key = self._key("slots", digest)
        queue_key = self._key("queue", digest)
        circuit_key = self._key("circuit", digest)
        probe_key = self._key("probe", digest)
        ticket = secrets.token_hex(16)
        await self._acquire_slot(slots_key, queue_key, ticket)
        heartbeat: asyncio.Task[None] | None = None
        try:
            permission, retry_after = await self._circuit_permission(
                circuit_key,
                probe_key,
                ticket,
            )
            if permission == 0:
                raise PlatformError(
                    "CIRCUIT_OPEN",
                    "The shared dependency circuit is open",
                    retryable=True,
                    http_status=503,
                    context={"retry_after_seconds": retry_after},
                )
            heartbeat = asyncio.create_task(
                self._heartbeat(slots_key, ticket),
                name="shared-reliability-lease-heartbeat",
            )
            try:
                result = await self._run_with_lease(operation, heartbeat)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if isinstance(exc, PlatformError) and exc.code == "SHARED_CONTROL_LEASE_LOST":
                    raise
                classify = is_failure or self._default_is_failure
                if classify(exc):
                    await self._record_failure(
                        circuit_key,
                        probe_key,
                        is_probe=permission == 2,
                    )
                elif permission == 2:
                    await self._record_success(circuit_key, probe_key)
                raise
            await self._record_success(circuit_key, probe_key)
            return result
        finally:
            if heartbeat is not None:
                heartbeat.cancel()
                await asyncio.gather(heartbeat, return_exceptions=True)
            await self._release_slot(slots_key, queue_key, ticket)

    async def _run_with_lease(
        self,
        operation: Callable[[], Awaitable[T]],
        heartbeat: asyncio.Task[None],
    ) -> T:
        provider = asyncio.ensure_future(operation())
        try:
            completed, _ = await asyncio.wait(
                {provider, heartbeat},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if heartbeat in completed:
                lease_error = heartbeat.exception()
                provider.cancel()
                await asyncio.gather(provider, return_exceptions=True)
                if lease_error is not None:
                    raise lease_error
                raise PlatformError(
                    "SHARED_CONTROL_LEASE_LOST",
                    "Shared dependency capacity heartbeat stopped unexpectedly",
                    retryable=True,
                    http_status=503,
                )
            return await provider
        except BaseException:
            if not provider.done():
                provider.cancel()
                await asyncio.gather(provider, return_exceptions=True)
            raise

    async def _acquire_slot(self, slots_key: str, queue_key: str, ticket: str) -> None:
        deadline = asyncio.get_running_loop().time() + self._config.queue_timeout_seconds
        poll_seconds = min(0.05, self._config.queue_timeout_seconds / 10)
        while True:
            raw = await self._eval(
                _ACQUIRE_SLOT_SCRIPT,
                (slots_key, queue_key),
                (
                    ticket,
                    math.ceil(self._config.lease_seconds * 1_000),
                    math.ceil(self._config.queue_timeout_seconds * 1_000_000),
                    self._config.max_in_flight,
                    self._config.max_queued,
                ),
            )
            outcome, in_flight, queued = self._parse_integer_tuple(raw, 3)
            if outcome == 1:
                return
            if outcome == -1:
                raise PlatformError(
                    "BACKPRESSURE_REJECTED",
                    "Shared dependency queue capacity is exhausted",
                    retryable=True,
                    http_status=503,
                    context={"in_flight": in_flight, "queued": queued},
                )
            if outcome != 0:
                raise self._invalid_response()
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                await self._release_slot(slots_key, queue_key, ticket)
                raise PlatformError(
                    "BACKPRESSURE_TIMEOUT",
                    "Shared dependency admission exceeded its queue deadline",
                    retryable=True,
                    http_status=503,
                    context={"in_flight": in_flight, "queued": queued},
                )
            await asyncio.sleep(min(poll_seconds, remaining))

    async def _heartbeat(self, slots_key: str, ticket: str) -> None:
        while True:
            await asyncio.sleep(self._config.heartbeat_seconds)
            raw = await self._eval(
                _RENEW_SLOT_SCRIPT,
                (slots_key,),
                (ticket, math.ceil(self._config.lease_seconds * 1_000)),
            )
            renewed = self._parse_integer_tuple(raw, 1)[0]
            if renewed != 1:
                raise PlatformError(
                    "SHARED_CONTROL_LEASE_LOST",
                    "Shared dependency capacity lease was lost",
                    retryable=True,
                    http_status=503,
                )

    async def _release_slot(self, slots_key: str, queue_key: str, ticket: str) -> None:
        await self._eval(
            _RELEASE_SLOT_SCRIPT,
            (slots_key, queue_key),
            (ticket,),
        )

    async def _circuit_permission(
        self,
        circuit_key: str,
        probe_key: str,
        ticket: str,
    ) -> tuple[int, int]:
        raw = await self._eval(
            _CIRCUIT_PERMISSION_SCRIPT,
            (circuit_key, probe_key),
            (
                math.ceil(self._config.circuit_recovery_seconds * 1_000),
                ticket,
            ),
        )
        permission, retry_after = self._parse_integer_tuple(raw, 2)
        if permission not in {0, 1, 2} or retry_after < 0:
            raise self._invalid_response()
        return permission, retry_after

    async def _record_success(self, circuit_key: str, probe_key: str) -> None:
        await self._eval(
            _CIRCUIT_SUCCESS_SCRIPT,
            (circuit_key, probe_key),
            (),
        )

    async def _record_failure(
        self,
        circuit_key: str,
        probe_key: str,
        *,
        is_probe: bool,
    ) -> None:
        await self._eval(
            _CIRCUIT_FAILURE_SCRIPT,
            (circuit_key, probe_key),
            (
                self._config.circuit_failure_threshold,
                math.ceil(self._config.circuit_recovery_seconds * 1_000),
                1 if is_probe else 0,
            ),
        )

    async def _eval(
        self,
        script: str,
        keys: tuple[str, ...],
        arguments: tuple[object, ...],
    ) -> Any:
        try:
            return await self._client.eval(
                script,
                len(keys),
                *keys,
                *arguments,
            )
        except PlatformError:
            raise
        except Exception as exc:
            raise PlatformError(
                "SHARED_CONTROL_BACKEND_UNAVAILABLE",
                "The shared capacity control backend is unavailable",
                retryable=True,
                http_status=503,
            ) from exc

    def _scope_digest(self, scope: str) -> str:
        normalized = scope.strip()
        if not normalized or len(normalized) > 1_024:
            raise ValueError("SHARED_CONTROL_SCOPE_INVALID")
        return hmac.new(
            self._secret,
            normalized.encode(),
            hashlib.sha256,
        ).hexdigest()

    def _key(self, kind: str, digest: str) -> str:
        return f"{self._namespace}:{_SHARED_HASH_TAG}:{kind}:{digest}"

    @staticmethod
    def _default_is_failure(error: Exception) -> bool:
        return not isinstance(error, PlatformError) or error.retryable

    @staticmethod
    def _parse_integer_tuple(raw: Any, size: int) -> tuple[int, ...]:
        if not isinstance(raw, (list, tuple)) or len(raw) != size:
            raise RedisSharedReliability._invalid_response()
        try:
            return tuple(int(value) for value in raw)
        except (TypeError, ValueError, OverflowError) as exc:
            raise RedisSharedReliability._invalid_response() from exc

    @staticmethod
    def _invalid_response() -> PlatformError:
        return PlatformError(
            "SHARED_CONTROL_RESPONSE_INVALID",
            "The shared capacity backend returned an invalid response",
            retryable=True,
            http_status=503,
        )


class TemporalQueueBacklogProbe:
    """Read both Temporal queue kinds and aggregate their admission pressure."""

    def __init__(
        self,
        client: Any,
        *,
        namespace: str,
        task_queue: str,
    ) -> None:
        if not namespace.strip() or not task_queue.strip():
            raise ValueError("TEMPORAL_QUEUE_PROBE_SCOPE_REQUIRED")
        self._client = client
        self._namespace = namespace.strip()
        self._task_queue = task_queue.strip()

    async def snapshot(self) -> QueueBacklog:
        backlog = 0
        oldest_age = 0.0
        try:
            for queue_type in (
                TaskQueueType.TASK_QUEUE_TYPE_WORKFLOW,
                TaskQueueType.TASK_QUEUE_TYPE_ACTIVITY,
            ):
                response = await self._client.workflow_service.describe_task_queue(
                    DescribeTaskQueueRequest(
                        namespace=self._namespace,
                        task_queue=TaskQueue(name=self._task_queue),
                        task_queue_type=queue_type,
                        report_stats=True,
                    )
                )
                stats = response.stats
                backlog += max(int(stats.approximate_backlog_count), 0)
                oldest_age = max(
                    oldest_age,
                    float(stats.approximate_backlog_age.ToTimedelta().total_seconds()),
                )
        except Exception as exc:
            raise PlatformError(
                "CAPACITY_QUEUE_PROBE_UNAVAILABLE",
                "Temporal queue pressure could not be verified",
                retryable=True,
                http_status=503,
            ) from exc
        return QueueBacklog(
            backlog=backlog,
            oldest_age_seconds=max(oldest_age, 0.0),
        )


class CostComponent(StrEnum):
    MODEL = "model"
    TOOL = "tool"
    SANDBOX = "sandbox"
    ARTIFACT = "artifact"
    WORKFLOW = "workflow"
    OBSERVABILITY = "observability"


class CostRates(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_call_usd: Decimal = Field(ge=0, max_digits=18, decimal_places=9)
    sandbox_cpu_second_usd: Decimal = Field(ge=0, max_digits=18, decimal_places=9)
    sandbox_memory_gib_second_usd: Decimal = Field(
        ge=0,
        max_digits=18,
        decimal_places=9,
    )
    artifact_storage_gib_month_usd: Decimal = Field(
        ge=0,
        max_digits=18,
        decimal_places=9,
    )
    artifact_transfer_gib_usd: Decimal = Field(ge=0, max_digits=18, decimal_places=9)
    workflow_second_usd: Decimal = Field(ge=0, max_digits=18, decimal_places=9)
    observability_event_usd: Decimal = Field(ge=0, max_digits=18, decimal_places=9)


class CostRateCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    catalog_id: str
    currency: Literal["USD"]
    effective_at: datetime
    rates: CostRates
    default_artifact_retention_days: int = Field(ge=1, le=3_650)

    @field_validator("catalog_id")
    @classmethod
    def validate_catalog_id(cls, value: str) -> str:
        if not _CATALOG_ID.fullmatch(value):
            raise ValueError("COST_RATE_CATALOG_ID_INVALID")
        return value

    @field_validator("effective_at")
    @classmethod
    def validate_effective_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("COST_RATE_EFFECTIVE_AT_TIMEZONE_REQUIRED")
        return value.astimezone(UTC)

    @classmethod
    def from_path(
        cls,
        path: str | Path,
        *,
        expected_sha256: str | None = None,
    ) -> CostRateCatalog:
        resolved = Path(path).expanduser().resolve(strict=True)
        if resolved.stat().st_size > 1_048_576:
            raise PlatformError(
                "COST_RATE_CATALOG_TOO_LARGE",
                "Cost rate catalog exceeds one MiB",
                http_status=500,
            )
        raw = resolved.read_bytes()
        actual = "sha256:" + hashlib.sha256(raw).hexdigest()
        if expected_sha256 is not None and not hmac.compare_digest(actual, expected_sha256):
            raise PlatformError(
                "COST_RATE_CATALOG_DIGEST_MISMATCH",
                "Cost rate catalog does not match its configured digest",
                http_status=500,
                context={"actual_digest": actual},
            )
        try:
            parsed = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
            return cls.model_validate(parsed)
        except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError) as exc:
            raise PlatformError(
                "COST_RATE_CATALOG_INVALID",
                "Cost rate catalog failed strict validation",
                http_status=500,
            ) from exc


class CostBreakdown(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rate_catalog_id: str
    components: dict[CostComponent, Decimal]
    total_usd: Decimal = Field(ge=0)
    source_counts: dict[str, int]
    reconciled_at: datetime

    @model_validator(mode="after")
    def validate_total_and_components(self) -> CostBreakdown:
        if set(self.components) != set(CostComponent):
            raise ValueError("COST_BREAKDOWN_COMPONENTS_INCOMPLETE")
        expected = _usd(sum(self.components.values(), Decimal("0")))
        if self.total_usd != expected:
            raise ValueError("COST_BREAKDOWN_TOTAL_MISMATCH")
        return self


class CapacityCostController:
    """Coordinate idempotent admission, queue pressure, and final cost settlement."""

    def __init__(
        self,
        repository: CapacityCostRepository,
        *,
        queue_probe: QueueProbe | None,
        key_hmac_secret: bytes,
        config: CapacityControlConfig | None = None,
        reconciler: AuditCostReconciler | None = None,
    ) -> None:
        if len(key_hmac_secret) < 32:
            raise ValueError("CAPACITY_CONTROL_KEY_SECRET_TOO_SHORT")
        self._repository = repository
        self._queue_probe = queue_probe
        self._secret = bytes(key_hmac_secret)
        self._config = config or CapacityControlConfig()
        self._reconciler = reconciler

    async def admit_run(
        self,
        *,
        tenant_id: str,
        idempotency_key: str,
        requested_cost_usd: Decimal,
        max_duration_seconds: int,
        priority: RunPriority,
    ) -> AdmissionDecision:
        reservation_key = self._reservation_key(tenant_id, idempotency_key)
        existing = await self._repository.find_reservation(tenant_id, reservation_key)
        if existing is not None and existing.active:
            return AdmissionDecision(
                newly_reserved=False,
                active_runs=1,
                budget_control_level=existing.budget_control_level,
                daily_utilization=existing.daily_utilization,
                monthly_utilization=existing.monthly_utilization,
            )
        if self._queue_probe is None:
            raise PlatformError(
                "CAPACITY_QUEUE_PROBE_REQUIRED",
                "Run admission requires an authoritative Temporal queue probe",
                http_status=500,
            )
        queue = await self._queue_probe.snapshot()
        self._require_queue_capacity(queue, priority)
        lease_seconds = max_duration_seconds + self._config.reservation_grace_seconds
        if max_duration_seconds < 1 or lease_seconds > 90_000:
            raise ValueError("CAPACITY_RESERVATION_DURATION_INVALID")
        decision = await self._repository.reserve(
            tenant_id=tenant_id,
            reservation_key=reservation_key,
            requested_cost_usd=_usd(requested_cost_usd),
            priority=priority,
            lease_seconds=lease_seconds,
            config=self._config,
        )
        return decision.model_copy(
            update={
                "queue_backlog": queue.backlog,
                "queue_oldest_age_seconds": queue.oldest_age_seconds,
            }
        )

    async def bind_run(
        self,
        *,
        tenant_id: str,
        idempotency_key: str,
        run_id: object,
    ) -> None:
        await self._repository.bind_run(
            tenant_id=tenant_id,
            reservation_key=self._reservation_key(tenant_id, idempotency_key),
            run_id=run_id,
        )

    async def release_if_unbound(
        self,
        *,
        tenant_id: str,
        idempotency_key: str,
    ) -> None:
        await self._repository.release(
            tenant_id=tenant_id,
            reservation_key=self._reservation_key(tenant_id, idempotency_key),
            only_if_unbound=True,
        )

    async def settle_run(self, run: RunRecord) -> CostSettlement:
        if self._reconciler is None:
            raise PlatformError(
                "COST_RECONCILER_REQUIRED",
                "Final Run settlement requires an auditable cost reconciler",
                http_status=500,
            )
        breakdown = await self._reconciler.reconcile(run)
        return await self._repository.settle(
            tenant_id=run.tenant_id,
            reservation_key=self._reservation_key(run.tenant_id, run.idempotency_key),
            run_id=run.run_id,
            run_limit_usd=_usd(run.contract.max_cost_usd),
            breakdown=breakdown,
            config=self._config,
        )

    def _require_queue_capacity(
        self,
        queue: QueueBacklog,
        priority: RunPriority,
    ) -> None:
        backlog_limit = self._config.queue_backlog_soft_limit
        age_limit = self._config.queue_oldest_age_soft_limit_seconds
        overloaded = queue.backlog > backlog_limit or queue.oldest_age_seconds > age_limit
        if not overloaded:
            return
        multiplier = self._config.critical_queue_multiplier
        hard_overloaded = (
            queue.backlog > backlog_limit * multiplier
            or queue.oldest_age_seconds > age_limit * multiplier
        )
        if priority is RunPriority.CRITICAL and not hard_overloaded:
            return
        code = "RUN_QUEUE_HARD_LIMIT" if hard_overloaded else "RUN_QUEUE_BACKPRESSURE"
        raise PlatformError(
            code,
            "Temporal queue pressure is above the bounded Run admission threshold",
            retryable=True,
            http_status=503,
            context={
                "backlog": queue.backlog,
                "oldest_age_seconds": queue.oldest_age_seconds,
                "priority": priority.value,
            },
        )

    def _reservation_key(self, tenant_id: str, idempotency_key: str) -> str:
        normalized_tenant = tenant_id.strip()
        normalized_idempotency = idempotency_key.strip()
        if (
            not normalized_tenant
            or not normalized_idempotency
            or len(normalized_tenant) > 512
            or len(normalized_idempotency) > 512
        ):
            raise ValueError("CAPACITY_RESERVATION_IDENTITY_INVALID")
        return hmac.new(
            self._secret,
            f"{normalized_tenant}\0{normalized_idempotency}".encode(),
            hashlib.sha256,
        ).hexdigest()


class AuditCostReconciler:
    """Derive one full-cost snapshot from immutable Run audit material."""

    _SANDBOX_KINDS = frozenset({"sandbox", "code", "code_execution", "programmatic"})

    def __init__(
        self,
        audit: AuditExporter,
        rate_catalog: CostRateCatalog,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._audit = audit
        self._catalog = rate_catalog
        self._clock = clock or (lambda: datetime.now(UTC))

    async def reconcile(self, run: RunRecord) -> CostBreakdown:
        exported = await self._audit.export_run(run.run_id, run.tenant_id)
        tasks = self._object_list(exported, "task_executions")
        tools = self._object_list(exported, "tool_invocations")
        artifacts = self._object_list(exported, "artifacts")
        events = self._object_list(exported, "events")

        sandbox_cpu_seconds = Decimal("0")
        sandbox_memory_gib_seconds = Decimal("0")
        sandbox_tasks = 0
        for task in tasks:
            if str(task.get("task_kind", "")).strip() not in self._SANDBOX_KINDS:
                continue
            sandbox_tasks += 1
            usage = task.get("usage")
            if not isinstance(usage, Mapping):
                raise self._usage_incomplete(task)
            try:
                cpu = Decimal(str(usage["sandbox_cpu_seconds"]))
                memory = Decimal(str(usage["sandbox_memory_gib_seconds"]))
            except (KeyError, InvalidOperation, TypeError, ValueError) as exc:
                raise self._usage_incomplete(task) from exc
            if cpu < 0 or memory < 0:
                raise self._usage_incomplete(task)
            sandbox_cpu_seconds += cpu
            sandbox_memory_gib_seconds += memory

        artifact_storage_gib_months = Decimal("0")
        artifact_transfer_gib = Decimal("0")
        active_artifacts = 0
        for artifact in artifacts:
            if artifact.get("deleted_at") is not None:
                continue
            size_bytes = self._nonnegative_decimal(artifact.get("size_bytes"), "size_bytes")
            active_artifacts += 1
            size_gib = size_bytes / _GIB
            artifact_transfer_gib += size_gib
            retention_days = self._retention_days(artifact)
            artifact_storage_gib_months += size_gib * retention_days / Decimal(30)

        started = self._aware(run.created_at, "run.created_at")
        stopped = self._aware(
            run.completed_at or run.updated_at or self._clock(),
            "run.completed_at",
        )
        workflow_seconds = Decimal(str(max((stopped - started).total_seconds(), 0.0)))
        rates = self._catalog.rates
        components = {
            CostComponent.MODEL: _usd(run.cost_actual_usd),
            CostComponent.TOOL: _usd(Decimal(len(tools)) * rates.tool_call_usd),
            CostComponent.SANDBOX: _usd(
                (sandbox_cpu_seconds * rates.sandbox_cpu_second_usd)
                + (sandbox_memory_gib_seconds * rates.sandbox_memory_gib_second_usd)
            ),
            CostComponent.ARTIFACT: _usd(
                (artifact_storage_gib_months * rates.artifact_storage_gib_month_usd)
                + (artifact_transfer_gib * rates.artifact_transfer_gib_usd)
            ),
            CostComponent.WORKFLOW: _usd(workflow_seconds * rates.workflow_second_usd),
            CostComponent.OBSERVABILITY: _usd(Decimal(len(events)) * rates.observability_event_usd),
        }
        return CostBreakdown(
            rate_catalog_id=self._catalog.catalog_id,
            components=components,
            total_usd=_usd(sum(components.values(), Decimal("0"))),
            source_counts={
                "artifacts": active_artifacts,
                "events": len(events),
                "sandbox_tasks": sandbox_tasks,
                "tool_invocations": len(tools),
            },
            reconciled_at=self._aware(self._clock(), "reconciled_at"),
        )

    def _retention_days(self, artifact: Mapping[str, Any]) -> Decimal:
        created_value = artifact.get("created_at")
        expires_value = artifact.get("expires_at")
        if created_value and expires_value:
            try:
                created = datetime.fromisoformat(str(created_value))
                expires = datetime.fromisoformat(str(expires_value))
                days = Decimal(str(max((expires - created).total_seconds(), 0.0))) / Decimal(86_400)
                if days > 0:
                    return days
            except ValueError as exc:
                raise PlatformError(
                    "COST_USAGE_INVALID",
                    "Artifact lifecycle timestamps are invalid",
                    http_status=500,
                ) from exc
        return Decimal(self._catalog.default_artifact_retention_days)

    @staticmethod
    def _object_list(exported: Mapping[str, Any], name: str) -> list[Mapping[str, Any]]:
        value = exported.get(name)
        if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
            raise PlatformError(
                "COST_AUDIT_EXPORT_INVALID",
                "Run audit export is missing a required structured collection",
                http_status=500,
                context={"collection": name},
            )
        return cast(list[Mapping[str, Any]], value)

    @staticmethod
    def _nonnegative_decimal(value: Any, field: str) -> Decimal:
        try:
            parsed = Decimal(str(value))
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise PlatformError(
                "COST_USAGE_INVALID",
                "A measured cost unit is invalid",
                http_status=500,
                context={"field": field},
            ) from exc
        if not parsed.is_finite() or parsed < 0:
            raise PlatformError(
                "COST_USAGE_INVALID",
                "A measured cost unit must be finite and non-negative",
                http_status=500,
                context={"field": field},
            )
        return parsed

    @staticmethod
    def _aware(value: datetime, field: str) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise PlatformError(
                "COST_TIMESTAMP_INVALID",
                "Cost reconciliation requires timezone-aware timestamps",
                http_status=500,
                context={"field": field},
            )
        return value.astimezone(UTC)

    @staticmethod
    def _usage_incomplete(task: Mapping[str, Any]) -> PlatformError:
        return PlatformError(
            "COST_USAGE_INCOMPLETE",
            "Sandbox cost reconciliation requires measured CPU and memory seconds",
            http_status=503,
            context={"task_id": str(task.get("task_id", "unknown"))},
        )


def _usd(value: Decimal | int | float | str) -> Decimal:
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError("COST_AMOUNT_INVALID") from exc
    if not parsed.is_finite() or parsed < 0:
        raise ValueError("COST_AMOUNT_INVALID")
    return parsed.quantize(_USD_QUANTUM, rounding=ROUND_HALF_UP)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"COST_RATE_CATALOG_DUPLICATE_KEY:{key}")
        result[key] = value
    return result
