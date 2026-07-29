"""Atomic multi-dimensional request quotas backed by Redis."""

from __future__ import annotations

import hashlib
import hmac
import math
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent_platform.application.errors import PlatformError

_DIMENSION_NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")

# Check every dimension before consuming any quota, so a rejected tenant request
# cannot drain another user or IP bucket. Redis executes the script atomically.
_ATOMIC_QUOTA_SCRIPT = """
local clock = redis.call("TIME")
local now = tonumber(clock[1])
local dimensions = #KEYS
for index = 1, dimensions do
  local limit = tonumber(ARGV[((index - 1) * 2) + 1])
  local window = tonumber(ARGV[((index - 1) * 2) + 2])
  local bucket = math.floor(now / window)
  local bucket_key = KEYS[index] .. ":" .. bucket
  local current = tonumber(redis.call("GET", bucket_key) or "0")
  if current >= limit then
    local retry_after = window - (now % window)
    return {0, retry_after, index}
  end
end
for index = 1, dimensions do
  local window = tonumber(ARGV[((index - 1) * 2) + 2])
  local bucket = math.floor(now / window)
  local bucket_key = KEYS[index] .. ":" .. bucket
  local current = redis.call("INCR", bucket_key)
  if current == 1 then
    redis.call("EXPIRE", bucket_key, window + 1)
  end
end
return {1, 0, 0}
""".strip()


class RedisScriptClient(Protocol):
    async def eval(
        self,
        script: str,
        numkeys: int,
        *keys_and_args: object,
    ) -> Any: ...


class QuotaDimension(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    value: str = Field(min_length=1, max_length=1_024)
    limit: int = Field(ge=1, le=1_000_000)
    window_seconds: int = Field(ge=1, le=86_400)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not _DIMENSION_NAME.fullmatch(value):
            raise ValueError("QUOTA_DIMENSION_NAME_INVALID")
        return value


@dataclass(frozen=True, slots=True)
class QuotaDecision:
    allowed: bool
    retry_after_seconds: int
    limited_dimension: str | None


class RedisQuotaLimiter:
    """Consume all applicable dimensions in one fail-closed Redis operation."""

    def __init__(
        self,
        client: RedisScriptClient,
        *,
        key_hmac_secret: bytes,
        namespace: str = "agent-platform:quota:v1",
    ) -> None:
        if len(key_hmac_secret) < 32:
            raise ValueError("QUOTA_KEY_SECRET_TOO_SHORT")
        if not namespace.strip() or len(namespace) > 128:
            raise ValueError("QUOTA_NAMESPACE_INVALID")
        self._client = client
        self._secret = bytes(key_hmac_secret)
        self._namespace = namespace.strip()

    async def consume(self, dimensions: Sequence[QuotaDimension]) -> QuotaDecision:
        if not dimensions:
            raise ValueError("QUOTA_DIMENSIONS_REQUIRED")
        names = [dimension.name for dimension in dimensions]
        if len(names) != len(set(names)):
            raise ValueError("QUOTA_DIMENSION_DUPLICATE")

        keys = [self._key(dimension) for dimension in dimensions]
        arguments: list[int] = []
        for dimension in dimensions:
            arguments.extend((dimension.limit, dimension.window_seconds))
        try:
            raw = await self._client.eval(
                _ATOMIC_QUOTA_SCRIPT,
                len(keys),
                *keys,
                *arguments,
            )
        except Exception as exc:
            raise PlatformError(
                "QUOTA_BACKEND_UNAVAILABLE",
                "The shared quota backend is unavailable",
                retryable=True,
                http_status=503,
            ) from exc

        allowed, retry_after, limited_index = self._parse_result(raw, len(dimensions))
        if allowed:
            return QuotaDecision(True, 0, None)
        return QuotaDecision(
            False,
            max(1, retry_after),
            dimensions[limited_index - 1].name,
        )

    def _key(self, dimension: QuotaDimension) -> str:
        identifier = hmac.new(
            self._secret,
            f"{dimension.name}\0{dimension.value}".encode(),
            hashlib.sha256,
        ).hexdigest()
        return f"{self._namespace}:{dimension.name}:{identifier}"

    @staticmethod
    def _parse_result(raw: Any, dimension_count: int) -> tuple[bool, int, int]:
        if not isinstance(raw, (list, tuple)) or len(raw) != 3:
            raise PlatformError(
                "QUOTA_BACKEND_RESPONSE_INVALID",
                "The shared quota backend returned an invalid response",
                http_status=503,
            )
        try:
            allowed = int(raw[0])
            retry_after = math.ceil(float(raw[1]))
            limited_index = int(raw[2])
        except (TypeError, ValueError, OverflowError) as exc:
            raise PlatformError(
                "QUOTA_BACKEND_RESPONSE_INVALID",
                "The shared quota backend returned an invalid response",
                http_status=503,
            ) from exc
        if allowed == 1 and retry_after == 0 and limited_index == 0:
            return True, 0, 0
        if allowed != 0 or retry_after < 0 or limited_index < 1 or limited_index > dimension_count:
            raise PlatformError(
                "QUOTA_BACKEND_RESPONSE_INVALID",
                "The shared quota backend returned an invalid response",
                http_status=503,
            )
        return False, retry_after, limited_index
