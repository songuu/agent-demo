from __future__ import annotations

from typing import Any

import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.infrastructure.quota import QuotaDimension, RedisQuotaLimiter


class FakeRedis:
    def __init__(self, result: object = (1, 0, 0)) -> None:
        self.result = result
        self.calls: list[tuple[str, int, tuple[object, ...]]] = []

    async def eval(
        self,
        script: str,
        numkeys: int,
        *keys_and_args: object,
    ) -> Any:
        self.calls.append((script, numkeys, keys_and_args))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _dimensions() -> tuple[QuotaDimension, ...]:
    return (
        QuotaDimension(name="user", value="user@example.com", limit=60, window_seconds=60),
        QuotaDimension(name="tenant", value="tenant-a", limit=600, window_seconds=60),
        QuotaDimension(
            name="use_case",
            value="document-review",
            limit=120,
            window_seconds=60,
        ),
        QuotaDimension(name="ip", value="203.0.113.9", limit=30, window_seconds=60),
    )


@pytest.mark.asyncio
async def test_all_dimensions_are_consumed_atomically_without_raw_identifiers() -> None:
    redis = FakeRedis()
    limiter = RedisQuotaLimiter(redis, key_hmac_secret=b"k" * 32)

    decision = await limiter.consume(_dimensions())

    assert decision.allowed is True
    script, numkeys, keys_and_args = redis.calls[0]
    assert numkeys == 4
    keys = tuple(str(item) for item in keys_and_args[:numkeys])
    assert all(key.startswith("agent-platform:quota:v1:") for key in keys)
    assert not any(
        identifier in key
        for key in keys
        for identifier in ("user@example.com", "tenant-a", "document-review", "203.0.113.9")
    )
    assert keys_and_args[numkeys:] == (60, 60, 600, 60, 120, 60, 30, 60)
    assert 'redis.call("TIME")' in script
    assert script.index('redis.call("GET"') < script.index('redis.call("INCR"')


@pytest.mark.asyncio
async def test_denial_identifies_dimension_and_returns_retry_after() -> None:
    limiter = RedisQuotaLimiter(
        FakeRedis((0, 17, 2)),
        key_hmac_secret=b"k" * 32,
    )

    decision = await limiter.consume(_dimensions())

    assert decision.allowed is False
    assert decision.retry_after_seconds == 17
    assert decision.limited_dimension == "tenant"


@pytest.mark.asyncio
async def test_backend_failure_and_invalid_response_fail_closed() -> None:
    unavailable = RedisQuotaLimiter(
        FakeRedis(OSError("redis unavailable")),
        key_hmac_secret=b"k" * 32,
    )
    with pytest.raises(PlatformError, match="QUOTA_BACKEND_UNAVAILABLE"):
        await unavailable.consume(_dimensions())

    invalid = RedisQuotaLimiter(
        FakeRedis((1, 9, 0)),
        key_hmac_secret=b"k" * 32,
    )
    with pytest.raises(PlatformError, match="QUOTA_BACKEND_RESPONSE_INVALID"):
        await invalid.consume(_dimensions())


@pytest.mark.asyncio
async def test_quota_configuration_is_bounded_and_unambiguous() -> None:
    with pytest.raises(ValueError, match="QUOTA_KEY_SECRET_TOO_SHORT"):
        RedisQuotaLimiter(FakeRedis(), key_hmac_secret=b"short")

    limiter = RedisQuotaLimiter(FakeRedis(), key_hmac_secret=b"k" * 32)
    duplicate = QuotaDimension(name="tenant", value="tenant-a", limit=10, window_seconds=60)
    with pytest.raises(ValueError, match="QUOTA_DIMENSION_DUPLICATE"):
        await limiter.consume((duplicate, duplicate))
