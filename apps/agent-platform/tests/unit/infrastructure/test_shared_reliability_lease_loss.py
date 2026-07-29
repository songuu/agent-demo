from __future__ import annotations

import asyncio
from typing import Any

import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.infrastructure.capacity_cost import (
    RedisSharedReliability,
    SharedReliabilityConfig,
)


class _Redis:
    def __init__(self) -> None:
        self.responses: list[object] = [
            (1, 1, 0),  # acquire
            (1, 0),  # circuit closed
            (0,),  # heartbeat cannot renew the lease
            (1,),  # release
        ]

    async def eval(
        self,
        script: str,
        numkeys: int,
        *keys_and_args: object,
    ) -> Any:
        del script, numkeys, keys_and_args
        return self.responses.pop(0)


@pytest.mark.asyncio
async def test_shared_control_cancels_provider_when_capacity_lease_is_lost() -> None:
    provider_cancelled = asyncio.Event()
    control = RedisSharedReliability(
        _Redis(),
        key_hmac_secret=b"k" * 32,
        config=SharedReliabilityConfig(
            lease_seconds=2,
            heartbeat_seconds=0.01,
            queue_timeout_seconds=0.2,
        ),
    )

    async def provider() -> str:
        try:
            await asyncio.Event().wait()
        finally:
            provider_cancelled.set()
        return "unreachable"

    with pytest.raises(PlatformError) as caught:
        await control.call("model:project:model", provider)

    assert caught.value.code == "SHARED_CONTROL_LEASE_LOST"
    assert provider_cancelled.is_set()
