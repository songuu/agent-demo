from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import pytest
from tests.unit.tools.test_enterprise_gateway_reliability import (
    _definition,
    _grant,
    _response,
)

from agent_platform.tools.adapters.enterprise_gateway import (
    EnterpriseToolGatewayAdapter,
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
        assert callable(kwargs["is_failure"])
        return await operation()


@pytest.mark.asyncio
async def test_enterprise_tool_calls_use_shared_tool_endpoint_control() -> None:
    shared = _SharedControl()
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(_response),
        trust_env=False,
    ) as client:
        adapter = EnterpriseToolGatewayAdapter(
            definition=_definition(),
            client=client,
            gateway_url="https://tool-gateway.platform.svc",
            catalog_digest="sha256:" + "a" * 64,
            shared_control=shared,
        )
        result = await adapter.read({"query": "bounded"}, _grant())

    assert result.data == {"items": []}
    assert shared.scopes == ["tool:https://tool-gateway.platform.svc:knowledge.search:1.0.0"]
