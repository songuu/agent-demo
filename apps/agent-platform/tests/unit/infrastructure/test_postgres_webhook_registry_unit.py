from __future__ import annotations

from collections import deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

from agent_platform.application.errors import NotFound, PlatformError
from agent_platform.infrastructure.persistence import postgres_webhook_registry
from agent_platform.infrastructure.persistence.governance_models import (
    WebhookEndpointSecretState,
)
from agent_platform.infrastructure.persistence.models import (
    WebhookEndpoint as DatabaseWebhookEndpoint,
)
from agent_platform.infrastructure.persistence.postgres_webhook_registry import (
    PostgresWebhookEndpointRegistry,
    SecretBroker,
)
from agent_platform.infrastructure.webhook_registry import WebhookEndpointView


class _RowsResult:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return self._rows


class _Result:
    def __init__(self, value: Any) -> None:
        self._value = value

    def one_or_none(self) -> Any:
        return self._value

    def all(self) -> list[Any]:
        return cast(list[Any], self._value)


class _Session:
    def __init__(
        self,
        *,
        scalar_results: list[Any] | None = None,
        execute_results: list[Any] | None = None,
    ) -> None:
        self.scalar_results = deque(scalar_results or [])
        self.execute_results = deque(execute_results or [])
        self.added: list[Any] = []
        self.flushes = 0
        self.commits = 0

    async def scalar(self, _statement: Any) -> Any:
        if not self.scalar_results:
            raise AssertionError("unexpected scalar query")
        return self.scalar_results.popleft()

    async def execute(self, _statement: Any) -> _Result:
        if not self.execute_results:
            raise AssertionError("unexpected execute query")
        value = self.execute_results.popleft()
        return value if isinstance(value, _Result) else _Result(value)

    def add(self, value: Any) -> None:
        self.added.append(value)

    async def flush(self) -> None:
        self.flushes += 1

    async def commit(self) -> None:
        self.commits += 1


class _Broker:
    def __init__(self) -> None:
        self.put = AsyncMock(return_value="secret://webhook/ref")
        self.get = AsyncMock(return_value=b"resolved-secret")
        self.delete = AsyncMock()


def _patch_session(monkeypatch: pytest.MonkeyPatch, session: _Session) -> None:
    @asynccontextmanager
    async def fake_tenant_session(
        _factory: Any,
        tenant_id: str,
    ) -> AsyncIterator[_Session]:
        assert tenant_id == "tenant-a"
        yield session

    monkeypatch.setattr(
        postgres_webhook_registry,
        "tenant_session",
        fake_tenant_session,
    )


def _endpoint(
    *,
    endpoint_id: UUID | None = None,
    enabled: bool = True,
    reference: str = "secret://webhook/ref",
) -> DatabaseWebhookEndpoint:
    return DatabaseWebhookEndpoint(
        endpoint_id=endpoint_id or uuid4(),
        tenant_id="tenant-a",
        endpoint_name="audit-events",
        url="https://hooks.example.test/agent",
        event_types=["run.completed", "action.committed"],
        signing_secret_ref=reference,
        enabled=enabled,
    )


def _state(endpoint_id: UUID, version: int = 1) -> WebhookEndpointSecretState:
    return WebhookEndpointSecretState(
        endpoint_id=endpoint_id,
        tenant_id="tenant-a",
        secret_version=version,
    )


def _view(endpoint: DatabaseWebhookEndpoint, version: int = 1) -> WebhookEndpointView:
    return WebhookEndpointView(
        endpoint_id=endpoint.endpoint_id,
        tenant_id=endpoint.tenant_id,
        endpoint_name=endpoint.endpoint_name,
        url=endpoint.url,
        event_types=frozenset(endpoint.event_types),
        enabled=endpoint.enabled,
        secret_version=version,
    )


def _registry(broker: _Broker | None = None) -> PostgresWebhookEndpointRegistry:
    selected = broker or _Broker()
    return PostgresWebhookEndpointRegistry(
        cast(Any, object()),
        secret_broker=cast(SecretBroker, selected),
    )


@pytest.mark.asyncio
async def test_register_returns_existing_endpoint_without_exposing_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broker = _Broker()
    registry = _registry(broker)
    endpoint = _endpoint()
    existing = _view(endpoint)
    find = AsyncMock(return_value=existing)
    monkeypatch.setattr(registry, "_find_by_name", find)

    view, secret = await registry.register(
        tenant_id="tenant-a",
        endpoint_name=endpoint.endpoint_name,
        url=endpoint.url,
        event_types=frozenset(endpoint.event_types),
    )

    assert view is existing
    assert secret == b""
    broker.put.assert_not_awaited()


@pytest.mark.asyncio
async def test_register_stores_secret_reference_and_database_state_atomically(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broker = _Broker()
    registry = _registry(broker)
    find = AsyncMock(return_value=None)
    expected = _view(_endpoint())
    view_in_session = AsyncMock(return_value=expected)
    monkeypatch.setattr(registry, "_find_by_name", find)
    monkeypatch.setattr(registry, "_view_in_session", view_in_session)
    signing_secret = b"customer-supplied-secret"
    session = _Session(scalar_results=[uuid4()])
    _patch_session(monkeypatch, session)

    view, secret = await registry.register(
        tenant_id="tenant-a",
        endpoint_name="audit-events",
        url="https://hooks.example.test/agent",
        event_types=frozenset({"run.completed"}),
        signing_secret=signing_secret,
    )

    assert view is expected
    assert secret == signing_secret
    broker.put.assert_awaited_once()
    broker.delete.assert_not_awaited()
    assert isinstance(session.added[0], WebhookEndpointSecretState)
    assert session.flushes == session.commits == 1


@pytest.mark.asyncio
async def test_register_database_race_returns_winner_and_cleans_loser_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broker = _Broker()
    registry = _registry(broker)
    winner = _view(_endpoint())
    monkeypatch.setattr(registry, "_find_by_name", AsyncMock(return_value=None))
    monkeypatch.setattr(
        registry,
        "_find_by_name_in_session",
        AsyncMock(return_value=winner),
    )
    session = _Session(scalar_results=[None])
    _patch_session(monkeypatch, session)

    view, secret = await registry.register(
        tenant_id="tenant-a",
        endpoint_name="audit-events",
        url="https://hooks.example.test/agent",
        event_types=frozenset({"run.completed"}),
    )

    assert view is winner
    assert secret == b""
    assert session.commits == 1
    broker.delete.assert_awaited_once_with("secret://webhook/ref")


@pytest.mark.asyncio
async def test_register_conflict_and_database_failure_compensate_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broker = _Broker()
    registry = _registry(broker)
    monkeypatch.setattr(registry, "_find_by_name", AsyncMock(return_value=None))
    monkeypatch.setattr(
        registry,
        "_find_by_name_in_session",
        AsyncMock(return_value=None),
    )
    _patch_session(monkeypatch, _Session(scalar_results=[None]))
    with pytest.raises(PlatformError) as conflict:
        await registry.register(
            tenant_id="tenant-a",
            endpoint_name="audit-events",
            url="https://hooks.example.test/agent",
            event_types=frozenset({"run.completed"}),
        )
    assert conflict.value.code == "WEBHOOK_ENDPOINT_CREATE_CONFLICT"
    broker.delete.assert_awaited()


@pytest.mark.asyncio
async def test_list_set_enabled_and_view_helpers_preserve_secret_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _registry()
    endpoint = _endpoint()
    state = _state(endpoint.endpoint_id, 3)
    list_session = _Session(execute_results=[[(endpoint, state)]])
    _patch_session(monkeypatch, list_session)

    listed = await registry.list("tenant-a")
    assert listed == (_view(endpoint, 3),)
    assert registry._view(endpoint, None).secret_version == 1

    view_in_session = AsyncMock(return_value=_view(endpoint, 3))
    monkeypatch.setattr(registry, "_view_in_session", view_in_session)
    enabled_session = _Session(scalar_results=[endpoint.endpoint_id])
    _patch_session(monkeypatch, enabled_session)
    assert (
        await registry.set_enabled(
            endpoint.endpoint_id,
            endpoint.tenant_id,
            enabled=False,
        )
    ).secret_version == 3
    assert enabled_session.commits == 1

    _patch_session(monkeypatch, _Session(scalar_results=[None]))
    with pytest.raises(NotFound):
        await registry.set_enabled(
            endpoint.endpoint_id,
            endpoint.tenant_id,
            enabled=False,
        )


@pytest.mark.asyncio
async def test_rotate_secret_updates_existing_state_or_creates_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broker = _Broker()
    registry = _registry(broker)
    endpoint = _endpoint()
    state = _state(endpoint.endpoint_id, 2)
    existing_session = _Session(scalar_results=[endpoint, state])
    _patch_session(monkeypatch, existing_session)
    view, secret = await registry.rotate_secret(endpoint.endpoint_id, endpoint.tenant_id)
    assert len(secret) == 32
    assert view.secret_version == 3
    assert state.secret_version == 3
    assert endpoint.signing_secret_ref == "secret://webhook/ref"
    assert existing_session.commits == 1

    fresh_endpoint = _endpoint()
    missing_state_session = _Session(scalar_results=[fresh_endpoint, None])
    _patch_session(monkeypatch, missing_state_session)
    fresh, _ = await registry.rotate_secret(
        fresh_endpoint.endpoint_id,
        fresh_endpoint.tenant_id,
    )
    assert fresh.secret_version == 2
    assert isinstance(missing_state_session.added[0], WebhookEndpointSecretState)

    _patch_session(monkeypatch, _Session(scalar_results=[None]))
    with pytest.raises(NotFound):
        await registry.rotate_secret(uuid4(), "tenant-a")


@pytest.mark.asyncio
async def test_rotate_secret_compensates_reference_when_database_write_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broker = _Broker()
    registry = _registry(broker)
    endpoint = _endpoint()
    session = _Session(scalar_results=[endpoint, None])
    _patch_session(monkeypatch, session)
    broker.put.return_value = "secret://webhook/new"

    async def failing_put(_hint: str, _secret: bytes) -> str:
        return "secret://webhook/new"

    monkeypatch.setattr(registry, "_put_secret", failing_put)

    original_flush = session.flush

    async def fail_flush() -> None:
        await original_flush()
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(session, "flush", fail_flush)
    with pytest.raises(RuntimeError, match="database unavailable"):
        await registry.rotate_secret(endpoint.endpoint_id, endpoint.tenant_id)
    broker.delete.assert_awaited_once_with("secret://webhook/new")


@pytest.mark.asyncio
async def test_delivery_endpoint_materializes_secret_outside_database_transaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broker = _Broker()
    registry = _registry(broker)
    endpoint = _endpoint(enabled=False)
    session = _Session(scalar_results=[endpoint])
    _patch_session(monkeypatch, session)

    delivery = await registry.delivery_endpoint(
        endpoint.endpoint_id,
        endpoint.tenant_id,
    )
    assert delivery.endpoint_id == endpoint.endpoint_id
    assert delivery.signing_secret == b"resolved-secret"
    assert delivery.enabled is False
    broker.get.assert_awaited_once_with(endpoint.signing_secret_ref)

    _patch_session(monkeypatch, _Session(scalar_results=[None]))
    with pytest.raises(NotFound):
        await registry.delivery_endpoint(uuid4(), "tenant-a")


@pytest.mark.asyncio
async def test_find_and_view_queries_handle_missing_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _registry()
    endpoint = _endpoint()
    state = _state(endpoint.endpoint_id, 4)

    found_session = _Session(execute_results=[(endpoint, state)])
    _patch_session(monkeypatch, found_session)
    found = await registry._find_by_name("tenant-a", endpoint.endpoint_name)
    assert found == _view(endpoint, 4)

    assert (
        await registry._find_by_name_in_session(
            cast(Any, _Session(execute_results=[None])),
            "tenant-a",
            endpoint.endpoint_name,
        )
        is None
    )
    with pytest.raises(NotFound):
        await registry._view_in_session(
            cast(Any, _Session(execute_results=[None])),
            endpoint.endpoint_id,
            endpoint.tenant_id,
        )
    assert await registry._view_in_session(
        cast(Any, _Session(execute_results=[(endpoint, state)])),
        endpoint.endpoint_id,
        endpoint.tenant_id,
    ) == _view(endpoint, 4)


@pytest.mark.asyncio
async def test_secret_broker_errors_are_explicit_and_retryable() -> None:
    broker = _Broker()
    registry = _registry(broker)
    broker.put.side_effect = RuntimeError("vault down")
    with pytest.raises(PlatformError) as put_error:
        await registry._put_secret("hint", b"secret")
    assert put_error.value.code == "WEBHOOK_SECRET_BROKER_UNAVAILABLE"
    assert put_error.value.retryable is True

    broker.put.side_effect = None
    broker.put.return_value = ""
    with pytest.raises(PlatformError) as empty_reference:
        await registry._put_secret("hint", b"secret")
    assert empty_reference.value.code == "WEBHOOK_SECRET_BROKER_INVALID_REFERENCE"

    broker.get.side_effect = RuntimeError("vault down")
    with pytest.raises(PlatformError) as get_error:
        await registry._get_secret("secret://ref")
    assert get_error.value.code == "WEBHOOK_SECRET_BROKER_UNAVAILABLE"

    broker.delete.side_effect = RuntimeError("vault down")
    with pytest.raises(PlatformError) as delete_error:
        await registry._delete_secret("secret://ref")
    assert delete_error.value.code == "WEBHOOK_SECRET_CLEANUP_FAILED"
    assert registry._reference_hint("tenant-a", UUID(int=1), 3).endswith("/versions/3")
