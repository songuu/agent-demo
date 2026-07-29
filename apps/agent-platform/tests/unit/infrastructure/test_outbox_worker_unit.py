from __future__ import annotations

from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest

from agent_platform.config import Settings
from agent_platform.infrastructure import outbox
from agent_platform.infrastructure.outbox import (
    BrokerSecretResolver,
    ClaimedDelivery,
    FileSecretResolver,
    PostgresOutboxWorker,
)
from agent_platform.infrastructure.persistence.session import AsyncSessionFactory


class _Rows:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return self._rows


class _Result:
    def __init__(self, value: Any) -> None:
        self._value = value

    def one_or_none(self) -> Any:
        return self._value


class _Transaction:
    async def __aenter__(self) -> _Transaction:
        return self

    async def __aexit__(self, *_args: Any) -> None:
        return None


class _Session:
    def __init__(
        self,
        *,
        scalar_results: list[Any] | None = None,
        scalars_results: list[list[Any]] | None = None,
        execute_results: list[Any] | None = None,
    ) -> None:
        self.scalar_results = deque(scalar_results or [])
        self.scalars_results = deque(scalars_results or [])
        self.execute_results = deque(execute_results or [])
        self.execute_calls = 0

    async def __aenter__(self) -> _Session:
        return self

    async def __aexit__(self, *_args: Any) -> None:
        return None

    def begin(self) -> _Transaction:
        return _Transaction()

    async def scalar(self, _statement: Any) -> Any:
        if not self.scalar_results:
            raise AssertionError("unexpected scalar query")
        return self.scalar_results.popleft()

    async def scalars(self, _statement: Any) -> _Rows:
        if not self.scalars_results:
            raise AssertionError("unexpected scalars query")
        return _Rows(self.scalars_results.popleft())

    async def execute(self, _statement: Any) -> _Result:
        self.execute_calls += 1
        value = self.execute_results.popleft() if self.execute_results else None
        return value if isinstance(value, _Result) else _Result(value)


class _Sessions:
    def __init__(self, *sessions: _Session) -> None:
        self._sessions = deque(sessions)

    def __call__(self) -> _Session:
        return self._sessions.popleft()


class _Secrets:
    def __init__(self, value: bytes = b"0123456789abcdef") -> None:
        self.resolve = AsyncMock(return_value=value)


def _claim(*, attempt: int = 1, payload: dict[str, Any] | None = None) -> ClaimedDelivery:
    return ClaimedDelivery(
        delivery_id=uuid4(),
        tenant_id="tenant-a",
        endpoint_id=uuid4(),
        outbox_id=uuid4(),
        url="https://hooks.example.test/agent",
        signing_secret_ref="secret-ref",
        event_type="run.completed",
        payload=payload or {"run_id": "run-1", "status": "completed"},
        occurred_at=datetime.now(UTC),
        attempt=attempt,
    )


def _worker(
    *,
    sessions: _Sessions | None = None,
    secrets: _Secrets | None = None,
    client: httpx.AsyncClient | None = None,
    max_attempts: int = 3,
) -> PostgresOutboxWorker:
    return PostgresOutboxWorker(
        session_factory=cast(AsyncSessionFactory, sessions or _Sessions()),
        secrets=secrets or _Secrets(),
        client=client
        or httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(204))),
        max_delivery_attempts=max_attempts,
    )


@pytest.mark.asyncio
async def test_secret_resolvers_validate_type_length_root_and_reference(
    tmp_path: Path,
) -> None:
    broker = SimpleNamespace(get=AsyncMock(return_value="not-bytes"))
    resolver = BrokerSecretResolver(broker)
    with pytest.raises(ValueError, match="WEBHOOK_SIGNING_SECRET_INVALID"):
        await resolver.resolve("reference")
    broker.get.return_value = b"short"
    with pytest.raises(ValueError, match="WEBHOOK_SIGNING_SECRET_TOO_SHORT"):
        await resolver.resolve("reference")

    not_directory = tmp_path / "file"
    not_directory.write_text("value", encoding="utf-8")
    with pytest.raises(ValueError, match="WEBHOOK_SECRET_ROOT_NOT_DIRECTORY"):
        FileSecretResolver(not_directory)

    root = tmp_path / "secrets"
    root.mkdir()
    (root / "short").write_bytes(b"short")
    (root / "directory").mkdir()
    file_resolver = FileSecretResolver(root)
    for invalid in ("", "bad\x00ref", "directory"):
        with pytest.raises(ValueError, match="WEBHOOK_SECRET_REFERENCE_INVALID"):
            await file_resolver.resolve(invalid)
    with pytest.raises(ValueError, match="WEBHOOK_SIGNING_SECRET_TOO_SHORT"):
        await file_resolver.resolve("short")


@pytest.mark.asyncio
async def test_run_once_counts_delivery_outcomes_and_stops_when_queue_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker()
    claims = [_claim(), _claim(), _claim(), None]
    expand = AsyncMock(return_value=4)
    claim = AsyncMock(side_effect=claims)
    send = AsyncMock(side_effect=["delivered", "retry", "dead_letter"])
    monkeypatch.setattr(worker, "_expand_outbox", expand)
    monkeypatch.setattr(worker, "_claim_delivery", claim)
    monkeypatch.setattr(worker, "_send", send)

    assert await worker.run_once(batch_size=10) == {
        "expanded": 4,
        "delivered": 1,
        "retried": 1,
        "dead_lettered": 1,
    }


@pytest.mark.asyncio
async def test_expand_outbox_creates_endpoint_deliveries_and_marks_published() -> None:
    event = SimpleNamespace(
        tenant_id="tenant-a",
        outbox_id=uuid4(),
        event_type="run.completed",
        published_at=None,
    )
    endpoints = [
        SimpleNamespace(endpoint_id=uuid4()),
        SimpleNamespace(endpoint_id=uuid4()),
    ]
    session = _Session(
        scalar_results=[True],
        scalars_results=[[event], endpoints],
    )
    worker = _worker(sessions=_Sessions(session))

    assert await worker._expand_outbox(batch_size=5) == 1
    assert event.published_at is not None
    assert session.execute_calls == 2
    assert worker._role_verified is True


@pytest.mark.asyncio
async def test_claim_delivery_leases_one_row_and_returns_none_when_empty() -> None:
    now = datetime.now(UTC)
    delivery = SimpleNamespace(
        delivery_id=uuid4(),
        tenant_id="tenant-a",
        status="pending",
        attempts=0,
        next_attempt_at=now,
        updated_at=now,
    )
    endpoint = SimpleNamespace(
        endpoint_id=uuid4(),
        url="https://hooks.example.test/agent",
        signing_secret_ref="secret-ref",
    )
    event = SimpleNamespace(
        outbox_id=uuid4(),
        event_type="run.completed",
        payload={"run_id": "run-1"},
        created_at=now,
    )
    claimed_session = _Session(
        scalar_results=[True],
        execute_results=[(delivery, endpoint, event)],
    )
    empty_session = _Session(
        scalar_results=[True],
        execute_results=[None],
    )

    claim = await _worker(sessions=_Sessions(claimed_session))._claim_delivery()
    assert claim is not None
    assert claim.delivery_id == delivery.delivery_id
    assert claim.attempt == 1
    assert delivery.status == "delivering"
    assert delivery.next_attempt_at > now

    assert await _worker(sessions=_Sessions(empty_session))._claim_delivery() is None


@pytest.mark.asyncio
async def test_send_retries_http_and_transport_failures_then_dead_letters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finishes: list[dict[str, Any]] = []

    async def capture_finish(_claim: ClaimedDelivery, **values: Any) -> None:
        finishes.append(values)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(503, content=b"unavailable"))
    ) as client:
        worker = _worker(client=client)
        monkeypatch.setattr(worker, "_finish", capture_finish)
        assert await worker._send(_claim(attempt=1)) == "retry"
    assert finishes[-1]["status"] == "retry"
    assert finishes[-1]["response_status"] == 503
    assert finishes[-1]["error_code"] == "HTTP_503"
    assert finishes[-1]["next_attempt_at"] is not None

    secrets = _Secrets()
    secrets.resolve.side_effect = ConnectionError("secret service unavailable")
    worker = _worker(secrets=secrets, max_attempts=2)
    monkeypatch.setattr(worker, "_finish", capture_finish)
    assert await worker._send(_claim(attempt=2)) == "dead_letter"
    assert finishes[-1]["status"] == "dead_letter"
    assert finishes[-1]["error_code"] == "TRANSPORT_CONNECTIONERROR"
    await worker._client.aclose()


@pytest.mark.asyncio
async def test_finish_persists_terminal_and_retry_timestamps() -> None:
    sessions = [
        _Session(scalar_results=[True]),
        _Session(scalar_results=[True]),
        _Session(scalar_results=[True]),
    ]
    worker = _worker(sessions=_Sessions(*sessions))
    claim = _claim()
    await worker._finish(
        claim,
        status="delivered",
        response_status=204,
        response_hash="a" * 64,
    )
    await worker._finish(
        claim,
        status="dead_letter",
        response_status=500,
        response_hash="b" * 64,
        error_code="HTTP_500",
    )
    await worker._finish(
        claim,
        status="retry",
        response_status=503,
        response_hash="c" * 64,
        error_code="HTTP_503",
        next_attempt_at=datetime.now(UTC),
    )
    assert [session.execute_calls for session in sessions] == [1, 1, 1]
    await worker._client.aclose()


@pytest.mark.asyncio
async def test_dispatch_role_verification_fails_closed_and_is_cached() -> None:
    worker = _worker()
    denied = _Session(scalar_results=[False])
    with pytest.raises(RuntimeError, match="OUTBOX_ROLE_MUST_BYPASS_RLS"):
        await worker._assert_dispatch_role(denied)

    allowed = _Session(scalar_results=[True])
    await worker._assert_dispatch_role(allowed)
    await worker._assert_dispatch_role(_Session())
    assert worker._role_verified is True
    await worker._client.aclose()


def test_secret_resolver_requires_configured_directory_and_builds_directory_broker(
    tmp_path: Path,
) -> None:
    missing = Settings(environment="test", webhook_secret_dir="")
    with pytest.raises(RuntimeError, match="AGENT_WEBHOOK_SECRET_DIR_REQUIRED"):
        outbox._secret_resolver(missing)

    root = tmp_path / "secrets"
    root.mkdir()
    configured = Settings(
        environment="test",
        webhook_secret_dir=str(root),
    )
    resolver, client = outbox._secret_resolver(configured)
    assert isinstance(resolver, BrokerSecretResolver)
    assert client is None


def test_approval_notification_retry_delay_caps_before_exponentiation() -> None:
    assert outbox._approval_notification_retry_delay_seconds(1) == 2
    assert outbox._approval_notification_retry_delay_seconds(8) == 256
    assert outbox._approval_notification_retry_delay_seconds(1_000_000) == 300


@pytest.mark.asyncio
async def test_approval_required_without_enabled_endpoint_stays_unpublished() -> None:
    available_at = datetime.now(UTC)
    event = SimpleNamespace(
        tenant_id="tenant-a",
        outbox_id=uuid4(),
        event_type="action.approval_required",
        published_at=None,
        available_at=available_at,
        attempts=0,
        last_error=None,
    )
    session = _Session(
        scalar_results=[True],
        scalars_results=[[event], []],
    )
    worker = _worker(sessions=_Sessions(session))

    assert await worker._expand_outbox(batch_size=5) == 0
    assert event.published_at is None
    assert event.attempts == 1
    assert event.last_error == "APPROVAL_NOTIFICATION_ENDPOINT_REQUIRED"
    assert event.available_at > available_at
    assert session.execute_calls == 0
