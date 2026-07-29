from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from agent_platform.infrastructure.webhooks import (
    WebhookDispatcher,
    WebhookEndpoint,
    WebhookEvent,
    WebhookSigner,
)


def test_webhook_signature_binds_timestamp_event_and_delivery() -> None:
    signer = WebhookSigner(replay_window_seconds=300)
    secret = b"tenant-secret"
    body = b'{"event_type":"run.completed"}'
    now = datetime(2026, 7, 24, 9, 0, tzinfo=UTC)

    signature = signer.sign(
        secret,
        body,
        timestamp=int(now.timestamp()),
        event_id="evt-1",
        delivery_id="delivery-1",
    )

    signer.verify(
        secret,
        body,
        signature=signature,
        timestamp=int(now.timestamp()),
        event_id="evt-1",
        delivery_id="delivery-1",
        now=now,
    )
    with pytest.raises(ValueError, match="WEBHOOK_SIGNATURE_INVALID"):
        signer.verify(
            secret,
            body + b"tampered",
            signature=signature,
            timestamp=int(now.timestamp()),
            event_id="evt-1",
            delivery_id="delivery-1",
            now=now,
        )


def test_webhook_signature_rejects_replay_outside_window() -> None:
    signer = WebhookSigner(replay_window_seconds=60)
    secret = b"tenant-secret"
    body = b"{}"
    sent_at = datetime(2026, 7, 24, 9, 0, tzinfo=UTC)
    signature = signer.sign(
        secret,
        body,
        timestamp=int(sent_at.timestamp()),
        event_id="evt-1",
        delivery_id="delivery-1",
    )

    with pytest.raises(ValueError, match="WEBHOOK_REPLAY_WINDOW_EXCEEDED"):
        signer.verify(
            secret,
            body,
            signature=signature,
            timestamp=int(sent_at.timestamp()),
            event_id="evt-1",
            delivery_id="delivery-1",
            now=datetime(2026, 7, 24, 9, 2, tzinfo=UTC),
        )


@pytest.mark.asyncio
async def test_dispatcher_retries_with_same_delivery_id_then_succeeds() -> None:
    attempts: list[tuple[str, bytes, Mapping[str, str]]] = []

    async def send(
        url: str, body: bytes, headers: Mapping[str, str]
    ) -> tuple[int, bytes]:
        attempts.append((url, body, headers))
        return (503, b"retry") if len(attempts) == 1 else (204, b"")

    async def no_sleep(_: float) -> None:
        return None

    event = WebhookEvent(
        event_id="evt-1",
        tenant_id="tenant-a",
        event_type="run.completed",
        payload={"run_id": str(uuid4()), "status": "completed"},
    )
    endpoint = WebhookEndpoint(
        endpoint_id=uuid4(),
        tenant_id="tenant-a",
        url="https://example.test/hooks",
        event_types=frozenset({"run.completed"}),
        signing_secret=b"secret",
    )
    dispatcher = WebhookDispatcher(send=send, sleep=no_sleep, max_attempts=3)

    delivery = await dispatcher.deliver(endpoint, event)

    assert delivery.status == "delivered"
    assert delivery.attempts == 2
    assert len(attempts) == 2
    assert attempts[0][2]["X-Agent-Delivery-ID"] == attempts[1][2][
        "X-Agent-Delivery-ID"
    ]
    assert attempts[0][1] == attempts[1][1]


@pytest.mark.asyncio
async def test_dispatcher_filters_events_and_dead_letters_failures() -> None:
    calls: list[dict[str, Any]] = []

    async def fail(
        url: str, body: bytes, headers: Mapping[str, str]
    ) -> tuple[int, bytes]:
        calls.append({"url": url, "body": body, "headers": headers})
        return 500, b"provider failure"

    async def no_sleep(_: float) -> None:
        return None

    endpoint = WebhookEndpoint(
        endpoint_id=uuid4(),
        tenant_id="tenant-a",
        url="https://example.test/hooks",
        event_types=frozenset({"run.completed"}),
        signing_secret=b"secret",
    )
    dispatcher = WebhookDispatcher(send=fail, sleep=no_sleep, max_attempts=2)
    filtered = await dispatcher.deliver(
        endpoint,
        WebhookEvent(
            event_id="evt-filtered",
            tenant_id="tenant-a",
            event_type="task.started",
            payload={"task_id": "task-1"},
        ),
    )
    dead_letter = await dispatcher.deliver(
        endpoint,
        WebhookEvent(
            event_id="evt-dead",
            tenant_id="tenant-a",
            event_type="run.completed",
            payload={"status": "completed"},
        ),
    )

    assert filtered.status == "filtered"
    assert filtered.attempts == 0
    assert dead_letter.status == "dead_letter"
    assert dead_letter.attempts == 2
    assert dead_letter.last_error == "HTTP_500"
    assert len(calls) == 2
