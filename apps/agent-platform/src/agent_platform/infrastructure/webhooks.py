"""Tenant-scoped Webhook signing and at-least-once delivery.

The dispatcher deliberately receives an injected sender. Production code can
bind an egress-restricted HTTP client while tests remain deterministic. The
body and delivery identifier are created once and reused across retries so the
receiver can safely de-duplicate.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import orjson

type WebhookSender = Callable[
    [str, bytes, Mapping[str, str]], Awaitable[tuple[int, bytes]]
]
type Sleep = Callable[[float], Awaitable[None]]

_FORBIDDEN_PAYLOAD_KEYS = frozenset(
    {
        "authorization",
        "artifact_content",
        "credential",
        "hidden_reasoning",
        "prompt",
        "secret",
        "tool_result",
    }
)


@dataclass(frozen=True, slots=True)
class WebhookEvent:
    event_id: str
    tenant_id: str
    event_type: str
    payload: Mapping[str, Any]
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def body(self) -> bytes:
        if _contains_forbidden_payload_key(self.payload):
            raise ValueError("WEBHOOK_PAYLOAD_CONTAINS_SENSITIVE_CONTENT")
        return orjson.dumps(
            {
                "event_id": self.event_id,
                "event_type": self.event_type,
                "occurred_at": self.occurred_at.isoformat(),
                "payload": self.payload,
                "schema_version": "1.0",
            },
            option=orjson.OPT_SORT_KEYS,
        )


@dataclass(frozen=True, slots=True)
class WebhookEndpoint:
    endpoint_id: UUID
    tenant_id: str
    url: str
    event_types: frozenset[str]
    signing_secret: bytes = field(repr=False)
    enabled: bool = True

    def __post_init__(self) -> None:
        _validate_webhook_url(self.url)
        if len(self.signing_secret) < 6:
            raise ValueError("WEBHOOK_SIGNING_SECRET_TOO_SHORT")


@dataclass(frozen=True, slots=True)
class WebhookDelivery:
    delivery_id: UUID
    endpoint_id: UUID
    event_id: str
    status: str
    attempts: int
    response_status: int | None = None
    response_hash: str | None = None
    last_error: str | None = None
    delivered_at: datetime | None = None
    dead_lettered_at: datetime | None = None


class WebhookSigner:
    def __init__(self, *, replay_window_seconds: int) -> None:
        if replay_window_seconds <= 0:
            raise ValueError("replay_window_seconds must be positive")
        self._replay_window_seconds = replay_window_seconds

    @staticmethod
    def sign(
        secret: bytes,
        body: bytes,
        *,
        timestamp: int,
        event_id: str,
        delivery_id: str,
    ) -> str:
        message = _signature_message(timestamp, event_id, delivery_id, body)
        digest = hmac.new(secret, message, hashlib.sha256).hexdigest()
        return f"v1={digest}"

    def verify(
        self,
        secret: bytes,
        body: bytes,
        *,
        signature: str,
        timestamp: int,
        event_id: str,
        delivery_id: str,
        now: datetime | None = None,
    ) -> None:
        current = now or datetime.now(UTC)
        if abs(int(current.timestamp()) - timestamp) > self._replay_window_seconds:
            raise ValueError("WEBHOOK_REPLAY_WINDOW_EXCEEDED")
        expected = self.sign(
            secret,
            body,
            timestamp=timestamp,
            event_id=event_id,
            delivery_id=delivery_id,
        )
        if not hmac.compare_digest(expected, signature):
            raise ValueError("WEBHOOK_SIGNATURE_INVALID")


class WebhookDispatcher:
    def __init__(
        self,
        *,
        send: WebhookSender,
        sleep: Sleep = asyncio.sleep,
        max_attempts: int = 5,
        initial_backoff_seconds: float = 1.0,
        max_backoff_seconds: float = 60.0,
        signer: WebhookSigner | None = None,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        self._send = send
        self._sleep = sleep
        self._max_attempts = max_attempts
        self._initial_backoff_seconds = initial_backoff_seconds
        self._max_backoff_seconds = max_backoff_seconds
        self._signer = signer or WebhookSigner(replay_window_seconds=300)

    async def deliver(
        self,
        endpoint: WebhookEndpoint,
        event: WebhookEvent,
    ) -> WebhookDelivery:
        delivery_id = uuid4()
        if endpoint.tenant_id != event.tenant_id:
            raise ValueError("WEBHOOK_TENANT_MISMATCH")
        if not endpoint.enabled or event.event_type not in endpoint.event_types:
            return WebhookDelivery(
                delivery_id=delivery_id,
                endpoint_id=endpoint.endpoint_id,
                event_id=event.event_id,
                status="filtered",
                attempts=0,
            )

        body = event.body()
        timestamp = int(datetime.now(UTC).timestamp())
        headers = {
            "Content-Type": "application/json",
            "X-Agent-Delivery-ID": str(delivery_id),
            "X-Agent-Event-ID": event.event_id,
            "X-Agent-Timestamp": str(timestamp),
            "X-Agent-Signature": self._signer.sign(
                endpoint.signing_secret,
                body,
                timestamp=timestamp,
                event_id=event.event_id,
                delivery_id=str(delivery_id),
            ),
        }
        last_status: int | None = None
        last_hash: str | None = None
        last_error: str | None = None
        for attempt in range(1, self._max_attempts + 1):
            try:
                last_status, response_body = await self._send(
                    endpoint.url, body, headers
                )
                last_hash = hashlib.sha256(response_body).hexdigest()
                if 200 <= last_status < 300:
                    return WebhookDelivery(
                        delivery_id=delivery_id,
                        endpoint_id=endpoint.endpoint_id,
                        event_id=event.event_id,
                        status="delivered",
                        attempts=attempt,
                        response_status=last_status,
                        response_hash=last_hash,
                        delivered_at=datetime.now(UTC),
                    )
                last_error = f"HTTP_{last_status}"
            except Exception as exc:
                # Raw provider text is intentionally excluded from persisted
                # delivery state because it can contain secrets or PII.
                last_error = f"TRANSPORT_{type(exc).__name__.upper()}"
            if attempt < self._max_attempts:
                delay = min(
                    self._initial_backoff_seconds * (2 ** (attempt - 1)),
                    self._max_backoff_seconds,
                )
                await self._sleep(delay)

        return WebhookDelivery(
            delivery_id=delivery_id,
            endpoint_id=endpoint.endpoint_id,
            event_id=event.event_id,
            status="dead_letter",
            attempts=self._max_attempts,
            response_status=last_status,
            response_hash=last_hash,
            last_error=last_error,
            dead_lettered_at=datetime.now(UTC),
        )


def _signature_message(
    timestamp: int,
    event_id: str,
    delivery_id: str,
    body: bytes,
) -> bytes:
    prefix = f"{timestamp}.{event_id}.{delivery_id}.".encode()
    return prefix + body


def _contains_forbidden_payload_key(value: object) -> bool:
    if isinstance(value, Mapping):
        return any(
            str(key).lower() in _FORBIDDEN_PAYLOAD_KEYS
            or _contains_forbidden_payload_key(item)
            for key, item in value.items()
        )
    if isinstance(value, list | tuple):
        return any(_contains_forbidden_payload_key(item) for item in value)
    return False


def _validate_webhook_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("WEBHOOK_URL_MUST_BE_PUBLIC_HTTPS")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        return
    if not address.is_global:
        raise ValueError("WEBHOOK_URL_MUST_BE_PUBLIC_HTTPS")
