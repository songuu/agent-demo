"""In-memory tenant registry mirroring production Webhook endpoint semantics."""

from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass
from uuid import UUID, uuid4

from agent_platform.application.errors import NotFound
from agent_platform.infrastructure.webhooks import WebhookEndpoint


@dataclass(frozen=True, slots=True)
class WebhookEndpointView:
    endpoint_id: UUID
    tenant_id: str
    endpoint_name: str
    url: str
    event_types: frozenset[str]
    enabled: bool
    secret_version: int


@dataclass(slots=True)
class _RegisteredEndpoint:
    endpoint_id: UUID
    tenant_id: str
    endpoint_name: str
    url: str
    event_types: frozenset[str]
    signing_secret: bytes
    enabled: bool
    secret_version: int


class WebhookEndpointRegistry:
    def __init__(self) -> None:
        self._records: dict[UUID, _RegisteredEndpoint] = {}
        self._names: dict[tuple[str, str], UUID] = {}
        self._lock = asyncio.Lock()

    async def register(
        self,
        *,
        tenant_id: str,
        endpoint_name: str,
        url: str,
        event_types: frozenset[str],
        signing_secret: bytes | None = None,
    ) -> tuple[WebhookEndpointView, bytes]:
        secret = signing_secret or secrets.token_bytes(32)
        # Constructing the delivery type applies URL and secret validation.
        WebhookEndpoint(
            endpoint_id=uuid4(),
            tenant_id=tenant_id,
            url=url,
            event_types=event_types,
            signing_secret=secret,
        )
        key = (tenant_id, endpoint_name)
        async with self._lock:
            existing_id = self._names.get(key)
            if existing_id is not None:
                return self._view(self._records[existing_id]), b""
            record = _RegisteredEndpoint(
                endpoint_id=uuid4(),
                tenant_id=tenant_id,
                endpoint_name=endpoint_name,
                url=url,
                event_types=event_types,
                signing_secret=secret,
                enabled=True,
                secret_version=1,
            )
            self._records[record.endpoint_id] = record
            self._names[key] = record.endpoint_id
            return self._view(record), secret

    async def list(self, tenant_id: str) -> tuple[WebhookEndpointView, ...]:
        async with self._lock:
            records = [
                self._view(record)
                for record in self._records.values()
                if record.tenant_id == tenant_id
            ]
        return tuple(sorted(records, key=lambda item: item.endpoint_name))

    async def set_enabled(
        self,
        endpoint_id: UUID,
        tenant_id: str,
        *,
        enabled: bool,
    ) -> WebhookEndpointView:
        async with self._lock:
            record = self._records.get(endpoint_id)
            if record is None or record.tenant_id != tenant_id:
                raise NotFound("webhook endpoint", str(endpoint_id))
            record.enabled = enabled
            return self._view(record)

    async def rotate_secret(
        self,
        endpoint_id: UUID,
        tenant_id: str,
    ) -> tuple[WebhookEndpointView, bytes]:
        async with self._lock:
            record = self._records.get(endpoint_id)
            if record is None or record.tenant_id != tenant_id:
                raise NotFound("webhook endpoint", str(endpoint_id))
            record.signing_secret = secrets.token_bytes(32)
            record.secret_version += 1
            return self._view(record), record.signing_secret

    async def delivery_endpoint(
        self,
        endpoint_id: UUID,
        tenant_id: str,
    ) -> WebhookEndpoint:
        async with self._lock:
            record = self._records.get(endpoint_id)
            if record is None or record.tenant_id != tenant_id:
                raise NotFound("webhook endpoint", str(endpoint_id))
            return WebhookEndpoint(
                endpoint_id=record.endpoint_id,
                tenant_id=record.tenant_id,
                url=record.url,
                event_types=record.event_types,
                signing_secret=record.signing_secret,
                enabled=record.enabled,
            )

    @staticmethod
    def _view(record: _RegisteredEndpoint) -> WebhookEndpointView:
        return WebhookEndpointView(
            endpoint_id=record.endpoint_id,
            tenant_id=record.tenant_id,
            endpoint_name=record.endpoint_name,
            url=record.url,
            event_types=record.event_types,
            enabled=record.enabled,
            secret_version=record.secret_version,
        )
