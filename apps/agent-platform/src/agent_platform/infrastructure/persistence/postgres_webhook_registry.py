"""Tenant-scoped Webhook registry with external secret custody."""

from __future__ import annotations

import secrets
from typing import Protocol
from uuid import UUID, uuid4

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from agent_platform.application.errors import NotFound, PlatformError
from agent_platform.infrastructure.persistence.governance_models import (
    WebhookEndpointSecretState,
)
from agent_platform.infrastructure.persistence.models import (
    WebhookEndpoint as DatabaseWebhookEndpoint,
)
from agent_platform.infrastructure.persistence.session import (
    AsyncSessionFactory,
    tenant_session,
)
from agent_platform.infrastructure.webhook_registry import WebhookEndpointView
from agent_platform.infrastructure.webhooks import WebhookEndpoint


class SecretBroker(Protocol):
    """Secret Manager port. PostgreSQL only receives the returned reference."""

    async def put(self, reference_hint: str, secret: bytes) -> str: ...
    async def get(self, reference: str) -> bytes: ...
    async def delete(self, reference: str) -> None: ...


class PostgresWebhookEndpointRegistry:
    def __init__(
        self,
        factory: AsyncSessionFactory,
        *,
        secret_broker: SecretBroker,
    ) -> None:
        self._factory = factory
        self._secret_broker = secret_broker

    async def register(
        self,
        *,
        tenant_id: str,
        endpoint_name: str,
        url: str,
        event_types: frozenset[str],
        signing_secret: bytes | None = None,
    ) -> tuple[WebhookEndpointView, bytes]:
        existing = await self._find_by_name(tenant_id, endpoint_name)
        if existing is not None:
            return existing, b""

        endpoint_id = uuid4()
        secret = signing_secret or secrets.token_bytes(32)
        WebhookEndpoint(
            endpoint_id=endpoint_id,
            tenant_id=tenant_id,
            url=url,
            event_types=event_types,
            signing_secret=secret,
        )
        reference = await self._put_secret(
            self._reference_hint(tenant_id, endpoint_id, 1),
            secret,
        )
        try:
            async with tenant_session(self._factory, tenant_id) as session:
                inserted = await session.scalar(
                    insert(DatabaseWebhookEndpoint)
                    .values(
                        endpoint_id=endpoint_id,
                        tenant_id=tenant_id,
                        endpoint_name=endpoint_name,
                        url=url,
                        event_types=sorted(event_types),
                        signing_secret_ref=reference,
                        enabled=True,
                    )
                    .on_conflict_do_nothing(
                        index_elements=[
                            DatabaseWebhookEndpoint.tenant_id,
                            DatabaseWebhookEndpoint.endpoint_name,
                        ]
                    )
                    .returning(DatabaseWebhookEndpoint.endpoint_id)
                )
                if inserted is None:
                    existing = await self._find_by_name_in_session(
                        session, tenant_id, endpoint_name
                    )
                    if existing is None:
                        raise PlatformError(
                            "WEBHOOK_ENDPOINT_CREATE_CONFLICT",
                            "Webhook endpoint identifiers conflict",
                            http_status=409,
                        )
                    await session.commit()
                    await self._delete_secret(reference)
                    return existing, b""
                session.add(
                    WebhookEndpointSecretState(
                        endpoint_id=endpoint_id,
                        tenant_id=tenant_id,
                        secret_version=1,
                    )
                )
                await session.flush()
                view = await self._view_in_session(session, endpoint_id, tenant_id)
                await session.commit()
                return view, secret
        except Exception:
            await self._delete_secret(reference)
            raise

    async def list(self, tenant_id: str) -> tuple[WebhookEndpointView, ...]:
        async with tenant_session(self._factory, tenant_id) as session:
            rows = (
                await session.execute(
                    select(
                        DatabaseWebhookEndpoint,
                        WebhookEndpointSecretState,
                    )
                    .outerjoin(
                        WebhookEndpointSecretState,
                        WebhookEndpointSecretState.endpoint_id
                        == DatabaseWebhookEndpoint.endpoint_id,
                    )
                    .where(DatabaseWebhookEndpoint.tenant_id == tenant_id)
                    .order_by(DatabaseWebhookEndpoint.endpoint_name)
                )
            ).all()
            return tuple(self._view(endpoint, state) for endpoint, state in rows)

    async def set_enabled(
        self,
        endpoint_id: UUID,
        tenant_id: str,
        *,
        enabled: bool,
    ) -> WebhookEndpointView:
        async with tenant_session(self._factory, tenant_id) as session:
            updated = await session.scalar(
                update(DatabaseWebhookEndpoint)
                .where(
                    DatabaseWebhookEndpoint.endpoint_id == endpoint_id,
                    DatabaseWebhookEndpoint.tenant_id == tenant_id,
                )
                .values(enabled=enabled)
                .returning(DatabaseWebhookEndpoint.endpoint_id)
            )
            if updated is None:
                raise NotFound("webhook endpoint", str(endpoint_id))
            view = await self._view_in_session(session, endpoint_id, tenant_id)
            await session.commit()
            return view

    async def rotate_secret(
        self,
        endpoint_id: UUID,
        tenant_id: str,
    ) -> tuple[WebhookEndpointView, bytes]:
        secret = secrets.token_bytes(32)
        reference: str | None = None
        try:
            async with tenant_session(self._factory, tenant_id) as session:
                endpoint = await session.scalar(
                    select(DatabaseWebhookEndpoint)
                    .where(
                        DatabaseWebhookEndpoint.endpoint_id == endpoint_id,
                        DatabaseWebhookEndpoint.tenant_id == tenant_id,
                    )
                    .with_for_update()
                )
                if endpoint is None:
                    raise NotFound("webhook endpoint", str(endpoint_id))
                state = await session.scalar(
                    select(WebhookEndpointSecretState)
                    .where(
                        WebhookEndpointSecretState.endpoint_id == endpoint_id,
                        WebhookEndpointSecretState.tenant_id == tenant_id,
                    )
                    .with_for_update()
                )
                version = (state.secret_version if state is not None else 1) + 1
                reference = await self._put_secret(
                    self._reference_hint(tenant_id, endpoint_id, version),
                    secret,
                )
                endpoint.signing_secret_ref = reference
                if state is None:
                    state = WebhookEndpointSecretState(
                        endpoint_id=endpoint_id,
                        tenant_id=tenant_id,
                        secret_version=version,
                    )
                    session.add(state)
                else:
                    state.secret_version = version
                await session.flush()
                view = self._view(endpoint, state)
                await session.commit()
                return view, secret
        except Exception:
            if reference is not None:
                await self._delete_secret(reference)
            raise

    async def delivery_endpoint(
        self,
        endpoint_id: UUID,
        tenant_id: str,
    ) -> WebhookEndpoint:
        async with tenant_session(self._factory, tenant_id) as session:
            endpoint = await session.scalar(
                select(DatabaseWebhookEndpoint).where(
                    DatabaseWebhookEndpoint.endpoint_id == endpoint_id,
                    DatabaseWebhookEndpoint.tenant_id == tenant_id,
                )
            )
            if endpoint is None:
                raise NotFound("webhook endpoint", str(endpoint_id))
            values = (
                endpoint.endpoint_id,
                endpoint.tenant_id,
                endpoint.url,
                frozenset(endpoint.event_types),
                endpoint.signing_secret_ref,
                endpoint.enabled,
            )
        secret = await self._get_secret(values[4])
        return WebhookEndpoint(
            endpoint_id=values[0],
            tenant_id=values[1],
            url=values[2],
            event_types=values[3],
            signing_secret=secret,
            enabled=values[5],
        )

    async def _find_by_name(self, tenant_id: str, endpoint_name: str) -> WebhookEndpointView | None:
        async with tenant_session(self._factory, tenant_id) as session:
            return await self._find_by_name_in_session(session, tenant_id, endpoint_name)

    async def _find_by_name_in_session(
        self,
        session: AsyncSession,
        tenant_id: str,
        endpoint_name: str,
    ) -> WebhookEndpointView | None:
        row = (
            await session.execute(
                select(
                    DatabaseWebhookEndpoint,
                    WebhookEndpointSecretState,
                )
                .outerjoin(
                    WebhookEndpointSecretState,
                    WebhookEndpointSecretState.endpoint_id == DatabaseWebhookEndpoint.endpoint_id,
                )
                .where(
                    DatabaseWebhookEndpoint.tenant_id == tenant_id,
                    DatabaseWebhookEndpoint.endpoint_name == endpoint_name,
                )
            )
        ).one_or_none()
        return self._view(row[0], row[1]) if row is not None else None

    async def _view_in_session(
        self,
        session: AsyncSession,
        endpoint_id: UUID,
        tenant_id: str,
    ) -> WebhookEndpointView:
        row = (
            await session.execute(
                select(
                    DatabaseWebhookEndpoint,
                    WebhookEndpointSecretState,
                )
                .outerjoin(
                    WebhookEndpointSecretState,
                    WebhookEndpointSecretState.endpoint_id == DatabaseWebhookEndpoint.endpoint_id,
                )
                .where(
                    DatabaseWebhookEndpoint.endpoint_id == endpoint_id,
                    DatabaseWebhookEndpoint.tenant_id == tenant_id,
                )
            )
        ).one_or_none()
        if row is None:
            raise NotFound("webhook endpoint", str(endpoint_id))
        return self._view(row[0], row[1])

    @staticmethod
    def _view(
        endpoint: DatabaseWebhookEndpoint,
        state: WebhookEndpointSecretState | None,
    ) -> WebhookEndpointView:
        return WebhookEndpointView(
            endpoint_id=endpoint.endpoint_id,
            tenant_id=endpoint.tenant_id,
            endpoint_name=endpoint.endpoint_name,
            url=endpoint.url,
            event_types=frozenset(endpoint.event_types),
            enabled=endpoint.enabled,
            secret_version=state.secret_version if state is not None else 1,
        )

    async def _put_secret(self, hint: str, secret: bytes) -> str:
        try:
            reference = await self._secret_broker.put(hint, secret)
        except Exception as exc:
            raise PlatformError(
                "WEBHOOK_SECRET_BROKER_UNAVAILABLE",
                "Webhook secret could not be stored",
                retryable=True,
                http_status=503,
            ) from exc
        if not reference:
            raise PlatformError(
                "WEBHOOK_SECRET_BROKER_INVALID_REFERENCE",
                "Webhook secret broker returned an empty reference",
                http_status=503,
            )
        return reference

    async def _get_secret(self, reference: str) -> bytes:
        try:
            return await self._secret_broker.get(reference)
        except Exception as exc:
            raise PlatformError(
                "WEBHOOK_SECRET_BROKER_UNAVAILABLE",
                "Webhook secret could not be resolved",
                retryable=True,
                http_status=503,
            ) from exc

    async def _delete_secret(self, reference: str) -> None:
        try:
            await self._secret_broker.delete(reference)
        except Exception as exc:
            raise PlatformError(
                "WEBHOOK_SECRET_CLEANUP_FAILED",
                "Webhook secret compensation failed",
                retryable=True,
                http_status=503,
            ) from exc

    @staticmethod
    def _reference_hint(tenant_id: str, endpoint_id: UUID, version: int) -> str:
        return f"agent-platform/webhooks/{tenant_id}/{endpoint_id}/versions/{version}"
