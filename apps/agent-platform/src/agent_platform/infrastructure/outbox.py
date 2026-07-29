"""PostgreSQL Outbox expansion and durable Webhook delivery worker."""

from __future__ import annotations

import asyncio
import hashlib
import signal
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

import boto3
import httpx
from sqlalchemy import Select, any_, literal, select, text, update
from sqlalchemy.dialects.postgresql import insert

from agent_platform.config import AWS_MANAGER_BACKEND, Settings
from agent_platform.domain.events import RunEventType
from agent_platform.infrastructure.persistence.models import (
    OutboxEvent,
    WebhookDelivery,
    WebhookEndpoint,
)
from agent_platform.infrastructure.persistence.session import (
    AsyncSessionFactory,
    create_session_factory,
    dispose_session_factory,
)
from agent_platform.infrastructure.secret_broker import (
    AwsSecretsManagerBroker,
    DirectorySecretBroker,
)
from agent_platform.infrastructure.webhooks import WebhookEvent, WebhookSigner


@dataclass(frozen=True, slots=True)
class ClaimedDelivery:
    delivery_id: UUID
    tenant_id: str
    endpoint_id: UUID
    outbox_id: UUID
    url: str
    signing_secret_ref: str
    event_type: str
    payload: dict[str, Any]
    occurred_at: datetime
    attempt: int


class SecretResolver(Protocol):
    async def resolve(self, reference: str) -> bytes: ...


def _approval_notification_retry_delay_seconds(attempts: int) -> int:
    bounded_exponent = min(max(attempts, 0), 9)
    return min(1 << bounded_exponent, 300)


class BrokerSecretResolver:
    """Adapt the platform SecretBroker to the delivery worker read port."""

    def __init__(self, broker: Any) -> None:
        self._broker = broker

    async def resolve(self, reference: str) -> bytes:
        value = await self._broker.get(reference)
        if not isinstance(value, bytes):
            raise ValueError("WEBHOOK_SIGNING_SECRET_INVALID")
        if len(value) < 16:
            raise ValueError("WEBHOOK_SIGNING_SECRET_TOO_SHORT")
        return value


class FileSecretResolver:
    """Read a mounted secret reference without allowing path traversal."""

    def __init__(self, root: Path) -> None:
        self._root = root.resolve(strict=True)
        if not self._root.is_dir():
            raise ValueError("WEBHOOK_SECRET_ROOT_NOT_DIRECTORY")

    async def resolve(self, reference: str) -> bytes:
        if not reference or "\x00" in reference:
            raise ValueError("WEBHOOK_SECRET_REFERENCE_INVALID")
        candidate = (self._root / reference).resolve(strict=True)
        try:
            candidate.relative_to(self._root)
        except ValueError as exc:
            raise ValueError("WEBHOOK_SECRET_REFERENCE_INVALID") from exc
        if not candidate.is_file():
            raise ValueError("WEBHOOK_SECRET_REFERENCE_INVALID")
        value = (await asyncio.to_thread(candidate.read_bytes)).strip()
        if len(value) < 16:
            raise ValueError("WEBHOOK_SIGNING_SECRET_TOO_SHORT")
        return value


class PostgresOutboxWorker:
    def __init__(
        self,
        *,
        session_factory: AsyncSessionFactory,
        secrets: SecretResolver,
        client: httpx.AsyncClient,
        replay_window_seconds: int = 300,
        max_delivery_attempts: int = 8,
        claim_lease_seconds: int = 60,
    ) -> None:
        self._sessions = session_factory
        self._secrets = secrets
        self._client = client
        self._signer = WebhookSigner(replay_window_seconds=replay_window_seconds)
        self._max_delivery_attempts = max_delivery_attempts
        self._claim_lease_seconds = claim_lease_seconds
        self._role_verified = False

    async def run_once(self, *, batch_size: int = 100) -> dict[str, int]:
        expanded = await self._expand_outbox(batch_size=batch_size)
        delivered = retried = dead_lettered = 0
        for _ in range(batch_size):
            claim = await self._claim_delivery()
            if claim is None:
                break
            outcome = await self._send(claim)
            if outcome == "delivered":
                delivered += 1
            elif outcome == "retry":
                retried += 1
            else:
                dead_lettered += 1
        return {
            "expanded": expanded,
            "delivered": delivered,
            "retried": retried,
            "dead_lettered": dead_lettered,
        }

    async def _expand_outbox(self, *, batch_size: int) -> int:
        async with self._sessions() as session, session.begin():
            await self._assert_dispatch_role(session)
            statement: Select[tuple[OutboxEvent]] = (
                select(OutboxEvent)
                .where(
                    OutboxEvent.published_at.is_(None),
                    OutboxEvent.available_at <= datetime.now(UTC),
                )
                .order_by(OutboxEvent.available_at, OutboxEvent.outbox_id)
                .limit(batch_size)
                .with_for_update(skip_locked=True)
            )
            events = list((await session.scalars(statement)).all())
            expanded = 0
            for event in events:
                endpoint_statement: Select[tuple[WebhookEndpoint]] = select(WebhookEndpoint).where(
                    WebhookEndpoint.tenant_id == event.tenant_id,
                    WebhookEndpoint.enabled.is_(True),
                    literal(event.event_type) == any_(WebhookEndpoint.event_types),
                )
                endpoints = list((await session.scalars(endpoint_statement)).all())
                if (
                    not endpoints
                    and event.event_type == RunEventType.ACTION_APPROVAL_REQUIRED.value
                ):
                    event.attempts = int(event.attempts or 0) + 1
                    event.last_error = "APPROVAL_NOTIFICATION_ENDPOINT_REQUIRED"
                    event.available_at = datetime.now(UTC) + timedelta(
                        seconds=_approval_notification_retry_delay_seconds(event.attempts)
                    )
                    continue
                for endpoint in endpoints:
                    await session.execute(
                        insert(WebhookDelivery)
                        .values(
                            tenant_id=event.tenant_id,
                            endpoint_id=endpoint.endpoint_id,
                            outbox_id=event.outbox_id,
                            status="pending",
                        )
                        .on_conflict_do_nothing(index_elements=["endpoint_id", "outbox_id"])
                    )
                event.published_at = datetime.now(UTC)
                expanded += 1
            return expanded

    async def _claim_delivery(self) -> ClaimedDelivery | None:
        now = datetime.now(UTC)
        async with self._sessions() as session, session.begin():
            await self._assert_dispatch_role(session)
            statement = (
                select(WebhookDelivery, WebhookEndpoint, OutboxEvent)
                .join(
                    WebhookEndpoint,
                    WebhookEndpoint.endpoint_id == WebhookDelivery.endpoint_id,
                )
                .join(
                    OutboxEvent,
                    OutboxEvent.outbox_id == WebhookDelivery.outbox_id,
                )
                .where(
                    WebhookDelivery.status.in_(("pending", "retry", "delivering")),
                    WebhookDelivery.next_attempt_at <= now,
                    WebhookEndpoint.enabled.is_(True),
                )
                .order_by(
                    WebhookDelivery.next_attempt_at,
                    WebhookDelivery.delivery_id,
                )
                .limit(1)
                .with_for_update(skip_locked=True, of=WebhookDelivery)
            )
            row = (await session.execute(statement)).one_or_none()
            if row is None:
                return None
            delivery, endpoint, event = row
            delivery.status = "delivering"
            delivery.attempts += 1
            delivery.next_attempt_at = now + timedelta(seconds=self._claim_lease_seconds)
            delivery.updated_at = now
            return ClaimedDelivery(
                delivery_id=delivery.delivery_id,
                tenant_id=delivery.tenant_id,
                endpoint_id=endpoint.endpoint_id,
                outbox_id=event.outbox_id,
                url=endpoint.url,
                signing_secret_ref=endpoint.signing_secret_ref,
                event_type=event.event_type,
                payload=dict(event.payload),
                occurred_at=event.created_at,
                attempt=delivery.attempts,
            )

    async def _send(self, claim: ClaimedDelivery) -> str:
        try:
            body = WebhookEvent(
                event_id=str(claim.outbox_id),
                tenant_id=claim.tenant_id,
                event_type=claim.event_type,
                payload=claim.payload,
                occurred_at=claim.occurred_at,
            ).body()
        except ValueError:
            await self._finish(
                claim,
                status="dead_letter",
                response_status=None,
                response_hash=None,
                error_code="WEBHOOK_PAYLOAD_REJECTED",
            )
            return "dead_letter"
        timestamp = int(datetime.now(UTC).timestamp())
        error_code: str | None = None
        response_status: int | None = None
        response_hash: str | None = None
        try:
            secret = await self._secrets.resolve(claim.signing_secret_ref)
            response = await self._client.post(
                claim.url,
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Agent-Delivery-ID": str(claim.delivery_id),
                    "X-Agent-Event-ID": str(claim.outbox_id),
                    "X-Agent-Timestamp": str(timestamp),
                    "X-Agent-Signature": self._signer.sign(
                        secret,
                        body,
                        timestamp=timestamp,
                        event_id=str(claim.outbox_id),
                        delivery_id=str(claim.delivery_id),
                    ),
                },
            )
            response_status = response.status_code
            response_hash = hashlib.sha256(response.content).hexdigest()
            if 200 <= response.status_code < 300:
                await self._finish(
                    claim,
                    status="delivered",
                    response_status=response_status,
                    response_hash=response_hash,
                )
                return "delivered"
            error_code = f"HTTP_{response.status_code}"
        except Exception as exc:
            error_code = f"TRANSPORT_{type(exc).__name__.upper()}"

        if claim.attempt >= self._max_delivery_attempts:
            await self._finish(
                claim,
                status="dead_letter",
                response_status=response_status,
                response_hash=response_hash,
                error_code=error_code,
            )
            return "dead_letter"
        await self._finish(
            claim,
            status="retry",
            response_status=response_status,
            response_hash=response_hash,
            error_code=error_code,
            next_attempt_at=datetime.now(UTC) + timedelta(seconds=min(2**claim.attempt, 300)),
        )
        return "retry"

    async def _finish(
        self,
        claim: ClaimedDelivery,
        *,
        status: str,
        response_status: int | None,
        response_hash: str | None,
        error_code: str | None = None,
        next_attempt_at: datetime | None = None,
    ) -> None:
        now = datetime.now(UTC)
        values: dict[str, Any] = {
            "status": status,
            "response_status": response_status,
            "response_hash": response_hash,
            "last_error": error_code,
            "updated_at": now,
        }
        if status == "delivered":
            values["delivered_at"] = now
        elif status == "dead_letter":
            values["dead_lettered_at"] = now
        elif next_attempt_at is not None:
            values["next_attempt_at"] = next_attempt_at
        async with self._sessions() as session, session.begin():
            await self._assert_dispatch_role(session)
            await session.execute(
                update(WebhookDelivery)
                .where(
                    WebhookDelivery.delivery_id == claim.delivery_id,
                    WebhookDelivery.tenant_id == claim.tenant_id,
                )
                .values(**values)
            )

    async def _assert_dispatch_role(self, session: Any) -> None:
        if self._role_verified:
            return
        allowed = await session.scalar(
            text("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user")
        )
        if allowed is not True:
            raise RuntimeError("OUTBOX_ROLE_MUST_BYPASS_RLS")
        self._role_verified = True


def _secret_resolver(settings: Settings) -> tuple[SecretResolver, Any | None]:
    if settings.secret_backend == AWS_MANAGER_BACKEND:
        client = boto3.client(
            "secretsmanager",
            region_name=settings.artifact_region or "us-east-1",
        )
        broker = AwsSecretsManagerBroker(
            client,
            prefix=settings.secrets_manager_prefix,
        )
        return BrokerSecretResolver(broker), client
    configured_root = settings.webhook_secret_dir.strip()
    if not configured_root:
        raise RuntimeError("AGENT_WEBHOOK_SECRET_DIR_REQUIRED")
    return BrokerSecretResolver(DirectorySecretBroker(Path(configured_root))), None


async def _run_forever() -> None:
    settings = Settings(process_role="outbox-worker")
    secrets, secrets_client = _secret_resolver(settings)
    sessions = create_session_factory(settings.database_dsn.get_secret_value())
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signum, stop.set)
        except NotImplementedError:
            pass
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(settings.webhook_delivery_timeout_seconds),
            follow_redirects=False,
            proxy=settings.webhook_egress_proxy_url,
            trust_env=False,
        ) as client:
            worker = PostgresOutboxWorker(
                session_factory=sessions,
                secrets=secrets,
                client=client,
                replay_window_seconds=settings.webhook_replay_window_seconds,
                max_delivery_attempts=settings.webhook_delivery_max_attempts,
            )
            while not stop.is_set():
                report = await worker.run_once(
                    batch_size=settings.webhook_worker_batch_size,
                )
                if sum(report.values()) == 0:
                    try:
                        await asyncio.wait_for(
                            stop.wait(),
                            timeout=settings.webhook_worker_poll_seconds,
                        )
                    except TimeoutError:
                        pass
    finally:
        await dispose_session_factory(sessions)
        if secrets_client is not None:
            secrets_client.close()


def main() -> None:
    asyncio.run(_run_forever())
