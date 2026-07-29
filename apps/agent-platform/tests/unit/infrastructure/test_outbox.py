from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import httpx
import pytest

from agent_platform.infrastructure.outbox import (
    BrokerSecretResolver,
    ClaimedDelivery,
    FileSecretResolver,
    PostgresOutboxWorker,
)
from agent_platform.infrastructure.persistence.session import AsyncSessionFactory


@pytest.mark.asyncio
async def test_file_secret_resolver_rejects_traversal(tmp_path: Path) -> None:
    secret_root = tmp_path / "secrets"
    secret_root.mkdir()
    (secret_root / "tenant-a-key").write_bytes(b"0123456789abcdef")
    outside = tmp_path / "outside"
    outside.write_bytes(b"0123456789abcdef")
    resolver = FileSecretResolver(secret_root)

    assert await resolver.resolve("tenant-a-key") == b"0123456789abcdef"
    with pytest.raises(ValueError, match="WEBHOOK_SECRET_REFERENCE_INVALID"):
        await resolver.resolve("../outside")


@pytest.mark.asyncio
async def test_broker_secret_resolver_reads_external_reference() -> None:
    class Broker:
        async def get(self, reference: str) -> bytes:
            assert reference == "arn:aws:secretsmanager:region:account:secret:webhook"
            return b"0123456789abcdef"

    resolver = BrokerSecretResolver(Broker())

    assert (
        await resolver.resolve("arn:aws:secretsmanager:region:account:secret:webhook")
        == b"0123456789abcdef"
    )


@pytest.mark.asyncio
async def test_outbox_delivery_uses_persisted_delivery_id(
    tmp_path: Path,
) -> None:
    secret_root = tmp_path / "secrets"
    secret_root.mkdir()
    (secret_root / "endpoint-key").write_bytes(b"0123456789abcdef")
    captured: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(204)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        worker = _CaptureWorker(
            session_factory=cast(AsyncSessionFactory, object()),
            secrets=FileSecretResolver(secret_root),
            client=client,
        )
        delivery_id = uuid4()
        outcome = await worker._send(
            ClaimedDelivery(
                delivery_id=delivery_id,
                tenant_id="tenant-a",
                endpoint_id=uuid4(),
                outbox_id=uuid4(),
                url="https://hooks.example.test/agent",
                signing_secret_ref="endpoint-key",
                event_type="run.completed",
                payload={"run_id": "run-1", "status": "completed"},
                occurred_at=datetime(2026, 7, 24, 9, 0, tzinfo=UTC),
                attempt=1,
            )
        )

    assert outcome == "delivered"
    assert captured[0].headers["X-Agent-Delivery-ID"] == str(delivery_id)
    assert captured[0].headers["X-Agent-Signature"].startswith("v1=")
    assert worker.finishes[0]["status"] == "delivered"


class _CaptureWorker(PostgresOutboxWorker):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.finishes: list[dict[str, Any]] = []

    async def _finish(self, claim: ClaimedDelivery, **values: Any) -> None:
        self.finishes.append({"claim": claim, **values})
