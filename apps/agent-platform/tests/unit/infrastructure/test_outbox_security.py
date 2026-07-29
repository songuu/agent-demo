from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import httpx
import pytest

from agent_platform.infrastructure.outbox import (
    ClaimedDelivery,
    FileSecretResolver,
    PostgresOutboxWorker,
)
from agent_platform.infrastructure.persistence.session import AsyncSessionFactory


@pytest.mark.asyncio
async def test_outbox_dead_letters_sensitive_payload_without_network(
    tmp_path: Path,
) -> None:
    secret_root = tmp_path / "secrets"
    secret_root.mkdir()
    (secret_root / "endpoint-key").write_bytes(b"0123456789abcdef")
    network_calls = 0

    async def handler(_: httpx.Request) -> httpx.Response:
        nonlocal network_calls
        network_calls += 1
        return httpx.Response(204)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        worker = _SecurityCaptureWorker(
            session_factory=cast(AsyncSessionFactory, object()),
            secrets=FileSecretResolver(secret_root),
            client=client,
        )
        outcome = await worker._send(
            ClaimedDelivery(
                delivery_id=uuid4(),
                tenant_id="tenant-a",
                endpoint_id=uuid4(),
                outbox_id=uuid4(),
                url="https://hooks.example.test/agent",
                signing_secret_ref="endpoint-key",
                event_type="run.completed",
                payload={"status": "completed", "prompt": "sensitive"},
                occurred_at=datetime(2026, 7, 24, 9, 0, tzinfo=UTC),
                attempt=1,
            )
        )

    assert outcome == "dead_letter"
    assert network_calls == 0
    assert worker.finishes[0]["error_code"] == "WEBHOOK_PAYLOAD_REJECTED"


class _SecurityCaptureWorker(PostgresOutboxWorker):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.finishes: list[dict[str, Any]] = []

    async def _finish(self, claim: ClaimedDelivery, **values: Any) -> None:
        self.finishes.append({"claim": claim, **values})
