from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from scripts.run_capacity_scenarios import _approval_manifest, approvals


def _manifest(path: Path, *, count: int = 1000) -> Path:
    expires_at = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    path.write_text(
        "\n".join(
            json.dumps(
                {
                    "action_id": f"00000000-0000-4000-8000-{index:012d}",
                    "run_id": "10000000-0000-4000-8000-000000000001",
                    "workflow_id": "agent-run-capacity-1",
                    "payload_hash": "a" * 64,
                    "expires_at": expires_at,
                    "cohort": "pending_backlog",
                }
            )
            for index in range(count)
        ),
        encoding="utf-8",
    )
    return path


def test_approval_manifest_scopes_real_state_queries_not_approval_writes(
    tmp_path: Path,
) -> None:
    rows = _approval_manifest(_manifest(tmp_path / "pending.jsonl"))

    assert len(rows) == 1000
    assert rows[0]["run_id"] == "10000000-0000-4000-8000-000000000001"
    assert rows[0]["workflow_id"] == "agent-run-capacity-1"
    assert rows[0]["cohort"] == "pending_backlog"


@pytest.mark.asyncio
async def test_pending_backlog_is_derived_from_action_and_run_readback(
    tmp_path: Path,
) -> None:
    manifest_path = _manifest(tmp_path / "pending.jsonl")
    manifest = _approval_manifest(manifest_path)
    actions = [
        {
            "action_id": row["action_id"],
            "run_id": row["run_id"],
            "payload_hash": row["payload_hash"],
            "approvals_received": 0,
            "status": "pending_approval",
            "expires_at": row["expires_at"],
        }
        for row in manifest
    ]
    run = {
        "run_id": manifest[0]["run_id"],
        "status": "waiting_approval",
        "pending_actions": [
            {"action_id": row["action_id"], "expires_at": row["expires_at"]} for row in manifest
        ],
    }
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        if request.url.path.endswith("/actions"):
            return httpx.Response(200, json=actions)
        return httpx.Response(200, json=run)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await approvals(client, manifest_path=manifest_path)

    assert methods == ["GET", "GET"]
    assert result.evidence["pending_approval_count"] == 1000
    assert result.evidence["status_query_verified"] is True
    assert result.evidence["notification_delivery_verified"] is False
    assert result.evidence["expiry_processing_verified"] is False
    assert result.evidence["resource_leak_free_verified"] is False
    assert result.passed is False
