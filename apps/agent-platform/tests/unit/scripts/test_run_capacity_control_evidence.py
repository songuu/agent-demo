from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from scripts.run_capacity_scenarios import _approval_manifest, approvals

RELEASE_ID = "release-123"
GIT_SHA = "a" * 40
IMAGE_DIGEST = f"sha256:{'b' * 64}"


def _digest(payload: object) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _asset(payload: dict[str, object]) -> dict[str, object]:
    raw_json = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    digest = "sha256:" + hashlib.sha256(raw_json.encode()).hexdigest()
    return {
        "content_uri": f"https://evidence.example.test/content/{digest}",
        "sha256": digest,
        "raw_json": raw_json,
    }


def _manifest(path: Path) -> Path:
    expires_at = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    path.write_text(
        "\n".join(
            json.dumps(
                {
                    "action_id": f"action-{index:04d}",
                    "run_id": "run-1",
                    "workflow_id": "workflow-1",
                    "payload_hash": "c" * 64,
                    "expires_at": expires_at,
                    "cohort": "pending_backlog",
                }
            )
            for index in range(1000)
        ),
        encoding="utf-8",
    )
    return path


def _control_evidence(path: Path, manifest_path: Path) -> tuple[Path, str]:
    rows = _approval_manifest(manifest_path)
    observed_at = datetime.now(UTC).isoformat()
    expiry_ids = [row["action_id"] for row in rows[:50]]
    root_payload = {
        "schema_version": "1.0",
        "release_id": RELEASE_ID,
        "git_sha": GIT_SHA,
        "image_digest": IMAGE_DIGEST,
        "manifest_sha256": "sha256:" + hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "scope": {
            "action_ids": [row["action_id"] for row in rows],
            "run_ids": ["run-1"],
            "workflow_ids": ["workflow-1"],
            "expiry_probe_action_ids": expiry_ids,
        },
        "notifications": _asset(
            {
                "receipts": [
                    {
                        "receipt_id": f"receipt-{index:04d}",
                        "action_id": row["action_id"],
                        "delivered": True,
                        "delivered_at": observed_at,
                    }
                    for index, row in enumerate(rows)
                ]
            }
        ),
        "expiry": _asset(
            {
                "observations": [
                    {
                        "action_id": action_id,
                        "status": "expired",
                        "observed_at": observed_at,
                    }
                    for action_id in expiry_ids
                ]
            }
        ),
        "resources": _asset(
            {
                "closed_workflow_ids": ["workflow-1"],
                "open_workflow_ids": [],
                "task_queue_backlog_before": 12,
                "task_queue_backlog_after": 0,
                "active_slots_before": 8,
                "active_slots_after": 0,
                "observed_at": observed_at,
            }
        ),
    }
    raw_json = json.dumps(root_payload, ensure_ascii=False, indent=2)
    path.write_text(raw_json, encoding="utf-8")
    digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    return path, f"https://evidence.example.test/control/{digest}"


@pytest.mark.asyncio
async def test_external_content_addressed_control_evidence_can_reach_true(
    tmp_path: Path,
) -> None:
    manifest_path = _manifest(tmp_path / "pending.jsonl")
    control_path, control_uri = _control_evidence(tmp_path / "control.json", manifest_path)
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
        "run_id": "run-1",
        "status": "waiting_approval",
        "pending_actions": [
            {"action_id": row["action_id"], "expires_at": row["expires_at"]} for row in manifest
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=actions if request.url.path.endswith("/actions") else run)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await approvals(
            client,
            manifest_path=manifest_path,
            control_evidence_path=control_path,
            control_evidence_uri=control_uri,
            release_id=RELEASE_ID,
            git_sha=GIT_SHA,
            image_digest=IMAGE_DIGEST,
        )

    assert result.passed is True
    assert result.evidence["notification_delivery_verified"] is True
    assert result.evidence["expiry_processing_verified"] is True
    assert result.evidence["resource_leak_free_verified"] is True
    assert result.evidence["operational_control_evidence_error"] is None
