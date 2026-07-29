from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from scripts.run_capacity_scenarios import (
    REQUIRED_SCENARIOS,
    RepeatingBytes,
    Sample,
    _approval_manifest,
    _artifact_streaming_observation,
    _controlled_admission,
    _long_run_passed,
    _p95,
    _require_complete_scenario_set,
    _summarize,
    _validated_release_identity,
)


@pytest.mark.asyncio
async def test_repeating_bytes_streams_exact_size_in_bounded_chunks() -> None:
    stream = RepeatingBytes(10, chunk_bytes=4)
    chunks = [chunk async for chunk in stream]

    assert [len(chunk) for chunk in chunks] == [4, 4, 2]
    assert b"".join(chunks) == b"\0" * 10


def test_capacity_result_preserves_controlled_backpressure_and_tail_latency() -> None:
    samples = [
        Sample(status=202, latency_seconds=0.1),
        Sample(
            status=503,
            latency_seconds=0.5,
            error_code="RUN_QUEUE_BACKPRESSURE",
        ),
        Sample(status=429, latency_seconds=0.2),
    ]

    assert all(_controlled_admission(sample) for sample in samples)
    assert _controlled_admission(Sample(status=503, latency_seconds=0.1)) is False
    assert _p95(samples) == 0.5
    result = _summarize(
        "burst",
        samples,
        passed=True,
        evidence={"offered_rps": 10},
    )
    assert result.statuses == {"202": 1, "503": 1, "429": 1}
    assert result.p95_seconds == 0.5


def test_approval_manifest_requires_at_least_one_thousand_bound_pending_actions(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "approvals.jsonl"
    expires_at = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    manifest.write_text(
        "\n".join(
            json.dumps(
                {
                    "action_id": f"action-{index}",
                    "run_id": "run-1",
                    "workflow_id": "workflow-1",
                    "payload_hash": "a" * 64,
                    "expires_at": expires_at,
                    "cohort": "pending_backlog",
                }
            )
            for index in range(1000)
        ),
        encoding="utf-8",
    )

    rows = _approval_manifest(manifest)

    assert len(rows) == 1000
    assert rows[999]["action_id"] == "action-999"

    manifest.write_text(
        json.dumps(
            {
                "action_id": "only-one",
                "run_id": "run-1",
                "workflow_id": "workflow-1",
                "payload_hash": "a" * 64,
                "expires_at": expires_at,
                "cohort": "pending_backlog",
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(
        ValueError,
        match="CAPACITY_APPROVAL_MANIFEST_MUST_CONTAIN_AT_LEAST_1000_ROWS",
    ):
        _approval_manifest(manifest)


def test_capacity_release_run_requires_every_architecture_scenario() -> None:
    _require_complete_scenario_set(set(REQUIRED_SCENARIOS))

    with pytest.raises(ValueError, match="CAPACITY_SCENARIO_SET_INCOMPLETE"):
        _require_complete_scenario_set(set(REQUIRED_SCENARIOS) - {"artifacts"})


def test_long_run_capacity_cannot_pass_when_every_request_is_backpressured() -> None:
    assert _long_run_passed([Sample(status=429, latency_seconds=0.1) for _ in range(100)]) is False
    assert _long_run_passed([Sample(status=202, latency_seconds=0.1) for _ in range(100)]) is True


def test_artifact_streaming_uses_server_observed_chunks_not_a_runner_claim() -> None:
    expected_sha256 = "a" * 64
    body = {
        "artifact_id": "artifact-1",
        "size_bytes": 200 * 1024 * 1024,
        "sha256": expected_sha256,
        "scan_status": "malware_clean",
        "object_version_id": "version-1",
        "scan_provenance": {
            "transport": {
                "mode": "request-stream-to-file",
                "request_size_bytes": 200 * 1024 * 1024,
                "request_sha256": expected_sha256,
                "chunk_count": 200,
                "max_request_chunk_bytes": 1024 * 1024,
            }
        },
    }

    passed, observation = _artifact_streaming_observation(
        body,
        expected_size=200 * 1024 * 1024,
        expected_sha256=expected_sha256,
    )

    assert passed is True
    assert observation["server_transport"]["chunk_count"] == 200
    body["scan_provenance"]["transport"]["chunk_count"] = 1
    body["scan_provenance"]["transport"]["max_request_chunk_bytes"] = 200 * 1024 * 1024
    assert (
        _artifact_streaming_observation(
            body,
            expected_size=200 * 1024 * 1024,
            expected_sha256=expected_sha256,
        )[0]
        is False
    )


def test_capacity_report_requires_bound_release_identity() -> None:
    assert _validated_release_identity(
        "12345-1",
        "a" * 40,
        f"sha256:{'b' * 64}",
    ) == ("12345-1", "a" * 40, f"sha256:{'b' * 64}")


@pytest.mark.parametrize(
    ("release_id", "git_sha", "image_digest", "error"),
    (
        ("bad release!", "a" * 40, f"sha256:{'b' * 64}", "CAPACITY_RELEASE_ID_INVALID"),
        ("12345-1", "A" * 40, f"sha256:{'b' * 64}", "CAPACITY_GIT_SHA_INVALID"),
        ("12345-1", "a" * 40, "sha256:bad", "CAPACITY_IMAGE_DIGEST_INVALID"),
    ),
)
def test_capacity_report_rejects_unbound_release_identity(
    release_id: str,
    git_sha: str,
    image_digest: str,
    error: str,
) -> None:
    with pytest.raises(ValueError, match=error):
        _validated_release_identity(release_id, git_sha, image_digest)
