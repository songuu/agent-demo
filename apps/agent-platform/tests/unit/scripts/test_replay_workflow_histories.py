from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from scripts import replay_workflow_histories


def _history_envelope(path: Path, *, workflow_id: str = "run-1") -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "workflow_id": workflow_id,
                "workflow_type": "AgentRunWorkflow",
                "history": {"events": []},
            }
        ),
        encoding="utf-8",
    )


def test_discovery_is_deterministic_and_requires_real_history_count(tmp_path: Path) -> None:
    _history_envelope(tmp_path / "b.json", workflow_id="run-b")
    _history_envelope(tmp_path / "a.json", workflow_id="run-a")

    paths = replay_workflow_histories.discover_history_paths(
        tmp_path,
        minimum_histories=2,
    )

    assert [path.name for path in paths] == ["a.json", "b.json"]
    with pytest.raises(ValueError, match="WORKFLOW_HISTORY_COUNT_NOT_MET"):
        replay_workflow_histories.discover_history_paths(
            tmp_path,
            minimum_histories=3,
        )


def test_history_envelope_rejects_missing_binding_and_empty_events(tmp_path: Path) -> None:
    missing_binding = tmp_path / "missing.json"
    missing_binding.write_text(
        json.dumps({"schema_version": "1.0", "history": {"events": [{}]}}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="WORKFLOW_HISTORY_BINDING_REQUIRED"):
        replay_workflow_histories.load_history_envelope(missing_binding)

    empty = tmp_path / "empty.json"
    _history_envelope(empty)
    with pytest.raises(ValueError, match="WORKFLOW_HISTORY_EVENTS_REQUIRED"):
        replay_workflow_histories.load_history_envelope(empty)


@pytest.mark.asyncio
async def test_replay_report_binds_each_history_hash_and_fails_on_replay_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    history_path = tmp_path / "run.json"
    _history_envelope(history_path)
    payload = json.loads(history_path.read_text(encoding="utf-8"))
    payload["history"]["events"] = [{"eventId": "1"}]
    history_path.write_text(json.dumps(payload), encoding="utf-8")

    async def successful_replay(_: Any) -> None:
        return None

    monkeypatch.setattr(replay_workflow_histories, "_replay_history", successful_replay)
    report = await replay_workflow_histories.replay_histories([history_path])

    assert report["passed"] is True
    assert report["history_count"] == 1
    result = report["histories"][0]
    assert result["workflow_id"] == "run-1"
    assert result["sha256"].startswith("sha256:")

    async def failed_replay(_: Any) -> None:
        raise RuntimeError("nondeterministic history")

    monkeypatch.setattr(replay_workflow_histories, "_replay_history", failed_replay)
    with pytest.raises(RuntimeError, match=r"WORKFLOW_REPLAY_FAILED.*run-1"):
        await replay_workflow_histories.replay_histories([history_path])
