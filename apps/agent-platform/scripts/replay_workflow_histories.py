"""Replay exported Temporal histories and fail closed on nondeterminism."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from temporalio.client import WorkflowHistory
from temporalio.worker import Replayer

from agent_platform.workflows.recovery_workflow import ActionRecoveryWorkflow
from agent_platform.workflows.temporal_workflow import AgentRunWorkflow

JsonObject = dict[str, Any]
SUPPORTED_WORKFLOW_TYPES = frozenset({"ActionRecoveryWorkflow", "AgentRunWorkflow"})


@dataclass(frozen=True, slots=True)
class HistoryEnvelope:
    """Content-addressed history plus the workflow identity needed by Temporal."""

    path: Path
    workflow_id: str
    workflow_type: str
    history: JsonObject
    sha256: str


def discover_history_paths(history_dir: Path, *, minimum_histories: int) -> list[Path]:
    if minimum_histories < 1:
        raise ValueError("WORKFLOW_HISTORY_MINIMUM_INVALID")
    paths = sorted(path for path in history_dir.glob("*.json") if path.is_file())
    if len(paths) < minimum_histories:
        raise ValueError(
            "WORKFLOW_HISTORY_COUNT_NOT_MET: "
            f"found {len(paths)} in {history_dir}, expected at least {minimum_histories}"
        )
    return paths


def load_history_envelope(path: Path) -> HistoryEnvelope:
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"WORKFLOW_HISTORY_ENVELOPE_REQUIRED: {path}")
    workflow_id = value.get("workflow_id")
    workflow_type = value.get("workflow_type")
    if not isinstance(workflow_id, str) or not workflow_id.strip():
        raise ValueError(f"WORKFLOW_HISTORY_BINDING_REQUIRED: workflow_id in {path}")
    if workflow_type not in SUPPORTED_WORKFLOW_TYPES:
        raise ValueError(f"WORKFLOW_HISTORY_BINDING_REQUIRED: workflow_type in {path}")
    history = value.get("history")
    if not isinstance(history, dict):
        raise ValueError(f"WORKFLOW_HISTORY_PAYLOAD_REQUIRED: {path}")
    events = history.get("events")
    if not isinstance(events, list) or not events:
        raise ValueError(f"WORKFLOW_HISTORY_EVENTS_REQUIRED: {path}")
    return HistoryEnvelope(
        path=path,
        workflow_id=workflow_id,
        workflow_type=workflow_type,
        history=history,
        sha256=f"sha256:{hashlib.sha256(raw).hexdigest()}",
    )


async def _replay_history(envelope: HistoryEnvelope) -> None:
    history = WorkflowHistory.from_json(envelope.workflow_id, envelope.history)
    result = await Replayer(workflows=[AgentRunWorkflow, ActionRecoveryWorkflow]).replay_workflow(
        history
    )
    if result.replay_failure is not None:
        raise result.replay_failure


async def replay_histories(paths: list[Path]) -> JsonObject:
    results: list[JsonObject] = []
    for path in paths:
        envelope = load_history_envelope(path)
        try:
            await _replay_history(envelope)
        except Exception as exc:
            raise RuntimeError(
                "WORKFLOW_REPLAY_FAILED: "
                f"{envelope.workflow_type}/{envelope.workflow_id}: {type(exc).__name__}: {exc}"
            ) from exc
        results.append(
            {
                "path": path.name,
                "workflow_id": envelope.workflow_id,
                "workflow_type": envelope.workflow_type,
                "sha256": envelope.sha256,
                "replayed": True,
            }
        )
    return {
        "schema_version": "1.0",
        "passed": True,
        "history_count": len(results),
        "histories": results,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Replay exported Temporal histories with current workflow definitions"
    )
    parser.add_argument("--history-dir", type=Path, required=True)
    parser.add_argument("--minimum-histories", type=int, default=1)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        paths = discover_history_paths(
            args.history_dir,
            minimum_histories=args.minimum_histories,
        )
        report = asyncio.run(replay_histories(paths))
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"workflow replay validation failed: {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
