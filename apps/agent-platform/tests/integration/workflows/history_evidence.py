"""Optional CI-only export of real Temporal histories for replay validation."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from temporalio.client import WorkflowHistory


def persist_history(
    history: WorkflowHistory,
    *,
    workflow_type: str,
) -> Path | None:
    configured = os.getenv("AGENT_WORKFLOW_HISTORY_DIR")
    if not configured:
        return None
    history_json = history.to_json()
    history_sha256 = hashlib.sha256(history_json.encode()).hexdigest()
    directory = Path(configured)
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"{workflow_type}-{history_sha256[:20]}.json"
    destination.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "workflow_id": history.workflow_id,
                "workflow_type": workflow_type,
                "history": json.loads(history_json),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return destination
