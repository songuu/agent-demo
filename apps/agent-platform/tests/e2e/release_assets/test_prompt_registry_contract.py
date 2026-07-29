from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_platform.agents.prompt_registry import PromptRegistry

PLATFORM_ROOT = Path(__file__).parents[3]
PROMPT_ROOT = PLATFORM_ROOT / "prompts"


def test_production_prompt_registry_loads_every_approved_content_addressed_prompt() -> None:
    document = json.loads((PROMPT_ROOT / "registry.json").read_text(encoding="utf-8"))
    assert document["schema_version"] == "1.0"
    assert len(document["prompts"]) == 5

    registry = PromptRegistry(PROMPT_ROOT)
    for record in document["prompts"]:
        assert record["status"] == "approved"
        assert record["role"] == record["prompt_id"]
        prompt_path = PROMPT_ROOT / record["path"]
        assert prompt_path.is_file()
        assert hashlib.sha256(prompt_path.read_bytes()).hexdigest() == record["sha256"]

        rendered = registry.render(
            record["prompt_id"],
            record["version"],
            {"contract": {"goal": "registry contract check"}},
        )
        assert rendered.startswith("---")
        assert "registry contract check" in rendered

    version_manifest = registry.version_manifest()
    assert set(version_manifest) == {
        "classifier",
        "planner",
        "worker",
        "verifier",
        "finalizer",
    }
