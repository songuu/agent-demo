from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PLATFORM_ROOT = Path(__file__).parents[3]
VALIDATOR = PLATFORM_ROOT / "deploy" / "ci" / "validate_environment_approval.py"


def _run(
    tmp_path: Path,
    reviews: object,
    *,
    environment: str = "agent-platform-production",
) -> subprocess.CompletedProcess[str]:
    reviews_path = tmp_path / "review-history.json"
    output_path = tmp_path / "approval.json"
    reviews_path.write_text(json.dumps(reviews), encoding="utf-8")
    return subprocess.run(  # noqa: S603 - repository-owned validator and fixed interpreter
        [
            sys.executable,
            str(VALIDATOR),
            "--reviews",
            str(reviews_path),
            "--expected-environment",
            environment,
            "--repository",
            "example/agent-platform",
            "--workflow-run-id",
            "12345",
            "--output",
            str(output_path),
        ],
        capture_output=True,
        check=False,
        text=True,
    )


def test_environment_approval_is_derived_from_github_review_history(
    tmp_path: Path,
) -> None:
    completed = _run(
        tmp_path,
        [
            {
                "state": "approved",
                "comment": "Production promotion approved.",
                "environments": [{"name": "agent-platform-production"}],
                "user": {"login": "release-reviewer", "type": "User"},
            }
        ],
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    approval = json.loads((tmp_path / "approval.json").read_text(encoding="utf-8"))
    assert approval["actor"] == "release-reviewer"
    assert approval["decision"] == "approved"
    assert approval["environment"] == "agent-platform-production"
    assert approval["source_uri"].endswith("/actions/runs/12345/approvals")


def test_environment_approval_fails_closed_without_matching_human_approval(
    tmp_path: Path,
) -> None:
    blocked = _run(
        tmp_path,
        [
            {
                "state": "rejected",
                "environments": [{"name": "agent-platform-production"}],
                "user": {"login": "release-reviewer", "type": "User"},
            },
            {
                "state": "approved",
                "environments": [{"name": "agent-platform-staging"}],
                "user": {"login": "staging-reviewer", "type": "User"},
            },
        ],
    )

    assert blocked.returncode == 2
    assert "PRODUCTION_ENVIRONMENT_APPROVAL_MISSING" in blocked.stderr
