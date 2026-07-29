"""Extract a real GitHub environment approval from workflow review history."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _load_reviews(path: Path) -> list[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError("GITHUB_REVIEW_HISTORY_INVALID")
    return value


def extract_approval(
    reviews: list[dict[str, Any]],
    *,
    expected_environment: str,
    repository: str,
    workflow_run_id: str,
) -> dict[str, Any]:
    matching: list[dict[str, Any]] = []
    for review in reviews:
        if review.get("state") != "approved":
            continue
        environments = review.get("environments")
        user = review.get("user")
        if not isinstance(environments, list) or not isinstance(user, dict):
            continue
        if user.get("type") != "User":
            continue
        login = user.get("login")
        if not isinstance(login, str) or not login:
            continue
        names = {
            str(environment.get("name"))
            for environment in environments
            if isinstance(environment, dict)
        }
        if expected_environment in names:
            matching.append(review)
    if not matching:
        raise ValueError("PRODUCTION_ENVIRONMENT_APPROVAL_MISSING")

    review = matching[-1]
    user = review["user"]
    return {
        "schema_version": "1.0",
        "actor": user["login"],
        "actor_type": "User",
        "role": "github-environment-reviewer",
        "decision": "approved",
        "environment": expected_environment,
        "comment": str(review.get("comment", "")),
        "recorded_at": datetime.now(UTC).isoformat(),
        "source_uri": (
            f"https://api.github.com/repos/{repository}/actions/runs/{workflow_run_id}/approvals"
        ),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Require an approved GitHub review for an exact environment"
    )
    parser.add_argument("--reviews", type=Path, required=True)
    parser.add_argument("--expected-environment", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        approval = extract_approval(
            _load_reviews(args.reviews),
            expected_environment=args.expected_environment,
            repository=args.repository,
            workflow_run_id=args.workflow_run_id,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"environment approval validation failed: {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(approval, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(approval, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
