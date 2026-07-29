"""Fail-closed validation for post-release observability runtime evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

JsonObject = dict[str, Any]
EXPECTED_DASHBOARDS = {
    "agent-platform-actions": "Agent Platform - Actions",
    "agent-platform-executive": "Agent Platform - Executive",
    "agent-platform-model": "Agent Platform - Model",
    "agent-platform-operations": "Agent Platform - Operations",
    "agent-platform-safety": "Agent Platform - Safety",
    "agent-platform-tools": "Agent Platform - Tools",
}


def _load_json(path: Path) -> JsonObject:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _timestamp(value: object, *, field: str, errors: list[str]) -> datetime | None:
    if not isinstance(value, str):
        errors.append(f"OBSERVABILITY_TIMESTAMP_INVALID: {field}")
        return None
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"OBSERVABILITY_TIMESTAMP_INVALID: {field}")
        return None
    if timestamp.tzinfo is None:
        errors.append(f"OBSERVABILITY_TIMESTAMP_TIMEZONE_MISSING: {field}")
        return None
    return timestamp


def validate_evidence(
    evidence: JsonObject,
    schema: JsonObject,
    *,
    expected_release_id: str,
    expected_git_sha: str,
    expected_image_digest: str,
    maximum_age_seconds: int,
    now: datetime | None = None,
) -> JsonObject:
    errors: list[str] = []
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for error in sorted(validator.iter_errors(evidence), key=lambda item: list(item.path)):
        location = ".".join(str(part) for part in error.path) or "$"
        errors.append(f"OBSERVABILITY_SCHEMA_INVALID: {location}: {error.message}")

    if evidence.get("release_id") != expected_release_id:
        errors.append("OBSERVABILITY_RELEASE_ID_MISMATCH")
    if evidence.get("git_sha") != expected_git_sha:
        errors.append("OBSERVABILITY_GIT_SHA_MISMATCH")
    if evidence.get("image_digest") != expected_image_digest:
        errors.append("OBSERVABILITY_IMAGE_DIGEST_MISMATCH")

    current_time = now or datetime.now(UTC)
    generated_at = _timestamp(evidence.get("generated_at"), field="generated_at", errors=errors)
    if generated_at is not None:
        age = current_time - generated_at
        if age < timedelta(minutes=-5) or age > timedelta(seconds=maximum_age_seconds):
            errors.append("OBSERVABILITY_EVIDENCE_TIMESTAMP_INVALID")

    grafana = evidence.get("grafana")
    dashboards = grafana.get("dashboards") if isinstance(grafana, dict) else None
    dashboard_rows = dashboards if isinstance(dashboards, list) else []
    actual_dashboards = {
        str(row.get("uid")): str(row.get("title"))
        for row in dashboard_rows
        if isinstance(row, dict)
    }
    if actual_dashboards != EXPECTED_DASHBOARDS or len(dashboard_rows) != 6:
        errors.append("OBSERVABILITY_DASHBOARD_CONTRACT_MISMATCH")
    expected_release_tags = {
        f"agent-platform-release-id:{expected_release_id}",
        f"agent-platform-git-sha:{expected_git_sha}",
        f"agent-platform-image-digest:{expected_image_digest}",
    }
    if any(
        not isinstance(row, dict)
        or row.get("release_identity_verified") is not True
        or not isinstance(row.get("release_tags"), list)
        or any(not isinstance(tag, str) for tag in row["release_tags"])
        or set(row["release_tags"]) != expected_release_tags
        for row in dashboard_rows
    ):
        errors.append("OBSERVABILITY_DASHBOARD_RELEASE_BINDING_MISSING")

    delivery = evidence.get("alert_delivery")
    delivery_row = delivery if isinstance(delivery, dict) else {}
    if (
        delivery_row.get("release_id") != expected_release_id
        or delivery_row.get("git_sha") != expected_git_sha
        or delivery_row.get("image_digest") != expected_image_digest
    ):
        errors.append("OBSERVABILITY_ALERT_RELEASE_BINDING_MISMATCH")
    received_at = _timestamp(
        delivery_row.get("received_at"),
        field="alert_delivery.received_at",
        errors=errors,
    )
    if received_at is not None:
        receipt_age = current_time - received_at
        if receipt_age < timedelta(minutes=-5) or receipt_age > timedelta(
            seconds=maximum_age_seconds
        ):
            errors.append("OBSERVABILITY_RECEIPT_TIMESTAMP_INVALID")
        if generated_at is not None and received_at > generated_at + timedelta(minutes=5):
            errors.append("OBSERVABILITY_RECEIPT_AFTER_EVIDENCE")

    receipt_sha256 = str(delivery_row.get("receipt_evidence_sha256", ""))
    receipt_uri = str(delivery_row.get("receipt_evidence_uri", ""))
    if receipt_sha256.removeprefix("sha256:") not in receipt_uri:
        errors.append("OBSERVABILITY_RECEIPT_URI_NOT_CONTENT_ADDRESSED")

    if errors:
        raise ValueError("\n".join(dict.fromkeys(errors)))
    return {
        "schema_version": "1.0",
        "release_id": expected_release_id,
        "git_sha": expected_git_sha,
        "image_digest": expected_image_digest,
        "dashboard_uids": sorted(EXPECTED_DASHBOARDS),
        "receipt_evidence_uri": receipt_uri,
        "receipt_evidence_sha256": receipt_sha256,
        "validated": True,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate exact-release observability runtime evidence"
    )
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--expected-release-id", required=True)
    parser.add_argument("--expected-git-sha", required=True)
    parser.add_argument("--expected-image-digest", required=True)
    parser.add_argument("--maximum-age-seconds", type=int, default=600)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.maximum_age_seconds <= 0:
            raise ValueError("maximum age must be positive")
        report = validate_evidence(
            _load_json(args.evidence),
            _load_json(args.schema),
            expected_release_id=args.expected_release_id,
            expected_git_sha=args.expected_git_sha,
            expected_image_digest=args.expected_image_digest,
            maximum_age_seconds=args.maximum_age_seconds,
        )
        report["observability_evidence_sha256"] = (
            f"sha256:{hashlib.sha256(args.evidence.read_bytes()).hexdigest()}"
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"observability evidence validation failed:\n{exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
