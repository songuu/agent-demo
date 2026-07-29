"""Fail-closed validation for externally produced progressive-delivery evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker

JsonObject = dict[str, Any]
FORBIDDEN_CONTROLLER_MARKERS = {
    "demo",
    "fake",
    "fixture",
    "local",
    "mock",
    "self-attested",
    "synthetic",
    "test",
}
DIGEST_URI_PATTERN = re.compile(r"/(sha256:[0-9a-f]{64})$")


def _load_json(path: Path) -> JsonObject:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _load_policy(path: Path) -> JsonObject:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a YAML object")
    return value


def _timestamp(value: object, *, field: str, errors: list[str]) -> datetime | None:
    if not isinstance(value, str):
        errors.append(f"CANARY_TIMESTAMP_INVALID: {field}")
        return None
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"CANARY_TIMESTAMP_INVALID: {field}")
        return None
    if timestamp.tzinfo is None:
        errors.append(f"CANARY_TIMESTAMP_TIMEZONE_MISSING: {field}")
        return None
    return timestamp


def _policy_phases(policy: JsonObject) -> list[JsonObject]:
    raw_phases = policy.get("phases")
    if not isinstance(raw_phases, list):
        raise ValueError("CANARY_POLICY_PHASES_MISSING")
    phases = [
        phase
        for phase in raw_phases
        if isinstance(phase, dict) and phase.get("promotion_stage") == "canary"
    ]
    if not phases:
        raise ValueError("CANARY_POLICY_PHASES_EMPTY")
    return phases


def _mapping(value: object) -> JsonObject:
    return value if isinstance(value, dict) else {}


def _uri_digest(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    matched = DIGEST_URI_PATTERN.search(value)
    return matched.group(1) if matched is not None else None


def _policy_value_matches(actual: object, expected: object) -> bool:
    if isinstance(expected, bool):
        return isinstance(actual, bool) and actual is expected
    if isinstance(expected, (int, float)):
        return (
            isinstance(actual, (int, float)) and not isinstance(actual, bool) and actual == expected
        )
    return type(actual) is type(expected) and actual == expected


def _threshold_passes(observed: object, comparison: object, threshold: object) -> bool:
    if comparison == "eq":
        return _policy_value_matches(observed, threshold)
    if (
        comparison in {"lte", "gte"}
        and isinstance(observed, (int, float))
        and not isinstance(observed, bool)
        and isinstance(threshold, (int, float))
        and not isinstance(threshold, bool)
    ):
        return observed <= threshold if comparison == "lte" else observed >= threshold
    return False


def _validate_phase_metrics(
    *,
    phase: JsonObject,
    phase_id: str,
    phase_started: datetime | None,
    phase_completed: datetime | None,
    policy: JsonObject,
    errors: list[str],
) -> None:
    metrics_sha256 = phase.get("metrics_sha256")
    if _uri_digest(phase.get("metrics_uri")) != metrics_sha256:
        errors.append(f"CANARY_PHASE_METRICS_URI_DIGEST_MISMATCH: {phase_id}")
    metric_policy = _mapping(policy.get("metric_gates"))
    raw_rows = phase.get("metrics")
    rows = raw_rows if isinstance(raw_rows, list) else []
    metric_rows = [row for row in rows if isinstance(row, dict)]
    actual_ids = [str(row.get("id")) for row in metric_rows]
    if len(actual_ids) != len(set(actual_ids)):
        errors.append(f"CANARY_PHASE_METRIC_IDS_DUPLICATED: {phase_id}")
    if set(actual_ids) != set(metric_policy) or len(metric_rows) != len(metric_policy):
        errors.append(f"CANARY_PHASE_METRICS_INCOMPLETE: {phase_id}")
    for index, row in enumerate(metric_rows):
        metric_id = str(row.get("id"))
        expected = _mapping(metric_policy.get(metric_id))
        expected_comparison = expected.get("comparison")
        expected_threshold = expected.get("threshold")
        if row.get("comparison") != expected_comparison:
            errors.append(f"CANARY_PHASE_METRIC_COMPARISON_MISMATCH: {phase_id}.{metric_id}")
        if not _policy_value_matches(row.get("threshold"), expected_threshold):
            errors.append(f"CANARY_PHASE_METRIC_THRESHOLD_MISMATCH: {phase_id}.{metric_id}")
        if not _threshold_passes(
            row.get("observed"),
            expected_comparison,
            expected_threshold,
        ):
            errors.append(f"CANARY_PHASE_METRIC_FAILED: {phase_id}.{metric_id}")
        metric_started = _timestamp(
            row.get("window_started_at"),
            field=f"phases.{phase_id}.metrics.{index}.window_started_at",
            errors=errors,
        )
        metric_completed = _timestamp(
            row.get("window_completed_at"),
            field=f"phases.{phase_id}.metrics.{index}.window_completed_at",
            errors=errors,
        )
        if metric_started != phase_started or metric_completed != phase_completed:
            errors.append(f"CANARY_PHASE_METRIC_WINDOW_MISMATCH: {phase_id}.{metric_id}")


def _validate_stop_condition_observations(
    *,
    conditions: list[object],
    policy: JsonObject,
    completed_at: datetime | None,
    generated_at: datetime | None,
    errors: list[str],
) -> None:
    expected_policy = _mapping(policy.get("stop_condition_gates"))
    rows = [row for row in conditions if isinstance(row, dict)]
    actual_ids = [str(row.get("id")) for row in rows]
    if len(actual_ids) != len(set(actual_ids)):
        errors.append("CANARY_STOP_CONDITION_IDS_DUPLICATED")
    if set(actual_ids) != set(expected_policy) or len(rows) != len(expected_policy):
        errors.append("CANARY_STOP_CONDITIONS_INCOMPLETE")
    for row in rows:
        condition_id = str(row.get("id"))
        expected = _mapping(expected_policy.get(condition_id))
        comparison = expected.get("comparison")
        threshold = expected.get("threshold")
        if row.get("comparison") != comparison:
            errors.append(f"CANARY_STOP_CONDITION_COMPARISON_MISMATCH: {condition_id}")
        if not _policy_value_matches(row.get("threshold"), threshold):
            errors.append(f"CANARY_STOP_CONDITION_THRESHOLD_MISMATCH: {condition_id}")
        if not _threshold_passes(row.get("observed"), comparison, threshold):
            errors.append(f"CANARY_STOP_CONDITION_TRIGGERED: {condition_id}")
        if _uri_digest(row.get("evidence_uri")) != row.get("evidence_sha256"):
            errors.append(f"CANARY_STOP_CONDITION_URI_DIGEST_MISMATCH: {condition_id}")
        evaluated_at = _timestamp(
            row.get("evaluated_at"),
            field=f"stop_conditions.{condition_id}.evaluated_at",
            errors=errors,
        )
        if (
            evaluated_at is not None
            and completed_at is not None
            and generated_at is not None
            and not completed_at <= evaluated_at <= generated_at
        ):
            errors.append(f"CANARY_STOP_CONDITION_TIMESTAMP_INVALID: {condition_id}")
        if row.get("status") != "clear":
            errors.append(f"CANARY_STOP_CONDITION_TRIGGERED: {condition_id}")


def validate_evidence(
    evidence: JsonObject,
    schema: JsonObject,
    policy: JsonObject,
    *,
    expected_release_id: str,
    expected_git_sha: str,
    expected_image_digest: str,
    minimum_observation_seconds: int,
    source_bytes: bytes,
    source_uri: str,
    policy_sha256: str,
    expected_signer_identity: str,
    expected_signer_issuer: str,
    maximum_age_seconds: int,
    now: datetime | None = None,
) -> JsonObject:
    errors: list[str] = []
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for error in sorted(validator.iter_errors(evidence), key=lambda item: list(item.path)):
        location = ".".join(str(part) for part in error.path) or "$"
        errors.append(f"CANARY_SCHEMA_INVALID: {location}: {error.message}")

    if evidence.get("release_id") != expected_release_id:
        errors.append("CANARY_RELEASE_ID_MISMATCH")
    if evidence.get("git_sha") != expected_git_sha:
        errors.append("CANARY_GIT_SHA_MISMATCH")
    if evidence.get("image_digest") != expected_image_digest:
        errors.append("CANARY_IMAGE_DIGEST_MISMATCH")

    source_sha256 = "sha256:" + hashlib.sha256(source_bytes).hexdigest()
    canonical_source = json.dumps(
        evidence,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    if source_bytes != canonical_source:
        errors.append("CANARY_SIGNED_CONTENT_NOT_CANONICAL")
    if not source_uri.startswith("https://") or _uri_digest(source_uri) != source_sha256:
        errors.append("CANARY_SOURCE_URI_DIGEST_MISMATCH")

    policy_version = policy.get("policy_version")
    evidence_policy = evidence.get("policy")
    if not isinstance(evidence_policy, dict) or evidence_policy.get("version") != policy_version:
        errors.append("CANARY_POLICY_VERSION_MISMATCH")
    else:
        if evidence_policy.get("sha256") != policy_sha256:
            errors.append("CANARY_POLICY_DIGEST_MISMATCH")
        if _uri_digest(evidence_policy.get("uri")) != policy_sha256:
            errors.append("CANARY_POLICY_URI_DIGEST_MISMATCH")

    signer = _mapping(evidence.get("signer"))
    if signer.get("identity") != expected_signer_identity:
        errors.append("CANARY_SIGNER_IDENTITY_MISMATCH")
    if signer.get("issuer") != expected_signer_issuer:
        errors.append("CANARY_SIGNER_ISSUER_MISMATCH")

    controller = _mapping(evidence.get("controller"))
    if controller.get("external") is not True:
        errors.append("CANARY_EXTERNAL_CONTROLLER_REQUIRED")
    else:
        controller_labels = [
            str(controller.get(field, "")).strip().lower() for field in ("provider", "product")
        ]
        if any(
            label in FORBIDDEN_CONTROLLER_MARKERS
            or any(label.startswith(f"{marker}-") for marker in FORBIDDEN_CONTROLLER_MARKERS)
            for label in controller_labels
        ):
            errors.append("CANARY_NON_PRODUCTION_CONTROLLER_REJECTED")
        if _uri_digest(controller.get("evidence_uri")) is None:
            errors.append("CANARY_CONTROLLER_EVIDENCE_URI_NOT_CONTENT_ADDRESSED")

    expected_phases = _policy_phases(policy)
    phase_rows = evidence.get("phases")
    actual_phases = phase_rows if isinstance(phase_rows, list) else []
    expected_ids = [str(phase["id"]) for phase in expected_phases]
    actual_ids = [str(phase.get("id")) for phase in actual_phases if isinstance(phase, dict)]
    if actual_ids != expected_ids or len(actual_phases) != len(expected_phases):
        errors.append(
            f"CANARY_PHASE_SEQUENCE_MISMATCH: expected={expected_ids}, actual={actual_ids}"
        )

    policy_minimum_total = 0
    observed_total = 0
    prior_completed: datetime | None = None
    expected_by_id = {
        str(phase["id"]): int(phase["minimum_observation_seconds"]) for phase in expected_phases
    }
    for index, raw_phase in enumerate(actual_phases):
        if not isinstance(raw_phase, dict):
            errors.append(f"CANARY_PHASE_INVALID: index={index}")
            continue
        phase_id = str(raw_phase.get("id", index))
        required_duration = expected_by_id.get(phase_id)
        if required_duration is None:
            continue
        policy_minimum_total += required_duration
        started = _timestamp(
            raw_phase.get("started_at"),
            field=f"phases.{phase_id}.started_at",
            errors=errors,
        )
        completed = _timestamp(
            raw_phase.get("completed_at"),
            field=f"phases.{phase_id}.completed_at",
            errors=errors,
        )
        _validate_phase_metrics(
            phase=raw_phase,
            phase_id=phase_id,
            phase_started=started,
            phase_completed=completed,
            policy=policy,
            errors=errors,
        )
        if started is None or completed is None:
            continue
        observed_duration = int((completed - started).total_seconds())
        observed_total += max(observed_duration, 0)
        if observed_duration < required_duration:
            errors.append(f"CANARY_PHASE_OBSERVATION_TOO_SHORT: {phase_id}")
        if raw_phase.get("minimum_observation_seconds") != required_duration:
            errors.append(f"CANARY_PHASE_POLICY_MINIMUM_MISMATCH: {phase_id}")
        if raw_phase.get("observed_duration_seconds") != observed_duration:
            errors.append(f"CANARY_PHASE_DURATION_MISMATCH: {phase_id}")
        if prior_completed is not None and started < prior_completed:
            errors.append(f"CANARY_PHASE_OVERLAP: {phase_id}")
        prior_completed = completed

    started_at = _timestamp(evidence.get("started_at"), field="started_at", errors=errors)
    completed_at = _timestamp(evidence.get("completed_at"), field="completed_at", errors=errors)
    generated_at = _timestamp(evidence.get("generated_at"), field="generated_at", errors=errors)
    current_time = (now or datetime.now(UTC)).astimezone(UTC)
    if maximum_age_seconds <= 0:
        errors.append("CANARY_MAXIMUM_AGE_INVALID")
    elif generated_at is not None:
        if generated_at < current_time - timedelta(seconds=maximum_age_seconds):
            errors.append("CANARY_EVIDENCE_EXPIRED")
        if generated_at > current_time + timedelta(minutes=5):
            errors.append("CANARY_EVIDENCE_FROM_FUTURE")
    if completed_at is not None and generated_at is not None:
        if not completed_at <= generated_at <= completed_at + timedelta(minutes=15):
            errors.append("CANARY_EVIDENCE_GENERATION_TIMELINE_INVALID")
    if started_at is not None and completed_at is not None:
        wall_clock_duration = int((completed_at - started_at).total_seconds())
        required_total = max(minimum_observation_seconds, policy_minimum_total)
        if wall_clock_duration < required_total or observed_total < required_total:
            errors.append(
                "CANARY_TOTAL_OBSERVATION_TOO_SHORT: "
                f"required={required_total}, wall_clock={wall_clock_duration}, "
                f"phases={observed_total}"
            )
        if actual_phases:
            first = actual_phases[0]
            last = actual_phases[-1]
            if (
                isinstance(first, dict)
                and isinstance(last, dict)
                and (
                    first.get("started_at") != evidence.get("started_at")
                    or last.get("completed_at") != evidence.get("completed_at")
                )
            ):
                errors.append("CANARY_OBSERVATION_BOUNDARY_MISMATCH")

    rollback_owner = evidence.get("rollback_owner")
    rollback_actor = ""
    if not isinstance(rollback_owner, dict):
        errors.append("CANARY_ROLLBACK_OWNER_REQUIRED")
    else:
        rollback_actor = str(rollback_owner.get("actor", ""))
        authenticated_at = _timestamp(
            rollback_owner.get("authenticated_at"),
            field="rollback_owner.authenticated_at",
            errors=errors,
        )
        acknowledged_at = _timestamp(
            rollback_owner.get("acknowledged_at"),
            field="rollback_owner.acknowledged_at",
            errors=errors,
        )
        if authenticated_at is not None and acknowledged_at is not None:
            if authenticated_at > acknowledged_at:
                errors.append("CANARY_ROLLBACK_AUTHENTICATION_AFTER_ACK")
            if started_at is not None:
                acknowledgement_age = (started_at - acknowledged_at).total_seconds()
                if acknowledgement_age < 0 or acknowledgement_age > 86400:
                    errors.append("CANARY_ROLLBACK_ACK_NOT_FRESH_AT_START")
        if rollback_owner.get("rollback_target_digest") == expected_image_digest:
            errors.append("CANARY_ROLLBACK_TARGET_NOT_PREVIOUS_RELEASE")
        if _uri_digest(rollback_owner.get("evidence_uri")) is None:
            errors.append("CANARY_ROLLBACK_OWNER_EVIDENCE_NOT_CONTENT_ADDRESSED")

    raw_conditions = evidence.get("stop_conditions")
    conditions = raw_conditions if isinstance(raw_conditions, list) else []
    _validate_stop_condition_observations(
        conditions=conditions,
        policy=policy,
        completed_at=completed_at,
        generated_at=generated_at,
        errors=errors,
    )
    if evidence.get("result") != "passed":
        errors.append("CANARY_RESULT_NOT_PASSED")

    if errors:
        raise ValueError("\n".join(dict.fromkeys(errors)))
    return {
        "schema_version": "1.1",
        "release_id": expected_release_id,
        "git_sha": expected_git_sha,
        "image_digest": expected_image_digest,
        "source_uri": source_uri,
        "canary_evidence_sha256": source_sha256,
        "policy_version": policy_version,
        "policy_sha256": policy_sha256,
        "controller_rollout_id": controller["rollout_id"],
        "rollback_owner_actor": rollback_actor,
        "signer_identity": expected_signer_identity,
        "signer_issuer": expected_signer_issuer,
        "validated_phase_ids": expected_ids,
        "metric_snapshot_sha256": {
            str(phase["id"]): phase["metrics_sha256"]
            for phase in actual_phases
            if isinstance(phase, dict)
        },
        "observed_duration_seconds": observed_total,
        "validated_at": current_time.isoformat(),
        "validated": True,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate external canary evidence against exact release identity"
    )
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--signature-bundle", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--source-uri", required=True)
    parser.add_argument("--expected-release-id", required=True)
    parser.add_argument("--expected-git-sha", required=True)
    parser.add_argument("--expected-image-digest", required=True)
    parser.add_argument("--expected-signer-identity", required=True)
    parser.add_argument("--expected-signer-issuer", required=True)
    parser.add_argument("--minimum-observation-seconds", type=int, required=True)
    parser.add_argument("--maximum-age-seconds", type=int, default=86400)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.evidence.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("CANARY_EVIDENCE_TOO_LARGE")
        if args.signature_bundle.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("CANARY_SIGNATURE_BUNDLE_TOO_LARGE")
        evidence_bytes = args.evidence.read_bytes()
        signature_bundle_bytes = args.signature_bundle.read_bytes()
        policy_bytes = args.policy.read_bytes()
        report = validate_evidence(
            _load_json(args.evidence),
            _load_json(args.schema),
            _load_policy(args.policy),
            expected_release_id=args.expected_release_id,
            expected_git_sha=args.expected_git_sha,
            expected_image_digest=args.expected_image_digest,
            minimum_observation_seconds=args.minimum_observation_seconds,
            source_bytes=evidence_bytes,
            source_uri=args.source_uri,
            policy_sha256="sha256:" + hashlib.sha256(policy_bytes).hexdigest(),
            expected_signer_identity=args.expected_signer_identity,
            expected_signer_issuer=args.expected_signer_issuer,
            maximum_age_seconds=args.maximum_age_seconds,
        )
        report["signature_bundle_sha256"] = (
            "sha256:" + hashlib.sha256(signature_bundle_bytes).hexdigest()
        )
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"canary evidence validation failed:\n{exc}", file=sys.stderr)
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
