"""Validate externally produced operational release-readiness evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn, TypeGuard
from urllib.parse import urlsplit

import httpx
from jsonschema import Draft202012Validator, FormatChecker

JsonObject = dict[str, Any]


class _NonFiniteJsonError(ValueError):
    pass


class _PayloadTooLarge(ValueError):
    pass


class _ContentTypeInvalid(ValueError):
    pass


def _reject_json_constant(value: str) -> NoReturn:
    raise _NonFiniteJsonError(f"non-finite JSON constant: {value}")


def _strict_json_loads(payload: str | bytes) -> Any:
    return json.loads(payload, parse_constant=_reject_json_constant)


def _is_finite_number(value: object) -> TypeGuard[int | float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return not isinstance(value, float) or math.isfinite(value)


REQUIRED_TRAINING_POPULATIONS = {"business-users", "approvers", "on-call"}
GatePolicy = tuple[str, bool | int | float | str]
GATE_CHECK_POLICIES: dict[str, dict[str, GatePolicy]] = {
    "supply_chain": {
        "image_signature_verified": ("eq", True),
        "sbom_complete": ("eq", True),
        "provenance_verified": ("eq", True),
        "high_critical_vulnerabilities_zero": ("eq", True),
        "iac_policy_passed": ("eq", True),
    },
    "bucket_governance": {
        "versioning_enabled": ("eq", True),
        "kms_key_bound": ("eq", True),
        "lifecycle_enabled": ("eq", True),
        "public_access_blocked": ("eq", True),
        "object_lock_enabled": ("eq", True),
        "restore_test_passed": ("eq", True),
    },
    "staging_e2e": {
        "database_compatibility": ("eq", True),
        "integration_no_skips": ("eq", True),
        "read_only_smoke": ("eq", True),
    },
    "workflow_replay": {
        "histories_at_least_two": ("gte", 2),
        "replay_failures_zero": ("eq", 0),
    },
    "red_team": {
        "critical_findings_zero": ("eq", 0),
        "high_findings_zero": ("eq", 0),
        "prompt_injection_blocked": ("eq", True),
        "data_exfiltration_blocked": ("eq", True),
    },
    "fault_injection": {
        "planner_failure_recovered": ("eq", True),
        "worker_kill_recovered": ("eq", True),
        "verifier_failure_recovered": ("eq", True),
        "approval_failure_failed_closed": ("eq", True),
        "commit_failure_recovered": ("eq", True),
        "model_failure_recovered": ("eq", True),
        "tool_failure_recovered": ("eq", True),
        "database_failure_recovered": ("eq", True),
        "artifact_failure_recovered": ("eq", True),
        "opa_failure_failed_closed": ("eq", True),
    },
    "disaster_recovery": {
        "postgres_pitr_restored": ("eq", True),
        "artifact_object_restored": ("eq", True),
        "temporal_state_restored": ("eq", True),
        "regional_gameday_passed": ("eq", True),
        "postgres_rpo_minutes": ("lte", 5),
        "postgres_rto_minutes": ("lte", 30),
        "artifact_rpo_minutes": ("lte", 5),
        "artifact_rto_minutes": ("lte", 60),
        "temporal_rto_minutes": ("lte", 30),
        "regional_rto_minutes": ("lte", 60),
    },
    "retention_policy": {
        "policy_versioned": ("eq", True),
        "legal_hold_enforced": ("eq", True),
        "immutable_archive_verified": ("eq", True),
        "deletion_readback_verified": ("eq", True),
        "owner_approved": ("eq", True),
    },
    "cost_budget": {
        "budget_owner_approved": ("eq", True),
        "cost_regression_lte_15_percent": ("lte", 15),
        "billing_reconciled": ("eq", True),
    },
    "capacity": {
        "burst_multiplier": ("gte", 10),
        "long_runs": ("gte", 100),
        "tool_p95_multiplier": ("gte", 5),
        "sustained_429_passed": ("eq", True),
        "artifact_size_mb": ("gte", 200),
        "pending_approval_backlog": ("gte", 1000),
        "pending_approval_notifications_verified": ("eq", True),
        "pending_approval_expiry_verified": ("eq", True),
        "pending_approval_no_resource_leak": ("eq", True),
    },
    "slo_latency": {
        "slo_met": ("eq", True),
        "p95_regression_percent": ("lte", 20),
        "error_budget_healthy": ("eq", True),
    },
    "observability": {
        "grafana_dashboard_api_readback_passed": ("eq", True),
        "grafana_dashboard_count": ("eq", 6),
        "synthetic_alert_api_readback_passed": ("eq", True),
        "receiver_delivery_receipt_verified": ("eq", True),
        "receipt_content_addressed": ("eq", True),
    },
}
REQUIRED_GATE_CHECKS: dict[str, frozenset[str]] = {
    gate_name: frozenset(policies) for gate_name, policies in GATE_CHECK_POLICIES.items()
}
RAW_EVIDENCE_SCHEMA_PATH = Path(__file__).with_name("operational-raw-evidence.schema.json")
RAW_COUNT_SAMPLE_CHECKS = frozenset(
    {
        ("workflow_replay", "histories_at_least_two"),
        ("workflow_replay", "replay_failures_zero"),
        ("red_team", "critical_findings_zero"),
        ("red_team", "high_findings_zero"),
        ("observability", "grafana_dashboard_count"),
    }
)

REQUIRED_FAULT_OUTCOMES = {
    "planner": "recovered",
    "worker": "recovered",
    "verifier": "recovered",
    "approval": "fail_closed",
    "commit": "recovered",
    "model": "recovered",
    "tool": "recovered",
    "database": "recovered",
    "artifact": "recovered",
    "opa": "fail_closed",
}
GateScopePolicy = tuple[str, frozenset[str]]
GATE_SCOPE_POLICIES: dict[str, GateScopePolicy] = {
    "supply_chain": ("production", frozenset({"image", "policy_bundle", "tool_catalog"})),
    "bucket_governance": ("production", frozenset({"artifact_bucket"})),
    "staging_e2e": (
        "staging",
        frozenset({"api", "postgresql", "temporal", "artifact_bucket", "opa"}),
    ),
    "workflow_replay": ("staging", frozenset({"temporal"})),
    "red_team": (
        "staging",
        frozenset({"api", "tool_gateway", "artifact_bucket"}),
    ),
    "fault_injection": (
        "staging",
        frozenset(
            {
                "api",
                "postgresql",
                "temporal",
                "artifact_bucket",
                "opa",
                "model_gateway",
                "tool_gateway",
            }
        ),
    ),
    "disaster_recovery": (
        "production",
        frozenset({"postgresql", "artifact_bucket", "temporal", "regional_stack"}),
    ),
    "retention_policy": (
        "production",
        frozenset({"postgresql", "artifact_bucket"}),
    ),
    "cost_budget": (
        "production",
        frozenset({"billing_export", "observability"}),
    ),
    "capacity": (
        "staging",
        frozenset({"api", "temporal", "artifact_bucket", "approval_store"}),
    ),
    "slo_latency": (
        "production",
        frozenset({"api", "temporal", "observability"}),
    ),
    "observability": (
        "staging",
        frozenset({"observability", "alert_receiver"}),
    ),
}
DrillPolicy = tuple[timedelta, int, int, frozenset[str], int]
DRILL_POLICIES: dict[str, DrillPolicy] = {
    "daily_restore": (
        timedelta(hours=36),
        5,
        30,
        frozenset({"postgresql", "temporal"}),
        1,
    ),
    "quarterly_db_artifact": (
        timedelta(days=100),
        5,
        60,
        frozenset({"postgresql", "artifact_bucket"}),
        1,
    ),
    "semiannual_region": (
        timedelta(days=200),
        5,
        60,
        frozenset({"regional_stack"}),
        2,
    ),
}


def _load_object(path: Path) -> JsonObject:
    value = _strict_json_loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _timestamp(value: object, *, field: str, errors: list[str]) -> datetime | None:
    if not isinstance(value, str):
        errors.append(f"OPERATIONAL_READINESS_TIMESTAMP_INVALID: {field}")
        return None
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"OPERATIONAL_READINESS_TIMESTAMP_INVALID: {field}")
        return None
    if timestamp.tzinfo is None:
        errors.append(f"OPERATIONAL_READINESS_TIMESTAMP_TIMEZONE_MISSING: {field}")
        return None
    return timestamp


def canonical_sha256(value: JsonObject) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def validate_readiness(
    evidence: JsonObject,
    schema: JsonObject,
    *,
    expected_release_id: str,
    expected_git_sha: str,
    expected_image_digest: str,
    expected_signer_identity: str,
    expected_signer_issuer: str,
    maximum_age_seconds: int,
    minimum_retention_days: int,
    source_sha256: str | None = None,
) -> JsonObject:
    if maximum_age_seconds <= 0:
        raise ValueError("OPERATIONAL_READINESS_MAXIMUM_AGE_INVALID")
    if minimum_retention_days <= 0:
        raise ValueError("OPERATIONAL_READINESS_MINIMUM_RETENTION_INVALID")

    errors: list[str] = []
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for error in sorted(validator.iter_errors(evidence), key=lambda item: list(item.path)):
        location = ".".join(str(part) for part in error.path) or "$"
        errors.append(f"OPERATIONAL_READINESS_SCHEMA_INVALID: {location}: {error.message}")

    if evidence.get("release_id") != expected_release_id:
        errors.append("OPERATIONAL_READINESS_RELEASE_ID_MISMATCH")
    if evidence.get("git_sha") != expected_git_sha:
        errors.append("OPERATIONAL_READINESS_GIT_SHA_MISMATCH")
    if evidence.get("image_digest") != expected_image_digest:
        errors.append("OPERATIONAL_READINESS_IMAGE_DIGEST_MISMATCH")

    generated_at = _timestamp(
        evidence.get("generated_at"),
        field="generated_at",
        errors=errors,
    )
    now = datetime.now(UTC)
    freshness_floor: datetime | None = None
    if generated_at is not None:
        age_seconds = (now - generated_at).total_seconds()
        freshness_floor = generated_at - timedelta(seconds=maximum_age_seconds)
        if age_seconds < -300:
            errors.append("OPERATIONAL_READINESS_GENERATED_IN_FUTURE")
        elif age_seconds > maximum_age_seconds:
            errors.append("OPERATIONAL_READINESS_EXPIRED")

    training = evidence.get("training")
    records = training.get("records") if isinstance(training, dict) else None
    populations = {
        str(record.get("population")) for record in records or [] if isinstance(record, dict)
    }
    if populations != REQUIRED_TRAINING_POPULATIONS:
        errors.append(
            "OPERATIONAL_READINESS_TRAINING_INCOMPLETE: "
            f"required={sorted(REQUIRED_TRAINING_POPULATIONS)}, "
            f"actual={sorted(populations)}"
        )
    for index, record in enumerate(records or []):
        completed_at = _timestamp(
            record.get("completed_at") if isinstance(record, dict) else None,
            field=f"training.records.{index}.completed_at",
            errors=errors,
        )
        if (
            completed_at is not None
            and generated_at is not None
            and freshness_floor is not None
            and not freshness_floor <= completed_at <= generated_at
        ):
            errors.append(f"OPERATIONAL_READINESS_TRAINING_STALE: index={index}")

    rollback = evidence.get("rollback")
    if isinstance(rollback, dict):
        for field in ("authenticated_at", "acknowledged_at"):
            timestamp = _timestamp(
                rollback.get(field),
                field=f"rollback.{field}",
                errors=errors,
            )
            if (
                timestamp is not None
                and generated_at is not None
                and freshness_floor is not None
                and not freshness_floor <= timestamp <= generated_at
            ):
                errors.append(f"OPERATIONAL_READINESS_ROLLBACK_ACK_STALE: {field}")

        if rollback.get("previous_image_digest") == expected_image_digest:
            errors.append("OPERATIONAL_READINESS_ROLLBACK_IMAGE_NOT_PREVIOUS")

    evidence_store = evidence.get("evidence_store")
    if not isinstance(evidence_store, dict):
        evidence_store = {}
    evidence_uri = str(evidence_store.get("uri", ""))
    if evidence_store.get("digest_uri") != f"{evidence_uri}.sha256":
        errors.append("OPERATIONAL_READINESS_DIGEST_URI_MISMATCH")
    if evidence_store.get("signature_bundle_uri") != f"{evidence_uri}.sigstore.json":
        errors.append("OPERATIONAL_READINESS_SIGNATURE_URI_MISMATCH")
    if evidence_store.get("signer_identity") != expected_signer_identity:
        errors.append("OPERATIONAL_READINESS_SIGNER_IDENTITY_MISMATCH")
    if evidence_store.get("signer_issuer") != expected_signer_issuer:
        errors.append("OPERATIONAL_READINESS_SIGNER_ISSUER_MISMATCH")
    retention_until = _timestamp(
        evidence_store.get("retention_until"),
        field="evidence_store.retention_until",
        errors=errors,
    )
    if generated_at is not None and retention_until is not None:
        required_retention = generated_at + timedelta(days=minimum_retention_days)
        if retention_until < required_retention:
            errors.append("OPERATIONAL_READINESS_RETENTION_TOO_SHORT")

    gates = evidence.get("gates")
    if isinstance(gates, dict):
        for gate_name, gate in gates.items():
            if not isinstance(gate, dict):
                continue
            if gate.get("gate_id") != gate_name:
                errors.append(f"OPERATIONAL_READINESS_GATE_ID_MISMATCH: {gate_name}")
            if gate.get("release_id") != expected_release_id:
                errors.append(f"OPERATIONAL_READINESS_GATE_RELEASE_ID_MISMATCH: {gate_name}")
            if gate.get("git_sha") != expected_git_sha:
                errors.append(f"OPERATIONAL_READINESS_GATE_GIT_SHA_MISMATCH: {gate_name}")
            if gate.get("image_digest") != expected_image_digest:
                errors.append(f"OPERATIONAL_READINESS_GATE_IMAGE_DIGEST_MISMATCH: {gate_name}")
            report_sha256 = str(gate.get("report_sha256", ""))
            if not is_content_addressed_uri(gate.get("evidence_uri"), report_sha256):
                errors.append(f"OPERATIONAL_READINESS_GATE_URI_NOT_CONTENT_ADDRESSED: {gate_name}")
            completed_at = _timestamp(
                gate.get("completed_at"),
                field=f"gates.{gate_name}.completed_at",
                errors=errors,
            )
            issuer = gate.get("issuer")
            issued_at = _timestamp(
                issuer.get("issued_at") if isinstance(issuer, dict) else None,
                field=f"gates.{gate_name}.issuer.issued_at",
                errors=errors,
            )
            for field, timestamp in (("completed_at", completed_at), ("issued_at", issued_at)):
                if (
                    timestamp is not None
                    and generated_at is not None
                    and freshness_floor is not None
                    and not freshness_floor <= timestamp <= generated_at
                ):
                    errors.append(
                        f"OPERATIONAL_READINESS_GATE_TIMESTAMP_INVALID: {gate_name}.{field}"
                    )

    if errors:
        raise ValueError("\n".join(dict.fromkeys(errors)))

    readiness_sha256 = source_sha256 or canonical_sha256(evidence)
    return {
        "schema_version": "1.0",
        "release_id": expected_release_id,
        "git_sha": expected_git_sha,
        "image_digest": expected_image_digest,
        "operational_readiness_sha256": readiness_sha256,
        "signer_identity": expected_signer_identity,
        "signer_issuer": expected_signer_issuer,
        "training_populations": sorted(populations),
        "validated_gate_ids": sorted(gates) if isinstance(gates, dict) else [],
        "evidence_version_id": evidence_store["version_id"],
        "validated": True,
    }


def _same_https_origin(left: str, right: str) -> bool:
    left_url = urlsplit(left)
    right_url = urlsplit(right)
    return (
        left_url.scheme == right_url.scheme == "https"
        and left_url.hostname == right_url.hostname
        and (left_url.port or 443) == (right_url.port or 443)
    )


def is_content_addressed_uri(uri: object, digest: object) -> bool:
    if not isinstance(uri, str) or not isinstance(digest, str):
        return False
    try:
        parsed = urlsplit(uri)
        parsed_port = parsed.port
    except ValueError:
        return False
    terminal = parsed.path.rstrip("/").rsplit("/", 1)[-1]
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and (parsed_port is None or parsed_port > 0)
        and not parsed.query
        and not parsed.fragment
        and terminal == digest
    )


def _read_bounded_chunks(chunks: Iterable[bytes], maximum_bytes: int) -> bytes:
    payload = bytearray()
    for chunk in chunks:
        if len(chunk) > maximum_bytes - len(payload):
            raise _PayloadTooLarge
        payload.extend(chunk)
    return bytes(payload)


def _read_bounded_file(path: Path, maximum_bytes: int) -> bytes:
    if path.stat().st_size > maximum_bytes:
        raise _PayloadTooLarge
    with path.open("rb") as handle:
        return _read_bounded_chunks(
            iter(lambda: handle.read(64 * 1024), b""),
            maximum_bytes,
        )


def _fetch_bounded_json(
    client: httpx.Client,
    uri: str,
    *,
    bearer_token: str | None,
    maximum_bytes: int,
) -> bytes:
    with client.stream(
        "GET",
        uri,
        headers={"Authorization": f"Bearer {bearer_token}"},
        follow_redirects=False,
    ) as response:
        response.raise_for_status()
        content_type = response.headers.get("content-type", "").lower()
        if "application/json" not in content_type:
            raise _ContentTypeInvalid
        content_length = response.headers.get("content-length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError:
                declared_length = 0
            if declared_length > maximum_bytes:
                raise _PayloadTooLarge
        return _read_bounded_chunks(response.iter_bytes(), maximum_bytes)


def _report_timestamp(
    value: object,
    *,
    field: str,
    gate_name: str,
    errors: list[str],
) -> datetime | None:
    if not isinstance(value, str):
        errors.append(f"OPERATIONAL_GATE_REPORT_TIMESTAMP_INVALID: {gate_name}.{field}")
        return None
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"OPERATIONAL_GATE_REPORT_TIMESTAMP_INVALID: {gate_name}.{field}")
        return None
    if timestamp.tzinfo is None:
        errors.append(f"OPERATIONAL_GATE_REPORT_TIMESTAMP_TIMEZONE_MISSING: {gate_name}.{field}")
        return None
    return timestamp


def _policy_value_matches(actual: object, expected: object) -> bool:
    if isinstance(expected, bool):
        return isinstance(actual, bool) and actual is expected
    if isinstance(expected, (int, float)):
        return _is_finite_number(actual) and _is_finite_number(expected) and actual == expected
    return type(actual) is type(expected) and actual == expected


def _threshold_passes(observed: object, comparison: str, threshold: object) -> bool:
    if comparison == "eq":
        return _policy_value_matches(observed, threshold)
    if (
        comparison in {"lte", "gte"}
        and _is_finite_number(observed)
        and _is_finite_number(threshold)
    ):
        return observed <= threshold if comparison == "lte" else observed >= threshold
    return False


def _derive_machine_measurement(
    *,
    gate_name: str,
    check_id: str,
    comparison: str,
    threshold: object,
    measurement: object,
    errors: list[str],
) -> bool | int | float | None:
    if not isinstance(measurement, dict):
        errors.append(f"OPERATIONAL_GATE_RAW_MEASUREMENT_REQUIRED: {gate_name}.{check_id}")
        return None
    raw_samples = measurement.get("samples")
    if not isinstance(raw_samples, list):
        errors.append(f"OPERATIONAL_GATE_RAW_SAMPLES_REQUIRED: {gate_name}.{check_id}")
        return None
    samples: list[object] = raw_samples

    if isinstance(threshold, bool):
        if not samples or any(type(sample) is not bool for sample in samples):
            errors.append(f"OPERATIONAL_GATE_RAW_BOOLEAN_SAMPLES_INVALID: {gate_name}.{check_id}")
            return None
        return all(sample is True for sample in samples)

    if (gate_name, check_id) in RAW_COUNT_SAMPLE_CHECKS:
        if any(not isinstance(sample, str) or not sample for sample in samples):
            errors.append(f"OPERATIONAL_GATE_RAW_COUNT_SAMPLES_INVALID: {gate_name}.{check_id}")
            return None
        sample_ids = [str(sample) for sample in samples]
        if len(sample_ids) != len(set(sample_ids)):
            errors.append(f"OPERATIONAL_GATE_RAW_COUNT_SAMPLES_DUPLICATED: {gate_name}.{check_id}")
            return None
        return len(sample_ids)

    numeric_samples = [sample for sample in samples if _is_finite_number(sample)]
    if len(numeric_samples) != len(samples) or not numeric_samples:
        errors.append(f"OPERATIONAL_GATE_RAW_NUMERIC_SAMPLES_INVALID: {gate_name}.{check_id}")
        return None
    if comparison == "lte":
        return max(numeric_samples)
    if comparison == "gte":
        return min(numeric_samples)
    errors.append(f"OPERATIONAL_GATE_RAW_REDUCER_UNSUPPORTED: {gate_name}.{check_id}")
    return None


def _validate_machine_raw_evidence(
    raw_evidence: JsonObject,
    raw_schema: JsonObject,
    *,
    gate_name: str,
    report: JsonObject,
    expected_release_id: str,
    expected_git_sha: str,
    expected_image_digest: str,
    maximum_age_seconds: int,
    errors: list[str],
) -> None:
    validator = Draft202012Validator(raw_schema, format_checker=FormatChecker())
    for error in sorted(validator.iter_errors(raw_evidence), key=lambda item: list(item.path)):
        location = ".".join(str(part) for part in error.path) or "$"
        errors.append(
            f"OPERATIONAL_GATE_RAW_EVIDENCE_SCHEMA_INVALID: {gate_name}.{location}: {error.message}"
        )

    expected_environment = GATE_SCOPE_POLICIES[gate_name][0]
    expected_fields = {
        "gate_id": gate_name,
        "release_id": expected_release_id,
        "git_sha": expected_git_sha,
        "image_digest": expected_image_digest,
        "environment": expected_environment,
    }
    for field, expected in expected_fields.items():
        if raw_evidence.get(field) != expected:
            errors.append(f"OPERATIONAL_GATE_RAW_EVIDENCE_{field.upper()}_MISMATCH: {gate_name}")

    captured_at = _report_timestamp(
        raw_evidence.get("captured_at"),
        field="raw_evidence.captured_at",
        gate_name=gate_name,
        errors=errors,
    )
    now = datetime.now(UTC)
    if captured_at is not None:
        age_seconds = (now - captured_at).total_seconds()
        if age_seconds < -300:
            errors.append(f"OPERATIONAL_GATE_RAW_EVIDENCE_GENERATED_IN_FUTURE: {gate_name}")
        elif age_seconds > maximum_age_seconds:
            errors.append(f"OPERATIONAL_GATE_RAW_EVIDENCE_EXPIRED: {gate_name}")
        started_at = _report_timestamp(
            report.get("started_at"), field="started_at", gate_name=gate_name, errors=errors
        )
        generated_at = _report_timestamp(
            report.get("generated_at"), field="generated_at", gate_name=gate_name, errors=errors
        )
        if (
            started_at is not None
            and generated_at is not None
            and not started_at <= captured_at <= generated_at
        ):
            errors.append(f"OPERATIONAL_GATE_RAW_EVIDENCE_TIMELINE_INVALID: {gate_name}")

    raw_measurements = raw_evidence.get("measurements")
    measurements = raw_measurements if isinstance(raw_measurements, dict) else {}
    policies = GATE_CHECK_POLICIES[gate_name]
    actual_measurement_ids = set(str(key) for key in measurements)
    missing = sorted(set(policies) - actual_measurement_ids)
    unexpected = sorted(actual_measurement_ids - set(policies))
    if missing:
        errors.append(f"OPERATIONAL_GATE_RAW_MEASUREMENTS_MISSING: {gate_name}: {missing}")
    if unexpected:
        errors.append(f"OPERATIONAL_GATE_RAW_MEASUREMENTS_UNEXPECTED: {gate_name}: {unexpected}")

    raw_checks = report.get("checks")
    checks = raw_checks if isinstance(raw_checks, list) else []
    reported_observed = {
        str(check.get("id")): check.get("observed") for check in checks if isinstance(check, dict)
    }
    for check_id, (comparison, threshold) in policies.items():
        if check_id not in measurements:
            continue
        derived = _derive_machine_measurement(
            gate_name=gate_name,
            check_id=check_id,
            comparison=comparison,
            threshold=threshold,
            measurement=measurements[check_id],
            errors=errors,
        )
        if derived is None:
            continue
        if not _threshold_passes(derived, comparison, threshold):
            errors.append(f"OPERATIONAL_GATE_RAW_THRESHOLD_FAILED: {gate_name}.{check_id}")
        if not _policy_value_matches(reported_observed.get(check_id), derived):
            errors.append(f"OPERATIONAL_GATE_RAW_DERIVED_CHECK_MISMATCH: {gate_name}.{check_id}")


def _validate_gate_raw_evidence_reference(
    report: JsonObject,
    raw_schema: JsonObject,
    *,
    gate_name: str,
    gate_report_uri: str,
    expected_release_id: str,
    expected_git_sha: str,
    expected_image_digest: str,
    report_directory: Path | None,
    client: httpx.Client | None,
    bearer_token: str | None,
    maximum_report_bytes: int,
    maximum_age_seconds: int,
    errors: list[str],
) -> JsonObject | None:
    reference = report.get("raw_evidence")
    if not isinstance(reference, dict):
        errors.append(f"OPERATIONAL_GATE_RAW_EVIDENCE_REFERENCE_REQUIRED: {gate_name}")
        return None
    raw_uri = str(reference.get("uri", ""))
    expected_digest = str(reference.get("sha256", ""))
    digest_hex = expected_digest.removeprefix("sha256:")
    origin_matches = _same_https_origin(gate_report_uri, raw_uri)
    if not origin_matches:
        errors.append(f"OPERATIONAL_GATE_RAW_EVIDENCE_ORIGIN_MISMATCH: {gate_name}")
    if report_directory is None and not origin_matches:
        return None
    if not _is_capacity_sha256(digest_hex):
        errors.append(f"OPERATIONAL_GATE_RAW_EVIDENCE_DIGEST_INVALID: {gate_name}")
        return None
    if not is_content_addressed_uri(raw_uri, expected_digest):
        errors.append(f"OPERATIONAL_GATE_RAW_EVIDENCE_URI_NOT_CONTENT_ADDRESSED: {gate_name}")
        return None

    payload: bytes
    if report_directory is not None:
        raw_path = report_directory / f"{digest_hex}.json"
        try:
            payload = _read_bounded_file(raw_path, maximum_report_bytes)
        except _PayloadTooLarge:
            errors.append(f"OPERATIONAL_GATE_RAW_EVIDENCE_TOO_LARGE: {gate_name}")
            return None
        except OSError as exc:
            errors.append(
                f"OPERATIONAL_GATE_RAW_EVIDENCE_READ_FAILED: {gate_name}: {type(exc).__name__}"
            )
            return None
    else:
        if client is None:
            raise RuntimeError("OPERATIONAL_GATE_REPORT_CLIENT_REQUIRED")
        try:
            payload = _fetch_bounded_json(
                client,
                raw_uri,
                bearer_token=bearer_token,
                maximum_bytes=maximum_report_bytes,
            )
        except _PayloadTooLarge:
            errors.append(f"OPERATIONAL_GATE_RAW_EVIDENCE_TOO_LARGE: {gate_name}")
            return None
        except _ContentTypeInvalid:
            errors.append(f"OPERATIONAL_GATE_RAW_EVIDENCE_CONTENT_TYPE_INVALID: {gate_name}")
            return None
        except httpx.HTTPError as exc:
            errors.append(
                f"OPERATIONAL_GATE_RAW_EVIDENCE_FETCH_FAILED: {gate_name}: {type(exc).__name__}"
            )
            return None
    actual_digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    if actual_digest != expected_digest:
        errors.append(f"OPERATIONAL_GATE_RAW_EVIDENCE_DIGEST_MISMATCH: {gate_name}")
        return None
    try:
        raw_evidence = _strict_json_loads(payload)
    except _NonFiniteJsonError:
        errors.append(f"OPERATIONAL_GATE_RAW_EVIDENCE_JSON_NON_FINITE: {gate_name}")
        return None
    except (UnicodeDecodeError, json.JSONDecodeError):
        errors.append(f"OPERATIONAL_GATE_RAW_EVIDENCE_JSON_INVALID: {gate_name}")
        return None
    if not isinstance(raw_evidence, dict):
        errors.append(f"OPERATIONAL_GATE_RAW_EVIDENCE_OBJECT_REQUIRED: {gate_name}")
        return None
    _validate_machine_raw_evidence(
        raw_evidence,
        raw_schema,
        gate_name=gate_name,
        report=report,
        expected_release_id=expected_release_id,
        expected_git_sha=expected_git_sha,
        expected_image_digest=expected_image_digest,
        maximum_age_seconds=maximum_age_seconds,
        errors=errors,
    )
    return {"uri": raw_uri, "sha256": actual_digest}


def _validate_gate_scope(
    *,
    report: JsonObject,
    gate_name: str,
    expected_release_id: str,
    expected_image_digest: str,
    errors: list[str],
) -> None:
    scope = report.get("scope")
    if not isinstance(scope, dict):
        errors.append(f"OPERATIONAL_GATE_REPORT_SCOPE_REQUIRED: {gate_name}")
        return
    policy = GATE_SCOPE_POLICIES.get(gate_name)
    if policy is None:
        errors.append(f"OPERATIONAL_GATE_REPORT_SCOPE_POLICY_MISSING: {gate_name}")
        return
    expected_environment, required_asset_types = policy
    if scope.get("environment") != expected_environment:
        errors.append(f"OPERATIONAL_GATE_REPORT_ENVIRONMENT_MISMATCH: {gate_name}")
    expected_release_asset_id = f"{expected_release_id}@{expected_image_digest}"
    if scope.get("release_asset_id") != expected_release_asset_id:
        errors.append(f"OPERATIONAL_GATE_REPORT_RELEASE_ASSET_MISMATCH: {gate_name}")

    raw_assets = scope.get("assets")
    assets = raw_assets if isinstance(raw_assets, list) else []
    asset_rows = [row for row in assets if isinstance(row, dict)]
    asset_ids = [str(row.get("asset_id")) for row in asset_rows]
    if len(asset_ids) != len(set(asset_ids)):
        errors.append(f"OPERATIONAL_GATE_REPORT_ASSET_IDS_DUPLICATED: {gate_name}")
    actual_asset_types = {str(row.get("asset_type")) for row in asset_rows}
    missing_asset_types = sorted(required_asset_types - actual_asset_types)
    if missing_asset_types:
        errors.append(
            f"OPERATIONAL_GATE_REPORT_ASSET_TYPES_MISSING: {gate_name}: {missing_asset_types}"
        )


def _validate_disaster_recovery_drills(
    *,
    report: JsonObject,
    completed_at: datetime | None,
    gate_name: str,
    errors: list[str],
) -> None:
    drills = report.get("drills")
    if not isinstance(drills, list):
        errors.append("OPERATIONAL_GATE_REPORT_DRILLS_REQUIRED: disaster_recovery")
        return
    drill_rows = [row for row in drills if isinstance(row, dict)]
    drill_types = [str(row.get("drill_type")) for row in drill_rows]
    if len(drill_types) != len(set(drill_types)):
        errors.append("OPERATIONAL_GATE_REPORT_DRILL_TYPES_DUPLICATED: disaster_recovery")
    missing = sorted(set(DRILL_POLICIES) - set(drill_types))
    unexpected = sorted(set(drill_types) - set(DRILL_POLICIES))
    if missing:
        errors.append(f"OPERATIONAL_GATE_REPORT_DRILLS_MISSING: {missing}")
    if unexpected:
        errors.append(f"OPERATIONAL_GATE_REPORT_DRILLS_UNEXPECTED: {unexpected}")

    scope = report.get("scope")
    if not isinstance(scope, dict):
        scope = {}
    raw_scope_assets = scope.get("assets")
    scope_assets = raw_scope_assets if isinstance(raw_scope_assets, list) else []
    scope_assets_by_id = {
        str(asset.get("asset_id")): str(asset.get("asset_type"))
        for asset in scope_assets
        if isinstance(asset, dict)
    }
    raw_scope_backup_ids = scope.get("backup_ids")
    scope_backup_ids = (
        {str(value) for value in raw_scope_backup_ids}
        if isinstance(raw_scope_backup_ids, list)
        else set()
    )
    raw_scope_regions = scope.get("regions")
    scope_regions = (
        {str(value) for value in raw_scope_regions}
        if isinstance(raw_scope_regions, list)
        else set()
    )
    if not scope_backup_ids:
        errors.append("OPERATIONAL_GATE_REPORT_BACKUP_IDS_REQUIRED: disaster_recovery")

    exercised_asset_ids: set[str] = set()
    exercised_backup_ids: set[str] = set()
    exercised_regions: set[str] = set()
    for index, drill in enumerate(drill_rows):
        drill_type = str(drill.get("drill_type"))
        policy = DRILL_POLICIES.get(drill_type)
        if policy is None:
            continue
        maximum_age, maximum_rpo, maximum_rto, expected_asset_types, minimum_regions = policy
        drill_completed_at = _report_timestamp(
            drill.get("completed_at"),
            field=f"drills.{index}.completed_at",
            gate_name=gate_name,
            errors=errors,
        )
        if completed_at is not None and drill_completed_at is not None:
            age = completed_at - drill_completed_at
            if age < timedelta(0):
                errors.append(f"OPERATIONAL_GATE_REPORT_DRILL_IN_FUTURE: {drill_type}")
            elif age > maximum_age:
                errors.append(f"OPERATIONAL_GATE_REPORT_DRILL_STALE: {drill_type}")
        observed_rpo = drill.get("observed_rpo_minutes")
        observed_rto = drill.get("observed_rto_minutes")
        if not _threshold_passes(observed_rpo, "lte", maximum_rpo):
            errors.append(f"OPERATIONAL_GATE_REPORT_DRILL_RPO_FAILED: {drill_type}")
        if not _threshold_passes(observed_rto, "lte", maximum_rto):
            errors.append(f"OPERATIONAL_GATE_REPORT_DRILL_RTO_FAILED: {drill_type}")

        raw_asset_types = drill.get("asset_types")
        drill_asset_types = (
            {str(value) for value in raw_asset_types}
            if isinstance(raw_asset_types, list)
            else set()
        )
        if drill_asset_types != expected_asset_types:
            errors.append(f"OPERATIONAL_GATE_REPORT_DRILL_ASSET_TYPES_MISMATCH: {drill_type}")
        raw_asset_ids = drill.get("asset_ids")
        drill_asset_ids = (
            {str(value) for value in raw_asset_ids} if isinstance(raw_asset_ids, list) else set()
        )
        actual_asset_types = {
            scope_assets_by_id[asset_id]
            for asset_id in drill_asset_ids
            if asset_id in scope_assets_by_id
        }
        if not drill_asset_ids.issubset(scope_assets_by_id) or (
            actual_asset_types != expected_asset_types
        ):
            errors.append(f"OPERATIONAL_GATE_REPORT_DRILL_ASSETS_OUT_OF_SCOPE: {drill_type}")
        raw_backup_ids = drill.get("backup_ids")
        drill_backup_ids = (
            {str(value) for value in raw_backup_ids} if isinstance(raw_backup_ids, list) else set()
        )
        if not drill_backup_ids.issubset(scope_backup_ids):
            errors.append(f"OPERATIONAL_GATE_REPORT_DRILL_BACKUPS_OUT_OF_SCOPE: {drill_type}")
        raw_regions = drill.get("regions")
        drill_regions = (
            {str(value) for value in raw_regions} if isinstance(raw_regions, list) else set()
        )
        if len(drill_regions) < minimum_regions:
            errors.append(f"OPERATIONAL_GATE_REPORT_DRILL_REGIONS_INSUFFICIENT: {drill_type}")
        if not drill_regions.issubset(scope_regions):
            errors.append(f"OPERATIONAL_GATE_REPORT_DRILL_REGIONS_OUT_OF_SCOPE: {drill_type}")
        exercised_asset_ids.update(drill_asset_ids)
        exercised_backup_ids.update(drill_backup_ids)
        exercised_regions.update(drill_regions)

    if exercised_asset_ids != set(scope_assets_by_id):
        errors.append("OPERATIONAL_GATE_REPORT_DRILL_ASSET_COVERAGE_INCOMPLETE")
    if exercised_backup_ids != scope_backup_ids:
        errors.append("OPERATIONAL_GATE_REPORT_DRILL_BACKUP_COVERAGE_INCOMPLETE")
    if exercised_regions != scope_regions:
        errors.append("OPERATIONAL_GATE_REPORT_DRILL_REGION_COVERAGE_INCOMPLETE")


def _validate_fault_matrix(
    *,
    report: JsonObject,
    started_at: datetime | None,
    completed_at: datetime | None,
    gate_name: str,
    errors: list[str],
) -> None:
    matrix = report.get("fault_matrix")
    if not isinstance(matrix, list):
        errors.append("OPERATIONAL_GATE_REPORT_FAULT_MATRIX_REQUIRED: fault_injection")
        return
    rows = [row for row in matrix if isinstance(row, dict)]
    components = [str(row.get("component")) for row in rows]
    if len(components) != len(set(components)):
        errors.append("OPERATIONAL_GATE_REPORT_FAULT_COMPONENTS_DUPLICATED: fault_injection")
    missing = sorted(set(REQUIRED_FAULT_OUTCOMES) - set(components))
    unexpected = sorted(set(components) - set(REQUIRED_FAULT_OUTCOMES))
    if missing:
        errors.append(f"OPERATIONAL_GATE_REPORT_FAULT_COMPONENTS_MISSING: {missing}")
    if unexpected:
        errors.append(f"OPERATIONAL_GATE_REPORT_FAULT_COMPONENTS_UNEXPECTED: {unexpected}")

    for index, row in enumerate(rows):
        component = str(row.get("component"))
        expected_outcome = REQUIRED_FAULT_OUTCOMES.get(component)
        if expected_outcome is None:
            continue
        if row.get("outcome") != expected_outcome:
            errors.append(f"OPERATIONAL_GATE_REPORT_FAULT_OUTCOME_MISMATCH: {component}")
        fault_completed_at = _report_timestamp(
            row.get("completed_at"),
            field=f"fault_matrix.{index}.completed_at",
            gate_name=gate_name,
            errors=errors,
        )
        if (
            fault_completed_at is not None
            and started_at is not None
            and fault_completed_at < started_at
        ) or (
            fault_completed_at is not None
            and completed_at is not None
            and fault_completed_at > completed_at
        ):
            errors.append(f"OPERATIONAL_GATE_REPORT_FAULT_TIMESTAMP_OUTSIDE_RUN: {component}")


CAPACITY_MIB = 1024 * 1024
CAPACITY_MAX_SERVER_CHUNK_BYTES = 8 * CAPACITY_MIB
REQUIRED_CAPACITY_SCENARIOS = frozenset(
    {
        "ten_x_burst_one_minute",
        "one_hundred_concurrent_long_runs",
        "tool_p95_five_x",
        "persistent_429",
        "artifact_streaming_50_to_200_mib",
        "pending_approval_backlog_at_least_one_thousand",
    }
)


def _capacity_int(value: object) -> int | None:
    return value if type(value) is int else None


def _capacity_number(value: object) -> float | None:
    if _is_finite_number(value):
        return float(value)
    return None


def _capacity_mapping(value: object) -> JsonObject:
    return value if isinstance(value, dict) else {}


def _capacity_statuses(value: object) -> dict[str, int] | None:
    if not isinstance(value, dict):
        return None
    statuses: dict[str, int] = {}
    for key, count in value.items():
        if not isinstance(key, str) or type(count) is not int or count < 0:
            return None
        statuses[key] = count
    return statuses


def _is_capacity_sha256(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(character in "0123456789abcdef" for character in value)


def _capacity_scenario_common(
    scenario: JsonObject,
    *,
    name: str,
    errors: list[str],
) -> tuple[int | None, dict[str, int] | None, bool]:
    requests = _capacity_int(scenario.get("requests"))
    statuses = _capacity_statuses(scenario.get("statuses"))
    valid = (
        scenario.get("name") == name
        and scenario.get("passed") is True
        and requests is not None
        and requests > 0
        and statuses is not None
        and sum(statuses.values()) == requests
    )
    if not valid:
        errors.append(f"OPERATIONAL_CAPACITY_SCENARIO_INVALID: {name}")
    return requests, statuses, valid


def _validate_capacity_artifacts(
    scenario: JsonObject,
    *,
    errors: list[str],
) -> int | None:
    requests, statuses, common_valid = _capacity_scenario_common(
        scenario,
        name="artifact_streaming_50_to_200_mib",
        errors=errors,
    )
    evidence = _capacity_mapping(scenario.get("evidence"))
    raw_sizes = evidence.get("sizes_bytes")
    sizes = raw_sizes if isinstance(raw_sizes, list) else []
    expected_sizes = [50 * CAPACITY_MIB, 200 * CAPACITY_MIB]
    size_values_valid = all(_capacity_int(value) is not None for value in sizes)
    size_contract_valid = size_values_valid and sorted(sizes) == expected_sizes
    client_chunk = _capacity_int(evidence.get("client_chunk_bytes"))
    declared_server_limit = _capacity_int(evidence.get("maximum_server_request_chunk_bytes"))
    scenario_valid = (
        common_valid
        and requests == 2
        and statuses == {"201": 2}
        and size_contract_valid
        and client_chunk is not None
        and 0 < client_chunk <= CAPACITY_MAX_SERVER_CHUNK_BYTES
        and declared_server_limit is not None
        and 0 < declared_server_limit <= CAPACITY_MAX_SERVER_CHUNK_BYTES
    )
    if not scenario_valid:
        errors.append("OPERATIONAL_CAPACITY_ARTIFACT_SCENARIO_INVALID")

    raw_observations = evidence.get("server_observations")
    observations = raw_observations if isinstance(raw_observations, list) else []
    observation_rows = [row for row in observations if isinstance(row, dict)]
    by_size = {
        row.get("size_bytes"): row
        for row in observation_rows
        if _capacity_int(row.get("size_bytes")) is not None
    }
    if len(observation_rows) != 2 or set(by_size) != set(expected_sizes):
        errors.append("OPERATIONAL_CAPACITY_ARTIFACT_SERVER_OBSERVATIONS_INCOMPLETE")
        return None

    observations_valid = True
    for size in expected_sizes:
        observation = by_size[size]
        digest = observation.get("sha256")
        transport = _capacity_mapping(observation.get("server_transport"))
        request_size = _capacity_int(transport.get("request_size_bytes"))
        chunk_count = _capacity_int(transport.get("chunk_count"))
        max_chunk = _capacity_int(transport.get("max_request_chunk_bytes"))
        chunk_evidence_valid = (
            chunk_count is not None
            and chunk_count >= 2
            and max_chunk is not None
            and 0 < max_chunk <= CAPACITY_MAX_SERVER_CHUNK_BYTES
            and max_chunk < size
            and chunk_count * max_chunk >= size
            and declared_server_limit is not None
            and max_chunk <= declared_server_limit
        )
        if not chunk_evidence_valid:
            errors.append(f"OPERATIONAL_CAPACITY_ARTIFACT_SERVER_CHUNKS_INVALID: {size}")
            observations_valid = False
        provenance_valid = (
            observation.get("passed") is True
            and isinstance(observation.get("artifact_id"), str)
            and bool(observation.get("artifact_id"))
            and observation.get("size_bytes") == size
            and _is_capacity_sha256(digest)
            and observation.get("scan_status") == "malware_clean"
            and isinstance(observation.get("object_version_id"), str)
            and bool(observation.get("object_version_id"))
            and transport.get("mode") == "request-stream-to-file"
            and request_size == size
            and transport.get("request_sha256") == digest
        )
        if not provenance_valid:
            errors.append(f"OPERATIONAL_CAPACITY_ARTIFACT_SERVER_OBSERVATION_INVALID: {size}")
            observations_valid = False
    return 200 if scenario_valid and observations_valid else None


def _capacity_raw_json_sha256(raw_json: str) -> str:
    return "sha256:" + hashlib.sha256(raw_json.encode("utf-8")).hexdigest()


def _capacity_content_addressed_payload(asset: object) -> JsonObject | None:
    if not isinstance(asset, dict):
        return None
    raw_json = asset.get("raw_json")
    digest = asset.get("sha256")
    if (
        not isinstance(raw_json, str)
        or not isinstance(digest, str)
        or not _is_capacity_sha256(digest.removeprefix("sha256:"))
        or digest != _capacity_raw_json_sha256(raw_json)
        or not is_content_addressed_uri(asset.get("content_uri"), digest)
    ):
        return None
    try:
        payload = _strict_json_loads(raw_json)
    except (_NonFiniteJsonError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _capacity_string_set(value: object) -> set[str] | None:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        return None
    values = set(value)
    return values if len(values) == len(value) else None


def _capacity_utc_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _derive_pending_control_checks(
    document: object,
    *,
    expected_release_id: str,
    expected_git_sha: str,
    expected_image_digest: str,
    manifest_sha256: str,
    action_ids: set[str],
    run_ids: set[str],
    workflow_ids: set[str],
) -> dict[str, bool]:
    result = {
        "notification_delivery_verified": False,
        "expiry_processing_verified": False,
        "resource_leak_free_verified": False,
    }
    root_payload = document if isinstance(document, dict) else None
    if root_payload is None:
        return result
    if (
        root_payload.get("schema_version") != "1.0"
        or root_payload.get("release_id") != expected_release_id
        or root_payload.get("git_sha") != expected_git_sha
        or root_payload.get("image_digest") != expected_image_digest
        or root_payload.get("manifest_sha256") != manifest_sha256
    ):
        return result
    scope = root_payload.get("scope")
    if not isinstance(scope, dict):
        return result
    scoped_action_ids = _capacity_string_set(scope.get("action_ids"))
    scoped_run_ids = _capacity_string_set(scope.get("run_ids"))
    scoped_workflow_ids = _capacity_string_set(scope.get("workflow_ids"))
    expiry_probe_action_ids = _capacity_string_set(scope.get("expiry_probe_action_ids"))
    if (
        scoped_action_ids != action_ids
        or scoped_run_ids != run_ids
        or scoped_workflow_ids != workflow_ids
        or not expiry_probe_action_ids
        or not expiry_probe_action_ids.issubset(action_ids)
    ):
        return result

    notification_payload = _capacity_content_addressed_payload(root_payload.get("notifications"))
    if notification_payload is not None:
        raw_receipts = notification_payload.get("receipts")
        receipts = raw_receipts if isinstance(raw_receipts, list) else []
        receipt_rows = [receipt for receipt in receipts if isinstance(receipt, dict)]
        delivered_action_ids = {
            str(receipt.get("action_id"))
            for receipt in receipt_rows
            if receipt.get("delivered") is True
        }
        receipt_ids = [receipt.get("receipt_id") for receipt in receipt_rows]
        timestamps_valid = all(
            _capacity_utc_timestamp(receipt.get("delivered_at")) is not None
            for receipt in receipt_rows
        )
        result["notification_delivery_verified"] = (
            len(receipt_rows) == len(receipts) == len(action_ids)
            and delivered_action_ids == action_ids
            and all(isinstance(receipt_id, str) and receipt_id for receipt_id in receipt_ids)
            and len(receipt_ids) == len(set(receipt_ids))
            and timestamps_valid
        )

    expiry_payload = _capacity_content_addressed_payload(root_payload.get("expiry"))
    if expiry_payload is not None:
        raw_observations = expiry_payload.get("observations")
        observations = raw_observations if isinstance(raw_observations, list) else []
        observation_rows = [row for row in observations if isinstance(row, dict)]
        observed_expired_ids = {
            str(row.get("action_id"))
            for row in observation_rows
            if row.get("status") == "expired"
            and _capacity_utc_timestamp(row.get("observed_at")) is not None
        }
        result["expiry_processing_verified"] = (
            len(observation_rows) == len(observations) == len(expiry_probe_action_ids)
            and observed_expired_ids == expiry_probe_action_ids
        )

    resource_payload = _capacity_content_addressed_payload(root_payload.get("resources"))
    if resource_payload is not None:
        closed_workflow_ids = _capacity_string_set(resource_payload.get("closed_workflow_ids"))
        open_workflow_ids = _capacity_string_set(resource_payload.get("open_workflow_ids"))
        backlog_before = _capacity_int(resource_payload.get("task_queue_backlog_before"))
        backlog_after = _capacity_int(resource_payload.get("task_queue_backlog_after"))
        active_before = _capacity_int(resource_payload.get("active_slots_before"))
        active_after = _capacity_int(resource_payload.get("active_slots_after"))
        bounded_counts = (
            backlog_before is not None
            and backlog_after is not None
            and active_before is not None
            and active_after is not None
            and 0 <= backlog_after <= backlog_before
            and 0 <= active_after <= active_before
        )
        result["resource_leak_free_verified"] = (
            closed_workflow_ids == workflow_ids
            and open_workflow_ids == set()
            and bounded_counts
            and _capacity_utc_timestamp(resource_payload.get("observed_at")) is not None
        )
    return result


def _validate_capacity_raw_report(
    raw_report: JsonObject,
    *,
    expected_release_id: str,
    expected_git_sha: str,
    expected_image_digest: str,
    maximum_age_seconds: int,
    errors: list[str],
) -> dict[str, bool | int | float]:
    if raw_report.get("schema_version") != "1.0":
        errors.append("OPERATIONAL_CAPACITY_RAW_REPORT_SCHEMA_VERSION_MISMATCH")
    if raw_report.get("release_id") != expected_release_id:
        errors.append("OPERATIONAL_CAPACITY_RAW_REPORT_RELEASE_ID_MISMATCH")
    if raw_report.get("git_sha") != expected_git_sha:
        errors.append("OPERATIONAL_CAPACITY_RAW_REPORT_GIT_SHA_MISMATCH")
    if raw_report.get("image_digest") != expected_image_digest:
        errors.append("OPERATIONAL_CAPACITY_RAW_REPORT_IMAGE_DIGEST_MISMATCH")
    if raw_report.get("environment") != "staging":
        errors.append("OPERATIONAL_CAPACITY_RAW_REPORT_ENVIRONMENT_MISMATCH")
    if raw_report.get("passed") is not True:
        errors.append("OPERATIONAL_CAPACITY_RAW_REPORT_NOT_PASSED")

    base_url = urlsplit(str(raw_report.get("base_url_origin", "")))
    if (
        base_url.scheme != "https"
        or not base_url.hostname
        or base_url.username is not None
        or base_url.password is not None
        or base_url.path not in {"", "/"}
        or base_url.query
        or base_url.fragment
    ):
        errors.append("OPERATIONAL_CAPACITY_RAW_REPORT_BASE_URL_INVALID")

    generated_at = _capacity_int(raw_report.get("generated_at_unix"))
    if generated_at is None:
        errors.append("OPERATIONAL_CAPACITY_RAW_REPORT_TIMESTAMP_INVALID")
    else:
        age_seconds = datetime.now(UTC).timestamp() - generated_at
        if age_seconds < -300:
            errors.append("OPERATIONAL_CAPACITY_RAW_REPORT_GENERATED_IN_FUTURE")
        elif age_seconds > maximum_age_seconds:
            errors.append("OPERATIONAL_CAPACITY_RAW_REPORT_EXPIRED")

    raw_scenarios = raw_report.get("scenarios")
    scenario_values = raw_scenarios if isinstance(raw_scenarios, list) else []
    scenario_rows = [row for row in scenario_values if isinstance(row, dict)]
    names = [str(row.get("name")) for row in scenario_rows]
    if len(names) != len(set(names)):
        errors.append("OPERATIONAL_CAPACITY_RAW_REPORT_SCENARIOS_DUPLICATED")
    if len(scenario_rows) != len(REQUIRED_CAPACITY_SCENARIOS) or set(names) != set(
        REQUIRED_CAPACITY_SCENARIOS
    ):
        errors.append("OPERATIONAL_CAPACITY_RAW_REPORT_SCENARIOS_INCOMPLETE")
    scenarios = {str(row.get("name")): row for row in scenario_rows}
    derived: dict[str, bool | int | float] = {}

    burst = scenarios.get("ten_x_burst_one_minute", {})
    burst_requests, burst_statuses, burst_common = _capacity_scenario_common(
        burst,
        name="ten_x_burst_one_minute",
        errors=errors,
    )
    burst_evidence = _capacity_mapping(burst.get("evidence"))
    baseline_rps = _capacity_number(burst_evidence.get("baseline_rps"))
    offered_rps = _capacity_number(burst_evidence.get("offered_rps"))
    duration = _capacity_int(burst_evidence.get("duration_seconds"))
    controlled = _capacity_int(burst_evidence.get("controlled_admission_responses"))
    burst_multiplier = (
        offered_rps / baseline_rps
        if baseline_rps is not None and baseline_rps > 0 and offered_rps is not None
        else None
    )
    burst_valid = (
        burst_common
        and burst_requests is not None
        and burst_statuses is not None
        and set(burst_statuses).issubset({"202", "429", "503"})
        and duration is not None
        and duration >= 60
        and offered_rps is not None
        and burst_requests >= offered_rps * duration
        and controlled == burst_requests
        and burst_multiplier is not None
        and burst_multiplier >= 10
    )
    if burst_valid and burst_multiplier is not None:
        derived["burst_multiplier"] = round(burst_multiplier, 3)
    else:
        errors.append("OPERATIONAL_CAPACITY_BURST_SCENARIO_INVALID")

    long_runs = scenarios.get("one_hundred_concurrent_long_runs", {})
    long_requests, long_statuses, long_common = _capacity_scenario_common(
        long_runs,
        name="one_hundred_concurrent_long_runs",
        errors=errors,
    )
    long_evidence = _capacity_mapping(long_runs.get("evidence"))
    long_valid = (
        long_common
        and long_requests == 100
        and long_statuses == {"202": 100}
        and _capacity_int(long_evidence.get("accepted_runs")) == 100
        and _capacity_int(long_evidence.get("concurrency")) == 100
    )
    if long_valid:
        derived["long_runs"] = 100
    else:
        errors.append("OPERATIONAL_CAPACITY_LONG_RUN_SCENARIO_INVALID")

    tool = scenarios.get("tool_p95_five_x", {})
    tool_requests, tool_statuses, tool_common = _capacity_scenario_common(
        tool,
        name="tool_p95_five_x",
        errors=errors,
    )
    tool_evidence = _capacity_mapping(tool.get("evidence"))
    baseline_p95 = _capacity_number(tool_evidence.get("baseline_p95_seconds"))
    degraded_p95 = _capacity_number(tool_evidence.get("degraded_p95_seconds"))
    claimed_multiplier = _capacity_number(tool_evidence.get("observed_multiplier"))
    calculated_multiplier = (
        degraded_p95 / baseline_p95
        if baseline_p95 is not None and baseline_p95 > 0 and degraded_p95 is not None
        else None
    )
    tool_statuses_valid = tool_statuses is not None and all(
        status.isdigit() and int(status) < 500 for status in tool_statuses
    )
    tool_valid = (
        tool_common
        and tool_requests is not None
        and tool_requests >= 100
        and tool_statuses_valid
        and calculated_multiplier is not None
        and calculated_multiplier >= 5
        and claimed_multiplier is not None
        and abs(claimed_multiplier - calculated_multiplier) <= 0.001
    )
    if tool_valid and calculated_multiplier is not None:
        derived["tool_p95_multiplier"] = round(calculated_multiplier, 3)
    else:
        errors.append("OPERATIONAL_CAPACITY_TOOL_SCENARIO_INVALID")

    throttling = scenarios.get("persistent_429", {})
    throttling_requests, throttling_statuses, throttling_common = _capacity_scenario_common(
        throttling,
        name="persistent_429",
        errors=errors,
    )
    if throttling_requests is None or throttling_requests < 200:
        errors.append("OPERATIONAL_CAPACITY_429_SAMPLE_COUNT_INSUFFICIENT")
    throttling_valid = (
        throttling_common
        and throttling_requests is not None
        and throttling_requests >= 200
        and throttling_statuses == {"429": throttling_requests}
    )
    if throttling_valid:
        derived["sustained_429_passed"] = True
    else:
        errors.append("OPERATIONAL_CAPACITY_429_SCENARIO_INVALID")

    artifact_size_mb = _validate_capacity_artifacts(
        scenarios.get("artifact_streaming_50_to_200_mib", {}),
        errors=errors,
    )
    if artifact_size_mb is not None:
        derived["artifact_size_mb"] = artifact_size_mb

    approvals = scenarios.get("pending_approval_backlog_at_least_one_thousand", {})
    approval_requests, approval_statuses, approval_common = _capacity_scenario_common(
        approvals,
        name="pending_approval_backlog_at_least_one_thousand",
        errors=errors,
    )
    approval_evidence = _capacity_mapping(approvals.get("evidence"))
    pending_count = _capacity_int(approval_evidence.get("pending_approval_count"))
    unique_action_count = _capacity_int(approval_evidence.get("unique_action_count"))
    queried_run_count = _capacity_int(approval_evidence.get("queried_run_count"))
    pending_action_ids = _capacity_string_set(approval_evidence.get("pending_action_ids"))
    queried_run_ids = _capacity_string_set(approval_evidence.get("queried_run_ids"))
    workflow_ids = _capacity_string_set(approval_evidence.get("workflow_ids"))
    manifest_sha256 = str(approval_evidence.get("manifest_sha256", ""))
    manifest_digest_valid = _is_capacity_sha256(manifest_sha256.removeprefix("sha256:"))
    approvals_valid = (
        approval_common
        and approval_requests is not None
        and approval_statuses == {"200": approval_requests}
        and pending_count is not None
        and pending_count >= 1000
        and unique_action_count == pending_count
        and pending_action_ids is not None
        and len(pending_action_ids) == pending_count
        and queried_run_count is not None
        and queried_run_count > 0
        and queried_run_ids is not None
        and len(queried_run_ids) == queried_run_count
        and workflow_ids is not None
        and bool(workflow_ids)
        and manifest_digest_valid
        and approval_evidence.get("observed_status") == "pending_approval"
        and approval_evidence.get("status_query_verified") is True
    )
    if approvals_valid and pending_count is not None:
        derived["pending_approval_backlog"] = pending_count
    else:
        errors.append("OPERATIONAL_CAPACITY_PENDING_APPROVAL_BACKLOG_INVALID")

    control_raw_json = approval_evidence.get("operational_control_evidence_raw_json")
    control_sha256 = str(approval_evidence.get("operational_control_evidence_sha256", ""))
    control_uri = approval_evidence.get("operational_control_evidence_uri")
    control_document: object = None
    control_binding_valid = (
        isinstance(control_raw_json, str)
        and _is_capacity_sha256(control_sha256.removeprefix("sha256:"))
        and control_sha256 == _capacity_raw_json_sha256(control_raw_json)
        and is_content_addressed_uri(control_uri, control_sha256)
    )
    if control_binding_valid and isinstance(control_raw_json, str):
        try:
            control_document = _strict_json_loads(control_raw_json)
        except _NonFiniteJsonError:
            errors.append("OPERATIONAL_CAPACITY_CONTROL_EVIDENCE_JSON_NON_FINITE")
        except json.JSONDecodeError:
            errors.append("OPERATIONAL_CAPACITY_CONTROL_EVIDENCE_JSON_INVALID")
    else:
        errors.append("OPERATIONAL_CAPACITY_CONTROL_EVIDENCE_RAW_BYTES_UNBOUND")

    verified_controls = _derive_pending_control_checks(
        control_document,
        expected_release_id=expected_release_id,
        expected_git_sha=expected_git_sha,
        expected_image_digest=expected_image_digest,
        manifest_sha256=manifest_sha256,
        action_ids=pending_action_ids or set(),
        run_ids=queried_run_ids or set(),
        workflow_ids=workflow_ids or set(),
    )
    operational_controls = {
        "notification_delivery_verified": (
            "pending_approval_notifications_verified",
            "OPERATIONAL_CAPACITY_PENDING_APPROVAL_NOTIFICATIONS_UNVERIFIED",
        ),
        "expiry_processing_verified": (
            "pending_approval_expiry_verified",
            "OPERATIONAL_CAPACITY_PENDING_APPROVAL_EXPIRY_UNVERIFIED",
        ),
        "resource_leak_free_verified": (
            "pending_approval_no_resource_leak",
            "OPERATIONAL_CAPACITY_PENDING_APPROVAL_RESOURCE_LEAK_UNVERIFIED",
        ),
    }
    for evidence_field, (check_id, error_code) in operational_controls.items():
        verified = verified_controls[evidence_field]
        if approval_evidence.get(evidence_field) is not verified:
            errors.append(
                f"OPERATIONAL_CAPACITY_CONTROL_EVIDENCE_DERIVED_MISMATCH: {evidence_field}"
            )
        if verified:
            derived[check_id] = True
        else:
            errors.append(error_code)
    return derived


def _validate_capacity_gate_derivations(
    report: JsonObject,
    derived: dict[str, bool | int | float],
    *,
    errors: list[str],
) -> None:
    raw_checks = report.get("checks")
    checks = raw_checks if isinstance(raw_checks, list) else []
    observed_by_id = {
        str(check.get("id")): check.get("observed") for check in checks if isinstance(check, dict)
    }
    for check_id in GATE_CHECK_POLICIES["capacity"]:
        if check_id not in derived:
            errors.append(f"OPERATIONAL_CAPACITY_RAW_DERIVATION_MISSING: {check_id}")
            continue
        if not _policy_value_matches(observed_by_id.get(check_id), derived[check_id]):
            errors.append(f"OPERATIONAL_CAPACITY_GATE_DERIVED_CHECK_MISMATCH: {check_id}")


def _validate_capacity_raw_report_reference(
    report: JsonObject,
    *,
    gate_report_uri: str,
    expected_release_id: str,
    expected_git_sha: str,
    expected_image_digest: str,
    report_directory: Path | None,
    client: httpx.Client | None,
    bearer_token: str | None,
    maximum_report_bytes: int,
    maximum_age_seconds: int,
    errors: list[str],
) -> None:
    reference = report.get("raw_capacity_report")
    if not isinstance(reference, dict):
        errors.append("OPERATIONAL_CAPACITY_RAW_REPORT_REFERENCE_REQUIRED")
        return
    raw_uri = str(reference.get("uri", ""))
    expected_digest = str(reference.get("sha256", ""))
    digest_hex = expected_digest.removeprefix("sha256:")
    origin_matches = _same_https_origin(gate_report_uri, raw_uri)
    if not origin_matches:
        errors.append("OPERATIONAL_CAPACITY_RAW_REPORT_ORIGIN_MISMATCH")
    if report_directory is None and not origin_matches:
        return
    if not _is_capacity_sha256(digest_hex):
        errors.append("OPERATIONAL_CAPACITY_RAW_REPORT_DIGEST_INVALID")
        return
    if not is_content_addressed_uri(raw_uri, expected_digest):
        errors.append("OPERATIONAL_CAPACITY_RAW_REPORT_URI_NOT_CONTENT_ADDRESSED")
        return

    payload: bytes
    if report_directory is not None:
        raw_path = report_directory / f"{digest_hex}.json"
        try:
            payload = _read_bounded_file(raw_path, maximum_report_bytes)
        except _PayloadTooLarge:
            errors.append("OPERATIONAL_CAPACITY_RAW_REPORT_TOO_LARGE")
            return
        except OSError as exc:
            errors.append(f"OPERATIONAL_CAPACITY_RAW_REPORT_READ_FAILED: {type(exc).__name__}")
            return
    else:
        if client is None:
            raise RuntimeError("OPERATIONAL_GATE_REPORT_CLIENT_REQUIRED")
        try:
            payload = _fetch_bounded_json(
                client,
                raw_uri,
                bearer_token=bearer_token,
                maximum_bytes=maximum_report_bytes,
            )
        except _PayloadTooLarge:
            errors.append("OPERATIONAL_CAPACITY_RAW_REPORT_TOO_LARGE")
            return
        except _ContentTypeInvalid:
            errors.append("OPERATIONAL_CAPACITY_RAW_REPORT_CONTENT_TYPE_INVALID")
            return
        except httpx.HTTPError as exc:
            errors.append(f"OPERATIONAL_CAPACITY_RAW_REPORT_FETCH_FAILED: {type(exc).__name__}")
            return
    actual_digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    if actual_digest != expected_digest:
        errors.append("OPERATIONAL_CAPACITY_RAW_REPORT_DIGEST_MISMATCH")
        return
    try:
        raw_report = _strict_json_loads(payload)
    except _NonFiniteJsonError:
        errors.append("OPERATIONAL_CAPACITY_RAW_REPORT_JSON_NON_FINITE")
        return
    except (UnicodeDecodeError, json.JSONDecodeError):
        errors.append("OPERATIONAL_CAPACITY_RAW_REPORT_JSON_INVALID")
        return
    if not isinstance(raw_report, dict):
        errors.append("OPERATIONAL_CAPACITY_RAW_REPORT_OBJECT_REQUIRED")
        return
    derived = _validate_capacity_raw_report(
        raw_report,
        expected_release_id=expected_release_id,
        expected_git_sha=expected_git_sha,
        expected_image_digest=expected_image_digest,
        maximum_age_seconds=maximum_age_seconds,
        errors=errors,
    )
    _validate_capacity_gate_derivations(report, derived, errors=errors)


def _validate_gate_report_payload(
    *,
    gate_name: str,
    gate: JsonObject,
    payload: bytes,
    schema: JsonObject,
    expected_release_id: str,
    expected_git_sha: str,
    expected_image_digest: str,
    errors: list[str],
) -> tuple[str, JsonObject | None]:
    expected_digest = str(gate.get("report_sha256", ""))
    actual_digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    if actual_digest != expected_digest:
        errors.append(f"OPERATIONAL_GATE_REPORT_DIGEST_MISMATCH: {gate_name}")
        return actual_digest, None
    try:
        report = _strict_json_loads(payload)
    except _NonFiniteJsonError:
        errors.append(f"OPERATIONAL_GATE_REPORT_JSON_NON_FINITE: {gate_name}")
        return actual_digest, None
    except (UnicodeDecodeError, json.JSONDecodeError):
        errors.append(f"OPERATIONAL_GATE_REPORT_JSON_INVALID: {gate_name}")
        return actual_digest, None
    if not isinstance(report, dict):
        errors.append(f"OPERATIONAL_GATE_REPORT_OBJECT_REQUIRED: {gate_name}")
        return actual_digest, None
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for error in sorted(validator.iter_errors(report), key=lambda item: list(item.path)):
        location = ".".join(str(part) for part in error.path) or "$"
        errors.append(
            f"OPERATIONAL_GATE_REPORT_SCHEMA_INVALID: {gate_name}.{location}: {error.message}"
        )

    raw_checks = report.get("checks")
    check_rows = raw_checks if isinstance(raw_checks, list) else []
    checks = [check for check in check_rows if isinstance(check, dict)]
    check_ids = [str(check.get("id")) for check in checks]
    if len(check_ids) != len(set(check_ids)):
        errors.append(f"OPERATIONAL_GATE_REPORT_CHECK_IDS_DUPLICATED: {gate_name}")
    policies = GATE_CHECK_POLICIES.get(gate_name)
    if policies is None:
        errors.append(f"OPERATIONAL_GATE_REPORT_GATE_UNSUPPORTED: {gate_name}")
        policies = {}
    missing_check_ids = sorted(set(policies) - set(check_ids))
    unexpected_check_ids = sorted(set(check_ids) - set(policies))
    if missing_check_ids:
        errors.append(
            f"OPERATIONAL_GATE_REPORT_REQUIRED_CHECKS_MISSING: {gate_name}: {missing_check_ids}"
        )
    if unexpected_check_ids:
        errors.append(
            f"OPERATIONAL_GATE_REPORT_CHECKS_UNEXPECTED: {gate_name}: {unexpected_check_ids}"
        )
    for index, check in enumerate(checks):
        check_id = str(check.get("id"))
        policy = policies.get(check_id)
        if policy is None:
            continue
        expected_comparison, expected_threshold = policy
        if check.get("comparison") != expected_comparison:
            errors.append(f"OPERATIONAL_GATE_REPORT_COMPARISON_MISMATCH: {gate_name}.{check_id}")
        if not _policy_value_matches(check.get("threshold"), expected_threshold):
            errors.append(
                f"OPERATIONAL_GATE_REPORT_THRESHOLD_POLICY_MISMATCH: {gate_name}.{check_id}"
            )
        if not _threshold_passes(check.get("observed"), expected_comparison, expected_threshold):
            errors.append(f"OPERATIONAL_GATE_REPORT_THRESHOLD_FAILED: {gate_name}.checks.{index}")

    expected_fields = {
        "gate_id": gate_name,
        "release_id": expected_release_id,
        "git_sha": expected_git_sha,
        "image_digest": expected_image_digest,
        "status": "passed",
    }
    for field, expected in expected_fields.items():
        if report.get(field) != expected:
            errors.append(f"OPERATIONAL_GATE_REPORT_{field.upper()}_MISMATCH: {gate_name}")
    if report.get("issuer") != gate.get("issuer"):
        errors.append(f"OPERATIONAL_GATE_REPORT_ISSUER_MISMATCH: {gate_name}")
    _validate_gate_scope(
        report=report,
        gate_name=gate_name,
        expected_release_id=expected_release_id,
        expected_image_digest=expected_image_digest,
        errors=errors,
    )

    started_at = _report_timestamp(
        report.get("started_at"), field="started_at", gate_name=gate_name, errors=errors
    )
    performed_at = _report_timestamp(
        report.get("performed_at"),
        field="performed_at",
        gate_name=gate_name,
        errors=errors,
    )
    completed_at = _report_timestamp(
        report.get("completed_at"),
        field="completed_at",
        gate_name=gate_name,
        errors=errors,
    )
    generated_at = _report_timestamp(
        report.get("generated_at"),
        field="generated_at",
        gate_name=gate_name,
        errors=errors,
    )
    wrapper_completed_at = _report_timestamp(
        gate.get("completed_at"),
        field="readiness.completed_at",
        gate_name=gate_name,
        errors=errors,
    )
    if (
        started_at is not None
        and performed_at is not None
        and completed_at is not None
        and generated_at is not None
        and not started_at <= performed_at <= completed_at <= generated_at
    ):
        errors.append(f"OPERATIONAL_GATE_REPORT_TIMELINE_INVALID: {gate_name}")
    if (
        completed_at is not None
        and generated_at is not None
        and generated_at - completed_at > timedelta(minutes=15)
    ):
        errors.append(f"OPERATIONAL_GATE_REPORT_GENERATION_DELAY_EXCESSIVE: {gate_name}")
    if completed_at is not None and wrapper_completed_at != completed_at:
        errors.append(f"OPERATIONAL_GATE_REPORT_COMPLETED_AT_MISMATCH: {gate_name}")

    if gate_name == "disaster_recovery":
        _validate_disaster_recovery_drills(
            report=report,
            completed_at=completed_at,
            gate_name=gate_name,
            errors=errors,
        )
    if gate_name == "fault_injection":
        _validate_fault_matrix(
            report=report,
            started_at=started_at,
            completed_at=completed_at,
            gate_name=gate_name,
            errors=errors,
        )
    return actual_digest, report


def validate_gate_reports(
    evidence: JsonObject,
    schema: JsonObject,
    *,
    expected_release_id: str,
    expected_git_sha: str,
    expected_image_digest: str,
    report_directory: Path | None = None,
    fetch_reports: bool = False,
    bearer_token: str | None = None,
    http_client: httpx.Client | None = None,
    maximum_report_bytes: int = 2 * 1024 * 1024,
    maximum_age_seconds: int = 86400,
) -> tuple[dict[str, str], dict[str, JsonObject]]:
    if (report_directory is None) == (not fetch_reports):
        raise ValueError("OPERATIONAL_GATE_REPORT_SOURCE_REQUIRED")
    if fetch_reports and not bearer_token:
        raise ValueError("OPERATIONAL_GATE_REPORT_BEARER_TOKEN_REQUIRED")
    if http_client is not None and not fetch_reports:
        raise ValueError("OPERATIONAL_GATE_REPORT_HTTP_CLIENT_UNEXPECTED")
    if maximum_report_bytes <= 0:
        raise ValueError("OPERATIONAL_GATE_REPORT_SIZE_LIMIT_INVALID")
    if maximum_age_seconds <= 0:
        raise ValueError("OPERATIONAL_CAPACITY_MAXIMUM_AGE_INVALID")

    gates = evidence.get("gates")
    evidence_store = evidence.get("evidence_store")
    if not isinstance(gates, dict) or not isinstance(evidence_store, dict):
        raise ValueError("OPERATIONAL_GATE_REPORT_REFERENCES_REQUIRED")
    readiness_uri = str(evidence_store.get("uri", ""))
    errors: list[str] = []
    validated: dict[str, str] = {}
    validated_raw_evidence: dict[str, JsonObject] = {}
    raw_evidence_schema = _load_object(RAW_EVIDENCE_SCHEMA_PATH)
    client = http_client
    owns_client = False
    if fetch_reports and client is None:
        client = httpx.Client(
            headers={"Authorization": f"Bearer {bearer_token}"},
            follow_redirects=False,
            timeout=httpx.Timeout(15.0),
        )
        owns_client = True
    try:
        for gate_name, raw_gate in gates.items():
            if not isinstance(raw_gate, dict):
                continue
            gate = raw_gate
            expected_digest = str(gate.get("report_sha256", ""))
            digest_hex = expected_digest.removeprefix("sha256:")
            report_uri = str(gate.get("evidence_uri", ""))
            payload: bytes
            if report_directory is not None:
                report_path = report_directory / f"{digest_hex}.json"
                try:
                    payload = _read_bounded_file(report_path, maximum_report_bytes)
                except _PayloadTooLarge:
                    errors.append(f"OPERATIONAL_GATE_REPORT_TOO_LARGE: {gate_name}")
                    continue
                except OSError as exc:
                    errors.append(
                        f"OPERATIONAL_GATE_REPORT_READ_FAILED: {gate_name}: {type(exc).__name__}"
                    )
                    continue
            else:
                if not _same_https_origin(readiness_uri, report_uri):
                    errors.append(f"OPERATIONAL_GATE_REPORT_ORIGIN_MISMATCH: {gate_name}")
                    continue
                if client is None:  # Defensive type narrowing.
                    raise RuntimeError("OPERATIONAL_GATE_REPORT_CLIENT_REQUIRED")
                try:
                    payload = _fetch_bounded_json(
                        client,
                        report_uri,
                        bearer_token=bearer_token,
                        maximum_bytes=maximum_report_bytes,
                    )
                except _PayloadTooLarge:
                    errors.append(f"OPERATIONAL_GATE_REPORT_TOO_LARGE: {gate_name}")
                    continue
                except _ContentTypeInvalid:
                    errors.append(f"OPERATIONAL_GATE_REPORT_CONTENT_TYPE_INVALID: {gate_name}")
                    continue
                except httpx.HTTPError as exc:
                    errors.append(
                        f"OPERATIONAL_GATE_REPORT_FETCH_FAILED: {gate_name}: {type(exc).__name__}"
                    )
                    continue
            actual_digest, parsed_report = _validate_gate_report_payload(
                gate_name=gate_name,
                gate=gate,
                payload=payload,
                schema=schema,
                expected_release_id=expected_release_id,
                expected_git_sha=expected_git_sha,
                expected_image_digest=expected_image_digest,
                errors=errors,
            )
            validated[gate_name] = actual_digest
            if parsed_report is not None and actual_digest == expected_digest:
                if gate_name == "capacity":
                    _validate_capacity_raw_report_reference(
                        parsed_report,
                        gate_report_uri=report_uri,
                        expected_release_id=expected_release_id,
                        expected_git_sha=expected_git_sha,
                        expected_image_digest=expected_image_digest,
                        report_directory=report_directory,
                        client=client,
                        bearer_token=bearer_token,
                        maximum_report_bytes=maximum_report_bytes,
                        maximum_age_seconds=maximum_age_seconds,
                        errors=errors,
                    )
                    capacity_reference = parsed_report.get("raw_capacity_report")
                    if isinstance(capacity_reference, dict):
                        validated_raw_evidence[gate_name] = {
                            "uri": str(capacity_reference.get("uri", "")),
                            "sha256": str(capacity_reference.get("sha256", "")),
                        }
                else:
                    raw_reference = _validate_gate_raw_evidence_reference(
                        parsed_report,
                        raw_evidence_schema,
                        gate_name=gate_name,
                        gate_report_uri=report_uri,
                        expected_release_id=expected_release_id,
                        expected_git_sha=expected_git_sha,
                        expected_image_digest=expected_image_digest,
                        report_directory=report_directory,
                        client=client,
                        bearer_token=bearer_token,
                        maximum_report_bytes=maximum_report_bytes,
                        maximum_age_seconds=maximum_age_seconds,
                        errors=errors,
                    )
                    if raw_reference is not None:
                        validated_raw_evidence[gate_name] = raw_reference
    finally:
        if owns_client and client is not None:
            client.close()

    if errors:
        raise ValueError("\n".join(dict.fromkeys(errors)))
    if set(validated) != set(gates):
        raise ValueError("OPERATIONAL_GATE_REPORT_SET_INCOMPLETE")
    if set(validated_raw_evidence) != set(gates):
        raise ValueError("OPERATIONAL_GATE_RAW_EVIDENCE_SET_INCOMPLETE")
    return validated, validated_raw_evidence


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate operational release-readiness evidence")
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--gate-report-schema", type=Path, required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--gate-reports-directory", type=Path)
    source.add_argument("--fetch-gate-reports", action="store_true")
    parser.add_argument("--report-bearer-token-env")
    parser.add_argument("--expected-release-id", required=True)
    parser.add_argument("--expected-git-sha", required=True)
    parser.add_argument("--expected-image-digest", required=True)
    parser.add_argument("--expected-signer-identity", required=True)
    parser.add_argument("--expected-signer-issuer", required=True)
    parser.add_argument("--maximum-age-seconds", type=int, default=86400)
    parser.add_argument("--minimum-retention-days", type=int, default=365)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        evidence_bytes = args.evidence.read_bytes()
        evidence = _load_object(args.evidence)
        source_sha256 = "sha256:" + hashlib.sha256(evidence_bytes).hexdigest()
        report = validate_readiness(
            evidence,
            _load_object(args.schema),
            expected_release_id=args.expected_release_id,
            expected_git_sha=args.expected_git_sha,
            expected_image_digest=args.expected_image_digest,
            expected_signer_identity=args.expected_signer_identity,
            expected_signer_issuer=args.expected_signer_issuer,
            maximum_age_seconds=args.maximum_age_seconds,
            minimum_retention_days=args.minimum_retention_days,
            source_sha256=source_sha256,
        )
        bearer_token = None
        if args.fetch_gate_reports:
            if not args.report_bearer_token_env:
                raise ValueError("OPERATIONAL_GATE_REPORT_BEARER_TOKEN_ENV_REQUIRED")
            bearer_token = os.environ.get(args.report_bearer_token_env)
        gate_report_digests, gate_raw_evidence = validate_gate_reports(
            evidence,
            _load_object(args.gate_report_schema),
            expected_release_id=args.expected_release_id,
            expected_git_sha=args.expected_git_sha,
            expected_image_digest=args.expected_image_digest,
            report_directory=args.gate_reports_directory,
            fetch_reports=args.fetch_gate_reports,
            bearer_token=bearer_token,
            maximum_age_seconds=args.maximum_age_seconds,
        )
        report["gate_report_sha256"] = gate_report_digests
        report["gate_raw_evidence"] = gate_raw_evidence
        report["gate_reports_validated"] = True
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"operational readiness validation failed:\n{exc}", file=sys.stderr)
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
