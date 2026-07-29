"""Fetch and validate human review evidence bound to one release candidate."""

from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from jsonschema import Draft202012Validator

JsonObject = dict[str, Any]
RUBRIC_DIMENSIONS = (
    "correctness",
    "completeness",
    "evidence",
    "uncertainty",
    "action_quality",
    "expression",
)
_MAX_REVIEWER_AUTH_AGE = timedelta(hours=12)
_MAX_CLOCK_SKEW = timedelta(minutes=5)


def canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _origin(url: str, *, error_code: str) -> str:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError(error_code)
    host = parsed.hostname.lower()
    port = f":{parsed.port}" if parsed.port is not None else ""
    return f"https://{host}{port}"


def _json_object(response: httpx.Response, *, error_code: str) -> JsonObject:
    try:
        value = response.json()
    except ValueError as exc:
        raise ValueError(f"{error_code}: response is not JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{error_code}: response must be an object")
    return value


def fetch_human_review_evidence(
    *,
    service_url: str,
    token: str,
    release_id: str,
    candidate_manifest: JsonObject,
    candidate_results: JsonObject,
    timeout_seconds: int,
    poll_seconds: float,
    client: httpx.Client | None = None,
) -> tuple[JsonObject, str]:
    """Submit one exact candidate and wait for external human review evidence."""

    service_origin = _origin(
        service_url,
        error_code="HUMAN_REVIEW_SERVICE_HTTPS_REQUIRED",
    )
    if not token:
        raise ValueError("HUMAN_REVIEW_SERVICE_TOKEN_REQUIRED")
    if timeout_seconds <= 0 or poll_seconds < 0:
        raise ValueError("HUMAN_REVIEW_WAIT_CONFIGURATION_INVALID")

    manifest_digest = canonical_sha256(candidate_manifest)
    results_digest = canonical_sha256(candidate_results)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Idempotency-Key": f"human-review-{release_id}-{results_digest[:16]}",
    }
    request_payload: JsonObject = {
        "schema_version": "1.0",
        "release_id": release_id,
        "candidate_manifest_sha256": manifest_digest,
        "candidate_results_sha256": results_digest,
        "candidate_manifest": candidate_manifest,
        "candidate_results": candidate_results,
        "requirements": {
            "minimum_samples": 50,
            "maximum_samples": 100,
            "minimum_unique_candidate_runs": 50,
            "risks": ["high", "critical"],
            "representative_dimensions": ["use_case", "risk", "dataset"],
            "candidate_binding_fields": [
                "case_id",
                "run_id",
                "use_case",
                "risk",
                "dataset",
                "category",
                "review_subject_sha256",
            ],
            "rubric_dimensions": list(RUBRIC_DIMENSIONS),
            "maximum_major_findings": 0,
        },
    }

    owns_client = client is None
    review_client = client or httpx.Client(
        timeout=httpx.Timeout(min(timeout_seconds, 60)),
        follow_redirects=False,
    )
    try:
        submitted = review_client.post(
            service_url,
            headers=headers,
            json=request_payload,
        )
        if submitted.status_code != 202:
            raise ValueError(
                f"HUMAN_REVIEW_SUBMISSION_FAILED: expected 202, got {submitted.status_code}"
            )
        submission = _json_object(
            submitted,
            error_code="HUMAN_REVIEW_SUBMISSION_INVALID",
        )
        request_id = submission.get("request_id")
        status_url = submission.get("status_url")
        if not isinstance(request_id, str) or not request_id:
            raise ValueError("HUMAN_REVIEW_REQUEST_ID_MISSING")
        if not isinstance(status_url, str) or not status_url:
            raise ValueError("HUMAN_REVIEW_STATUS_URL_MISSING")
        if (
            _origin(status_url, error_code="HUMAN_REVIEW_STATUS_URL_HTTPS_REQUIRED")
            != service_origin
        ):
            raise ValueError("HUMAN_REVIEW_STATUS_URL_ORIGIN_MISMATCH")

        deadline = time.monotonic() + timeout_seconds
        while True:
            response = review_client.get(status_url, headers=headers)
            if response.status_code == 200:
                evidence = _json_object(
                    response,
                    error_code="HUMAN_REVIEW_EVIDENCE_INVALID",
                )
                provenance = evidence.get("provenance")
                if not isinstance(provenance, dict) or provenance.get("request_id") != request_id:
                    raise ValueError("HUMAN_REVIEW_REQUEST_ID_MISMATCH")
                return evidence, request_id
            if response.status_code != 202:
                raise ValueError(
                    f"HUMAN_REVIEW_POLL_FAILED: expected 200 or 202, got {response.status_code}"
                )
            if time.monotonic() >= deadline:
                raise ValueError("HUMAN_REVIEW_TIMEOUT")
            if poll_seconds:
                time.sleep(min(poll_seconds, max(deadline - time.monotonic(), 0.0)))
    finally:
        if owns_client:
            review_client.close()


def _timestamp(value: object, *, code: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(code) from exc
    if parsed.tzinfo is None:
        raise ValueError(code)
    return parsed.astimezone(UTC)


def _validate_schema(evidence: JsonObject, schema_path: Path) -> None:
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"HUMAN_REVIEW_SCHEMA_UNAVAILABLE: {exc}") from exc
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(evidence), key=lambda item: list(item.path))
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.path) or "<root>"
        raise ValueError(f"HUMAN_REVIEW_SCHEMA_INVALID: {location}: {first.message}")


_REPRESENTATIVE_DIMENSIONS = frozenset({"use_case", "risk", "dataset"})
_REVIEWABLE_DIMENSIONS = frozenset({"use_case", "risk", "dataset", "category"})
_HIGH_RISKS = frozenset({"high", "critical"})
_SUPPORTED_RISKS = frozenset({"low", "medium", "high", "critical"})
_LIVE_DATASETS = frozenset({"golden", "edge", "adversarial", "production-sample"})
_CANDIDATE_METADATA_FIELDS = ("use_case", "risk", "dataset", "category")


def _required_string(row: JsonObject, field: str, *, code: str) -> str:
    value = row.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(code)
    return value


def _required_non_negative_int(row: JsonObject, field: str, *, code: str) -> int:
    value = row.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(code)
    return value


def _representative_distribution(
    population: list[JsonObject],
    sample: list[JsonObject],
    dimensions: tuple[str, ...],
) -> bool:
    if not population or not sample:
        return False
    population_counts = Counter(tuple(row[field] for field in dimensions) for row in population)
    sample_counts = Counter(tuple(row[field] for field in dimensions) for row in sample)
    if set(population_counts) != set(sample_counts):
        return False
    tolerance = max(0.05, 1 / len(sample))
    return all(
        abs(sample_counts[stratum] / len(sample) - count / len(population)) <= tolerance
        for stratum, count in population_counts.items()
    )


def _candidate_review_subject(
    row: JsonObject,
    *,
    expected_release_id: str,
) -> str:
    subject = row.get("review_subject")
    subject_digest = row.get("review_subject_sha256")
    if not isinstance(subject, dict) or not isinstance(subject_digest, str):
        raise ValueError("HUMAN_REVIEW_SUBJECT_REQUIRED")
    if canonical_sha256(subject) != subject_digest:
        raise ValueError("HUMAN_REVIEW_SUBJECT_DIGEST_INVALID")
    required = {
        "schema_version",
        "release_id",
        "case_id",
        "source_case_id",
        "run_id",
        "dataset",
        "category",
        "use_case",
        "risk",
        "source_scenario_sha256",
        "input_sha256",
        "final_result",
        "claims",
        "evidence",
        "audit_ref",
        "artifact_refs",
        "grader_results",
        "expected_capability_trajectory",
        "observed_capability_trajectory",
        "tool_trajectory_binding",
        "fault_injection_receipt",
        "case_contract_sha256",
    }
    if set(subject) != required or subject.get("schema_version") != "1.1":
        raise ValueError("HUMAN_REVIEW_SUBJECT_SCHEMA_INVALID")
    if subject.get("release_id") != expected_release_id:
        raise ValueError("HUMAN_REVIEW_SUBJECT_RELEASE_MISMATCH")
    for field in (
        "case_id",
        "source_case_id",
        "run_id",
        "dataset",
        "category",
        "use_case",
        "risk",
    ):
        if subject.get(field) != row.get(field):
            raise ValueError("HUMAN_REVIEW_SUBJECT_CASE_MISMATCH")
    for field in ("source_scenario_sha256", "input_sha256", "case_contract_sha256"):
        value = subject.get(field)
        if not isinstance(value, str) or len(value) != 64:
            raise ValueError("HUMAN_REVIEW_SUBJECT_DIGEST_INVALID")
    expected_trajectory = subject.get("expected_capability_trajectory")
    observed_trajectory = subject.get("observed_capability_trajectory")
    if not isinstance(expected_trajectory, list) or not expected_trajectory:
        raise ValueError("HUMAN_REVIEW_SUBJECT_EXPECTED_TRAJECTORY_REQUIRED")
    if not isinstance(observed_trajectory, list):
        raise ValueError("HUMAN_REVIEW_SUBJECT_OBSERVED_TRAJECTORY_REQUIRED")
    if (
        expected_trajectory != row.get("expected_capability_trajectory")
        or observed_trajectory != row.get("observed_capability_trajectory")
        or canonical_sha256(expected_trajectory) != row.get("expected_capability_trajectory_sha256")
        or canonical_sha256(observed_trajectory) != row.get("observed_capability_trajectory_sha256")
    ):
        raise ValueError("HUMAN_REVIEW_SUBJECT_TRAJECTORY_MISMATCH")
    binding = subject.get("tool_trajectory_binding")
    binding_fields = (
        "release_id",
        "git_sha",
        "image_digest",
        "case_id",
        "source_case_id",
        "run_id",
        "source_scenario_sha256",
        "input_sha256",
        "expected_capability_trajectory_sha256",
        "observed_capability_trajectory_sha256",
    )
    if not isinstance(binding, dict) or set(binding) != set(binding_fields):
        raise ValueError("HUMAN_REVIEW_SUBJECT_TRAJECTORY_BINDING_INVALID")
    expected_binding = {field: row.get(field) for field in binding_fields}
    expected_binding["release_id"] = expected_release_id
    if binding != expected_binding:
        raise ValueError("HUMAN_REVIEW_SUBJECT_TRAJECTORY_BINDING_MISMATCH")
    final_result = subject.get("final_result")
    if not isinstance(final_result, dict):
        raise ValueError("HUMAN_REVIEW_SUBJECT_FINAL_RESULT_REQUIRED")
    if subject.get("claims") != final_result.get("claims"):
        raise ValueError("HUMAN_REVIEW_SUBJECT_CLAIMS_MISMATCH")
    if subject.get("evidence") != final_result.get("evidence"):
        raise ValueError("HUMAN_REVIEW_SUBJECT_EVIDENCE_MISMATCH")
    audit_ref = subject.get("audit_ref")
    if (
        not isinstance(audit_ref, dict)
        or set(audit_ref) != {"sha256", "uri"}
        or not isinstance(audit_ref.get("sha256"), str)
        or len(audit_ref["sha256"]) != 64
        or not isinstance(audit_ref.get("uri"), str)
        or not audit_ref["uri"].startswith("https://")
    ):
        raise ValueError("HUMAN_REVIEW_SUBJECT_AUDIT_REF_INVALID")
    if not isinstance(subject.get("artifact_refs"), list):
        raise ValueError("HUMAN_REVIEW_SUBJECT_ARTIFACT_REFS_INVALID")
    if not isinstance(subject.get("grader_results"), list) or not subject["grader_results"]:
        raise ValueError("HUMAN_REVIEW_SUBJECT_GRADERS_REQUIRED")
    return subject_digest


def _candidate_population(
    candidate_manifest: JsonObject,
    candidate_results: JsonObject,
    *,
    expected_release_id: str,
) -> tuple[dict[tuple[str, str], JsonObject], list[JsonObject]]:
    if candidate_manifest.get("release_id") != expected_release_id:
        raise ValueError("HUMAN_REVIEW_CANDIDATE_MANIFEST_RELEASE_MISMATCH")
    if candidate_results.get("release_id") != expected_release_id:
        raise ValueError("HUMAN_REVIEW_CANDIDATE_RESULTS_RELEASE_MISMATCH")
    manifest_git_sha = _required_string(
        candidate_manifest,
        "git_sha",
        code="HUMAN_REVIEW_CANDIDATE_GIT_SHA_REQUIRED",
    )
    manifest_image_digest = _required_string(
        candidate_manifest,
        "image_digest",
        code="HUMAN_REVIEW_CANDIDATE_IMAGE_DIGEST_REQUIRED",
    )
    manifest_digest = canonical_sha256(candidate_manifest)
    if candidate_results.get("candidate_manifest_sha256") != manifest_digest:
        raise ValueError("HUMAN_REVIEW_CANDIDATE_RESULTS_MANIFEST_MISMATCH")

    planned_rows = candidate_manifest.get("candidate_cases")
    result_rows = candidate_results.get("cases")
    if not isinstance(planned_rows, list) or not isinstance(result_rows, list):
        raise ValueError("HUMAN_REVIEW_CANDIDATE_CASES_INVALID")
    if candidate_manifest.get("planned_candidate_case_count") != len(planned_rows):
        raise ValueError("HUMAN_REVIEW_CANDIDATE_COUNT_MISMATCH")
    if len(result_rows) != len(planned_rows):
        raise ValueError("HUMAN_REVIEW_CANDIDATE_RESULT_COUNT_MISMATCH")

    planned_by_id: dict[str, JsonObject] = {}
    for raw_row in planned_rows:
        if not isinstance(raw_row, dict):
            raise ValueError("HUMAN_REVIEW_CANDIDATE_CASE_INVALID")
        case_id = _required_string(
            raw_row,
            "case_id",
            code="HUMAN_REVIEW_CANDIDATE_CASE_ID_REQUIRED",
        )
        _required_string(
            raw_row,
            "source_case_id",
            code="HUMAN_REVIEW_CANDIDATE_SOURCE_CASE_ID_REQUIRED",
        )
        for field in _CANDIDATE_METADATA_FIELDS:
            _required_string(
                raw_row,
                field,
                code=f"HUMAN_REVIEW_CANDIDATE_{field.upper()}_REQUIRED",
            )
        if raw_row["risk"] not in _SUPPORTED_RISKS:
            raise ValueError("HUMAN_REVIEW_CANDIDATE_RISK_INVALID")
        if raw_row["dataset"] not in _LIVE_DATASETS:
            raise ValueError("HUMAN_REVIEW_CANDIDATE_DATASET_INVALID")
        expected_trajectory = raw_row.get("expected_capability_trajectory")
        expected_trajectory_digest = raw_row.get("expected_capability_trajectory_sha256")
        if (
            not isinstance(expected_trajectory, list)
            or not expected_trajectory
            or not isinstance(expected_trajectory_digest, str)
            or canonical_sha256(expected_trajectory) != expected_trajectory_digest
        ):
            raise ValueError("HUMAN_REVIEW_CANDIDATE_TRAJECTORY_INVALID")
        if case_id in planned_by_id:
            raise ValueError("HUMAN_REVIEW_CANDIDATE_CASE_ID_DUPLICATE")
        planned_by_id[case_id] = raw_row

    candidate_pairs: dict[tuple[str, str], JsonObject] = {}
    run_ids: set[str] = set()
    result_case_ids: set[str] = set()
    result_dataset_counts: Counter[str] = Counter()
    eligible: list[JsonObject] = []
    for raw_row in result_rows:
        if not isinstance(raw_row, dict):
            raise ValueError("HUMAN_REVIEW_CANDIDATE_RESULT_INVALID")
        case_id = _required_string(
            raw_row,
            "case_id",
            code="HUMAN_REVIEW_CANDIDATE_CASE_ID_REQUIRED",
        )
        run_id = _required_string(
            raw_row,
            "run_id",
            code="HUMAN_REVIEW_CANDIDATE_RUN_ID_REQUIRED",
        )
        if case_id in result_case_ids:
            raise ValueError("HUMAN_REVIEW_CANDIDATE_CASE_ID_DUPLICATE")
        if run_id in run_ids:
            raise ValueError("HUMAN_REVIEW_CANDIDATE_RUN_DUPLICATE")
        planned = planned_by_id.get(case_id)
        if planned is None:
            raise ValueError("HUMAN_REVIEW_CANDIDATE_NOT_PLANNED")
        for field in ("source_case_id", *_CANDIDATE_METADATA_FIELDS):
            value = _required_string(
                raw_row,
                field,
                code=f"HUMAN_REVIEW_CANDIDATE_{field.upper()}_REQUIRED",
            )
            if value != planned.get(field):
                raise ValueError("HUMAN_REVIEW_CANDIDATE_METADATA_MISMATCH")
        for field, expected_value in (
            ("release_id", expected_release_id),
            ("git_sha", manifest_git_sha),
            ("image_digest", manifest_image_digest),
        ):
            if raw_row.get(field) != expected_value:
                raise ValueError("HUMAN_REVIEW_CANDIDATE_IDENTITY_MISMATCH")
        for field in (
            "expected_capability_trajectory",
            "expected_capability_trajectory_sha256",
        ):
            if raw_row.get(field) != planned.get(field):
                raise ValueError("HUMAN_REVIEW_CANDIDATE_TRAJECTORY_MISMATCH")
        _candidate_review_subject(
            raw_row,
            expected_release_id=expected_release_id,
        )
        pair = (case_id, run_id)
        candidate_pairs[pair] = raw_row
        result_case_ids.add(case_id)
        run_ids.add(run_id)
        result_dataset_counts[str(raw_row["dataset"])] += 1
        if raw_row["risk"] in _HIGH_RISKS:
            eligible.append(raw_row)

    if set(planned_by_id) != result_case_ids:
        raise ValueError("HUMAN_REVIEW_CANDIDATE_PLAN_RESULT_MISMATCH")
    declared_counts = candidate_manifest.get("dataset_execution_counts")
    if not isinstance(declared_counts, dict) or declared_counts != dict(
        sorted(result_dataset_counts.items())
    ):
        raise ValueError("HUMAN_REVIEW_CANDIDATE_DATASET_COUNTS_MISMATCH")
    if candidate_manifest.get("live_datasets") != sorted(result_dataset_counts):
        raise ValueError("HUMAN_REVIEW_CANDIDATE_DATASETS_MISMATCH")
    if candidate_manifest.get("high_risk_candidate_count") != len(eligible):
        raise ValueError("HUMAN_REVIEW_HIGH_RISK_POPULATION_MISMATCH")
    if len(eligible) < 50:
        raise ValueError("HUMAN_REVIEW_HIGH_RISK_POPULATION_TOO_SMALL")

    dataset_summary = candidate_results.get("dataset_summary")
    if not isinstance(dataset_summary, dict):
        raise ValueError("HUMAN_REVIEW_DATASET_SUMMARY_REQUIRED")
    for dataset, total in result_dataset_counts.items():
        summary = dataset_summary.get(dataset)
        if not isinstance(summary, dict) or summary.get("source") != "staging-api":
            raise ValueError("HUMAN_REVIEW_DATASET_SUMMARY_MISMATCH")
        summary_total = _required_non_negative_int(
            summary,
            "total",
            code="HUMAN_REVIEW_DATASET_SUMMARY_MISMATCH",
        )
        summary_passed = _required_non_negative_int(
            summary,
            "passed",
            code="HUMAN_REVIEW_DATASET_SUMMARY_MISMATCH",
        )
        summary_failed = _required_non_negative_int(
            summary,
            "failed",
            code="HUMAN_REVIEW_DATASET_SUMMARY_MISMATCH",
        )
        if summary_total != total or summary_passed + summary_failed != total:
            raise ValueError("HUMAN_REVIEW_DATASET_SUMMARY_MISMATCH")
    incident = dataset_summary.get("incident-derived")
    offline_sources = candidate_manifest.get("offline_dataset_sources")
    if not isinstance(incident, dict) or not isinstance(offline_sources, dict):
        raise ValueError("HUMAN_REVIEW_INCIDENT_PROVENANCE_INVALID")
    incident_total = _required_non_negative_int(
        incident,
        "total",
        code="HUMAN_REVIEW_INCIDENT_PROVENANCE_INVALID",
    )
    incident_passed = _required_non_negative_int(
        incident,
        "passed",
        code="HUMAN_REVIEW_INCIDENT_PROVENANCE_INVALID",
    )
    incident_failed = _required_non_negative_int(
        incident,
        "failed",
        code="HUMAN_REVIEW_INCIDENT_PROVENANCE_INVALID",
    )
    if (
        offline_sources.get("incident-derived") != "offline-hard-control"
        or incident.get("source") != "offline-hard-control"
        or incident_total < 1
        or incident_passed != incident_total
        or incident_failed != 0
    ):
        raise ValueError("HUMAN_REVIEW_INCIDENT_PROVENANCE_INVALID")
    return candidate_pairs, eligible


def validate_human_review_evidence(
    evidence: JsonObject,
    *,
    schema_path: Path,
    expected_release_id: str,
    candidate_manifest: JsonObject,
    candidate_results: JsonObject,
    expected_request_id: str,
    expected_service_origin: str,
    now: datetime | None = None,
    maximum_age_seconds: int = 86_400,
) -> dict[str, int]:
    """Validate schema plus exact-release, uniqueness, provenance and freshness invariants."""

    _validate_schema(evidence, schema_path)
    checked_at = (now or datetime.now(UTC)).astimezone(UTC)
    if maximum_age_seconds <= 0:
        raise ValueError("HUMAN_REVIEW_MAXIMUM_AGE_INVALID")
    if evidence["release_id"] != expected_release_id:
        raise ValueError("HUMAN_REVIEW_RELEASE_MISMATCH")
    if evidence["candidate_manifest_sha256"] != canonical_sha256(candidate_manifest):
        raise ValueError("HUMAN_REVIEW_MANIFEST_DIGEST_MISMATCH")
    if evidence["candidate_results_sha256"] != canonical_sha256(candidate_results):
        raise ValueError("HUMAN_REVIEW_RESULTS_DIGEST_MISMATCH")
    if evidence["status"] != "approved":
        raise ValueError("HUMAN_REVIEW_NOT_APPROVED")
    candidate_pairs, eligible_candidates = _candidate_population(
        candidate_manifest,
        candidate_results,
        expected_release_id=expected_release_id,
    )

    provenance = evidence["provenance"]
    if provenance["request_id"] != expected_request_id:
        raise ValueError("HUMAN_REVIEW_REQUEST_ID_MISMATCH")
    expected_origin = _origin(
        expected_service_origin,
        error_code="HUMAN_REVIEW_SERVICE_HTTPS_REQUIRED",
    )
    evidence_origin = _origin(
        provenance["evidence_uri"],
        error_code="HUMAN_REVIEW_EVIDENCE_URI_HTTPS_REQUIRED",
    )
    if evidence_origin != expected_origin:
        raise ValueError("HUMAN_REVIEW_EVIDENCE_ORIGIN_MISMATCH")

    requested_at = _timestamp(
        provenance["requested_at"],
        code="HUMAN_REVIEW_REQUESTED_AT_INVALID",
    )
    completed_at = _timestamp(
        provenance["completed_at"],
        code="HUMAN_REVIEW_COMPLETED_AT_INVALID",
    )
    issued_at = _timestamp(
        provenance["issued_at"],
        code="HUMAN_REVIEW_ISSUED_AT_INVALID",
    )
    expires_at = _timestamp(
        provenance["expires_at"],
        code="HUMAN_REVIEW_EXPIRES_AT_INVALID",
    )
    if not requested_at <= completed_at <= issued_at <= expires_at:
        raise ValueError("HUMAN_REVIEW_TIME_ORDER_INVALID")
    if issued_at > checked_at + _MAX_CLOCK_SKEW:
        raise ValueError("HUMAN_REVIEW_ISSUED_IN_FUTURE")
    if checked_at - issued_at > timedelta(seconds=maximum_age_seconds):
        raise ValueError("HUMAN_REVIEW_STALE")
    if expires_at <= checked_at:
        raise ValueError("HUMAN_REVIEW_EXPIRED")

    sampling = evidence["sampling"]
    reviews = evidence["reviews"]
    if sampling["sample_count"] != len(reviews):
        raise ValueError("HUMAN_REVIEW_SAMPLE_COUNT_MISMATCH")
    if sampling["population_size"] != len(eligible_candidates):
        raise ValueError("HUMAN_REVIEW_POPULATION_INVALID")
    if len(reviews) > len(eligible_candidates):
        raise ValueError("HUMAN_REVIEW_SAMPLE_EXCEEDS_POPULATION")
    representative_dimensions = set(sampling["representative_dimensions"])
    if (
        sampling["strategy"] != "stratified-risk"
        or not _REPRESENTATIVE_DIMENSIONS <= representative_dimensions
        or not representative_dimensions <= _REVIEWABLE_DIMENSIONS
    ):
        raise ValueError("HUMAN_REVIEW_REPRESENTATIVE_DIMENSIONS_INVALID")

    reviewer_auth: dict[str, datetime] = {}
    reviewer_subjects: set[str] = set()
    for reviewer in evidence["reviewers"]:
        reviewer_id = reviewer["reviewer_id"]
        subject = reviewer["auth"]["subject"]
        if reviewer_id in reviewer_auth:
            raise ValueError("HUMAN_REVIEW_REVIEWER_ID_DUPLICATE")
        if subject in reviewer_subjects:
            raise ValueError("HUMAN_REVIEW_AUTH_SUBJECT_DUPLICATE")
        reviewer_auth[reviewer_id] = _timestamp(
            reviewer["auth"]["authenticated_at"],
            code="HUMAN_REVIEW_AUTHENTICATED_AT_INVALID",
        )
        reviewer_subjects.add(subject)

    sample_ids: set[str] = set()
    subject_digests: set[str] = set()
    reviewed_candidates: set[tuple[str, str]] = set()
    reviewed_rows: list[JsonObject] = []
    major_findings = 0
    for review in reviews:
        sample_id = review["sample_id"]
        subject_digest = review["subject_sha256"]
        if sample_id in sample_ids:
            raise ValueError("HUMAN_REVIEW_SAMPLE_ID_DUPLICATE")
        if subject_digest in subject_digests:
            raise ValueError("HUMAN_REVIEW_SUBJECT_DUPLICATE")
        candidate_pair = (review["case_id"], review["run_id"])
        candidate = candidate_pairs.get(candidate_pair)
        if candidate is None:
            raise ValueError("HUMAN_REVIEW_CASE_RUN_MISMATCH")
        if candidate_pair in reviewed_candidates:
            raise ValueError("HUMAN_REVIEW_CANDIDATE_SAMPLE_DUPLICATE")
        if review["subject_sha256"] != candidate["review_subject_sha256"]:
            raise ValueError("HUMAN_REVIEW_SUBJECT_DIGEST_MISMATCH")
        if review["risk"] != candidate["risk"]:
            raise ValueError("HUMAN_REVIEW_RISK_MISMATCH")
        if any(review[field] != candidate[field] for field in ("use_case", "dataset", "category")):
            raise ValueError("HUMAN_REVIEW_DIMENSION_MISMATCH")
        if review["reviewer_id"] not in reviewer_auth:
            raise ValueError("HUMAN_REVIEW_REVIEWER_UNKNOWN")
        reviewed_at = _timestamp(
            review["reviewed_at"],
            code="HUMAN_REVIEW_REVIEWED_AT_INVALID",
        )
        authenticated_at = reviewer_auth[review["reviewer_id"]]
        if not requested_at <= reviewed_at <= completed_at:
            raise ValueError("HUMAN_REVIEW_REVIEW_TIME_INVALID")
        if not authenticated_at <= reviewed_at:
            raise ValueError("HUMAN_REVIEW_AUTH_AFTER_REVIEW")
        if reviewed_at - authenticated_at > _MAX_REVIEWER_AUTH_AGE:
            raise ValueError("HUMAN_REVIEW_AUTH_STALE")
        if review["decision"] != "pass":
            raise ValueError("HUMAN_REVIEW_SAMPLE_FAILED")
        major_findings += sum(
            finding["severity"] in {"major", "critical"} for finding in review["findings"]
        )
        sample_ids.add(sample_id)
        subject_digests.add(subject_digest)
        reviewed_candidates.add(candidate_pair)
        reviewed_rows.append(candidate)

    if len(reviewed_candidates) < 50:
        raise ValueError("HUMAN_REVIEW_UNIQUE_CANDIDATE_SAMPLES_TOO_SMALL")
    for dimension in representative_dimensions:
        population_values = {row[dimension] for row in eligible_candidates}
        reviewed_values = {row[dimension] for row in reviewed_rows}
        if reviewed_values != population_values:
            raise ValueError(f"HUMAN_REVIEW_REPRESENTATION_MISMATCH: {dimension}")
    stratum_dimensions = tuple(sorted(representative_dimensions))
    if not _representative_distribution(
        eligible_candidates,
        reviewed_rows,
        stratum_dimensions,
    ):
        raise ValueError("HUMAN_REVIEW_REPRESENTATION_MISMATCH: distribution")
    if major_findings:
        raise ValueError("HUMAN_REVIEW_MAJOR_FINDING")
    return {
        "high_risk_human_review_samples": len(reviewed_candidates),
        "major_human_review_findings": major_findings,
    }
