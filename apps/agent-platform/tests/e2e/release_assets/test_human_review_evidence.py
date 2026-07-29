from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from evals.human_review_evidence import (
    RUBRIC_DIMENSIONS,
    canonical_sha256,
    fetch_human_review_evidence,
    validate_human_review_evidence,
)

PLATFORM_ROOT = Path(__file__).parents[3]
SCHEMA = PLATFORM_ROOT / "deploy" / "ci" / "human-review-evidence.schema.json"
NOW = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)
RELEASE_ID = "12345-1"
GIT_SHA = "a" * 40
IMAGE_DIGEST = f"sha256:{'b' * 64}"


def _candidate(
    *,
    candidate_count: int = 50,
) -> tuple[dict[str, object], dict[str, object], str, str]:
    dimensions = (
        ("golden", "evidence_research", "approved_market_research"),
        ("edge", "empty_data", "empty_dataset_reporting"),
        ("adversarial", "direct_injection", "prompt_injection_resistance"),
        ("production-sample", "deidentified_read_only", "production_drift_sampling"),
    )
    candidate_cases: list[dict[str, object]] = []
    result_cases: list[dict[str, object]] = []
    for index in range(candidate_count):
        dataset, category, use_case = dimensions[index % len(dimensions)]
        arguments = {"limit": 8, "query": f"Reviewed tool query {index}"}
        expected_trajectory = [
            {
                "sequence": 1,
                "capability": "knowledge.search",
                "arguments": arguments,
                "arguments_sha256": canonical_sha256(arguments),
                "receipt": {
                    "status": "succeeded",
                    "result_hash_required": True,
                    "provider_request_id_required": True,
                },
            }
        ]
        receipt = {
            "invocation_id": f"invocation-{index:03d}",
            "status": "succeeded",
            "result_hash": f"{index + 5000:064x}",
            "provider_request_id": f"provider-{index:03d}",
        }
        observed_trajectory = [
            {
                "sequence": 1,
                "capability": "knowledge.search",
                "arguments_sha256": canonical_sha256(arguments),
                "receipt": receipt,
                "receipt_sha256": canonical_sha256(receipt),
            }
        ]
        case = {
            "case_id": f"candidate-{index:03d}",
            "source_case_id": f"{dataset}-source-{index:03d}",
            "dataset": dataset,
            "category": category,
            "use_case": use_case,
            "risk": "critical" if dataset == "adversarial" else "high",
            "source_scenario_sha256": f"{index + 1000:064x}",
            "input_sha256": f"{index + 2000:064x}",
            "expected_capability_trajectory": expected_trajectory,
            "expected_capability_trajectory_sha256": canonical_sha256(expected_trajectory),
        }
        candidate_cases.append(case)
        result_case: dict[str, object] = {
            **case,
            "run_id": f"run-{index:03d}",
            "release_id": RELEASE_ID,
            "git_sha": GIT_SHA,
            "image_digest": IMAGE_DIGEST,
            "expected_capability_trajectory": expected_trajectory,
            "expected_capability_trajectory_sha256": canonical_sha256(expected_trajectory),
            "observed_capability_trajectory": observed_trajectory,
            "observed_capability_trajectory_sha256": canonical_sha256(observed_trajectory),
            "tool_receipt_count": len(observed_trajectory),
            "passed": True,
        }
        final_result = {
            "schema_version": "1.0",
            "summary": f"Reviewed final result {index}",
            "claims": [],
            "evidence": [],
            "criterion_verifications": [],
            "artifacts": [],
            "receipts": [],
            "caveats": [],
            "incomplete_items": [],
        }
        review_subject = {
            "schema_version": "1.1",
            "release_id": RELEASE_ID,
            **{
                field: result_case[field]
                for field in (
                    "case_id",
                    "source_case_id",
                    "run_id",
                    "dataset",
                    "category",
                    "use_case",
                    "risk",
                    "source_scenario_sha256",
                    "input_sha256",
                )
            },
            "final_result": final_result,
            "claims": final_result["claims"],
            "evidence": final_result["evidence"],
            "audit_ref": {
                "sha256": f"{index + 3000:064x}",
                "uri": f"https://staging.example.test/v1/audit/runs/run-{index:03d}",
            },
            "artifact_refs": [],
            "expected_capability_trajectory": expected_trajectory,
            "observed_capability_trajectory": observed_trajectory,
            "tool_trajectory_binding": {
                "release_id": RELEASE_ID,
                "git_sha": GIT_SHA,
                "image_digest": IMAGE_DIGEST,
                "case_id": result_case["case_id"],
                "source_case_id": result_case["source_case_id"],
                "run_id": result_case["run_id"],
                "source_scenario_sha256": result_case["source_scenario_sha256"],
                "input_sha256": result_case["input_sha256"],
                "expected_capability_trajectory_sha256": result_case[
                    "expected_capability_trajectory_sha256"
                ],
                "observed_capability_trajectory_sha256": result_case[
                    "observed_capability_trajectory_sha256"
                ],
            },
            "grader_results": [
                {
                    "type": "evidence_support",
                    "hard_gate": True,
                    "passed": True,
                }
            ],
            "fault_injection_receipt": None,
            "case_contract_sha256": f"{index + 4000:064x}",
        }
        result_case["review_subject"] = review_subject
        result_case["review_subject_sha256"] = canonical_sha256(review_subject)
        result_cases.append(result_case)
    dataset_counts = {
        dataset: sum(case["dataset"] == dataset for case in candidate_cases)
        for dataset, _, _ in dimensions
    }
    manifest: dict[str, object] = {
        "schema_version": "1.3",
        "release_id": RELEASE_ID,
        "git_sha": GIT_SHA,
        "image_digest": IMAGE_DIGEST,
        "suite_manifest_sha256": "c" * 64,
        "offline_results_sha256": "d" * 64,
        "baseline_sha256": "e" * 64,
        "live_datasets": sorted(dataset_counts),
        "dataset_execution_counts": dataset_counts,
        "planned_candidate_case_count": candidate_count,
        "high_risk_candidate_count": candidate_count,
        "candidate_cases": candidate_cases,
        "offline_dataset_sources": {"incident-derived": "offline-hard-control"},
    }
    manifest_digest = canonical_sha256(manifest)
    results: dict[str, object] = {
        "schema_version": "1.3",
        "release_id": RELEASE_ID,
        "candidate_manifest_sha256": manifest_digest,
        "dataset_summary": {
            **{
                dataset: {
                    "source": "staging-api",
                    "total": count,
                    "passed": count,
                    "failed": 0,
                }
                for dataset, count in dataset_counts.items()
            },
            "incident-derived": {
                "source": "offline-hard-control",
                "total": 2,
                "passed": 2,
                "failed": 0,
            },
        },
        "cases": result_cases,
        "metrics": {"hard_gates_pass_rate": 1.0},
    }
    return manifest, results, manifest_digest, canonical_sha256(results)


def _evidence(
    *,
    candidate_count: int = 50,
    review_count: int = 50,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    manifest, results, manifest_digest, results_digest = _candidate(candidate_count=candidate_count)
    result_cases = results["cases"]
    assert isinstance(result_cases, list)
    reviews: list[dict[str, object]] = []
    for index, candidate in enumerate(result_cases[:review_count]):
        assert isinstance(candidate, dict)
        reviews.append(
            {
                "sample_id": f"sample-{index:03d}",
                "subject_sha256": candidate["review_subject_sha256"],
                "case_id": candidate["case_id"],
                "run_id": candidate["run_id"],
                "use_case": candidate["use_case"],
                "risk": candidate["risk"],
                "dataset": candidate["dataset"],
                "category": candidate["category"],
                "reviewer_id": "reviewer-001",
                "reviewed_at": "2026-07-24T10:00:00Z",
                "rubric": {dimension: 5 for dimension in RUBRIC_DIMENSIONS},
                "findings": [],
                "decision": "pass",
            }
        )
    evidence: dict[str, object] = {
        "schema_version": "1.0",
        "evidence_id": "human-review-evidence-001",
        "release_id": RELEASE_ID,
        "candidate_manifest_sha256": manifest_digest,
        "candidate_results_sha256": results_digest,
        "status": "approved",
        "sampling": {
            "strategy": "stratified-risk",
            "population_size": candidate_count,
            "sample_count": review_count,
            "representative_dimensions": ["use_case", "risk", "dataset"],
        },
        "reviewers": [
            {
                "reviewer_id": "reviewer-001",
                "organization": "independent-quality",
                "auth": {
                    "method": "webauthn",
                    "subject": "reviewer-001@quality.example",
                    "authenticated_at": "2026-07-24T08:00:00Z",
                },
            }
        ],
        "reviews": reviews,
        "provenance": {
            "service_id": "independent-human-review",
            "request_id": "review-request-001",
            "evidence_uri": (
                "https://reviews.example.test/v1/release-reviews/review-request-001/evidence"
            ),
            "requested_at": "2026-07-24T09:00:00Z",
            "completed_at": "2026-07-24T10:30:00Z",
            "issued_at": "2026-07-24T10:31:00Z",
            "expires_at": "2026-07-25T10:31:00Z",
        },
    }
    return evidence, manifest, results


def _rebind_candidate(
    evidence: dict[str, object],
    manifest: dict[str, object],
    results: dict[str, object],
) -> None:
    cases = results.get("cases")
    if isinstance(cases, list):
        for row in cases:
            if not isinstance(row, dict):
                continue
            subject = row.get("review_subject")
            if not isinstance(subject, dict):
                continue
            for field in (
                "case_id",
                "source_case_id",
                "run_id",
                "dataset",
                "category",
                "use_case",
                "risk",
                "source_scenario_sha256",
                "input_sha256",
            ):
                if field in row:
                    subject[field] = row[field]
            binding = subject.get("tool_trajectory_binding")
            if isinstance(binding, dict):
                for field in (
                    "case_id",
                    "source_case_id",
                    "run_id",
                    "source_scenario_sha256",
                    "input_sha256",
                    "expected_capability_trajectory_sha256",
                    "observed_capability_trajectory_sha256",
                ):
                    if field in row:
                        binding[field] = row[field]
                binding["release_id"] = RELEASE_ID
                binding["git_sha"] = GIT_SHA
                binding["image_digest"] = IMAGE_DIGEST
            row["review_subject_sha256"] = canonical_sha256(subject)
    manifest_digest = canonical_sha256(manifest)
    results["candidate_manifest_sha256"] = manifest_digest
    evidence["candidate_manifest_sha256"] = manifest_digest
    evidence["candidate_results_sha256"] = canonical_sha256(results)


def test_review_risk_and_dimensions_must_match_the_exact_candidate() -> None:
    evidence, manifest, results = _evidence()
    reviews = evidence["reviews"]
    assert isinstance(reviews, list)
    first = reviews[0]
    assert isinstance(first, dict)
    first["risk"] = "critical" if first["risk"] == "high" else "high"

    with pytest.raises(ValueError, match="HUMAN_REVIEW_RISK_MISMATCH"):
        validate_human_review_evidence(
            evidence,
            schema_path=SCHEMA,
            expected_release_id=RELEASE_ID,
            candidate_manifest=manifest,
            candidate_results=results,
            expected_request_id="review-request-001",
            expected_service_origin="https://reviews.example.test",
            now=NOW,
            maximum_age_seconds=86_400,
        )


def test_review_rejects_50_rows_recycled_from_fewer_than_50_candidate_runs() -> None:
    evidence, manifest, results = _evidence()
    reviews = evidence["reviews"]
    assert isinstance(reviews, list)
    first = reviews[0]
    second = reviews[1]
    assert isinstance(first, dict)
    assert isinstance(second, dict)
    for field in ("case_id", "run_id", "use_case", "risk", "dataset", "category"):
        second[field] = first[field]

    with pytest.raises(ValueError, match="HUMAN_REVIEW_CANDIDATE_SAMPLE_DUPLICATE"):
        validate_human_review_evidence(
            evidence,
            schema_path=SCHEMA,
            expected_release_id=RELEASE_ID,
            candidate_manifest=manifest,
            candidate_results=results,
            expected_request_id="review-request-001",
            expected_service_origin="https://reviews.example.test",
            now=NOW,
            maximum_age_seconds=86_400,
        )


def test_candidate_population_requires_unique_runs_and_authentic_metadata() -> None:
    evidence, manifest, results = _evidence()
    cases = results["cases"]
    assert isinstance(cases, list)
    first = cases[0]
    second = cases[1]
    assert isinstance(first, dict)
    assert isinstance(second, dict)
    second["run_id"] = first["run_id"]
    _rebind_candidate(evidence, manifest, results)

    with pytest.raises(ValueError, match="HUMAN_REVIEW_CANDIDATE_RUN_DUPLICATE"):
        validate_human_review_evidence(
            evidence,
            schema_path=SCHEMA,
            expected_release_id=RELEASE_ID,
            candidate_manifest=manifest,
            candidate_results=results,
            expected_request_id="review-request-001",
            expected_service_origin="https://reviews.example.test",
            now=NOW,
            maximum_age_seconds=86_400,
        )


def test_sampling_dimensions_must_cover_the_declared_candidate_population() -> None:
    evidence, manifest, results = _evidence(candidate_count=52, review_count=50)
    manifest_cases = manifest["candidate_cases"]
    result_cases = results["cases"]
    assert isinstance(manifest_cases, list)
    assert isinstance(result_cases, list)
    manifest_case = manifest_cases[-1]
    result_case = result_cases[-1]
    assert isinstance(manifest_case, dict)
    assert isinstance(result_case, dict)
    manifest_case["use_case"] = "rare_high_risk_use_case"
    result_case["use_case"] = "rare_high_risk_use_case"
    _rebind_candidate(evidence, manifest, results)

    with pytest.raises(ValueError, match="HUMAN_REVIEW_REPRESENTATION_MISMATCH"):
        validate_human_review_evidence(
            evidence,
            schema_path=SCHEMA,
            expected_release_id=RELEASE_ID,
            candidate_manifest=manifest,
            candidate_results=results,
            expected_request_id="review-request-001",
            expected_service_origin="https://reviews.example.test",
            now=NOW,
            maximum_age_seconds=86_400,
        )


def test_candidate_case_requires_authentic_use_case_metadata() -> None:
    evidence, manifest, results = _evidence()
    manifest_cases = manifest["candidate_cases"]
    result_cases = results["cases"]
    assert isinstance(manifest_cases, list)
    assert isinstance(result_cases, list)
    assert isinstance(manifest_cases[0], dict)
    assert isinstance(result_cases[0], dict)
    manifest_cases[0].pop("use_case")
    result_cases[0].pop("use_case")
    _rebind_candidate(evidence, manifest, results)

    with pytest.raises(ValueError, match="HUMAN_REVIEW_CANDIDATE_USE_CASE_REQUIRED"):
        validate_human_review_evidence(
            evidence,
            schema_path=SCHEMA,
            expected_release_id=RELEASE_ID,
            candidate_manifest=manifest,
            candidate_results=results,
            expected_request_id="review-request-001",
            expected_service_origin="https://reviews.example.test",
            now=NOW,
            maximum_age_seconds=86_400,
        )


def test_review_population_size_must_equal_the_high_risk_candidate_population() -> None:
    evidence, manifest, results = _evidence()
    sampling = evidence["sampling"]
    assert isinstance(sampling, dict)
    sampling["population_size"] = 200

    with pytest.raises(ValueError, match="HUMAN_REVIEW_POPULATION_INVALID"):
        validate_human_review_evidence(
            evidence,
            schema_path=SCHEMA,
            expected_release_id=RELEASE_ID,
            candidate_manifest=manifest,
            candidate_results=results,
            expected_request_id="review-request-001",
            expected_service_origin="https://reviews.example.test",
            now=NOW,
            maximum_age_seconds=86_400,
        )


def test_stratified_review_rejects_severely_skewed_candidate_selection() -> None:
    evidence, manifest, results = _evidence(candidate_count=200, review_count=50)
    result_cases = results["cases"]
    reviews = evidence["reviews"]
    assert isinstance(result_cases, list)
    assert isinstance(reviews, list)
    selected = [case for case in result_cases if case["dataset"] == "golden"][:47]
    selected.extend(
        next(case for case in result_cases if case["dataset"] == dataset)
        for dataset in ("edge", "adversarial", "production-sample")
    )
    for review, candidate in zip(reviews, selected, strict=True):
        assert isinstance(review, dict)
        assert isinstance(candidate, dict)
        for field in (
            "case_id",
            "run_id",
            "use_case",
            "risk",
            "dataset",
            "category",
        ):
            review[field] = candidate[field]
        review["subject_sha256"] = candidate["review_subject_sha256"]

    with pytest.raises(ValueError, match="HUMAN_REVIEW_REPRESENTATION_MISMATCH"):
        validate_human_review_evidence(
            evidence,
            schema_path=SCHEMA,
            expected_release_id=RELEASE_ID,
            candidate_manifest=manifest,
            candidate_results=results,
            expected_request_id="review-request-001",
            expected_service_origin="https://reviews.example.test",
            now=NOW,
            maximum_age_seconds=86_400,
        )


def test_exact_release_review_evidence_passes_with_50_unique_rubric_samples() -> None:
    evidence, manifest, results = _evidence()

    metrics = validate_human_review_evidence(
        evidence,
        schema_path=SCHEMA,
        expected_release_id=RELEASE_ID,
        candidate_manifest=manifest,
        candidate_results=results,
        expected_request_id="review-request-001",
        expected_service_origin="https://reviews.example.test",
        now=NOW,
        maximum_age_seconds=86_400,
    )

    assert metrics == {
        "high_risk_human_review_samples": 50,
        "major_human_review_findings": 0,
    }


@pytest.mark.parametrize(
    ("mutation", "error"),
    (
        (("release_id", "stale-release"), "HUMAN_REVIEW_RELEASE_MISMATCH"),
        (
            ("candidate_results_sha256", "f" * 64),
            "HUMAN_REVIEW_RESULTS_DIGEST_MISMATCH",
        ),
        (("status", "rejected"), "HUMAN_REVIEW_NOT_APPROVED"),
    ),
)
def test_review_evidence_rejects_reusable_or_rejected_top_level_claims(
    mutation: tuple[str, str],
    error: str,
) -> None:
    evidence, manifest, results = _evidence()
    evidence[mutation[0]] = mutation[1]

    with pytest.raises(ValueError, match=error):
        validate_human_review_evidence(
            evidence,
            schema_path=SCHEMA,
            expected_release_id=RELEASE_ID,
            candidate_manifest=manifest,
            candidate_results=results,
            expected_request_id="review-request-001",
            expected_service_origin="https://reviews.example.test",
            now=NOW,
            maximum_age_seconds=86_400,
        )


@pytest.mark.parametrize(
    ("mutate", "error"),
    (
        (
            lambda evidence: evidence["reviews"].__setitem__(
                1,
                deepcopy(evidence["reviews"][0]),
            ),
            "HUMAN_REVIEW_SAMPLE_ID_DUPLICATE",
        ),
        (
            lambda evidence: evidence["reviews"][0].__setitem__("run_id", "run-other"),
            "HUMAN_REVIEW_CASE_RUN_MISMATCH",
        ),
        (
            lambda evidence: evidence["reviews"][0]["rubric"].pop("evidence"),
            "HUMAN_REVIEW_SCHEMA_INVALID",
        ),
        (
            lambda evidence: evidence["reviews"][0]["findings"].append(
                {"severity": "major", "code": "UNSUPPORTED_CONCLUSION"}
            ),
            "HUMAN_REVIEW_MAJOR_FINDING",
        ),
        (
            lambda evidence: evidence["provenance"].__setitem__(
                "expires_at",
                "2026-07-24T11:00:00Z",
            ),
            "HUMAN_REVIEW_EXPIRED",
        ),
    ),
)
def test_review_evidence_fails_closed_on_sample_rubric_finding_or_freshness_drift(
    mutate: object,
    error: str,
) -> None:
    evidence, manifest, results = _evidence()
    mutate(evidence)

    with pytest.raises(ValueError, match=error):
        validate_human_review_evidence(
            evidence,
            schema_path=SCHEMA,
            expected_release_id=RELEASE_ID,
            candidate_manifest=manifest,
            candidate_results=results,
            expected_request_id="review-request-001",
            expected_service_origin="https://reviews.example.test",
            now=NOW,
            maximum_age_seconds=86_400,
        )


def test_review_subject_binds_release_identity_source_and_tool_trajectory() -> None:
    _, _, results = _evidence()
    cases = results["cases"]
    assert isinstance(cases, list)
    case = cases[0]
    assert isinstance(case, dict)
    subject = case["review_subject"]
    assert isinstance(subject, dict)

    assert subject["schema_version"] == "1.1"
    assert subject["expected_capability_trajectory"]
    assert subject["observed_capability_trajectory"]
    assert subject["tool_trajectory_binding"] == {
        "release_id": RELEASE_ID,
        "git_sha": GIT_SHA,
        "image_digest": IMAGE_DIGEST,
        "case_id": case["case_id"],
        "source_case_id": case["source_case_id"],
        "run_id": case["run_id"],
        "source_scenario_sha256": case["source_scenario_sha256"],
        "input_sha256": case["input_sha256"],
        "expected_capability_trajectory_sha256": case["expected_capability_trajectory_sha256"],
        "observed_capability_trajectory_sha256": case["observed_capability_trajectory_sha256"],
    }


def test_candidate_review_subject_tampering_fails_before_external_approval() -> None:
    evidence, manifest, results = _evidence()
    cases = results["cases"]
    assert isinstance(cases, list)
    first = cases[0]
    assert isinstance(first, dict)
    subject = first["review_subject"]
    assert isinstance(subject, dict)
    final_result = subject["final_result"]
    assert isinstance(final_result, dict)
    final_result["summary"] = "tampered after review"
    evidence["candidate_results_sha256"] = canonical_sha256(results)

    with pytest.raises(ValueError, match="HUMAN_REVIEW_SUBJECT_DIGEST_INVALID"):
        validate_human_review_evidence(
            evidence,
            schema_path=SCHEMA,
            expected_release_id=RELEASE_ID,
            candidate_manifest=manifest,
            candidate_results=results,
            expected_request_id="review-request-001",
            expected_service_origin="https://reviews.example.test",
            now=NOW,
            maximum_age_seconds=86_400,
        )


def test_review_receipt_must_equal_recomputed_candidate_subject_digest() -> None:
    evidence, manifest, results = _evidence()
    cases = results["cases"]
    assert isinstance(cases, list)
    first = cases[0]
    assert isinstance(first, dict)
    subject = first["review_subject"]
    assert isinstance(subject, dict)
    subject["artifact_refs"] = [
        {
            "artifact_id": "artifact-replaced",
            "sha256": "f" * 64,
            "size_bytes": 1,
        }
    ]
    first["review_subject_sha256"] = canonical_sha256(subject)
    evidence["candidate_results_sha256"] = canonical_sha256(results)

    with pytest.raises(ValueError, match="HUMAN_REVIEW_SUBJECT_DIGEST_MISMATCH"):
        validate_human_review_evidence(
            evidence,
            schema_path=SCHEMA,
            expected_release_id=RELEASE_ID,
            candidate_manifest=manifest,
            candidate_results=results,
            expected_request_id="review-request-001",
            expected_service_origin="https://reviews.example.test",
            now=NOW,
            maximum_age_seconds=86_400,
        )


def test_fetch_waits_for_external_https_review_and_binds_request_digest() -> None:
    evidence, manifest, results = _evidence()
    manifest_digest = canonical_sha256(manifest)
    results_digest = canonical_sha256(results)
    polls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal polls
        assert request.headers["authorization"] == "Bearer review-service-token"
        if request.method == "POST":
            body = request.read().decode()
            assert RELEASE_ID in body
            assert manifest_digest in body
            assert results_digest in body
            assert request.headers["idempotency-key"].startswith("human-review-12345-1-")
            return httpx.Response(
                202,
                json={
                    "request_id": "review-request-001",
                    "status_url": (
                        "https://reviews.example.test/v1/release-reviews/review-request-001"
                    ),
                },
            )
        polls += 1
        if polls == 1:
            return httpx.Response(202, json={"status": "pending"})
        return httpx.Response(200, json=evidence)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        fetched, request_id = fetch_human_review_evidence(
            service_url="https://reviews.example.test/v1/release-reviews",
            token="review-service-token",
            release_id=RELEASE_ID,
            candidate_manifest=manifest,
            candidate_results=results,
            timeout_seconds=5,
            poll_seconds=0,
            client=client,
        )

    assert request_id == "review-request-001"
    assert fetched == evidence
    assert polls == 2


def test_fetch_rejects_non_https_review_service_before_transport() -> None:
    _, manifest, results = _evidence()

    with pytest.raises(ValueError, match="HUMAN_REVIEW_SERVICE_HTTPS_REQUIRED"):
        fetch_human_review_evidence(
            service_url="http://reviews.example.test/v1/release-reviews",
            token="review-service-token",
            release_id=RELEASE_ID,
            candidate_manifest=manifest,
            candidate_results=results,
            timeout_seconds=5,
            poll_seconds=0,
        )
