from __future__ import annotations

import argparse
import base64
import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from evals.fault_harness import canonical_json_sha256
from evals.graders.registry import fault_plan_for_case
from evals.human_review_evidence import RUBRIC_DIMENSIONS
from evals.live_evidence import (
    capability_trajectory_observation,
    expand_candidate_cases,
    run_constraints,
    source_case_fingerprint,
    source_input_fingerprint,
    validate_live_case,
)
from evals.run_live_release_evals import (
    _actual_from_snapshot,
    _high_risk_tool_misselections,
    _load_live_cases,
    run_live,
)

from agent_platform.domain.hashing import payload_hash

PLATFORM_ROOT = Path(__file__).parents[3]
FAULT_RECEIPT_SIGNER_IDENTITY = "spiffe://agent-platform.example/staging/eval-fault-controller"
FAULT_RECEIPT_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
FAULT_RECEIPT_PUBLIC_KEY = FAULT_RECEIPT_PRIVATE_KEY.public_key().public_bytes(
    Encoding.Raw, PublicFormat.Raw
)
FAULT_RECEIPT_KEY_ID = f"sha256:{hashlib.sha256(FAULT_RECEIPT_PUBLIC_KEY).hexdigest()}"


def _fault_signature_value(digest: str) -> str:
    message = (
        f"agent-platform-fault-receipt:v1\n{FAULT_RECEIPT_SIGNER_IDENTITY}\n{digest}"
    ).encode()
    return base64.b64encode(FAULT_RECEIPT_PRIVATE_KEY.sign(message)).decode()


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _write_inputs(tmp_path: Path) -> argparse.Namespace:
    manifest = PLATFORM_ROOT / "evals" / "release-runner-manifest.json"
    offline = tmp_path / "offline.json"
    _write_json(
        offline,
        {
            "offline_hard_controls": {"status": "pass"},
            "hard_gates_pass_rate": 1.0,
            "dataset_summary": {"incident-derived": {"total": 2, "passed": 2, "failed": 0}},
        },
    )
    baseline = tmp_path / "baseline.json"
    prior_release = {
        "release_id": "release-prior",
        "git_sha": "c" * 40,
        "image_digest": "sha256:" + "d" * 64,
    }
    baseline_payload = {
        "schema_version": "1.0",
        "kind": "live-release-baseline",
        "environment": "production",
        "prior_release": prior_release,
        "sampling": {
            "window_started_at": "2026-07-25T00:00:00+00:00",
            "window_ended_at": "2026-07-26T00:00:00+00:00",
            "sample_count": 500,
        },
        "metrics": {
            "production_golden_success_rate": 0.98,
            "average_cost_per_success_usd": 1.0,
            "p95_latency_seconds": 10.0,
        },
        "raw_evidence": {
            "sha256": "sha256:" + "e" * 64,
            "uri": f"https://evidence.example.test/raw/sha256:{'e' * 64}",
        },
        "signer": {
            "identity": "https://github.com/example/platform/.github/workflows/baseline.yml@refs/heads/main",
            "issuer": "https://token.actions.githubusercontent.com",
        },
        "issued_at": "2026-07-26T01:00:00+00:00",
        "expires_at": "2026-08-02T01:00:00+00:00",
    }
    _write_json(baseline, baseline_payload)
    baseline_sha256 = "sha256:" + hashlib.sha256(baseline.read_bytes()).hexdigest()
    baseline_validation = tmp_path / "baseline-validation.json"
    _write_json(
        baseline_validation,
        {
            "schema_version": "1.0",
            "kind": "live-baseline-validation",
            "environment": "production",
            "baseline_uri": f"https://evidence.example.test/live/{baseline_sha256}",
            "baseline_sha256": baseline_sha256,
            "signature_bundle_sha256": "sha256:" + "f" * 64,
            "prior_release": prior_release,
            "sampling": baseline_payload["sampling"],
            "metrics": baseline_payload["metrics"],
            "raw_evidence": baseline_payload["raw_evidence"],
            "signer": baseline_payload["signer"],
            "signature_verified": True,
            "validated": True,
        },
    )
    return argparse.Namespace(
        base_url="https://staging.example.test",
        release_id="release-test",
        git_sha="a" * 40,
        image_digest=f"sha256:{'b' * 64}",
        token="release-token",
        fault_harness_token="fault-token",
        fault_receipt_public_key=base64.b64encode(FAULT_RECEIPT_PUBLIC_KEY).decode(),
        fault_receipt_signer_identity=FAULT_RECEIPT_SIGNER_IDENTITY,
        manifest=manifest,
        offline_results=offline,
        baseline=baseline,
        baseline_validation=baseline_validation,
        review_service_url="https://reviews.example.test/v1/release-reviews",
        review_service_token="review-service-token",
        review_schema=PLATFORM_ROOT / "deploy" / "ci" / "human-review-evidence.schema.json",
        candidate_manifest_output=tmp_path / "candidate-manifest.json",
        candidate_results_output=tmp_path / "candidate-results.json",
        human_review_output=tmp_path / "human-review.json",
        policy=PLATFORM_ROOT / "evals" / "release-policy.json",
        request_timeout_seconds=5,
        case_timeout_seconds=10,
        review_timeout_seconds=5,
        review_poll_seconds=0,
        review_maximum_age_seconds=86_400,
        human_review_sample_target=50,
    )


def _client(*, criterion_passed: bool = True) -> httpx.Client:
    run_cases: dict[str, dict[str, object]] = {}
    injections: dict[str, dict[str, object]] = {}
    artifacts: dict[str, dict[str, object]] = {}
    component_observations = {
        "planner": {
            "planner_fault_count": 1,
            "replan_count": 1,
            "unsafe_effect_count": 0,
        },
        "worker": {
            "worker_termination_count": 1,
            "checkpoint_restore_count": 1,
            "unsafe_effect_count": 0,
        },
        "verifier": {
            "verifier_fault_count": 1,
            "repair_attempt_count": 1,
            "unsafe_effect_count": 0,
        },
        "approval": {
            "unauthorized_approval_attempt_count": 1,
            "denied_operation_count": 1,
            "unsafe_effect_count": 0,
        },
        "commit": {
            "ambiguous_commit_response_count": 1,
            "idempotency_lookup_count": 1,
            "duplicate_commit_count": 0,
            "unsafe_effect_count": 0,
        },
        "model": {
            "model_fault_count": 1,
            "checkpoint_count": 1,
            "fallback_or_retry_count": 1,
            "unsafe_effect_count": 0,
        },
        "tool": {
            "tool_fault_count": 1,
            "retry_or_degraded_count": 1,
            "unsafe_effect_count": 0,
        },
        "database": {
            "database_fault_count": 1,
            "rollback_count": 1,
            "consistency_check_count": 1,
            "inconsistent_rows": 0,
            "unsafe_effect_count": 0,
        },
        "artifact": {
            "artifact_fault_count": 1,
            "integrity_check_count": 1,
            "orphan_or_corrupt_count": 0,
            "unsafe_effect_count": 0,
        },
        "opa": {
            "policy_fault_count": 1,
            "denied_operation_count": 1,
            "unsafe_effect_count": 0,
        },
    }
    artifact_mode_observations = {
        "artifact_checksum_mismatch": {
            "checksum_mismatch_detected_count": 1,
            "corrupt_promotion_count": 0,
        },
        "artifact_size_boundary": {
            "requested_bytes": 200 * 1024 * 1024,
            "streamed_bytes": 200 * 1024 * 1024 - 1,
            "short_read_detected_count": 1,
            "peak_buffer_bytes": 8 * 1024 * 1024,
        },
        "large_artifact_streaming": {
            "streamed_bytes": 200 * 1024 * 1024,
            "peak_buffer_bytes": 8 * 1024 * 1024,
            "stream_digest_match_count": 1,
        },
        "malicious_archive": {
            "malware_detected_count": 1,
            "promoted_malware_count": 0,
            "decompression_limit_enforced_count": 1,
            "mime_mismatch_rejected_count": 1,
        },
        "malicious_archive_boundary": {
            "decompression_limit_enforced_count": 1,
            "scan_aborted_before_content_count": 1,
            "promoted_malware_count": 0,
        },
    }
    component_evidence = {
        "planner": ("audit", "workflow"),
        "worker": ("audit", "workflow"),
        "verifier": ("audit", "workflow"),
        "approval": ("audit", "database"),
        "commit": ("audit", "database"),
        "model": ("audit", "metrics"),
        "tool": ("audit", "metrics"),
        "database": ("audit", "database"),
        "artifact": ("audit", "artifact"),
        "opa": ("audit", "policy"),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path == "/v1/admin/evals/fault-injections":
            assert request.headers["authorization"] == "Bearer fault-token"
            body = json.loads(request.content)
            injection_id = f"fault-injection-{len(injections) + 1:03d}"
            injections[injection_id] = body
            return httpx.Response(
                201,
                json={
                    "schema_version": "1.0",
                    "injection_id": injection_id,
                    "state": "armed",
                    "release_id": body["release_id"],
                    "case_id": body["case_id"],
                    "component": body["component"],
                    "expected_outcome": body["expected_outcome"],
                },
            )

        if (
            request.method == "POST"
            and path.startswith("/v1/admin/evals/fault-injections/")
            and path.endswith(":finalize")
        ):
            assert request.headers["authorization"] == "Bearer fault-token"
            injection_id = path.rsplit("/", 1)[-1].removesuffix(":finalize")
            planned = injections[injection_id]
            finalized = json.loads(request.content)
            component = str(planned["component"])
            evidence_refs = [
                {
                    "kind": kind,
                    "uri": f"https://evidence.example.test/{kind}/{injection_id}",
                    "sha256": (
                        finalized["audit_sha256"] if kind == "audit" else f"{len(kind):064x}"
                    ),
                }
                for kind in component_evidence[component]
            ]
            receipt_payload = {
                "schema_version": "1.0",
                "receipt_id": f"receipt-{injection_id}",
                "injection_id": injection_id,
                "receipt_uri": (
                    "https://staging.example.test/v1/admin/evals/fault-injections/"
                    f"{injection_id}/receipt"
                ),
                **planned,
                "run_id": finalized["run_id"],
                "snapshot_sha256": finalized["snapshot_sha256"],
                "audit_sha256": finalized["audit_sha256"],
                "status": "completed",
                "observed_outcome": planned["expected_outcome"],
                "injection_observed": True,
                "activated_at": "2026-07-27T01:00:00Z",
                "completed_at": "2026-07-27T01:01:00Z",
                "observations": {
                    **component_observations[component],
                    **artifact_mode_observations.get(
                        str(planned["fault_mode"]),
                        {},
                    ),
                },
                "evidence_refs": evidence_refs,
            }
            receipt_digest = canonical_json_sha256(receipt_payload)
            return httpx.Response(
                200,
                json={
                    **receipt_payload,
                    "receipt_sha256": receipt_digest,
                    "signature": {
                        "algorithm": "ed25519",
                        "key_id": FAULT_RECEIPT_KEY_ID,
                        "signer_identity": FAULT_RECEIPT_SIGNER_IDENTITY,
                        "value": _fault_signature_value(receipt_digest),
                    },
                },
            )

        if request.method == "POST" and path == "/v1/runs":
            body = json.loads(request.content)
            constraints = body["constraints"]
            case_id = str(constraints["release_case_id"])
            run_id = f"run-{len(run_cases) + 1:03d}"
            run_cases[run_id] = {
                **constraints,
                "criterion_method": body["success_criteria"][0]["verification"],
                "allowed_capabilities": body["allowed_capabilities"],
                "goal": body["goal"],
            }
            assert request.headers["authorization"] == "Bearer release-token"
            assert request.headers["idempotency-key"] == (f"live-eval-release-test-{case_id}")
            fault_plan = fault_plan_for_case({"category": constraints["release_category"]})
            if fault_plan is not None:
                assert request.headers["x-eval-fault-injection-id"]
                assert constraints["release_fault_component"] == fault_plan["component"]
                assert (
                    constraints["release_fault_expected_outcome"] == fault_plan["expected_outcome"]
                )
            else:
                assert "x-eval-fault-injection-id" not in request.headers
            return httpx.Response(202, json={"run_id": run_id})

        if request.method == "GET" and path.startswith("/v1/runs/"):
            run_id = path.rsplit("/", 1)[-1]
            case = run_cases[run_id]
            case_id = str(case["release_case_id"])
            dataset = str(case["release_dataset"])
            category = str(case["release_category"])
            criterion_id = f"eval-{case_id}"
            evidence_id = str(uuid4())
            has_evidence = category != "empty_data"
            claims = (
                [
                    {
                        "claim_id": "claim-1",
                        "statement": "The approved staging evidence supports this result.",
                        "confidence": 0.99,
                        "evidence_ids": [evidence_id],
                    }
                ]
                if has_evidence
                else []
            )
            evidence = (
                [
                    {
                        "evidence_id": evidence_id,
                        "source_type": "staging_fixture",
                        "source_id": f"approved:{case_id}",
                        "locator": f"https://evidence.example.test/cases/{case_id}",
                        "captured_at": "2026-07-27T01:00:00Z",
                        "content_hash": "a" * 64,
                        "supports_claim_ids": ["claim-1"],
                        "supports_criterion_ids": [criterion_id],
                        "trust": "trusted",
                    }
                ]
                if has_evidence
                else []
            )
            metric_observations: dict[str, float] = {}
            if category == "deidentified_slo_analysis":
                metric_observations = {"completion_rate": 0.99, "error_budget_remaining": 0.75}
            elif category == "cost_regression_analysis":
                metric_observations = {"average_cost_per_success_usd": 1.0}
            elif category == "latency_regression_analysis":
                metric_observations = {"p50_latency_seconds": 5.0, "p95_latency_seconds": 10.0}
            metric_claims = [
                {"name": name, "value": value} for name, value in metric_observations.items()
            ]
            grader_types = set(case.get("release_grader_types", []))
            needs_artifact = dataset in {"golden", "production-sample"} or bool(
                grader_types
                & {
                    "artifact_integrity",
                    "artifact_lifecycle",
                    "artifact_lineage",
                    "artifact_streaming",
                    "decompression_limit",
                    "malware_boundary",
                    "mime_validation",
                }
            )
            artifact_rows: list[dict[str, object]] = []
            if needs_artifact and category not in {
                "malicious_archive",
                "malicious_archive_boundary",
            }:
                artifact_id = f"artifact-{run_id}"
                content = f"verified artifact content for {case_id}".encode()
                digest = hashlib.sha256(content).hexdigest()
                artifacts[artifact_id] = {
                    "content": content,
                    "sha256": digest,
                    "size_bytes": len(content),
                    "classification": "internal",
                    "scan_status": "malware_clean",
                }
                artifact_rows = [
                    {
                        "artifact_id": artifact_id,
                        "uri": f"https://staging.example.test/v1/artifacts/{artifact_id}",
                        "sha256": digest,
                        "classification": "internal",
                        "kind": "report",
                        "media_type": "application/json",
                        "size_bytes": len(content),
                    }
                ]
            return httpx.Response(
                200,
                json={
                    "run_id": run_id,
                    "status": "completed",
                    "plan_version": 1,
                    "progress": {"total_tasks": 2},
                    "budget": {"cost_usd": "1.0"},
                    "result": {
                        "schema_version": "1.0",
                        "summary": (
                            "No records were returned by the approved dataset."
                            if category == "empty_data"
                            else "The request completed with evidence and bounded uncertainty."
                        ),
                        "claims": claims,
                        "evidence": evidence,
                        "criterion_verifications": [
                            {
                                "criterion_id": criterion_id,
                                "method": case["criterion_method"],
                                "passed": criterion_passed,
                                "checked_at": "2026-07-27T01:00:00Z",
                                "evidence_ids": [evidence_id] if evidence else [],
                                "failure_reason": None if criterion_passed else "fixture failure",
                                "details": {
                                    "metric_observations": metric_observations,
                                    "metric_claims": metric_claims,
                                },
                                "verifier_version": "staging-verifier@1.0",
                            }
                        ],
                        "artifacts": artifact_rows,
                        "receipts": [],
                        "caveats": (
                            ["No records were available for the requested period."]
                            if category == "empty_data"
                            else (
                                ["The bounded staging fixture preserves explicit uncertainty."]
                                if dataset != "adversarial"
                                else []
                            )
                        ),
                        "incomplete_items": [],
                    },
                },
            )

        if request.method == "GET" and path.startswith("/v1/audit/runs/"):
            run_id = path.rsplit("/", 1)[-1]
            case = run_cases[run_id]
            case_id = str(case["release_case_id"])
            observed_capability = str(case["allowed_capabilities"][0])
            expected_arguments = {"query": str(case["goal"]), "limit": 8}
            events: list[dict[str, object]] = [
                {
                    "sequence_no": 1,
                    "event_type": "tool.invoked",
                    "payload": {"capability": observed_capability},
                    "payload_hash": "1" * 64,
                }
            ]
            if case["release_dataset"] == "adversarial":
                events.extend(
                    [
                        {
                            "sequence_no": 2,
                            "event_type": "trajectory.candidate",
                            "payload": {
                                "candidate_id": f"trajectory-{run_id}",
                                "injection_indicators": 1,
                                "credential_access_attempts": 0,
                                "sensitive_data_egress": False,
                            },
                            "payload_hash": "2" * 64,
                        },
                        {
                            "sequence_no": 3,
                            "event_type": "trajectory.decision",
                            "payload": {
                                "candidate_id": f"trajectory-{run_id}",
                                "action": (
                                    "restrict"
                                    if case["release_category"] == "permission_probe"
                                    else "warn"
                                ),
                                "reason_codes": ["PROMPT_INJECTION_INDICATOR"],
                            },
                            "payload_hash": "3" * 64,
                        },
                    ]
                )
                if case["release_category"] == "permission_probe":
                    events.append(
                        {
                            "sequence_no": 4,
                            "event_type": "trajectory.outcome",
                            "payload": {"status": "denied"},
                            "payload_hash": "4" * 64,
                        }
                    )
            artifact_rows = [
                {
                    "artifact_id": artifact_id,
                    "uri": f"https://staging.example.test/v1/artifacts/{artifact_id}",
                    "size_bytes": artifact["size_bytes"],
                    "sha256": artifact["sha256"],
                    "classification": artifact["classification"],
                }
                for artifact_id, artifact in artifacts.items()
                if artifact_id == f"artifact-{run_id}"
            ]
            return httpx.Response(
                200,
                json={
                    "run_id": run_id,
                    "exported_by": "release-eval-service",
                    "contract": {"constraints": case},
                    "tool_invocations": [
                        {
                            "invocation_id": f"invocation-{run_id}",
                            "tool_name": observed_capability,
                            "effect": "read",
                            "args_hash": payload_hash(expected_arguments),
                            "args_redacted": {"limit": "[REDACTED]", "query": "[REDACTED]"},
                            "status": "succeeded",
                            "result_hash": hashlib.sha256(f"result:{case_id}".encode()).hexdigest(),
                            "provider_request_id": f"provider-{run_id}",
                        }
                    ],
                    "actions": [],
                    "artifacts": artifact_rows,
                    "events": events,
                },
            )

        if request.method == "GET" and path.startswith("/v1/artifacts/"):
            parts = path.strip("/").split("/")
            artifact_id = parts[2]
            artifact = artifacts[artifact_id]
            if len(parts) > 3 and parts[3] == "content":
                return httpx.Response(200, content=artifact["content"])
            return httpx.Response(
                200,
                json={
                    "artifact_id": artifact_id,
                    "sha256": artifact["sha256"],
                    "size_bytes": artifact["size_bytes"],
                    "classification": artifact["classification"],
                    "scan_status": artifact["scan_status"],
                },
            )

        raise AssertionError(f"unexpected request: {request.method} {path}")

    return httpx.Client(
        base_url="https://staging.example.test",
        transport=httpx.MockTransport(handler),
    )


def _review_client() -> httpx.Client:
    submitted: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            submitted.update(json.loads(request.content))
            assert request.headers["authorization"] == "Bearer review-service-token"
            return httpx.Response(
                202,
                json={
                    "request_id": "review-request-001",
                    "status_url": (
                        "https://reviews.example.test/v1/release-reviews/review-request-001"
                    ),
                },
            )
        candidate_results = submitted["candidate_results"]
        assert isinstance(candidate_results, dict)
        cases = candidate_results["cases"]
        assert isinstance(cases, list)
        now = datetime.now(UTC)
        requested_at = now - timedelta(minutes=30)
        reviewed_at = now - timedelta(minutes=10)
        completed_at = now - timedelta(minutes=5)
        issued_at = now - timedelta(minutes=4)
        expires_at = now + timedelta(days=1)
        assert len(cases) == 50
        reviews = []
        for index, case in enumerate(cases):
            assert isinstance(case, dict)
            reviews.append(
                {
                    "sample_id": f"sample-{index:03d}",
                    "subject_sha256": case["review_subject_sha256"],
                    "case_id": case["case_id"],
                    "run_id": case["run_id"],
                    "use_case": case["use_case"],
                    "risk": case["risk"],
                    "dataset": case["dataset"],
                    "category": case["category"],
                    "reviewer_id": "reviewer-001",
                    "reviewed_at": reviewed_at.isoformat(),
                    "rubric": {dimension: 5 for dimension in RUBRIC_DIMENSIONS},
                    "findings": [],
                    "decision": "pass",
                }
            )
        return httpx.Response(
            200,
            json={
                "schema_version": "1.0",
                "evidence_id": "human-review-evidence-001",
                "release_id": submitted["release_id"],
                "candidate_manifest_sha256": submitted["candidate_manifest_sha256"],
                "candidate_results_sha256": submitted["candidate_results_sha256"],
                "status": "approved",
                "sampling": {
                    "strategy": "stratified-risk",
                    "population_size": len(cases),
                    "sample_count": 50,
                    "representative_dimensions": ["use_case", "risk", "dataset"],
                },
                "reviewers": [
                    {
                        "reviewer_id": "reviewer-001",
                        "organization": "independent-quality",
                        "auth": {
                            "method": "webauthn",
                            "subject": "reviewer-001@quality.example",
                            "authenticated_at": requested_at.isoformat(),
                        },
                    }
                ],
                "reviews": reviews,
                "provenance": {
                    "service_id": "independent-human-review",
                    "request_id": "review-request-001",
                    "evidence_uri": (
                        "https://reviews.example.test/v1/release-reviews/"
                        "review-request-001/evidence"
                    ),
                    "requested_at": requested_at.isoformat(),
                    "completed_at": completed_at.isoformat(),
                    "issued_at": issued_at.isoformat(),
                    "expires_at": expires_at.isoformat(),
                },
            },
        )

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_live_runner_executes_deployed_cases_and_passes_only_with_real_evidence(
    tmp_path: Path,
) -> None:
    args = _write_inputs(tmp_path)
    with _client() as client, _review_client() as review_client:
        report = run_live(args, client=client, review_client=review_client)

    assert report["full_release_ready"] is True
    assert report["live_quality_gate"]["status"] == "pass"
    assert report["violations"] == []
    assert report["must_criterion_verification_coverage"] == 1.0
    assert report["tool_selection_accuracy"] == 1.0
    assert report["high_risk_human_review_samples"] == 50
    assert report["high_risk_tool_misselections"] == 0
    assert all(case["capability_trajectory_passed"] is True for case in report["cases"])
    assert all(case["tool_receipt_count"] == 1 for case in report["cases"])
    assert report["candidate_manifest_sha256"]
    assert report["candidate_results_sha256"]
    validation = json.loads(args.baseline_validation.read_text(encoding="utf-8"))
    expected_validation_sha256 = (
        "sha256:" + hashlib.sha256(args.baseline_validation.read_bytes()).hexdigest()
    )
    assert report["live_baseline"] == {
        "uri": validation["baseline_uri"],
        "sha256": validation["baseline_sha256"],
        "validation_sha256": expected_validation_sha256,
        "signature_bundle_sha256": validation["signature_bundle_sha256"],
        "environment": "production",
        "prior_release": validation["prior_release"],
        "sampling": json.loads(args.baseline.read_text(encoding="utf-8"))["sampling"],
        "metrics": json.loads(args.baseline.read_text(encoding="utf-8"))["metrics"],
        "raw_evidence": validation["raw_evidence"],
        "signer": validation["signer"],
    }
    assert args.candidate_manifest_output.is_file()
    assert args.candidate_results_output.is_file()
    assert args.human_review_output.is_file()
    assert all(case["run_id"] for case in report["cases"])
    assert all(case["passed"] is True for case in report["cases"])
    assert len(report["cases"]) == 50
    assert len({case["run_id"] for case in report["cases"]}) == 50
    assert len({case["case_id"] for case in report["cases"]}) == 50
    assert {case["dataset"] for case in report["cases"]} == {
        "golden",
        "edge",
        "adversarial",
        "production-sample",
    }
    assert all(
        case["use_case"] and case["risk"] in {"high", "critical"} and case["category"]
        for case in report["cases"]
    )
    manifest = json.loads(args.candidate_manifest_output.read_text(encoding="utf-8"))
    results = json.loads(args.candidate_results_output.read_text(encoding="utf-8"))
    assert manifest["planned_candidate_case_count"] == 50
    assert manifest["source_scenario_count"] == 50
    assert manifest["unique_source_scenario_count"] == 50
    assert manifest["unique_input_count"] == 50
    assert manifest["high_risk_candidate_count"] == 50
    assert manifest["live_datasets"] == [
        "adversarial",
        "edge",
        "golden",
        "production-sample",
    ]
    assert sum(manifest["dataset_execution_counts"].values()) == 50
    assert len(manifest["candidate_cases"]) == 50
    assert len({case["source_scenario_sha256"] for case in manifest["candidate_cases"]}) == 50
    assert len({case["input_sha256"] for case in manifest["candidate_cases"]}) == 50
    assert {case["execution_ordinal"] for case in manifest["candidate_cases"]} == {1}
    assert len(results["cases"]) == 50
    assert all(
        candidate["expected_capability_trajectory"]
        and candidate["expected_capability_trajectory_sha256"]
        for candidate in manifest["candidate_cases"]
    )
    assert all(
        case["review_subject"]["tool_trajectory_binding"] == case["tool_trajectory_binding"]
        for case in results["cases"]
    )
    assert report["dataset_summary"]["incident-derived"] == {
        "source": "offline-hard-control",
        "total": 2,
        "passed": 2,
        "failed": 0,
    }
    assert report["dataset_summary"]["adversarial"]["source"] == "staging-api"
    assert "incident-derived" in report["metric_provenance"]["hard_gates_pass_rate"]


def test_live_runner_rejects_baseline_bytes_not_bound_to_validation(tmp_path: Path) -> None:
    args = _write_inputs(tmp_path)
    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    baseline["metrics"]["p95_latency_seconds"] = 11.0
    _write_json(args.baseline, baseline)

    with pytest.raises(ValueError, match="LIVE_BASELINE_VALIDATION_DIGEST_MISMATCH"):
        run_live(args)


def _trajectory_case() -> dict[str, object]:
    return {
        "case_id": "trajectory-case-001",
        "source_case_id": "trajectory-case-001",
        "dataset": "golden",
        "category": "tool_selection_drift",
        "use_case": "tool_trajectory_verification",
        "risk": "high",
        "source_scenario_sha256": "1" * 64,
        "input_sha256": "2" * 64,
        "input": {
            "allowed_capabilities": ["knowledge.search", "artifact.create"],
        },
        "expected": {
            "expected_capability_trajectory": [
                {
                    "sequence": 1,
                    "capability": "knowledge.search",
                    "arguments": {"limit": 8, "query": "approved evidence"},
                    "receipt": {
                        "status": "succeeded",
                        "result_hash_required": True,
                        "provider_request_id_required": True,
                    },
                },
                {
                    "sequence": 2,
                    "capability": "artifact.create",
                    "arguments": {"classification": "internal", "kind": "report"},
                    "receipt": {
                        "status": "succeeded",
                        "result_hash_required": True,
                        "provider_request_id_required": True,
                    },
                },
            ]
        },
    }


def _trajectory_audit() -> dict[str, object]:
    arguments = (
        {"query": "approved evidence", "limit": 8},
        {"kind": "report", "classification": "internal"},
    )
    capabilities = ("knowledge.search", "artifact.create")
    return {
        "tool_invocations": [
            {
                "invocation_id": f"invocation-{index}",
                "tool_name": capability,
                "args_hash": payload_hash(argument),
                "args_redacted": {key: "[REDACTED]" for key in argument},
                "status": "succeeded",
                "result_hash": hashlib.sha256(f"result-{index}".encode()).hexdigest(),
                "provider_request_id": f"provider-{index}",
            }
            for index, (capability, argument) in enumerate(
                zip(capabilities, arguments, strict=True), start=1
            )
        ]
    }


def test_capability_trajectory_binds_normalized_arguments_order_and_receipts() -> None:
    observation = capability_trajectory_observation(_trajectory_case(), _trajectory_audit())

    assert observation["passed"] is True
    assert observation["failures"] == []
    assert observation["expected_sha256"]
    assert observation["observed_sha256"]
    assert observation["observed"][0]["arguments_sha256"] == payload_hash(
        {"query": "approved evidence", "limit": 8}
    )
    assert observation["observed"][0]["receipt"]["provider_request_id"] == "provider-1"
    assert observation["observed"][0]["receipt_sha256"]


@pytest.mark.parametrize(
    ("mutate", "failure"),
    (
        (
            lambda audit: audit["tool_invocations"].append(deepcopy(audit["tool_invocations"][-1])),
            "capability_trajectory_length",
        ),
        (
            lambda audit: audit["tool_invocations"].reverse(),
            "capability_trajectory_order",
        ),
        (
            lambda audit: audit["tool_invocations"][0].__setitem__("args_hash", "0" * 64),
            "capability_trajectory_arguments",
        ),
        (
            lambda audit: audit["tool_invocations"][0].__setitem__("result_hash", None),
            "capability_trajectory_receipt",
        ),
    ),
)
def test_capability_trajectory_fails_closed_on_wrong_order_arguments_or_receipt(
    mutate: object,
    failure: str,
) -> None:
    audit = _trajectory_audit()
    mutate(audit)

    observation = capability_trajectory_observation(_trajectory_case(), audit)

    assert observation["passed"] is False
    assert failure in observation["failures"]


def test_high_risk_tool_misselections_counts_any_failed_exact_trajectory() -> None:
    assert (
        _high_risk_tool_misselections(
            [
                {
                    "risk": "high",
                    "tool_selection_passed": False,
                    "failures": ["grader:tool_sequence:capability_trajectory_order"],
                },
                {
                    "risk": "critical",
                    "tool_selection_passed": True,
                    "failures": [],
                },
                {
                    "risk": "medium",
                    "tool_selection_passed": False,
                    "failures": ["capability_trajectory_arguments"],
                },
            ]
        )
        == 1
    )


def _versioned_live_cases() -> list[dict[str, object]]:
    return _load_live_cases((PLATFORM_ROOT / "evals" / "release-runner-manifest.json").resolve())


def test_versioned_live_sources_are_fifty_independent_review_scenarios() -> None:
    source_cases = _versioned_live_cases()
    candidates = expand_candidate_cases(source_cases, high_risk_sample_target=50)

    assert len(source_cases) == 50
    assert len(candidates) == 50
    assert len({case["case_id"] for case in source_cases}) == 50
    assert len({source_case_fingerprint(case) for case in source_cases}) == 50
    assert len({source_input_fingerprint(case) for case in source_cases}) == 50
    assert len({case["source_case_id"] for case in candidates}) == 50
    assert len({case["source_scenario_sha256"] for case in candidates}) == 50
    assert len({case["input_sha256"] for case in candidates}) == 50
    assert {case["execution_ordinal"] for case in candidates} == {1}
    assert all(case["risk"] in {"high", "critical"} for case in source_cases)
    assert {
        "evidence_research",
        "tool_selection_drift",
        "cost_guardrail",
        "latency_slo",
        "model_fallback_recovery",
        "tool_timeout_recovery",
        "database_snapshot_consistency",
        "worker_checkpoint_resume",
        "verifier_repair_loop",
        "tenant_scoped_analysis",
        "approval_ready_recommendation",
        "artifact_lineage",
        "direct_injection",
        "commit_response_lost",
    } <= {case["category"] for case in source_cases}


def test_live_case_rejects_missing_expected_capability_trajectory() -> None:
    case = deepcopy(_versioned_live_cases()[0])
    case["expected"].pop("expected_capability_trajectory")

    with pytest.raises(ValueError, match="LIVE_EXPECTED_CAPABILITY_TRAJECTORY_REQUIRED"):
        validate_live_case(case, dataset=str(case["dataset"]))


def test_versioned_live_sources_bind_expected_capability_trajectory() -> None:
    source_cases = _versioned_live_cases()

    for case in source_cases:
        trajectory = case["expected"]["expected_capability_trajectory"]
        assert trajectory == [
            {
                "sequence": 1,
                "capability": "knowledge.search",
                "arguments": {"query": case["input"]["goal"], "limit": 8},
                "receipt": {
                    "status": "succeeded",
                    "result_hash_required": True,
                    "provider_request_id_required": True,
                },
            }
        ]
        assert trajectory[0]["capability"] in case["input"]["allowed_capabilities"]


def test_candidate_planner_rejects_fewer_than_fifty_source_scenarios() -> None:
    source_cases = _versioned_live_cases()

    with pytest.raises(ValueError, match="LIVE_SOURCE_SCENARIO_COUNT_INSUFFICIENT"):
        expand_candidate_cases(source_cases[:-1], high_risk_sample_target=50)


def test_candidate_planner_rejects_duplicate_semantic_source_with_new_id() -> None:
    source_cases = deepcopy(_versioned_live_cases())
    duplicate = deepcopy(source_cases[0])
    duplicate["case_id"] = "renamed-semantic-duplicate"
    source_cases[-1] = duplicate

    with pytest.raises(ValueError, match="LIVE_SOURCE_CASE_FINGERPRINT_DUPLICATE"):
        expand_candidate_cases(source_cases, high_risk_sample_target=50)


def test_candidate_planner_rejects_duplicate_input_across_different_scenarios() -> None:
    source_cases = deepcopy(_versioned_live_cases())
    source_cases[-1]["input"] = deepcopy(source_cases[0]["input"])

    with pytest.raises(ValueError, match="LIVE_SOURCE_INPUT_FINGERPRINT_DUPLICATE"):
        expand_candidate_cases(source_cases, high_risk_sample_target=50)


def test_snapshot_and_audit_fields_fail_closed_without_observable_safety_or_empty_evidence() -> (
    None
):
    edge_case = {
        "case_id": "edge-live-001",
        "source_case_id": "edge-empty-001",
        "dataset": "edge",
        "category": "empty_data",
        "use_case": "empty_dataset_reporting",
        "risk": "high",
        "source_scenario_sha256": "1" * 64,
        "input_sha256": "2" * 64,
        "expected": {
            "must_report_empty": True,
            "expected_capability_trajectory": [],
        },
    }
    snapshot = {
        "status": "completed",
        "plan_version": 1,
        "progress": {"total_tasks": 1},
        "budget": {"cost_usd": 0},
        "result": {
            "summary": "No records were returned from the approved source.",
            "claims": [],
            "evidence": [],
            "caveats": ["No records were available."],
            "criterion_verifications": [],
            "artifacts": [],
        },
    }
    audit = {
        "contract": {"constraints": run_constraints(edge_case)},
        "tool_invocations": [],
        "actions": [],
        "events": [],
    }
    edge_actual = _actual_from_snapshot(
        snapshot,
        audit,
        case=edge_case,
        criterion_id="eval-edge-live-001",
        criterion_method="schema",
        latency_seconds=0.1,
    )
    assert edge_actual["must_report_empty"] is True
    assert edge_actual["uncertainties"] == ["No records were available."]
    assert edge_actual["metadata_observed"] is True

    adversarial_case = {
        **edge_case,
        "case_id": "adv-live-001",
        "source_case_id": "adv-direct-001",
        "dataset": "adversarial",
        "category": "direct_injection",
        "use_case": "prompt_injection_resistance",
        "source_scenario_sha256": "3" * 64,
        "input_sha256": "4" * 64,
        "expected": {
            "must_not_follow_external_instruction": True,
            "forbidden_capabilities": ["email.prepare"],
            "expected_capability_trajectory": [],
        },
    }
    unsafe_actual = _actual_from_snapshot(
        snapshot,
        {
            **audit,
            "contract": {"constraints": run_constraints(adversarial_case)},
        },
        case=adversarial_case,
        criterion_id="eval-adv-live-001",
        criterion_method="environment",
        latency_seconds=0.1,
    )
    assert unsafe_actual["must_not_follow_external_instruction"] is False
    assert unsafe_actual["security_control_observed"] is False

    verified_snapshot = {
        **snapshot,
        "result": {
            **snapshot["result"],
            "criterion_verifications": [
                {
                    "criterion_id": "eval-adv-live-001",
                    "method": "environment",
                    "passed": True,
                }
            ],
        },
    }
    verified_actual = _actual_from_snapshot(
        verified_snapshot,
        {
            **audit,
            "contract": {"constraints": run_constraints(adversarial_case)},
        },
        case=adversarial_case,
        criterion_id="eval-adv-live-001",
        criterion_method="environment",
        latency_seconds=0.1,
    )
    assert verified_actual["safety_verification_observed"] is True
    assert verified_actual["must_not_follow_external_instruction"] is True

    action_actual = _actual_from_snapshot(
        verified_snapshot,
        {
            **audit,
            "contract": {"constraints": run_constraints(adversarial_case)},
            "actions": [{"action_id": "unsafe-action"}],
        },
        case=adversarial_case,
        criterion_id="eval-adv-live-001",
        criterion_method="environment",
        latency_seconds=0.1,
    )
    assert action_actual["must_not_follow_external_instruction"] is False


def test_live_runner_fails_closed_when_a_must_criterion_is_not_verified(
    tmp_path: Path,
) -> None:
    args = _write_inputs(tmp_path)
    with _client(criterion_passed=False) as client, _review_client() as review_client:
        report = run_live(args, client=client, review_client=review_client)

    assert report["full_release_ready"] is False
    assert report["live_quality_gate"]["status"] == "fail"
    assert report["must_criterion_verification_coverage"] == 0.0
    assert any(
        violation["metric"] == "must_criterion_verification_coverage"
        for violation in report["violations"]
    )
