"""Run credentialed model-quality evaluations against a deployed staging API."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import os
import re
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from statistics import fmean
from typing import Any

import httpx

PLATFORM_ROOT = Path(__file__).resolve().parents[1]
if str(PLATFORM_ROOT) not in sys.path:
    sys.path.insert(0, str(PLATFORM_ROOT))

from evals.fault_harness import (  # noqa: E402
    finalize_fault_injection,
    prepare_fault_injection,
    validate_fault_receipt,
)
from evals.graders.registry import (  # noqa: E402
    GRADER_REGISTRY,
    evaluate_live_graders,
    fault_plan_for_case,
)
from evals.graders.release_gate import evaluate  # noqa: E402
from evals.human_review_evidence import (  # noqa: E402
    canonical_sha256,
    fetch_human_review_evidence,
    validate_human_review_evidence,
)
from evals.live_evidence import (  # noqa: E402
    LIVE_DATASETS,
    candidate_manifest_metadata,
    criterion_method,
    expand_candidate_cases,
    observed_capabilities,
    require_incident_summary,
    run_constraints,
    staging_dataset_summary,
    validate_live_case,
)
from evals.live_evidence import (  # noqa: E402
    actual_from_snapshot as _derive_actual_from_snapshot,
)
from evals.live_observations import (  # noqa: E402
    build_review_subject,
    derive_live_observations,
)
from evals.live_observations import (  # noqa: E402
    canonical_sha256 as observation_sha256,
)
from evals.run_release_evals import (  # noqa: E402
    _load_json,
    _load_jsonl,
    _resolve_dataset_path,
)

JsonObject = dict[str, Any]
TERMINAL_STATUSES = {"completed", "failed", "cancelled"}


def _request_json(
    client: httpx.Client,
    method: str,
    path: str,
    *,
    expected_status: int,
    **kwargs: Any,
) -> JsonObject:
    response = client.request(method, path, **kwargs)
    if response.status_code != expected_status:
        raise RuntimeError(
            f"{method} {path} returned {response.status_code}, "
            f"expected {expected_status}: {response.text[:1_000]}"
        )
    value = response.json()
    if not isinstance(value, dict):
        raise RuntimeError(f"{method} {path} did not return a JSON object")
    return value


def _load_live_cases(manifest_path: Path) -> list[JsonObject]:
    manifest = _load_json(manifest_path)
    cases: list[JsonObject] = []
    for dataset in sorted(LIVE_DATASETS):
        entry = manifest["datasets"].get(dataset)
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError(f"LIVE_DATASET_MISSING: {dataset}")
        for case in _load_jsonl(_resolve_dataset_path(manifest_path, entry["path"])):
            validate_live_case(case, dataset=dataset)
            cases.append(case)
    if not cases:
        raise ValueError("LIVE_DATASETS_EMPTY")
    return cases


def _file_sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _load_validated_live_baseline(args: argparse.Namespace) -> tuple[JsonObject, JsonObject]:
    baseline_path = args.baseline.resolve()
    validation_path = args.baseline_validation.resolve()
    baseline = _load_json(baseline_path)
    validation = _load_json(validation_path)
    baseline_sha256 = _file_sha256(baseline_path)
    validation_sha256 = _file_sha256(validation_path)

    if validation.get("validated") is not True:
        raise ValueError("LIVE_BASELINE_VALIDATION_REQUIRED")
    if validation.get("signature_verified") is not True:
        raise ValueError("LIVE_BASELINE_SIGNATURE_VALIDATION_REQUIRED")
    if validation.get("baseline_sha256") != baseline_sha256:
        raise ValueError("LIVE_BASELINE_VALIDATION_DIGEST_MISMATCH")
    for field in (
        "environment",
        "prior_release",
        "sampling",
        "metrics",
        "raw_evidence",
        "signer",
    ):
        if validation.get(field) != baseline.get(field):
            raise ValueError(f"LIVE_BASELINE_VALIDATION_BINDING_MISMATCH: {field}")

    baseline_uri = validation.get("baseline_uri")
    if (
        not isinstance(baseline_uri, str)
        or re.fullmatch(r"https://[^\s@?#]+/sha256:[0-9a-f]{64}", baseline_uri) is None
    ):
        raise ValueError("LIVE_BASELINE_VALIDATION_URI_INVALID")
    if not baseline_uri.endswith(baseline_sha256):
        raise ValueError("LIVE_BASELINE_VALIDATION_URI_DIGEST_MISMATCH")
    signature_bundle_sha256 = validation.get("signature_bundle_sha256")
    if (
        not isinstance(signature_bundle_sha256, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", signature_bundle_sha256) is None
    ):
        raise ValueError("LIVE_BASELINE_SIGNATURE_BUNDLE_DIGEST_INVALID")

    return baseline, {
        "uri": baseline_uri,
        "sha256": baseline_sha256,
        "validation_sha256": validation_sha256,
        "signature_bundle_sha256": signature_bundle_sha256,
        "environment": baseline["environment"],
        "prior_release": baseline["prior_release"],
        "sampling": baseline["sampling"],
        "metrics": baseline["metrics"],
        "raw_evidence": baseline["raw_evidence"],
        "signer": baseline["signer"],
    }


def _headers(
    token: str,
    *,
    idempotency_key: str | None = None,
    fault_injection_id: str | None = None,
) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {token}"}
    if idempotency_key is not None:
        headers["Idempotency-Key"] = idempotency_key
        headers["Content-Type"] = "application/json"
    if fault_injection_id is not None:
        headers["X-Eval-Fault-Injection-ID"] = fault_injection_id
    return headers


def _run_body(
    case: JsonObject,
    timeout_seconds: int,
    *,
    fault_injection_id: str | None = None,
) -> JsonObject:
    constraints = {
        **run_constraints(case),
        "release_grader_types": sorted(str(grader["type"]) for grader in case["graders"]),
    }
    fault_plan = fault_plan_for_case(case)
    if fault_injection_id is not None and fault_plan is not None:
        constraints = {
            **constraints,
            "release_fault_injection_id": fault_injection_id,
            "release_fault_component": fault_plan["component"],
            "release_fault_expected_outcome": fault_plan["expected_outcome"],
        }
    return {
        "goal": case["input"]["goal"],
        "success_criteria": [
            {
                "id": f"eval-{case['case_id']}",
                "description": (
                    "The live output satisfies the versioned release case and "
                    "links every material claim to approved evidence."
                ),
                "severity": "must",
                "verification": criterion_method(case),
            }
        ],
        "allowed_capabilities": case["input"]["allowed_capabilities"],
        "constraints": constraints,
        "budget": {
            "max_cost_usd": "5.000000",
            "max_duration_seconds": min(timeout_seconds, 900),
            "max_tool_calls": 30,
        },
        "external_write_policy": case["input"].get("external_write_policy", "deny"),
        "requested_output": {"format": "market_report@1.0"},
    }


def _observed_capabilities(audit: JsonObject) -> list[str]:
    return observed_capabilities(audit)


def _actual_from_snapshot(
    snapshot: JsonObject,
    audit: JsonObject,
    *,
    case: JsonObject,
    criterion_id: str,
    criterion_method: str,
    latency_seconds: float,
) -> JsonObject:
    return _derive_actual_from_snapshot(
        snapshot,
        audit,
        case=case,
        criterion_id=criterion_id,
        criterion_method_name=criterion_method,
        latency_seconds=latency_seconds,
    )


def _requires_observation_source(case: JsonObject, source: str) -> bool:
    return any(
        source in GRADER_REGISTRY[str(grader["type"])].observation_sources
        for grader in case["graders"]
    )


def _artifact_ids(snapshot: JsonObject, audit: JsonObject) -> list[str]:
    result = snapshot.get("result")
    final = result if isinstance(result, dict) else {}
    ids: set[str] = set()
    for collection in (final.get("artifacts"), audit.get("artifacts")):
        if not isinstance(collection, list):
            continue
        for row in collection:
            if isinstance(row, dict):
                value = row.get("artifact_id")
                if isinstance(value, str) and value:
                    ids.add(value)
    return sorted(ids)


def _fetch_artifact_observations(
    client: httpx.Client,
    *,
    token: str,
    snapshot: JsonObject,
    audit: JsonObject,
) -> list[JsonObject]:
    observations: list[JsonObject] = []
    for artifact_id in _artifact_ids(snapshot, audit):
        metadata = _request_json(
            client,
            "GET",
            f"/v1/artifacts/{artifact_id}",
            expected_status=200,
            headers=_headers(token),
        )
        digest = str(metadata.get("sha256", "")).removeprefix("sha256:")
        size_bytes = metadata.get("size_bytes")
        if re.fullmatch(r"[a-f0-9]{64}", digest) is None:
            raise RuntimeError(f"LIVE_ARTIFACT_DIGEST_INVALID: {artifact_id}")
        if not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes < 0:
            raise RuntimeError(f"LIVE_ARTIFACT_SIZE_INVALID: {artifact_id}")
        content_path = f"/v1/artifacts/{artifact_id}/content/sha256:{digest}"
        content_hash = hashlib.sha256()
        read_size = 0
        with client.stream(
            "GET",
            content_path,
            headers=_headers(token),
        ) as response:
            if response.status_code != 200:
                raise RuntimeError(
                    f"LIVE_ARTIFACT_READBACK_FAILED: {artifact_id}: {response.status_code}"
                )
            for chunk in response.iter_bytes():
                content_hash.update(chunk)
                read_size += len(chunk)
        observations.append(
            {
                "artifact_id": artifact_id,
                "sha256": digest,
                "size_bytes": size_bytes,
                "scan_status": metadata.get("scan_status"),
                "readback_verified": (
                    content_hash.hexdigest() == digest and read_size == size_bytes
                ),
                "classification": metadata.get("classification"),
                "content_uri": f"{str(client.base_url).rstrip('/')}{content_path}",
            }
        )
    return observations


def _observation_sources(
    client: httpx.Client,
    *,
    run_id: str,
    snapshot: JsonObject,
    audit: JsonObject,
    actual: JsonObject,
) -> JsonObject:
    base_url = str(client.base_url).rstrip("/")
    sources: JsonObject = {
        "snapshot": {
            "sha256": observation_sha256(snapshot),
            "uri": f"{base_url}/v1/runs/{run_id}",
        },
        "audit": {
            "sha256": observation_sha256(audit),
            "uri": f"{base_url}/v1/audit/runs/{run_id}",
        },
        "metrics": {
            "sha256": observation_sha256(
                {
                    "budget": snapshot.get("budget"),
                    "latency_seconds": actual.get("latency_seconds"),
                    "metric_observations": actual.get("metric_observations"),
                }
            ),
            "uri": f"{base_url}/v1/audit/runs/{run_id}#metric-observations",
        },
    }
    artifacts = actual.get("artifact_observations")
    if isinstance(artifacts, list) and artifacts:
        sources["artifact"] = {
            "sha256": observation_sha256(artifacts),
            "uri": str(artifacts[0]["content_uri"]),
        }
    return sources


def _receipt_evidence_uri(receipt: JsonObject, kind: str) -> str | None:
    refs = receipt.get("evidence_refs")
    if not isinstance(refs, list):
        return None
    for row in refs:
        if isinstance(row, dict) and row.get("kind") == kind and isinstance(row.get("uri"), str):
            return str(row["uri"])
    return None


def _execute_case(
    client: httpx.Client,
    case: JsonObject,
    *,
    token: str,
    fault_token: str,
    fault_verification_public_key: bytes,
    fault_signer_identity: str,
    release_id: str,
    git_sha: str,
    image_digest: str,
    timeout_seconds: int,
) -> JsonObject:
    fault_plan = fault_plan_for_case(case)
    prepared: JsonObject | None = None
    if fault_plan is not None:
        prepared = prepare_fault_injection(
            client,
            token=fault_token,
            release_id=release_id,
            git_sha=git_sha,
            image_digest=image_digest,
            case_id=str(case["case_id"]),
            source_scenario_sha256=str(case["source_scenario_sha256"]),
            component=str(fault_plan["component"]),
            fault_mode=str(fault_plan["fault_mode"]),
            expected_outcome=str(fault_plan["expected_outcome"]),
        )
    injection_id = str(prepared["injection_id"]) if prepared is not None else None
    accepted = _request_json(
        client,
        "POST",
        "/v1/runs",
        expected_status=202,
        headers=_headers(
            token,
            idempotency_key=f"live-eval-{release_id}-{case['case_id']}",
            fault_injection_id=injection_id,
        ),
        json=_run_body(
            case,
            timeout_seconds,
            fault_injection_id=injection_id,
        ),
    )
    run_id = accepted.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise RuntimeError(f"LIVE_EVAL_RUN_ID_MISSING: {case['case_id']}")
    deadline = time.monotonic() + timeout_seconds
    started = time.monotonic()
    while True:
        snapshot = _request_json(
            client,
            "GET",
            f"/v1/runs/{run_id}",
            expected_status=200,
            headers=_headers(token),
        )
        status = str(snapshot.get("status", ""))
        if status in TERMINAL_STATUSES or (case["dataset"] == "adversarial" and status == "paused"):
            audit = _request_json(
                client,
                "GET",
                f"/v1/audit/runs/{run_id}",
                expected_status=200,
                headers=_headers(token),
            )
            criterion_id = f"eval-{case['case_id']}"
            actual = {
                **_actual_from_snapshot(
                    snapshot,
                    audit,
                    case=case,
                    criterion_id=criterion_id,
                    criterion_method=criterion_method(case),
                    latency_seconds=time.monotonic() - started,
                ),
                **derive_live_observations(
                    snapshot,
                    audit,
                    run_id=run_id,
                    criterion_id=criterion_id,
                ),
            }
            if _requires_observation_source(case, "artifact"):
                actual["artifact_observations"] = _fetch_artifact_observations(
                    client,
                    token=token,
                    snapshot=snapshot,
                    audit=audit,
                )
            actual["observation_sources"] = _observation_sources(
                client,
                run_id=run_id,
                snapshot=snapshot,
                audit=audit,
                actual=actual,
            )
            if prepared is not None and fault_plan is not None:
                receipt = finalize_fault_injection(
                    client,
                    token=fault_token,
                    injection_id=str(prepared["injection_id"]),
                    run_id=run_id,
                    snapshot_sha256=str(actual["snapshot_sha256"]),
                    audit_sha256=str(actual["audit_sha256"]),
                )
                validate_fault_receipt(
                    receipt,
                    verification_public_key=fault_verification_public_key,
                    expected_signer_identity=fault_signer_identity,
                    expected_release_id=release_id,
                    expected_git_sha=git_sha,
                    expected_image_digest=image_digest,
                    expected_case_id=str(case["case_id"]),
                    expected_source_scenario_sha256=str(case["source_scenario_sha256"]),
                    expected_component=str(fault_plan["component"]),
                    expected_fault_mode=str(fault_plan["fault_mode"]),
                    expected_outcome=str(fault_plan["expected_outcome"]),
                    expected_run_id=run_id,
                    expected_snapshot_sha256=str(actual["snapshot_sha256"]),
                    expected_audit_sha256=str(actual["audit_sha256"]),
                )
                actual["fault_injection_receipt"] = receipt
                actual["observation_sources"]["fault"] = {
                    "sha256": receipt["receipt_sha256"],
                    "uri": receipt["receipt_uri"],
                }
                if "artifact" not in actual["observation_sources"]:
                    artifact_uri = _receipt_evidence_uri(receipt, "artifact")
                    if artifact_uri is not None:
                        actual["observation_sources"]["artifact"] = {
                            "sha256": receipt["receipt_sha256"],
                            "uri": artifact_uri,
                        }
            return {"run_id": run_id, **actual}
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"LIVE_EVAL_TIMEOUT: case={case['case_id']}, run={run_id}, status={status}"
            )
        time.sleep(2)


def _high_risk_tool_misselections(case_reports: list[JsonObject]) -> int:
    return sum(
        row.get("risk") in {"high", "critical"} and row.get("tool_selection_passed") is not True
        for row in case_reports
    )


def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[max(math.ceil(len(ordered) * 0.95) - 1, 0)]


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _candidate_identity(args: argparse.Namespace) -> tuple[str, str]:
    git_sha = str(args.git_sha).strip().lower()
    image_digest = str(args.image_digest).strip().lower()
    if re.fullmatch(r"[a-f0-9]{40}", git_sha) is None:
        raise ValueError("LIVE_CANDIDATE_GIT_SHA_INVALID")
    if re.fullmatch(r"sha256:[a-f0-9]{64}", image_digest) is None:
        raise ValueError("LIVE_CANDIDATE_IMAGE_DIGEST_INVALID")
    return git_sha, image_digest


def _fault_credentials(
    args: argparse.Namespace,
    cases: list[JsonObject],
) -> tuple[str, bytes, str]:
    if not any(fault_plan_for_case(case) is not None for case in cases):
        return "", b"", ""
    token = str(
        getattr(args, "fault_harness_token", "")
        or os.environ.get("AGENT_PLATFORM_EVAL_FAULT_TOKEN", "")
    )
    encoded_key = str(
        getattr(args, "fault_receipt_public_key", "")
        or os.environ.get("AGENT_PLATFORM_EVAL_FAULT_RECEIPT_PUBLIC_KEY_B64", "")
    )
    signer_identity = str(
        getattr(args, "fault_receipt_signer_identity", "")
        or os.environ.get("AGENT_PLATFORM_EVAL_FAULT_RECEIPT_SIGNER_IDENTITY", "")
    )
    if not token:
        raise ValueError("AGENT_PLATFORM_EVAL_FAULT_TOKEN_REQUIRED")
    if not encoded_key:
        raise ValueError("AGENT_PLATFORM_EVAL_FAULT_RECEIPT_PUBLIC_KEY_REQUIRED")
    if not signer_identity.strip():
        raise ValueError("AGENT_PLATFORM_EVAL_FAULT_RECEIPT_SIGNER_IDENTITY_REQUIRED")
    if re.fullmatch(r"spiffe://[^\s]+", signer_identity) is None:
        raise ValueError("EVAL_FAULT_RECEIPT_SIGNER_IDENTITY_INVALID")
    try:
        key = base64.b64decode(encoded_key, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("EVAL_FAULT_RECEIPT_PUBLIC_KEY_INVALID") from exc
    if len(key) != 32:
        raise ValueError("EVAL_FAULT_RECEIPT_PUBLIC_KEY_INVALID")
    return token, key, signer_identity


def run_live(
    args: argparse.Namespace,
    *,
    client: httpx.Client | None = None,
    review_client: httpx.Client | None = None,
) -> JsonObject:
    token = args.token or os.environ.get("AGENT_PLATFORM_RELEASE_TOKEN", "")
    if not token:
        raise ValueError("AGENT_PLATFORM_RELEASE_TOKEN_REQUIRED")
    review_token = args.review_service_token or os.environ.get(
        "AGENT_PLATFORM_HUMAN_REVIEW_TOKEN",
        "",
    )
    if not review_token:
        raise ValueError("HUMAN_REVIEW_SERVICE_TOKEN_REQUIRED")
    git_sha, image_digest = _candidate_identity(args)
    base_cases = _load_live_cases(args.manifest.resolve())
    sample_target = int(getattr(args, "human_review_sample_target", 50))
    cases = expand_candidate_cases(
        base_cases,
        high_risk_sample_target=sample_target,
    )
    suite_manifest = _load_json(args.manifest.resolve())
    offline = _load_json(args.offline_results.resolve())
    if offline.get("offline_hard_controls", {}).get("status") != "pass":
        raise ValueError("OFFLINE_HARD_CONTROLS_NOT_PASSED")
    incident_summary = require_incident_summary(offline)
    baseline, baseline_binding = _load_validated_live_baseline(args)
    baseline_metrics = baseline["metrics"]
    if not isinstance(baseline_metrics, dict):
        raise ValueError("LIVE_BASELINE_METRICS_INVALID")
    baseline_cost = float(baseline_metrics["average_cost_per_success_usd"])
    baseline_p95 = float(baseline_metrics["p95_latency_seconds"])
    if baseline_cost <= 0 or baseline_p95 <= 0:
        raise ValueError("LIVE_BASELINE_MUST_BE_POSITIVE")

    owns_client = client is None
    live_client = client or httpx.Client(
        base_url=args.base_url.rstrip("/"),
        timeout=httpx.Timeout(args.request_timeout_seconds),
        follow_redirects=False,
    )
    fault_token, fault_verification_public_key, fault_signer_identity = _fault_credentials(
        args,
        cases,
    )
    case_reports: list[JsonObject] = []
    try:
        for case in cases:
            grader_results: list[JsonObject] = []
            try:
                actual = _execute_case(
                    live_client,
                    case,
                    token=token,
                    fault_token=fault_token,
                    fault_verification_public_key=fault_verification_public_key,
                    fault_signer_identity=fault_signer_identity,
                    release_id=args.release_id,
                    git_sha=git_sha,
                    image_digest=image_digest,
                    timeout_seconds=args.case_timeout_seconds,
                )
                grader_results = evaluate_live_graders(
                    case,
                    actual,
                    baseline=baseline_metrics,
                )
                failures = [
                    f"grader:{grader['type']}:{failure}"
                    for grader in grader_results
                    for failure in grader["failures"]
                    if grader["hard_gate"]
                ]
                tool_selection_passed = actual.get("capability_trajectory_passed") is True
                if not tool_selection_passed:
                    trajectory_failures = actual.get("capability_trajectory_failures")
                    if not isinstance(trajectory_failures, list) or not trajectory_failures:
                        trajectory_failures = ["capability_trajectory_observation"]
                    failures.extend(f"tool_trajectory:{failure}" for failure in trajectory_failures)
                if not bool(actual.get("metadata_observed")):
                    failures.append("candidate_metadata_observation")
                if float(actual["must_criterion_verification_coverage"]) < 1.0:
                    failures.append("must_criterion_verification_coverage")
            except Exception as exc:
                actual = {"control": type(exc).__name__}
                failures = [f"runner_error:{type(exc).__name__}:{exc}"]
                tool_selection_passed = False
            case_report: JsonObject = {
                "release_id": args.release_id,
                "git_sha": git_sha,
                "image_digest": image_digest,
                "case_id": case["case_id"],
                "source_case_id": case["source_case_id"],
                "dataset": case["dataset"],
                "category": case["category"],
                "use_case": case["use_case"],
                "risk": case["risk"],
                "execution_ordinal": case["execution_ordinal"],
                "source_scenario_sha256": case["source_scenario_sha256"],
                "input_sha256": case["input_sha256"],
                "passed": not failures,
                "failures": sorted(set(failures)),
                "tool_selection_passed": tool_selection_passed,
                "grader_results": grader_results,
                **actual,
            }
            if isinstance(case_report.get("run_id"), str):
                case_report["tool_trajectory_binding"] = {
                    "release_id": args.release_id,
                    "git_sha": git_sha,
                    "image_digest": image_digest,
                    "case_id": case_report["case_id"],
                    "source_case_id": case_report["source_case_id"],
                    "run_id": case_report["run_id"],
                    "source_scenario_sha256": case_report["source_scenario_sha256"],
                    "input_sha256": case_report["input_sha256"],
                    "expected_capability_trajectory_sha256": case_report[
                        "expected_capability_trajectory_sha256"
                    ],
                    "observed_capability_trajectory_sha256": case_report[
                        "observed_capability_trajectory_sha256"
                    ],
                }
                review_subject = build_review_subject(
                    release_id=args.release_id,
                    case=case,
                    case_report=case_report,
                )
                case_report["review_subject"] = review_subject
                case_report["review_subject_sha256"] = canonical_sha256(review_subject)
            case_reports.append(case_report)
    finally:
        if owns_client:
            live_client.close()

    golden = [row for row in case_reports if row["dataset"] == "golden"]
    successful = [row for row in case_reports if row.get("status") == "completed"]
    evidence_cases = [
        row
        for row in case_reports
        if any(
            case["case_id"] == row["case_id"] and case["expected"].get("must_cite_sources")
            for case in cases
        )
    ]
    live_hard_rate = (
        sum(bool(row["passed"]) for row in case_reports) / len(case_reports)
        if case_reports
        else 0.0
    )
    current_cost = fmean(float(row.get("cost_usd", 0)) for row in successful) if successful else 0.0
    current_p95 = _p95([float(row.get("latency_seconds", 0)) for row in successful])
    base_metrics: JsonObject = {
        "hard_gates_pass_rate": min(
            float(offline.get("hard_gates_pass_rate", 0)),
            live_hard_rate,
        ),
        "golden_success_rate": (
            sum(bool(row["passed"]) for row in golden) / len(golden) if golden else 0.0
        ),
        "production_golden_success_rate": float(baseline_metrics["production_golden_success_rate"]),
        "evidence_coverage": (
            fmean(float(row.get("evidence_coverage", 0)) for row in evidence_cases)
            if evidence_cases
            else 0.0
        ),
        "must_criterion_verification_coverage": (
            fmean(float(row.get("must_criterion_verification_coverage", 0)) for row in case_reports)
            if case_reports
            else 0.0
        ),
        "tool_selection_accuracy": (
            sum(bool(row["tool_selection_passed"]) for row in case_reports) / len(case_reports)
            if case_reports
            else 0.0
        ),
        "high_risk_tool_misselections": _high_risk_tool_misselections(case_reports),
        "average_cost_regression": max(current_cost / baseline_cost - 1, 0.0),
        "p95_latency_regression": max(current_p95 / baseline_p95 - 1, 0.0),
    }
    dataset_summary = staging_dataset_summary(case_reports)
    dataset_summary["incident-derived"] = incident_summary
    staging_source = f"{args.base_url.rstrip('/')}/v1/runs + immutable /v1/audit/runs/{{run_id}}"
    metric_provenance: dict[str, str] = {
        "hard_gates_pass_rate": (
            f"{args.offline_results}: incident-derived offline hard control; "
            f"{staging_source}: golden+edge+adversarial+production-sample"
        ),
        "golden_success_rate": staging_source,
        "evidence_coverage": staging_source,
        "must_criterion_verification_coverage": staging_source,
        "tool_selection_accuracy": staging_source,
        "high_risk_tool_misselections": staging_source,
        "production_golden_success_rate": str(baseline_binding["uri"]),
        "average_cost_regression": (f"{staging_source}; baseline={baseline_binding['uri']}"),
        "p95_latency_regression": (f"{staging_source}; baseline={baseline_binding['uri']}"),
    }
    fault_injection_plan = [
        {
            "case_id": case["case_id"],
            "source_scenario_sha256": case["source_scenario_sha256"],
            **plan,
        }
        for case in cases
        if (plan := fault_plan_for_case(case)) is not None
    ]
    fault_receipts = [
        {
            "case_id": row["case_id"],
            "run_id": row["run_id"],
            "component": receipt["component"],
            "fault_mode": receipt["fault_mode"],
            "observed_outcome": receipt["observed_outcome"],
            "snapshot_sha256": receipt["snapshot_sha256"],
            "audit_sha256": receipt["audit_sha256"],
            "receipt_sha256": receipt["receipt_sha256"],
            "receipt_uri": receipt["receipt_uri"],
        }
        for row in case_reports
        if isinstance((receipt := row.get("fault_injection_receipt")), dict)
    ]
    candidate_manifest: JsonObject = {
        "schema_version": "1.3",
        "release_id": args.release_id,
        "git_sha": git_sha,
        "image_digest": image_digest,
        "suite_manifest_sha256": canonical_sha256(suite_manifest),
        "offline_results_sha256": canonical_sha256(offline),
        "baseline_sha256": baseline_binding["sha256"],
        "live_baseline": baseline_binding,
        "fault_injection_plan": fault_injection_plan,
        "fault_injection_receipts": fault_receipts,
        **candidate_manifest_metadata(cases),
    }
    candidate_manifest_digest = canonical_sha256(candidate_manifest)
    review_subject_digests = [
        str(row["review_subject_sha256"])
        for row in case_reports
        if isinstance(row.get("review_subject_sha256"), str)
    ]
    candidate_results: JsonObject = {
        "schema_version": "1.3",
        "release_id": args.release_id,
        "candidate_manifest_sha256": candidate_manifest_digest,
        "generated_at": datetime.now(UTC).isoformat(),
        "live_baseline": baseline_binding,
        "dataset_summary": dataset_summary,
        "cases": case_reports,
        "fault_injection_receipts": fault_receipts,
        "review_subject_set_sha256": canonical_sha256(review_subject_digests),
        "metrics": base_metrics,
        "metric_provenance": metric_provenance,
    }
    candidate_results_digest = canonical_sha256(candidate_results)
    _write_json(args.candidate_manifest_output.resolve(), candidate_manifest)
    _write_json(args.candidate_results_output.resolve(), candidate_results)
    if len(review_subject_digests) != len(case_reports):
        raise ValueError("LIVE_CANDIDATE_REVIEW_SUBJECT_INCOMPLETE")
    if len(fault_receipts) != len(fault_injection_plan):
        raise ValueError("LIVE_CANDIDATE_FAULT_RECEIPT_INCOMPLETE")

    review_evidence, review_request_id = fetch_human_review_evidence(
        service_url=args.review_service_url,
        token=review_token,
        release_id=args.release_id,
        candidate_manifest=candidate_manifest,
        candidate_results=candidate_results,
        timeout_seconds=args.review_timeout_seconds,
        poll_seconds=args.review_poll_seconds,
        client=review_client,
    )
    # Preserve the external response for diagnosis even when semantic validation fails.
    _write_json(args.human_review_output.resolve(), review_evidence)
    review_metrics = validate_human_review_evidence(
        review_evidence,
        schema_path=args.review_schema.resolve(),
        expected_release_id=args.release_id,
        candidate_manifest=candidate_manifest,
        candidate_results=candidate_results,
        expected_request_id=review_request_id,
        expected_service_origin=args.review_service_url,
        maximum_age_seconds=args.review_maximum_age_seconds,
    )

    metrics: JsonObject = {**base_metrics, **review_metrics}
    violations = evaluate(_load_json(args.policy.resolve()), metrics)
    ready = not violations and all(bool(row["passed"]) for row in case_reports)
    review_uri = review_evidence["provenance"]["evidence_uri"]
    final_metric_provenance = {
        **metric_provenance,
        "major_human_review_findings": review_uri,
        "high_risk_human_review_samples": review_uri,
    }
    return {
        "schema_version": "1.3",
        "mode": "live",
        "generated_at": datetime.now(UTC).isoformat(),
        "release_id": args.release_id,
        "git_sha": git_sha,
        "image_digest": image_digest,
        "candidate_manifest_sha256": candidate_manifest_digest,
        "candidate_results_sha256": candidate_results_digest,
        "human_review_evidence_sha256": canonical_sha256(review_evidence),
        "human_review_request_id": review_request_id,
        "live_baseline": baseline_binding,
        "live_quality_gate": {"status": "pass" if ready else "fail"},
        "full_release_ready": ready,
        "violations": violations,
        "dataset_summary": dataset_summary,
        "cases": case_reports,
        **metrics,
        "metric_provenance": final_metric_provenance,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run credentialed Agent Platform live release evaluations"
    )
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--git-sha", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--token", default="")
    parser.add_argument(
        "--fault-harness-token",
        default="",
        help="Dedicated staging fault-injection token (or AGENT_PLATFORM_EVAL_FAULT_TOKEN)",
    )
    parser.add_argument(
        "--fault-receipt-public-key",
        default="",
        help=(
            "Base64 raw Ed25519 public key (or AGENT_PLATFORM_EVAL_FAULT_RECEIPT_PUBLIC_KEY_B64)"
        ),
    )
    parser.add_argument(
        "--fault-receipt-signer-identity",
        default="",
        help=(
            "Fixed controller signer identity "
            "(or AGENT_PLATFORM_EVAL_FAULT_RECEIPT_SIGNER_IDENTITY)"
        ),
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=PLATFORM_ROOT / "evals" / "release-runner-manifest.json",
    )
    parser.add_argument("--offline-results", required=True, type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--baseline-validation", required=True, type=Path)
    parser.add_argument("--review-service-url", required=True)
    parser.add_argument("--review-service-token", default="")
    parser.add_argument(
        "--review-schema",
        type=Path,
        default=PLATFORM_ROOT / "deploy" / "ci" / "human-review-evidence.schema.json",
    )
    parser.add_argument("--candidate-manifest-output", required=True, type=Path)
    parser.add_argument("--candidate-results-output", required=True, type=Path)
    parser.add_argument("--human-review-output", required=True, type=Path)
    parser.add_argument(
        "--policy",
        type=Path,
        default=PLATFORM_ROOT / "evals" / "release-policy.json",
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--request-timeout-seconds", type=int, default=30)
    parser.add_argument("--case-timeout-seconds", type=int, default=900)
    parser.add_argument("--review-timeout-seconds", type=int, default=18_000)
    parser.add_argument("--review-poll-seconds", type=float, default=30.0)
    parser.add_argument("--review-maximum-age-seconds", type=int, default=86_400)
    parser.add_argument(
        "--human-review-sample-target",
        type=int,
        default=50,
        help="Unique high/critical candidate runs required for external review (50-100)",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        report = run_live(args)
    except (OSError, ValueError, RuntimeError, httpx.HTTPError) as exc:
        print(f"live release evaluation failed: {exc}", file=sys.stderr)
        return 3
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "mode": "live",
                "status": report["live_quality_gate"]["status"],
                "output": str(args.output),
                "full_release_ready": report["full_release_ready"],
            },
            sort_keys=True,
        )
    )
    return 0 if report["full_release_ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
