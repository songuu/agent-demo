from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

PLATFORM_ROOT = Path(__file__).parents[3]
RUNNER = PLATFORM_ROOT / "evals" / "run_release_evals.py"
POLICY = PLATFORM_ROOT / "evals" / "release-policy.json"
RELEASE_GATE = PLATFORM_ROOT / "evals" / "graders" / "release_gate.py"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.pop("OPENAI_API_KEY", None)
    return subprocess.run(  # noqa: S603 - repository-owned executable and arguments
        [sys.executable, str(RUNNER), *args],
        cwd=PLATFORM_ROOT,
        capture_output=True,
        check=False,
        env=environment,
        text=True,
    )


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def test_offline_runner_executes_every_local_dataset_and_writes_gate_metrics(
    tmp_path: Path,
) -> None:
    output = tmp_path / "offline-results.json"

    completed = _run("--mode", "offline", "--output", str(output))

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    expected_datasets = {
        "smoke",
        "golden",
        "edge",
        "adversarial",
        "synthetic",
        "incident-derived",
        "production-sample",
    }
    assert set(report["dataset_summary"]) == expected_datasets
    assert all(item["failed"] == 0 for item in report["dataset_summary"].values())
    assert report["offline_hard_controls"]["status"] == "pass"
    assert report["live_quality_gate"]["status"] == "not_run"
    assert report["full_release_ready"] is False

    required_metrics = {
        "hard_gates_pass_rate",
        "golden_success_rate",
        "production_golden_success_rate",
        "evidence_coverage",
        "must_criterion_verification_coverage",
        "tool_selection_accuracy",
        "high_risk_tool_misselections",
        "average_cost_regression",
        "p95_latency_regression",
        "major_human_review_findings",
        "high_risk_human_review_samples",
    }
    assert required_metrics <= report.keys()
    assert report["hard_gates_pass_rate"] == 1.0
    assert report["must_criterion_verification_coverage"] == 1.0
    assert all(
        item["must_criterion_verification_coverage"] == 1.0
        for item in report["cases"]
        if item["control"] == "DeterministicAgentRuntime"
    )
    assert report["high_risk_human_review_samples"] == 0
    assert report["major_human_review_findings"] == 0
    assert {item["control"] for item in report["cases"]} >= {
        "DeterministicAgentRuntime",
        "TrajectoryMonitor",
        "validate_plan_against_contract",
    }

    gate = subprocess.run(  # noqa: S603 - repository-owned executable and arguments
        [
            sys.executable,
            str(RELEASE_GATE),
            "--policy",
            str(POLICY),
            "--results",
            str(output),
        ],
        cwd=PLATFORM_ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    assert gate.returncode == 2
    assert "high_risk_human_review_samples" in gate.stdout


def test_offline_runner_does_not_hardcode_pass_for_changed_expectations(
    tmp_path: Path,
) -> None:
    case = _load_jsonl(PLATFORM_ROOT / "evals" / "datasets" / "offline-smoke.jsonl")[0]
    case["expected"]["status"] = "failed"
    dataset = tmp_path / "tampered-smoke.jsonl"
    dataset.write_text(json.dumps(case) + "\n", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "datasets": {
                    "smoke": {
                        "path": str(dataset),
                        "purpose": "negative contract test",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "results.json"

    completed = _run(
        "--mode",
        "offline",
        "--manifest",
        str(manifest),
        "--output",
        str(output),
    )

    assert completed.returncode == 2
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["offline_hard_controls"]["status"] == "fail"
    assert report["cases"][0]["passed"] is False
    assert "status" in report["cases"][0]["failures"]


def test_offline_runner_rejects_unknown_grader_type(
    tmp_path: Path,
) -> None:
    case = _load_jsonl(PLATFORM_ROOT / "evals" / "datasets" / "offline-smoke.jsonl")[0]
    case["graders"] = [{"type": "self_report_only", "weight": 1.0, "hard_gate": True}]
    dataset = tmp_path / "unknown-grader.jsonl"
    dataset.write_text(json.dumps(case) + "\n", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "datasets": {
                    "smoke": {
                        "path": str(dataset),
                        "purpose": "unknown grader negative contract test",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "results.json"

    completed = _run(
        "--mode",
        "offline",
        "--manifest",
        str(manifest),
        "--output",
        str(output),
    )

    assert completed.returncode == 2
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["offline_hard_controls"]["status"] == "fail"
    assert "LIVE_GRADER_TYPE_UNKNOWN" in report["cases"][0]["failures"][0]


def test_manifest_declares_offline_and_live_release_gate_boundaries() -> None:
    manifest = json.loads(
        (PLATFORM_ROOT / "evals" / "release-runner-manifest.json").read_text(encoding="utf-8")
    )

    assert manifest["execution_modes"]["offline"]["requires_api_key"] is False
    assert manifest["execution_modes"]["live"]["requires_api_key"] is True
    assert manifest["execution_modes"]["live"]["human_review_is_external"] is True
    fault = manifest["execution_modes"]["live"]["fault_injection_contract"]
    assert fault["environment"] == "staging"
    assert set(fault["authorization"]) == {
        "eval:fault:inject",
        "eval:fault:read",
        "admin",
        "mfa",
    }
    assert fault["receipt_integrity"] == "ed25519"
    assert fault["receipt_schema"] == "evals/fault-receipt.schema.json"
    assert fault["verifier"]["private_key_available_to_runner"] is False
    assert fault["verifier"]["private_key_available_to_workflow"] is False
    assert set(fault["components"]) == {
        "planner",
        "worker",
        "verifier",
        "approval",
        "commit",
        "model",
        "tool",
        "database",
        "artifact",
        "opa",
    }
    source_contract = manifest["execution_modes"]["live"]["source_scenario_contract"]
    assert source_contract == {
        "minimum_scenarios": 50,
        "one_candidate_run_per_source": True,
        "unique_case_ids": True,
        "unique_source_scenario_sha256": True,
        "unique_input_sha256": True,
    }
    trajectory = manifest["execution_modes"]["live"]["expected_capability_trajectory_contract"]
    assert trajectory["dataset_field"] == "expected.expected_capability_trajectory"
    assert trajectory["argument_normalization"] == ("agent_platform.domain.hashing.payload_hash")
    assert set(trajectory["receipt_fields"]) == {
        "invocation_id",
        "status",
        "result_hash",
        "provider_request_id",
    }
    assert {
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
    } == set(trajectory["exact_binding"])
    review = manifest["execution_modes"]["live"]["human_review_contract"]
    assert review["schema"] == "deploy/ci/human-review-evidence.schema.json"
    assert review["review_subject_schema_version"] == "1.1"
    assert review["minimum_samples"] == 50
    assert review["maximum_samples"] == 100
    assert review["minimum_unique_candidate_runs"] == 50
    assert set(review["representative_dimensions"]) == {"use_case", "risk", "dataset"}
    assert set(review["exact_binding"]) == {
        "release_id",
        "candidate_manifest_sha256",
        "candidate_results_sha256",
        "case_id",
        "run_id",
        "use_case",
        "risk",
        "dataset",
        "category",
        "review_subject_sha256",
    }
    assert set(manifest["execution_modes"]["live"]["live_datasets"]) == {
        "golden",
        "edge",
        "adversarial",
        "production-sample",
    }
    assert manifest["execution_modes"]["live"]["offline_service_backed_datasets"] == [
        "incident-derived"
    ]
    assert set(review["rubric_dimensions"]) == {
        "correctness",
        "completeness",
        "evidence",
        "uncertainty",
        "action_quality",
        "expression",
    }
    assert "smoke" in manifest["datasets"]


def test_offline_entrypoint_routes_live_mode_to_credentialed_runner(
    tmp_path: Path,
) -> None:
    output = tmp_path / "live-results.json"

    completed = _run("--mode", "live", "--output", str(output))

    assert completed.returncode == 3
    assert "evals/run_live_release_evals.py" in completed.stderr
    assert "AGENT_PLATFORM_RELEASE_TOKEN" in completed.stderr
    assert not output.exists()
