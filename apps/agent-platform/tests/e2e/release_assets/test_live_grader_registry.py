from __future__ import annotations

from copy import deepcopy

import pytest
from evals.graders.registry import (
    GRADER_REGISTRY,
    evaluate_live_graders,
    fault_plan_for_case,
    validate_grader_config,
)


def _case(*, grader_type: str = "evidence_support") -> dict[str, object]:
    return {
        "case_id": "case-001",
        "source_case_id": "source-001",
        "dataset": "golden",
        "category": "evidence_research",
        "use_case": "evidence_research",
        "risk": "high",
        "source_scenario_sha256": "a" * 64,
        "input": {
            "goal": "Produce a source-backed answer.",
            "allowed_capabilities": ["knowledge.search"],
        },
        "expected": {
            "status": "completed",
            "must_cite_sources": True,
            "minimum_evidence_coverage": 0.99,
        },
        "graders": [{"type": grader_type, "weight": 1.0, "hard_gate": True}],
    }


def _observed() -> dict[str, object]:
    return {
        "status": "completed",
        "evidence": 1,
        "evidence_coverage": 1.0,
        "observation_sources": {
            "snapshot": {
                "sha256": "b" * 64,
                "uri": "https://staging.example.test/v1/runs/run-001",
            },
            "audit": {
                "sha256": "c" * 64,
                "uri": "https://staging.example.test/v1/audit/runs/run-001",
            },
        },
    }


@pytest.mark.parametrize(
    ("grader", "error"),
    (
        (
            {"type": "made_up_grader", "weight": 1.0, "hard_gate": True},
            "LIVE_GRADER_TYPE_UNKNOWN",
        ),
        (
            {"type": "evidence_support", "weight": 1.0},
            "LIVE_GRADER_SCHEMA_INVALID",
        ),
        (
            {
                "type": "evidence_support",
                "weight": 1.0,
                "hard_gate": True,
                "ignored": True,
            },
            "LIVE_GRADER_SCHEMA_INVALID",
        ),
        (
            {"type": "evidence_support", "weight": 0.0, "hard_gate": True},
            "LIVE_GRADER_SCHEMA_INVALID",
        ),
    ),
)
def test_grader_config_is_closed_and_unknown_types_fail_closed(
    grader: dict[str, object],
    error: str,
) -> None:
    with pytest.raises(ValueError, match=error):
        validate_grader_config(grader, case_id="case-001")


def test_every_registered_hard_grader_declares_observation_sources_and_assertions() -> None:
    assert len(GRADER_REGISTRY) >= 50
    for grader_type, spec in GRADER_REGISTRY.items():
        assert spec.observation_sources, grader_type
        assert spec.assertion_ids, grader_type


def test_hard_grader_cannot_pass_without_immutable_snapshot_and_audit_bindings() -> None:
    actual = _observed()
    actual["observation_sources"] = {}

    results = evaluate_live_graders(_case(), actual, baseline={})

    assert len(results) == 1
    assert results[0]["passed"] is False
    assert "observation_source:snapshot" in results[0]["failures"]
    assert "observation_source:audit" in results[0]["failures"]


def test_metric_grader_uses_observed_values_and_release_baseline() -> None:
    case = _case(grader_type="cost_regression")
    case["category"] = "cost_regression_analysis"
    actual = _observed()
    actual["cost_usd"] = 1.16
    actual["observation_sources"]["metrics"] = {
        "sha256": "d" * 64,
        "uri": "https://staging.example.test/v1/audit/runs/run-001#metrics",
    }

    results = evaluate_live_graders(
        case,
        actual,
        baseline={"average_cost_per_success_usd": 1.0, "p95_latency_seconds": 10.0},
    )

    assert results[0]["passed"] is False
    assert "average_cost_regression" in results[0]["failures"]


def test_artifact_integrity_grader_rejects_unverifiable_artifact_metadata() -> None:
    case = _case(grader_type="artifact_integrity")
    case["category"] = "artifact_checksum_mismatch"
    actual = _observed()
    actual["artifact_observations"] = [
        {
            "artifact_id": "artifact-001",
            "sha256": "not-a-digest",
            "size_bytes": 50 * 1024 * 1024,
            "scan_status": "malware_clean",
            "readback_verified": True,
        }
    ]
    actual["observation_sources"]["artifact"] = {
        "sha256": "e" * 64,
        "uri": "https://staging.example.test/v1/artifacts/artifact-001",
    }

    results = evaluate_live_graders(case, actual, baseline={})

    assert results[0]["passed"] is False
    assert "artifact_integrity" in results[0]["failures"]


def test_tool_sequence_grader_requires_exact_capability_trajectory() -> None:
    case = _case(grader_type="tool_sequence")
    case["expected"]["expected_capability_trajectory"] = [
        {
            "sequence": 1,
            "capability": "knowledge.search",
            "arguments": {"limit": 8, "query": "Produce a source-backed answer."},
            "receipt": {
                "status": "succeeded",
                "result_hash_required": True,
                "provider_request_id_required": True,
            },
        }
    ]
    actual = _observed()
    actual["capability_trajectory_passed"] = False
    actual["capability_trajectory_failures"] = ["capability_trajectory_order"]

    results = evaluate_live_graders(case, actual, baseline={})

    assert results[0]["passed"] is False
    assert "capability_trajectory_order" in results[0]["failures"]
    assert results[0]["assertions_executed"] == [
        "expected_contract",
        "capability_trajectory",
    ]


def test_fault_class_grader_requires_exact_release_bound_injection_receipt() -> None:
    case = _case(grader_type="model_recovery")
    case["category"] = "model_fallback_recovery"
    actual = _observed()

    results = evaluate_live_graders(case, actual, baseline={})

    assert results[0]["passed"] is False
    assert "fault_injection_receipt:model" in results[0]["failures"]


@pytest.mark.parametrize(
    ("category", "component", "outcome"),
    (
        ("plan_efficiency", "planner", "recovered"),
        ("worker_checkpoint_resume", "worker", "recovered"),
        ("verifier_repair_loop", "verifier", "recovered"),
        ("approval_bypass", "approval", "fail_closed"),
        ("commit_response_lost", "commit", "recovered"),
        ("model_fallback_recovery", "model", "recovered"),
        ("tool_timeout_recovery", "tool", "recovered"),
        ("database_replica_lag", "database", "recovered"),
        ("artifact_checksum_mismatch", "artifact", "recovered"),
        ("policy_alias_bypass", "opa", "fail_closed"),
    ),
)
def test_fault_case_plan_matches_operational_fault_matrix(
    category: str,
    component: str,
    outcome: str,
) -> None:
    case = deepcopy(_case())
    case["category"] = category

    assert fault_plan_for_case(case) == {
        "component": component,
        "fault_mode": category,
        "expected_outcome": outcome,
    }


@pytest.mark.parametrize("field", ("payload_hashes_valid", "export_actor_observed"))
def test_audit_grader_requires_all_independent_integrity_checks(field: str) -> None:
    case = _case(grader_type="audit_traceability")
    actual = _observed()
    actual["audit_integrity"] = {
        "sequence_contiguous": True,
        "run_binding_verified": True,
        "payload_hashes_valid": True,
        "export_actor_observed": True,
    }
    actual["audit_integrity"][field] = False

    results = evaluate_live_graders(case, actual, baseline={})

    assert results[0]["passed"] is False
    assert "audit_integrity" in results[0]["failures"]


@pytest.mark.parametrize(
    ("grader_type", "observation_name", "observed", "claimed"),
    (
        ("cost_regression", "average_cost_per_success_usd", 1.0, 0.5),
        ("latency_regression", "p95_latency_seconds", 10.0, 5.0),
    ),
)
def test_regression_grader_rejects_tampered_metric_claims(
    grader_type: str,
    observation_name: str,
    observed: float,
    claimed: float,
) -> None:
    case = _case(grader_type=grader_type)
    actual = _observed()
    actual["cost_usd"] = 1.0
    actual["latency_seconds"] = 10.0
    actual["metric_observations"] = {observation_name: observed}
    actual["metric_claims"] = [{"name": observation_name, "value": claimed}]
    actual["observation_sources"]["metrics"] = {
        "sha256": "d" * 64,
        "uri": "https://staging.example.test/v1/audit/runs/run-001#metrics",
    }

    results = evaluate_live_graders(
        case,
        actual,
        baseline={
            "average_cost_per_success_usd": 1.0,
            "p95_latency_seconds": 10.0,
        },
    )

    assert results[0]["passed"] is False
    assert "metric_accuracy" in results[0]["failures"]
