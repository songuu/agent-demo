from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

PLATFORM_ROOT = Path(__file__).parents[3]
VALIDATOR = PLATFORM_ROOT / "deploy" / "ci" / "validate_canary_evidence.py"
SCHEMA = PLATFORM_ROOT / "deploy" / "ci" / "canary-evidence.schema.json"
POLICY = PLATFORM_ROOT / "deploy" / "ci" / "canary-policy.yaml"
GIT_SHA = "a" * 40
IMAGE_DIGEST = f"sha256:{'b' * 64}"
RELEASE_ID = "12345-1"

PHASES = (
    ("shadow", 900),
    ("internal", 1800),
    ("1%", 14400),
    ("10%", 28800),
    ("50%", 14400),
)


def _evidence() -> dict[str, Any]:
    policy_digest = "sha256:" + hashlib.sha256(POLICY.read_bytes()).hexdigest()
    total_duration = sum(duration for _, duration in PHASES)
    cursor = datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=total_duration + 300)
    metric_policy = {
        "request_success_rate_percent": ("gte", 99, 99.9),
        "p95_latency_regression_percent": ("lte", 20, 10),
        "cost_regression_percent": ("lte", 15, 5),
        "error_budget_burn_rate": ("lte", 1, 0.5),
        "critical_safety_alerts": ("eq", 0, 0),
        "duplicate_external_side_effects": ("eq", 0, 0),
    }
    phases: list[dict[str, Any]] = []
    for phase_index, (phase_id, duration) in enumerate(PHASES):
        started_at = cursor
        completed_at = started_at + timedelta(seconds=duration)
        metrics_sha256 = f"sha256:{phase_index + 1:064x}"
        phases.append(
            {
                "id": phase_id,
                "status": "completed",
                "started_at": started_at.isoformat().replace("+00:00", "Z"),
                "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
                "minimum_observation_seconds": duration,
                "observed_duration_seconds": duration,
                "traffic": "copied" if phase_id == "shadow" else phase_id,
                "metrics_uri": (f"https://rollouts.example.test/metrics/{metrics_sha256}"),
                "metrics_sha256": metrics_sha256,
                "metrics": [
                    {
                        "id": metric_id,
                        "status": "passed",
                        "comparison": comparison,
                        "observed": observed,
                        "threshold": threshold,
                        "sample_count": 100,
                        "query_id": f"{phase_id}-{metric_id}",
                        "source": "prometheus-query-api",
                        "window_started_at": started_at.isoformat().replace("+00:00", "Z"),
                        "window_completed_at": completed_at.isoformat().replace("+00:00", "Z"),
                    }
                    for metric_id, (comparison, threshold, observed) in metric_policy.items()
                ],
                "stop_conditions_clear": True,
                "rollback_ready": True,
            }
        )
        cursor = completed_at
    stop_observations = {
        "any_hard_gate_failure": (0, 0),
        "sev1_or_sev2_safety_alert": (0, 0),
        "slo_fast_burn": (False, False),
        "duplicate_external_side_effect": (0, 0),
    }
    return {
        "schema_version": "1.1",
        "release_id": RELEASE_ID,
        "git_sha": GIT_SHA,
        "image_digest": IMAGE_DIGEST,
        "controller": {
            "provider": "example-managed-rollouts",
            "product": "traffic-controller",
            "kind": "progressive-delivery-controller",
            "rollout_id": "rollout-20260724-001",
            "identity": "spiffe://example.test/release-controller",
            "evidence_uri": (f"https://rollouts.example.test/controller/sha256:{'c' * 64}"),
            "external": True,
        },
        "policy": {
            "version": "1.1",
            "uri": f"https://rollouts.example.test/policy/{policy_digest}",
            "sha256": policy_digest,
        },
        "started_at": phases[0]["started_at"],
        "completed_at": phases[-1]["completed_at"],
        "phases": phases,
        "rollback_owner": {
            "actor": "production-rollback-owner",
            "role": "sre",
            "authentication": {
                "assurance": "phishing-resistant",
                "method": "webauthn",
            },
            "authenticated_at": phases[0]["started_at"],
            "acknowledged_at": phases[0]["started_at"],
            "runbook_version": "release-rollback@1.0",
            "rollback_target_digest": f"sha256:{'d' * 64}",
            "evidence_uri": (f"https://rollouts.example.test/rollback/sha256:{'e' * 64}"),
        },
        "stop_conditions": [
            {
                "id": condition,
                "status": "clear",
                "evaluated_at": phases[-1]["completed_at"],
                "comparison": "eq",
                "observed": observed,
                "threshold": threshold,
                "query_id": f"stop-{condition}",
                "source": "prometheus-alert-api",
                "sample_count": 100,
                "evidence_sha256": f"sha256:{index + 100:064x}",
                "evidence_uri": (
                    f"https://rollouts.example.test/stop-conditions/sha256:{index + 100:064x}"
                ),
            }
            for index, (condition, (observed, threshold)) in enumerate(stop_observations.items())
        ],
        "signer": {
            "identity": "https://github.com/example/release-controller/.github/workflows/canary.yml@refs/heads/main",
            "issuer": "https://token.actions.githubusercontent.com",
        },
        "result": "passed",
        "generated_at": phases[-1]["completed_at"],
    }


def _run(tmp_path: Path, evidence: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    evidence_path = tmp_path / "canary-evidence.json"
    signature_bundle_path = tmp_path / "canary-evidence.json.sigstore.json"
    report_path = tmp_path / "validation-report.json"
    payload = json.dumps(
        evidence,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    evidence_path.write_bytes(payload)
    signature_bundle_path.write_bytes(b'{"bundle":"verified-test-fixture"}')
    source_sha256 = "sha256:" + hashlib.sha256(payload).hexdigest()
    return subprocess.run(  # noqa: S603 - repository-owned validator and fixed interpreter
        [
            sys.executable,
            str(VALIDATOR),
            "--evidence",
            str(evidence_path),
            "--signature-bundle",
            str(signature_bundle_path),
            "--schema",
            str(SCHEMA),
            "--policy",
            str(POLICY),
            "--source-uri",
            f"https://rollouts.example.test/evidence/{source_sha256}",
            "--expected-release-id",
            RELEASE_ID,
            "--expected-git-sha",
            GIT_SHA,
            "--expected-image-digest",
            IMAGE_DIGEST,
            "--expected-signer-identity",
            str(evidence["signer"]["identity"]),
            "--expected-signer-issuer",
            str(evidence["signer"]["issuer"]),
            "--minimum-observation-seconds",
            str(sum(duration for _, duration in PHASES)),
            "--maximum-age-seconds",
            "86400",
            "--output",
            str(report_path),
        ],
        capture_output=True,
        check=False,
        text=True,
    )


def test_canary_evidence_schema_is_a_valid_draft_2020_12_schema() -> None:
    Draft202012Validator.check_schema(json.loads(SCHEMA.read_text(encoding="utf-8")))


def test_canary_validator_accepts_complete_external_controller_evidence(
    tmp_path: Path,
) -> None:
    completed = _run(tmp_path, _evidence())

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert '"validated": true' in completed.stdout
    report = json.loads((tmp_path / "validation-report.json").read_text(encoding="utf-8"))
    assert report["signature_bundle_sha256"] == (
        "sha256:" + hashlib.sha256(b'{"bundle":"verified-test-fixture"}').hexdigest()
    )


def test_canary_validator_rejects_wrong_digest_and_release_identity(tmp_path: Path) -> None:
    evidence = _evidence()
    evidence["image_digest"] = f"sha256:{'c' * 64}"
    evidence["release_id"] = "other-release"

    blocked = _run(tmp_path, evidence)

    assert blocked.returncode == 2
    assert "CANARY_RELEASE_ID_MISMATCH" in blocked.stderr
    assert "CANARY_IMAGE_DIGEST_MISMATCH" in blocked.stderr


def test_canary_validator_uses_timestamps_not_claimed_duration(tmp_path: Path) -> None:
    evidence = _evidence()
    phase = evidence["phases"][2]
    phase["completed_at"] = (
        (datetime.fromisoformat(phase["started_at"].replace("Z", "+00:00")) + timedelta(hours=1))
        .isoformat()
        .replace("+00:00", "Z")
    )

    blocked = _run(tmp_path, evidence)

    assert blocked.returncode == 2
    assert "CANARY_PHASE_OBSERVATION_TOO_SHORT: 1%" in blocked.stderr


def test_canary_validator_rejects_missing_phase_or_triggered_stop_condition(
    tmp_path: Path,
) -> None:
    evidence = _evidence()
    evidence["phases"] = evidence["phases"][:-1]
    evidence["stop_conditions"][0]["status"] = "triggered"

    blocked = _run(tmp_path, evidence)

    assert blocked.returncode == 2
    assert "CANARY_PHASE_SEQUENCE_MISMATCH" in blocked.stderr
    assert "CANARY_STOP_CONDITION_TRIGGERED" in blocked.stderr


def test_canary_validator_rejects_unusable_rollback_target(tmp_path: Path) -> None:
    evidence = _evidence()
    evidence["rollback_owner"]["rollback_target_digest"] = IMAGE_DIGEST

    blocked = _run(tmp_path, evidence)

    assert blocked.returncode == 2
    assert "CANARY_ROLLBACK_TARGET_NOT_PREVIOUS_RELEASE" in blocked.stderr


def test_canary_schema_requires_signed_embedded_metric_and_stop_observations() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    assert schema["properties"]["schema_version"]["const"] == "1.1"
    assert "signer" in schema["required"]
    phase = schema["properties"]["phases"]["items"]
    assert {"metrics_sha256", "metrics", "metrics_uri"} <= set(phase["required"])
    condition = schema["properties"]["stop_conditions"]["items"]
    assert {
        "comparison",
        "observed",
        "threshold",
        "query_id",
        "source",
        "sample_count",
        "evidence_sha256",
    } <= set(condition["required"])


def test_canary_validator_rejects_stale_or_mutable_evidence_references(
    tmp_path: Path,
) -> None:
    evidence = _evidence()
    evidence["generated_at"] = "2026-01-01T00:00:00Z"
    evidence["phases"][0]["metrics_uri"] = "https://rollouts.example.test/metrics/mutable.json"

    blocked = _run(tmp_path, evidence)

    assert blocked.returncode == 2
    assert "CANARY_EVIDENCE_EXPIRED" in blocked.stderr
    assert "CANARY_PHASE_METRICS_URI_DIGEST_MISMATCH: shadow" in blocked.stderr
