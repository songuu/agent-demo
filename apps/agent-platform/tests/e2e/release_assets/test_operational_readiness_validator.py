from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import pytest
from deploy.ci.validate_operational_readiness import (
    GATE_CHECK_POLICIES,
    GATE_SCOPE_POLICIES,
    RAW_COUNT_SAMPLE_CHECKS,
    validate_gate_reports,
)
from jsonschema import Draft202012Validator

PLATFORM_ROOT = Path(__file__).parents[3]
VALIDATOR = PLATFORM_ROOT / "deploy" / "ci" / "validate_operational_readiness.py"
SCHEMA = PLATFORM_ROOT / "deploy" / "ci" / "operational-readiness.schema.json"
GATE_REPORT_SCHEMA = PLATFORM_ROOT / "deploy" / "ci" / "operational-gate-report.schema.json"
RAW_EVIDENCE_SCHEMA = PLATFORM_ROOT / "deploy" / "ci" / "operational-raw-evidence.schema.json"
RELEASE_ID = "12345-1"
GIT_SHA = "a" * 40
IMAGE_DIGEST = f"sha256:{'b' * 64}"
MIB = 1024 * 1024
CAPACITY_SCENARIO_NAMES = {
    "ten_x_burst_one_minute",
    "one_hundred_concurrent_long_runs",
    "tool_p95_five_x",
    "persistent_429",
    "artifact_streaming_50_to_200_mib",
    "pending_approval_backlog_at_least_one_thousand",
}


def readiness_evidence() -> dict[str, Any]:
    generated = datetime.now(UTC) - timedelta(minutes=5)
    completed = generated - timedelta(minutes=5)
    gate = {
        "status": "passed",
        "release_id": RELEASE_ID,
        "git_sha": GIT_SHA,
        "image_digest": IMAGE_DIGEST,
        "owner": "platform-control-owner",
        "completed_at": completed.isoformat(),
        "evidence_uri": f"https://evidence.example.test/gates/sha256:{'c' * 64}",
        "report_sha256": f"sha256:{'c' * 64}",
        "issuer": {
            "identity": "spiffe://example.test/release-governance",
            "authentication": "spiffe-mtls",
            "issued_at": completed.isoformat(),
            "evidence_uri": "https://evidence.example.test/issuers/governance.json",
        },
    }
    return {
        "schema_version": "1.0",
        "release_id": RELEASE_ID,
        "git_sha": GIT_SHA,
        "image_digest": IMAGE_DIGEST,
        "versions": {
            "base_image_digest": (
                "sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90"
            ),
            "workflow_code": "agent-run-workflow@1.0.0",
            "sdk": "agent-platform@1.0.0",
            "model_route": "production-model-route@2026-07-27",
            "contract_schema": "task-contract@1.0",
            "alembic_revision": "20260727_0009",
        },
        "training": {
            "records": [
                {
                    "population": population,
                    "owner": f"{population}-owner",
                    "completed_at": completed.isoformat(),
                    "evidence_uri": (f"https://evidence.example.test/training/{population}.json"),
                }
                for population in ("business-users", "approvers", "on-call")
            ]
        },
        "rollback": {
            "owner": "release-rollback-owner",
            "owner_role": "sre",
            "authenticated_at": completed.isoformat(),
            "authentication": {
                "assurance": "phishing-resistant",
                "method": "webauthn",
            },
            "acknowledged_at": generated.isoformat(),
            "previous_image_digest": f"sha256:{'e' * 64}",
            "previous_helm_revision": 17,
            "previous_git_sha": "e" * 40,
            "previous_tool_catalog_id": "enterprise-tools-2026-07-24",
            "previous_tool_catalog_digest": f"sha256:{'d' * 64}",
            "database_compatibility_approved": True,
            "runbook_version": "release-rollback@1.0",
            "evidence_uri": "https://evidence.example.test/rollback/ack.json",
        },
        "observation": {
            "owner": "release-observation-owner",
            "minimum_window_seconds": 60300,
            "success_criteria": [
                "all hard gates pass",
                "no SLO fast burn",
                "zero duplicate side effects",
            ],
            "stop_conditions": [
                "hard gate failure",
                "Sev1 or Sev2 safety alert",
                "SLO fast burn",
            ],
            "evidence_uri": "https://evidence.example.test/observation/policy.json",
        },
        "gates": {
            name: {**gate, "gate_id": name}
            for name in (
                "supply_chain",
                "bucket_governance",
                "staging_e2e",
                "workflow_replay",
                "red_team",
                "fault_injection",
                "disaster_recovery",
                "retention_policy",
                "cost_budget",
                "capacity",
                "slo_latency",
                "observability",
            )
        },
        "evidence_store": {
            "uri": "https://evidence.example.test/releases/12345-1/readiness.json",
            "version_id": "version-00017",
            "digest_uri": ("https://evidence.example.test/releases/12345-1/readiness.json.sha256"),
            "signature_bundle_uri": (
                "https://evidence.example.test/releases/12345-1/readiness.json.sigstore.json"
            ),
            "signer_identity": (
                "https://github.com/example/release-governance/"
                ".github/workflows/publish.yml@refs/heads/main"
            ),
            "signer_issuer": "https://token.actions.githubusercontent.com",
            "retention_until": (generated + timedelta(days=366)).isoformat(),
            "access_audit_uri": (
                "https://evidence.example.test/releases/12345-1/access-audit.json"
            ),
        },
        "generated_at": generated.isoformat(),
    }


def _raw_json_asset(payload: dict[str, Any], *, asset_type: str) -> dict[str, Any]:
    raw_json = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    digest = "sha256:" + hashlib.sha256(raw_json.encode()).hexdigest()
    return {
        "content_uri": f"https://evidence.example.test/capacity/{asset_type}/{digest}",
        "sha256": digest,
        "raw_json": raw_json,
    }


def capacity_raw_report(*, generated_at: datetime) -> dict[str, Any]:
    artifact_observations = [
        {
            "artifact_id": f"artifact-{size // MIB}",
            "size_bytes": size,
            "sha256": digest,
            "scan_status": "malware_clean",
            "object_version_id": f"version-{size // MIB}",
            "server_transport": {
                "mode": "request-stream-to-file",
                "request_size_bytes": size,
                "request_sha256": digest,
                "chunk_count": size // MIB,
                "max_request_chunk_bytes": MIB,
            },
            "passed": True,
        }
        for size, digest in ((50 * MIB, "1" * 64), (200 * MIB, "2" * 64))
    ]
    action_ids = [f"action-{index:04d}" for index in range(1000)]
    run_ids = [f"run-{index:03d}" for index in range(100)]
    workflow_ids = [f"workflow-{index:03d}" for index in range(100)]
    expiry_probe_action_ids = action_ids[:50]
    observed_at = generated_at.isoformat()
    manifest_sha256 = f"sha256:{'d' * 64}"
    control_document = {
        "schema_version": "1.0",
        "release_id": RELEASE_ID,
        "git_sha": GIT_SHA,
        "image_digest": IMAGE_DIGEST,
        "manifest_sha256": manifest_sha256,
        "scope": {
            "action_ids": action_ids,
            "run_ids": run_ids,
            "workflow_ids": workflow_ids,
            "expiry_probe_action_ids": expiry_probe_action_ids,
        },
        "notifications": _raw_json_asset(
            {
                "receipts": [
                    {
                        "receipt_id": f"receipt-{index:04d}",
                        "action_id": action_id,
                        "delivered": True,
                        "delivered_at": observed_at,
                    }
                    for index, action_id in enumerate(action_ids)
                ]
            },
            asset_type="notifications",
        ),
        "expiry": _raw_json_asset(
            {
                "observations": [
                    {
                        "action_id": action_id,
                        "status": "expired",
                        "observed_at": observed_at,
                    }
                    for action_id in expiry_probe_action_ids
                ]
            },
            asset_type="expiry",
        ),
        "resources": _raw_json_asset(
            {
                "closed_workflow_ids": workflow_ids,
                "open_workflow_ids": [],
                "task_queue_backlog_before": 100,
                "task_queue_backlog_after": 0,
                "active_slots_before": 100,
                "active_slots_after": 0,
                "observed_at": observed_at,
            },
            asset_type="resources",
        ),
    }
    control_raw_json = json.dumps(
        control_document,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    control_sha256 = "sha256:" + hashlib.sha256(control_raw_json.encode()).hexdigest()
    return {
        "schema_version": "1.0",
        "release_id": RELEASE_ID,
        "git_sha": GIT_SHA,
        "image_digest": IMAGE_DIGEST,
        "environment": "staging",
        "base_url_origin": "https://staging-agent.example.test",
        "generated_at_unix": int(generated_at.timestamp()),
        "passed": True,
        "scenarios": [
            {
                "name": "ten_x_burst_one_minute",
                "passed": True,
                "requests": 600,
                "statuses": {"202": 600},
                "p95_seconds": 0.5,
                "evidence": {
                    "baseline_rps": 1.0,
                    "offered_rps": 10.0,
                    "duration_seconds": 60,
                    "controlled_admission_responses": 600,
                },
            },
            {
                "name": "one_hundred_concurrent_long_runs",
                "passed": True,
                "requests": 100,
                "statuses": {"202": 100},
                "p95_seconds": 1.5,
                "evidence": {
                    "concurrency": 100,
                    "max_duration_seconds": 3600,
                    "accepted_runs": 100,
                },
            },
            {
                "name": "tool_p95_five_x",
                "passed": True,
                "requests": 100,
                "statuses": {"200": 100},
                "p95_seconds": 2.5,
                "evidence": {
                    "baseline_p95_seconds": 0.5,
                    "degraded_p95_seconds": 2.5,
                    "observed_multiplier": 5.0,
                },
            },
            {
                "name": "persistent_429",
                "passed": True,
                "requests": 200,
                "statuses": {"429": 200},
                "p95_seconds": 0.2,
                "evidence": {"expected_status": 429},
            },
            {
                "name": "artifact_streaming_50_to_200_mib",
                "passed": True,
                "requests": 2,
                "statuses": {"201": 2},
                "p95_seconds": 5.0,
                "evidence": {
                    "sizes_bytes": [50 * MIB, 200 * MIB],
                    "client_chunk_bytes": MIB,
                    "maximum_server_request_chunk_bytes": 8 * MIB,
                    "server_observations": artifact_observations,
                },
            },
            {
                "name": "pending_approval_backlog_at_least_one_thousand",
                "passed": True,
                "requests": 200,
                "statuses": {"200": 200},
                "p95_seconds": 0.8,
                "evidence": {
                    "pending_approval_count": 1000,
                    "unique_action_count": 1000,
                    "queried_run_count": 100,
                    "pending_action_ids": action_ids,
                    "queried_run_ids": run_ids,
                    "workflow_ids": workflow_ids,
                    "manifest_sha256": manifest_sha256,
                    "observed_status": "pending_approval",
                    "status_query_verified": True,
                    "operational_control_evidence_raw_json": control_raw_json,
                    "operational_control_evidence_sha256": control_sha256,
                    "operational_control_evidence_uri": (
                        f"https://evidence.example.test/capacity/control/{control_sha256}"
                    ),
                    "operational_control_evidence_error": None,
                    "notification_delivery_verified": True,
                    "expiry_processing_verified": True,
                    "resource_leak_free_verified": True,
                },
            },
        ],
        "latency_summary": {"median_p95_seconds": 1.15},
    }


def operational_raw_evidence(
    *,
    gate_id: str,
    environment: str,
    captured_at: datetime,
) -> dict[str, Any]:
    measurements: dict[str, dict[str, Any]] = {}
    for check_id, (comparison, threshold) in GATE_CHECK_POLICIES[gate_id].items():
        if isinstance(threshold, bool):
            samples: list[object] = [threshold]
        elif (gate_id, check_id) in RAW_COUNT_SAMPLE_CHECKS:
            assert isinstance(threshold, int)
            samples = [f"{check_id}-sample-{index}" for index in range(threshold)]
        elif comparison in {"lte", "gte"}:
            samples = [threshold]
        else:  # The fixture must fail if a new reducer is added without raw evidence semantics.
            raise AssertionError(f"unsupported raw measurement policy: {gate_id}.{check_id}")
        measurements[check_id] = {
            "samples": samples,
            "source_uri": (f"https://evidence.example.test/machine/{gate_id}/{check_id}/run-12345"),
        }
    return {
        "schema_version": "1.0",
        "gate_id": gate_id,
        "release_id": RELEASE_ID,
        "git_sha": GIT_SHA,
        "image_digest": IMAGE_DIGEST,
        "environment": environment,
        "captured_at": captured_at.isoformat(),
        "producer": {
            "kind": "machine",
            "collector": f"agent-platform-{gate_id}-collector",
            "run_id": "12345",
            "evidence_uri": f"https://evidence.example.test/machine/{gate_id}/runs/12345",
        },
        "measurements": measurements,
    }


def _prepare_gate_reports(
    tmp_path: Path,
    evidence: dict[str, Any],
    *,
    tamper_gate_report: str | None = None,
    report_mutator: Callable[[str, dict[str, Any]], None] | None = None,
    raw_capacity_mutator: Callable[[dict[str, Any]], None] | None = None,
    raw_evidence_mutator: Callable[[str, dict[str, Any]], None] | None = None,
    tamper_raw_capacity_report: bool = False,
    tamper_raw_evidence: str | None = None,
) -> Path:
    report_directory = tmp_path / "gate-reports"
    report_directory.mkdir()
    for gate_id, gate in evidence["gates"].items():
        environment, required_asset_types = GATE_SCOPE_POLICIES[gate_id]
        asset_ids_by_type = {
            asset_type: f"{environment}-{asset_type}-01" for asset_type in required_asset_types
        }
        scope_regions = (
            ["cn-hangzhou", "cn-shanghai"] if gate_id == "disaster_recovery" else ["cn-hangzhou"]
        )
        report = {
            "schema_version": "1.0",
            "gate_id": gate_id,
            "release_id": RELEASE_ID,
            "git_sha": GIT_SHA,
            "image_digest": IMAGE_DIGEST,
            "status": "passed",
            "started_at": gate["completed_at"],
            "performed_at": gate["completed_at"],
            "completed_at": gate["completed_at"],
            "scope": {
                "environment": environment,
                "release_asset_id": f"{RELEASE_ID}@{IMAGE_DIGEST}",
                "assets": [
                    {
                        "asset_type": asset_type,
                        "asset_id": asset_ids_by_type[asset_type],
                        "evidence_uri": (
                            "https://evidence.example.test/assets/"
                            f"{asset_ids_by_type[asset_type]}.json"
                        ),
                    }
                    for asset_type in sorted(required_asset_types)
                ],
                "regions": scope_regions,
            },
            "checks": [
                {
                    "id": check_id,
                    "status": "passed",
                    "comparison": policy[0],
                    "observed": policy[1],
                    "threshold": policy[1],
                    "evidence_uri": (
                        f"https://evidence.example.test/gates/{gate_id}/{check_id}.json"
                    ),
                }
                for check_id, policy in sorted(GATE_CHECK_POLICIES[gate_id].items())
            ],
            "blocking_findings": {"critical": 0, "high": 0},
            "issuer": gate["issuer"],
            "generated_at": gate["completed_at"],
        }
        if gate_id == "disaster_recovery":
            completed_at = datetime.fromisoformat(gate["completed_at"])
            report["scope"]["backup_ids"] = [
                "backup-postgres-17",
                "temporal-history-17",
                "backup-postgres-q3",
                "artifact-version-q3",
                "region-snapshot-h1",
            ]
            report["drills"] = [
                {
                    "id": "daily-restore-17",
                    "drill_type": "daily_restore",
                    "completed_at": completed_at.isoformat(),
                    "asset_types": ["postgresql", "temporal"],
                    "asset_ids": [
                        asset_ids_by_type["postgresql"],
                        asset_ids_by_type["temporal"],
                    ],
                    "backup_ids": ["backup-postgres-17", "temporal-history-17"],
                    "regions": ["cn-hangzhou"],
                    "observed_rpo_minutes": 5,
                    "observed_rto_minutes": 30,
                    "evidence_uri": "https://evidence.example.test/drills/daily-17.json",
                },
                {
                    "id": "quarterly-db-artifact-17",
                    "drill_type": "quarterly_db_artifact",
                    "completed_at": (completed_at - timedelta(days=30)).isoformat(),
                    "asset_types": ["postgresql", "artifact_bucket"],
                    "asset_ids": [
                        asset_ids_by_type["postgresql"],
                        asset_ids_by_type["artifact_bucket"],
                    ],
                    "backup_ids": ["backup-postgres-q3", "artifact-version-q3"],
                    "regions": ["cn-hangzhou"],
                    "observed_rpo_minutes": 5,
                    "observed_rto_minutes": 60,
                    "evidence_uri": "https://evidence.example.test/drills/quarterly-q3.json",
                },
                {
                    "id": "semiannual-region-17",
                    "drill_type": "semiannual_region",
                    "completed_at": (completed_at - timedelta(days=90)).isoformat(),
                    "asset_types": ["regional_stack"],
                    "asset_ids": [asset_ids_by_type["regional_stack"]],
                    "backup_ids": ["region-snapshot-h1"],
                    "regions": ["cn-hangzhou", "cn-shanghai"],
                    "observed_rpo_minutes": 5,
                    "observed_rto_minutes": 60,
                    "evidence_uri": "https://evidence.example.test/drills/region-h1.json",
                },
            ]
        if gate_id == "fault_injection":
            fail_closed_components = {"approval", "opa"}
            report["fault_matrix"] = [
                {
                    "component": component,
                    "outcome": (
                        "fail_closed" if component in fail_closed_components else "recovered"
                    ),
                    "completed_at": gate["completed_at"],
                    "evidence_uri": (f"https://evidence.example.test/faults/{component}.json"),
                }
                for component in (
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
                )
            ]
        if gate_id == "capacity":
            raw_report = capacity_raw_report(
                generated_at=datetime.fromisoformat(gate["completed_at"]),
            )
            if raw_capacity_mutator is not None:
                raw_capacity_mutator(raw_report)
            raw_payload = (
                json.dumps(
                    raw_report,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode()
            raw_digest_hex = hashlib.sha256(raw_payload).hexdigest()
            report["raw_capacity_report"] = {
                "uri": f"https://evidence.example.test/gates/capacity/sha256:{raw_digest_hex}",
                "sha256": f"sha256:{raw_digest_hex}",
            }
            raw_path = report_directory / f"{raw_digest_hex}.json"
            raw_path.write_bytes(raw_payload)
            if tamper_raw_capacity_report:
                raw_path.write_bytes(raw_payload + b" ")
        else:
            raw_evidence = operational_raw_evidence(
                gate_id=gate_id,
                environment=environment,
                captured_at=datetime.fromisoformat(gate["completed_at"]),
            )
            if raw_evidence_mutator is not None:
                raw_evidence_mutator(gate_id, raw_evidence)
            raw_payload = (
                json.dumps(
                    raw_evidence,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode()
            raw_digest_hex = hashlib.sha256(raw_payload).hexdigest()
            report["raw_evidence"] = {
                "uri": f"https://evidence.example.test/gates/{gate_id}/sha256:{raw_digest_hex}",
                "sha256": f"sha256:{raw_digest_hex}",
            }
            raw_path = report_directory / f"{raw_digest_hex}.json"
            raw_path.write_bytes(raw_payload)
            if gate_id == tamper_raw_evidence:
                raw_path.write_bytes(raw_payload + b" ")
        if report_mutator is not None:
            report_mutator(gate_id, report)
        payload = (
            json.dumps(report, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
        ).encode()
        digest_hex = hashlib.sha256(payload).hexdigest()
        gate["report_sha256"] = f"sha256:{digest_hex}"
        gate["evidence_uri"] = f"https://evidence.example.test/gates/sha256:{digest_hex}"
        report_path = report_directory / f"{digest_hex}.json"
        report_path.write_bytes(payload)
        if gate_id == tamper_gate_report:
            report_path.write_bytes(payload + b" ")
    return report_directory


def _run(
    tmp_path: Path,
    evidence: dict[str, Any],
    *,
    tamper_gate_report: str | None = None,
    report_mutator: Callable[[str, dict[str, Any]], None] | None = None,
    raw_capacity_mutator: Callable[[dict[str, Any]], None] | None = None,
    raw_evidence_mutator: Callable[[str, dict[str, Any]], None] | None = None,
    tamper_raw_capacity_report: bool = False,
    tamper_raw_evidence: str | None = None,
) -> subprocess.CompletedProcess[str]:
    evidence_path = tmp_path / "operational-readiness.json"
    report_path = tmp_path / "operational-readiness-validation.json"
    gate_report_directory = _prepare_gate_reports(
        tmp_path,
        evidence,
        tamper_gate_report=tamper_gate_report,
        report_mutator=report_mutator,
        raw_capacity_mutator=raw_capacity_mutator,
        raw_evidence_mutator=raw_evidence_mutator,
        tamper_raw_capacity_report=tamper_raw_capacity_report,
        tamper_raw_evidence=tamper_raw_evidence,
    )
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    return subprocess.run(  # noqa: S603 - fixed repository validator and interpreter
        [
            sys.executable,
            str(VALIDATOR),
            "--evidence",
            str(evidence_path),
            "--schema",
            str(SCHEMA),
            "--gate-report-schema",
            str(GATE_REPORT_SCHEMA),
            "--gate-reports-directory",
            str(gate_report_directory),
            "--expected-release-id",
            RELEASE_ID,
            "--expected-git-sha",
            GIT_SHA,
            "--expected-image-digest",
            IMAGE_DIGEST,
            "--maximum-age-seconds",
            "86400",
            "--minimum-retention-days",
            "365",
            "--expected-signer-identity",
            (
                "https://github.com/example/release-governance/"
                ".github/workflows/publish.yml@refs/heads/main"
            ),
            "--expected-signer-issuer",
            "https://token.actions.githubusercontent.com",
            "--output",
            str(report_path),
        ],
        capture_output=True,
        check=False,
        text=True,
    )


def test_operational_readiness_schema_is_valid_draft_2020_12() -> None:
    Draft202012Validator.check_schema(json.loads(SCHEMA.read_text(encoding="utf-8")))
    Draft202012Validator.check_schema(json.loads(GATE_REPORT_SCHEMA.read_text(encoding="utf-8")))
    Draft202012Validator.check_schema(json.loads(RAW_EVIDENCE_SCHEMA.read_text(encoding="utf-8")))


def test_operational_readiness_accepts_bound_complete_evidence(tmp_path: Path) -> None:
    completed = _run(tmp_path, readiness_evidence())

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert '"validated": true' in completed.stdout
    assert '"gate_raw_evidence": {' in completed.stdout
    assert '"training_populations": ["approvers", "business-users", "on-call"]' in (
        completed.stdout
    )


def test_operational_readiness_requires_raw_evidence_for_every_gate(tmp_path: Path) -> None:
    def remove_staging_raw_evidence(gate_id: str, report: dict[str, Any]) -> None:
        if gate_id == "staging_e2e":
            report.pop("raw_evidence")

    blocked = _run(
        tmp_path,
        readiness_evidence(),
        report_mutator=remove_staging_raw_evidence,
    )

    assert blocked.returncode == 2
    assert "OPERATIONAL_GATE_RAW_EVIDENCE_REFERENCE_REQUIRED: staging_e2e" in blocked.stderr


def test_operational_readiness_rejects_tampered_generic_raw_evidence(tmp_path: Path) -> None:
    blocked = _run(
        tmp_path,
        readiness_evidence(),
        tamper_raw_evidence="staging_e2e",
    )

    assert blocked.returncode == 2
    assert "OPERATIONAL_GATE_RAW_EVIDENCE_DIGEST_MISMATCH: staging_e2e" in blocked.stderr


def test_operational_readiness_rederives_gate_checks_from_raw_samples(tmp_path: Path) -> None:
    def remove_one_history(gate_id: str, raw_evidence: dict[str, Any]) -> None:
        if gate_id == "workflow_replay":
            raw_evidence["measurements"]["histories_at_least_two"]["samples"] = ["history-01"]

    blocked = _run(
        tmp_path,
        readiness_evidence(),
        raw_evidence_mutator=remove_one_history,
    )

    assert blocked.returncode == 2
    assert (
        "OPERATIONAL_GATE_RAW_THRESHOLD_FAILED: workflow_replay.histories_at_least_two"
        in blocked.stderr
    )
    assert (
        "OPERATIONAL_GATE_RAW_DERIVED_CHECK_MISMATCH: workflow_replay.histories_at_least_two"
    ) in blocked.stderr


def test_operational_readiness_rejects_generic_raw_identity_freshness_and_origin(
    tmp_path: Path,
) -> None:
    def drift_raw_identity(gate_id: str, raw_evidence: dict[str, Any]) -> None:
        if gate_id == "red_team":
            raw_evidence["release_id"] = "other-release"
            raw_evidence["environment"] = "production"
            raw_evidence["captured_at"] = datetime.fromtimestamp(1, UTC).isoformat()

    def move_raw_origin(gate_id: str, report: dict[str, Any]) -> None:
        if gate_id == "red_team":
            report["raw_evidence"]["uri"] = report["raw_evidence"]["uri"].replace(
                "evidence.example.test",
                "other.example.test",
            )

    blocked = _run(
        tmp_path,
        readiness_evidence(),
        report_mutator=move_raw_origin,
        raw_evidence_mutator=drift_raw_identity,
    )

    assert blocked.returncode == 2
    assert "OPERATIONAL_GATE_RAW_EVIDENCE_ORIGIN_MISMATCH: red_team" in blocked.stderr
    assert "OPERATIONAL_GATE_RAW_EVIDENCE_RELEASE_ID_MISMATCH: red_team" in blocked.stderr
    assert "OPERATIONAL_GATE_RAW_EVIDENCE_ENVIRONMENT_MISMATCH: red_team" in blocked.stderr
    assert "OPERATIONAL_GATE_RAW_EVIDENCE_EXPIRED: red_team" in blocked.stderr


def test_operational_readiness_rejects_missing_and_unknown_raw_measurements(
    tmp_path: Path,
) -> None:
    def drift_measurements(gate_id: str, raw_evidence: dict[str, Any]) -> None:
        if gate_id == "slo_latency":
            raw_evidence["measurements"].pop("slo_met")
            raw_evidence["measurements"]["issuer_claimed_passed"] = {
                "samples": [True],
                "source_uri": "https://evidence.example.test/machine/unsupported",
            }

    blocked = _run(
        tmp_path,
        readiness_evidence(),
        raw_evidence_mutator=drift_measurements,
    )

    assert blocked.returncode == 2
    assert "OPERATIONAL_GATE_RAW_MEASUREMENTS_MISSING: slo_latency" in blocked.stderr
    assert "OPERATIONAL_GATE_RAW_MEASUREMENTS_UNEXPECTED: slo_latency" in blocked.stderr


def test_operational_readiness_rejects_identity_and_training_drift(tmp_path: Path) -> None:
    evidence = readiness_evidence()
    evidence["image_digest"] = f"sha256:{'9' * 64}"
    evidence["training"]["records"] = evidence["training"]["records"][:2]

    blocked = _run(tmp_path, evidence)

    assert blocked.returncode == 2
    assert "OPERATIONAL_READINESS_IMAGE_DIGEST_MISMATCH" in blocked.stderr
    assert "OPERATIONAL_READINESS_TRAINING_INCOMPLETE" in blocked.stderr


def test_operational_readiness_rejects_short_evidence_retention(tmp_path: Path) -> None:
    evidence = readiness_evidence()
    generated = datetime.fromisoformat(evidence["generated_at"])
    evidence["evidence_store"]["retention_until"] = (generated + timedelta(days=30)).isoformat()

    blocked = _run(tmp_path, evidence)

    assert blocked.returncode == 2
    assert "OPERATIONAL_READINESS_RETENTION_TOO_SHORT" in blocked.stderr


def test_operational_readiness_rejects_gate_release_drift(tmp_path: Path) -> None:
    evidence = readiness_evidence()
    evidence["gates"]["red_team"]["git_sha"] = "9" * 40

    blocked = _run(tmp_path, evidence)

    assert blocked.returncode == 2
    assert "OPERATIONAL_READINESS_GATE_GIT_SHA_MISMATCH: red_team" in blocked.stderr


def test_operational_readiness_rejects_tampered_gate_report(tmp_path: Path) -> None:
    blocked = _run(
        tmp_path,
        readiness_evidence(),
        tamper_gate_report="fault_injection",
    )

    assert blocked.returncode == 2
    assert "OPERATIONAL_GATE_REPORT_DIGEST_MISMATCH: fault_injection" in blocked.stderr


def test_operational_readiness_rejects_boolean_substitution_for_numeric_policy(
    tmp_path: Path,
) -> None:
    def substitute_boolean(gate_id: str, report: dict[str, Any]) -> None:
        if gate_id != "capacity":
            return
        check = next(row for row in report["checks"] if row["id"] == "burst_multiplier")
        check.update({"comparison": "eq", "observed": True, "threshold": True})

    blocked = _run(
        tmp_path,
        readiness_evidence(),
        report_mutator=substitute_boolean,
    )

    assert blocked.returncode == 2
    assert "OPERATIONAL_GATE_REPORT_COMPARISON_MISMATCH: capacity.burst_multiplier" in (
        blocked.stderr
    )
    assert "OPERATIONAL_GATE_REPORT_THRESHOLD_POLICY_MISMATCH" in blocked.stderr


def test_operational_readiness_rejects_stale_disaster_recovery_drill(
    tmp_path: Path,
) -> None:
    def expire_region_drill(gate_id: str, report: dict[str, Any]) -> None:
        if gate_id != "disaster_recovery":
            return
        completed_at = datetime.fromisoformat(report["completed_at"])
        drill = next(row for row in report["drills"] if row["drill_type"] == "semiannual_region")
        drill["completed_at"] = (completed_at - timedelta(days=201)).isoformat()

    blocked = _run(
        tmp_path,
        readiness_evidence(),
        report_mutator=expire_region_drill,
    )

    assert blocked.returncode == 2
    assert "OPERATIONAL_GATE_REPORT_DRILL_STALE: semiannual_region" in blocked.stderr


def test_operational_readiness_rejects_incomplete_fault_matrix(tmp_path: Path) -> None:
    def remove_planner_fault(gate_id: str, report: dict[str, Any]) -> None:
        if gate_id == "fault_injection":
            report["fault_matrix"] = [
                row for row in report["fault_matrix"] if row["component"] != "planner"
            ]

    blocked = _run(
        tmp_path,
        readiness_evidence(),
        report_mutator=remove_planner_fault,
    )

    assert blocked.returncode == 2
    assert "OPERATIONAL_GATE_REPORT_FAULT_COMPONENTS_MISSING: ['planner']" in (blocked.stderr)


def test_operational_readiness_rejects_drill_asset_outside_signed_scope(
    tmp_path: Path,
) -> None:
    def replace_drill_asset(gate_id: str, report: dict[str, Any]) -> None:
        if gate_id == "disaster_recovery":
            report["drills"][0]["asset_ids"] = ["unknown-postgres"]

    blocked = _run(
        tmp_path,
        readiness_evidence(),
        report_mutator=replace_drill_asset,
    )

    assert blocked.returncode == 2
    assert "OPERATIONAL_GATE_REPORT_DRILL_ASSETS_OUT_OF_SCOPE: daily_restore" in (blocked.stderr)


def test_operational_readiness_rejects_gate_environment_drift(tmp_path: Path) -> None:
    def move_staging_gate_to_production(gate_id: str, report: dict[str, Any]) -> None:
        if gate_id == "staging_e2e":
            report["scope"]["environment"] = "production"

    blocked = _run(
        tmp_path,
        readiness_evidence(),
        report_mutator=move_staging_gate_to_production,
    )

    assert blocked.returncode == 2
    assert "OPERATIONAL_GATE_REPORT_ENVIRONMENT_MISMATCH: staging_e2e" in (blocked.stderr)


def test_operational_readiness_rejects_tampered_raw_capacity_report(tmp_path: Path) -> None:
    blocked = _run(
        tmp_path,
        readiness_evidence(),
        tamper_raw_capacity_report=True,
    )

    assert blocked.returncode == 2
    assert "OPERATIONAL_CAPACITY_RAW_REPORT_DIGEST_MISMATCH" in blocked.stderr


def test_operational_readiness_rejects_capacity_gate_derived_value_drift(
    tmp_path: Path,
) -> None:
    def inflate_gate_check(gate_id: str, report: dict[str, Any]) -> None:
        if gate_id == "capacity":
            check = next(row for row in report["checks"] if row["id"] == "burst_multiplier")
            check["observed"] = 11

    blocked = _run(
        tmp_path,
        readiness_evidence(),
        report_mutator=inflate_gate_check,
    )

    assert blocked.returncode == 2
    assert "OPERATIONAL_CAPACITY_GATE_DERIVED_CHECK_MISMATCH: burst_multiplier" in blocked.stderr


def test_operational_readiness_rejects_incomplete_or_unproven_capacity_scenarios(
    tmp_path: Path,
) -> None:
    def remove_artifact_and_reduce_429(raw_report: dict[str, Any]) -> None:
        raw_report["scenarios"] = [
            scenario
            for scenario in raw_report["scenarios"]
            if scenario["name"] != "artifact_streaming_50_to_200_mib"
        ]
        persistent = next(
            scenario for scenario in raw_report["scenarios"] if scenario["name"] == "persistent_429"
        )
        persistent["requests"] = 199
        persistent["statuses"] = {"429": 199}

    blocked = _run(
        tmp_path,
        readiness_evidence(),
        raw_capacity_mutator=remove_artifact_and_reduce_429,
    )

    assert blocked.returncode == 2
    assert "OPERATIONAL_CAPACITY_RAW_REPORT_SCENARIOS_INCOMPLETE" in blocked.stderr
    assert "OPERATIONAL_CAPACITY_429_SAMPLE_COUNT_INSUFFICIENT" in blocked.stderr


def test_operational_readiness_rejects_unbound_artifact_server_observation(
    tmp_path: Path,
) -> None:
    def corrupt_artifact_transport(raw_report: dict[str, Any]) -> None:
        artifact = next(
            scenario
            for scenario in raw_report["scenarios"]
            if scenario["name"] == "artifact_streaming_50_to_200_mib"
        )
        observation = artifact["evidence"]["server_observations"][1]
        observation["server_transport"]["chunk_count"] = 1
        observation["server_transport"]["max_request_chunk_bytes"] = 200 * MIB

    blocked = _run(
        tmp_path,
        readiness_evidence(),
        raw_capacity_mutator=corrupt_artifact_transport,
    )

    assert blocked.returncode == 2
    assert "OPERATIONAL_CAPACITY_ARTIFACT_SERVER_CHUNKS_INVALID: 209715200" in blocked.stderr


def test_operational_readiness_rejects_capacity_raw_identity_freshness_and_origin(
    tmp_path: Path,
) -> None:
    def drift_raw_identity(raw_report: dict[str, Any]) -> None:
        raw_report["release_id"] = "other-release"
        raw_report["environment"] = "production"
        raw_report["generated_at_unix"] = 1

    def move_raw_origin(gate_id: str, report: dict[str, Any]) -> None:
        if gate_id == "capacity":
            report["raw_capacity_report"]["uri"] = report["raw_capacity_report"]["uri"].replace(
                "evidence.example.test",
                "other.example.test",
            )

    blocked = _run(
        tmp_path,
        readiness_evidence(),
        report_mutator=move_raw_origin,
        raw_capacity_mutator=drift_raw_identity,
    )

    assert blocked.returncode == 2
    assert "OPERATIONAL_CAPACITY_RAW_REPORT_ORIGIN_MISMATCH" in blocked.stderr
    assert "OPERATIONAL_CAPACITY_RAW_REPORT_RELEASE_ID_MISMATCH" in blocked.stderr
    assert "OPERATIONAL_CAPACITY_RAW_REPORT_ENVIRONMENT_MISMATCH" in blocked.stderr
    assert "OPERATIONAL_CAPACITY_RAW_REPORT_EXPIRED" in blocked.stderr


def test_operational_readiness_fetch_mode_reads_and_hashes_every_raw_evidence(
    tmp_path: Path,
) -> None:
    evidence = readiness_evidence()
    report_directory = _prepare_gate_reports(tmp_path, evidence)
    payloads = {
        urlsplit(gate["evidence_uri"]).path: (
            report_directory / f"{gate['report_sha256'].removeprefix('sha256:')}.json"
        ).read_bytes()
        for gate in evidence["gates"].values()
    }
    for gate_id, gate in evidence["gates"].items():
        gate_payload = payloads[urlsplit(gate["evidence_uri"]).path]
        gate_report = json.loads(gate_payload)
        reference_name = "raw_capacity_report" if gate_id == "capacity" else "raw_evidence"
        raw_reference = gate_report[reference_name]
        raw_digest = raw_reference["sha256"].removeprefix("sha256:")
        payloads[urlsplit(raw_reference["uri"]).path] = (
            report_directory / f"{raw_digest}.json"
        ).read_bytes()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer operational-token"
        payload = payloads.get(request.url.path)
        if payload is None:
            return httpx.Response(404)
        return httpx.Response(
            200,
            content=payload,
            headers={"Content-Type": "application/json"},
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        validated, raw_evidence = validate_gate_reports(
            evidence,
            json.loads(GATE_REPORT_SCHEMA.read_text(encoding="utf-8")),
            expected_release_id=RELEASE_ID,
            expected_git_sha=GIT_SHA,
            expected_image_digest=IMAGE_DIGEST,
            fetch_reports=True,
            bearer_token="operational-token",
            http_client=client,
            maximum_age_seconds=86400,
        )

    assert set(validated) == set(evidence["gates"])
    assert set(raw_evidence) == set(evidence["gates"])
    assert all(ref["sha256"].removeprefix("sha256:") in ref["uri"] for ref in raw_evidence.values())


@pytest.mark.parametrize(
    ("field", "value", "expected_error"),
    (
        (
            "previous_image_digest",
            IMAGE_DIGEST,
            "OPERATIONAL_READINESS_ROLLBACK_IMAGE_NOT_PREVIOUS",
        ),
        ("previous_helm_revision", True, "OPERATIONAL_READINESS_SCHEMA_INVALID"),
        ("previous_git_sha", "not-a-sha", "OPERATIONAL_READINESS_SCHEMA_INVALID"),
        ("previous_tool_catalog_id", "", "OPERATIONAL_READINESS_SCHEMA_INVALID"),
        (
            "previous_tool_catalog_digest",
            "sha256:bad",
            "OPERATIONAL_READINESS_SCHEMA_INVALID",
        ),
        (
            "database_compatibility_approved",
            False,
            "OPERATIONAL_READINESS_SCHEMA_INVALID",
        ),
    ),
)
def test_operational_readiness_rejects_invalid_rollback_target(
    tmp_path: Path,
    field: str,
    value: object,
    expected_error: str,
) -> None:
    evidence = readiness_evidence()
    evidence["rollback"][field] = value

    blocked = _run(tmp_path, evidence)

    assert blocked.returncode == 2
    assert expected_error in blocked.stderr


@pytest.mark.parametrize(
    "field",
    (
        "previous_helm_revision",
        "previous_git_sha",
        "previous_tool_catalog_id",
        "previous_tool_catalog_digest",
        "database_compatibility_approved",
    ),
)
def test_operational_readiness_requires_complete_rollback_target(
    tmp_path: Path,
    field: str,
) -> None:
    evidence = readiness_evidence()
    evidence["rollback"].pop(field)

    blocked = _run(tmp_path, evidence)

    assert blocked.returncode == 2
    assert "OPERATIONAL_READINESS_SCHEMA_INVALID" in blocked.stderr
    assert field in blocked.stderr


def test_operational_readiness_rejects_non_content_addressed_capacity_raw_uri(
    tmp_path: Path,
) -> None:
    def detach_raw_uri(gate_id: str, report: dict[str, Any]) -> None:
        if gate_id == "capacity":
            report["raw_capacity_report"]["uri"] = (
                "https://evidence.example.test/gates/capacity/latest.json"
            )

    blocked = _run(
        tmp_path,
        readiness_evidence(),
        report_mutator=detach_raw_uri,
    )

    assert blocked.returncode == 2
    assert "OPERATIONAL_CAPACITY_RAW_REPORT_URI_NOT_CONTENT_ADDRESSED" in blocked.stderr


def test_operational_readiness_rejects_burst_claim_without_one_minute_volume(
    tmp_path: Path,
) -> None:
    def shrink_burst(raw_report: dict[str, Any]) -> None:
        raw_report["schema_version"] = "2.0"
        burst = next(
            scenario
            for scenario in raw_report["scenarios"]
            if scenario["name"] == "ten_x_burst_one_minute"
        )
        burst["requests"] = 1
        burst["statuses"] = {"202": 1}
        burst["evidence"]["controlled_admission_responses"] = 1

    blocked = _run(
        tmp_path,
        readiness_evidence(),
        raw_capacity_mutator=shrink_burst,
    )

    assert blocked.returncode == 2
    assert "OPERATIONAL_CAPACITY_RAW_REPORT_SCHEMA_VERSION_MISMATCH" in blocked.stderr
    assert "OPERATIONAL_CAPACITY_BURST_SCENARIO_INVALID" in blocked.stderr
