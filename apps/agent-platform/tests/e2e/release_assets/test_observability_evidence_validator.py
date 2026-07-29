from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

PLATFORM_ROOT = Path(__file__).parents[3]
VALIDATOR = PLATFORM_ROOT / "deploy" / "ci" / "validate_observability_evidence.py"
SCHEMA = PLATFORM_ROOT / "deploy" / "ci" / "observability-evidence.schema.json"
RELEASE_ID = "12345-1"
GIT_SHA = "a" * 40
IMAGE_DIGEST = f"sha256:{'b' * 64}"
RECEIPT_SHA256 = f"sha256:{'c' * 64}"
DASHBOARDS = (
    ("agent-platform-actions", "Agent Platform - Actions"),
    ("agent-platform-executive", "Agent Platform - Executive"),
    ("agent-platform-model", "Agent Platform - Model"),
    ("agent-platform-operations", "Agent Platform - Operations"),
    ("agent-platform-safety", "Agent Platform - Safety"),
    ("agent-platform-tools", "Agent Platform - Tools"),
)


def observability_evidence() -> dict[str, object]:
    generated_at = datetime.now(UTC) - timedelta(minutes=1)
    return {
        "schema_version": "1.0",
        "release_id": RELEASE_ID,
        "namespace": "agent-platform",
        "git_sha": GIT_SHA,
        "image_digest": IMAGE_DIGEST,
        "generated_at": generated_at.isoformat(),
        "prometheus_rule": "agent-platform",
        "grafana_configmap": "agent-platform-grafana-dashboards",
        "otel_collector": {
            "namespace": "observability",
            "service": "otel-collector",
            "health": "ok",
        },
        "prometheus": {
            "namespace": "observability",
            "service": "prometheus-operated",
            "scrape_target_up": True,
            "query_api": "ok",
            "rules_loaded": True,
        },
        "alertmanager": {
            "namespace": "observability",
            "service": "alertmanager-operated",
            "prometheus_active_alertmanager": True,
            "route_receiver_config_present": True,
        },
        "trace_backend": {
            "namespace": "observability",
            "service": "tempo-query-frontend",
            "trace_id": "a" * 32,
            "synthetic_trace_roundtrip": True,
        },
        "grafana": {
            "api_url": "https://grafana.example.test",
            "runtime_api_readback": True,
            "dashboard_count": 6,
            "dashboards": [
                {
                    "uid": uid,
                    "title": title,
                    "version": 17,
                    "release_tags": [
                        f"agent-platform-release-id:{RELEASE_ID}",
                        f"agent-platform-git-sha:{GIT_SHA}",
                        f"agent-platform-image-digest:{IMAGE_DIGEST}",
                    ],
                    "release_identity_verified": True,
                }
                for uid, title in DASHBOARDS
            ],
        },
        "alert_delivery": {
            "alertmanager_api_url": "https://alertmanager.example.test",
            "delivery_id": f"release-check-{'d' * 64}",
            "release_id": RELEASE_ID,
            "git_sha": GIT_SHA,
            "image_digest": IMAGE_DIGEST,
            "synthetic_alert_submitted": True,
            "alertmanager_api_readback": True,
            "synthetic_alert_resolved": True,
            "receiver_delivery_verified": True,
            "receiver": "release-verification-receiver",
            "received_at": generated_at.isoformat(),
            "receipt_evidence_uri": (
                f"https://receipts.example.test/v1/evidence/{RECEIPT_SHA256}.json"
            ),
            "receipt_evidence_sha256": RECEIPT_SHA256,
            "immutable_receipt_readback": True,
        },
        "applied": True,
    }


def _run(tmp_path: Path, evidence: dict[str, object]) -> subprocess.CompletedProcess[str]:
    evidence_path = tmp_path / "observability.json"
    output_path = tmp_path / "validation.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    return subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(VALIDATOR),
            "--evidence",
            str(evidence_path),
            "--schema",
            str(SCHEMA),
            "--expected-release-id",
            RELEASE_ID,
            "--expected-git-sha",
            GIT_SHA,
            "--expected-image-digest",
            IMAGE_DIGEST,
            "--maximum-age-seconds",
            "600",
            "--output",
            str(output_path),
        ],
        cwd=PLATFORM_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_observability_evidence_accepts_exact_runtime_and_delivery_readback(
    tmp_path: Path,
) -> None:
    completed = _run(tmp_path, observability_evidence())

    assert completed.returncode == 0, completed.stderr
    validation = json.loads((tmp_path / "validation.json").read_text(encoding="utf-8"))
    assert validation["validated"] is True
    assert validation["release_id"] == RELEASE_ID
    assert validation["dashboard_uids"] == sorted(uid for uid, _ in DASHBOARDS)
    assert validation["receipt_evidence_sha256"] == RECEIPT_SHA256
    assert validation["observability_evidence_sha256"].startswith("sha256:")


def test_observability_evidence_rejects_dashboard_identity_drift(tmp_path: Path) -> None:
    evidence = observability_evidence()
    grafana = evidence["grafana"]
    assert isinstance(grafana, dict)
    dashboards = grafana["dashboards"]
    assert isinstance(dashboards, list)
    first = dashboards[0]
    assert isinstance(first, dict)
    first["title"] = "Wrong title"

    completed = _run(tmp_path, evidence)

    assert completed.returncode == 2
    assert "OBSERVABILITY_DASHBOARD_CONTRACT_MISMATCH" in completed.stderr


def test_observability_evidence_rejects_receiver_release_drift(tmp_path: Path) -> None:
    evidence = observability_evidence()
    evidence["git_sha"] = "f" * 40

    completed = _run(tmp_path, evidence)

    assert completed.returncode == 2
    assert "OBSERVABILITY_GIT_SHA_MISMATCH" in completed.stderr


def test_observability_evidence_rejects_non_content_addressed_receipt(
    tmp_path: Path,
) -> None:
    evidence = observability_evidence()
    delivery = evidence["alert_delivery"]
    assert isinstance(delivery, dict)
    delivery["receipt_evidence_uri"] = "https://receipts.example.test/v1/evidence/latest.json"

    completed = _run(tmp_path, evidence)

    assert completed.returncode == 2
    assert "OBSERVABILITY_RECEIPT_URI_NOT_CONTENT_ADDRESSED" in completed.stderr


def test_observability_evidence_rejects_stale_receipt(tmp_path: Path) -> None:
    evidence = observability_evidence()
    delivery = evidence["alert_delivery"]
    assert isinstance(delivery, dict)
    delivery["received_at"] = (datetime.now(UTC) - timedelta(hours=1)).isoformat()

    completed = _run(tmp_path, evidence)

    assert completed.returncode == 2
    assert "OBSERVABILITY_RECEIPT_TIMESTAMP_INVALID" in completed.stderr


def test_observability_evidence_rejects_dashboard_release_tag_drift(
    tmp_path: Path,
) -> None:
    evidence = observability_evidence()
    grafana = evidence["grafana"]
    assert isinstance(grafana, dict)
    dashboards = grafana["dashboards"]
    assert isinstance(dashboards, list)
    first = dashboards[0]
    assert isinstance(first, dict)
    first["release_tags"] = ["agent-platform-release-id:stale-release"]

    completed = _run(tmp_path, evidence)

    assert completed.returncode == 2
    assert "OBSERVABILITY_DASHBOARD_RELEASE_BINDING_MISSING" in completed.stderr


def test_observability_evidence_rejects_alert_release_binding_drift(
    tmp_path: Path,
) -> None:
    evidence = observability_evidence()
    delivery = evidence["alert_delivery"]
    assert isinstance(delivery, dict)
    delivery["git_sha"] = "f" * 40

    completed = _run(tmp_path, evidence)

    assert completed.returncode == 2
    assert "OBSERVABILITY_ALERT_RELEASE_BINDING_MISMATCH" in completed.stderr


def test_observability_evidence_fails_closed_for_malformed_release_tags(
    tmp_path: Path,
) -> None:
    evidence = observability_evidence()
    grafana = evidence["grafana"]
    assert isinstance(grafana, dict)
    dashboards = grafana["dashboards"]
    assert isinstance(dashboards, list)
    first = dashboards[0]
    assert isinstance(first, dict)
    first["release_tags"] = [{"unexpected": "object"}]

    completed = _run(tmp_path, evidence)

    assert completed.returncode == 2
    assert "OBSERVABILITY_SCHEMA_INVALID" in completed.stderr
    assert "Traceback" not in completed.stderr
