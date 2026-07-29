from __future__ import annotations

import hashlib
import json
import subprocess
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from deploy.ci import validate_live_baseline as validator_module
from deploy.ci.validate_live_baseline import (
    validate_live_baseline,
    verify_cosign_signature,
)

PLATFORM_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = PLATFORM_ROOT / "deploy" / "ci" / "live-baseline.schema.json"
NOW = datetime(2026, 7, 27, 9, 0, tzinfo=UTC)
SIGNER_IDENTITY = (
    "https://github.com/example/platform/.github/workflows/"
    "publish-live-baseline.yml@refs/heads/main"
)
SIGNER_ISSUER = "https://token.actions.githubusercontent.com"


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest_uri(digest: str) -> str:
    return f"https://evidence.example.test/live-baselines/{digest}"


def live_baseline(*, now: datetime = NOW) -> dict[str, Any]:
    raw_digest = "sha256:" + "d" * 64
    return {
        "schema_version": "1.0",
        "kind": "live-release-baseline",
        "environment": "production",
        "prior_release": {
            "release_id": "release-2026-07-20",
            "git_sha": "a" * 40,
            "image_digest": "sha256:" + "b" * 64,
        },
        "sampling": {
            "window_started_at": (now - timedelta(days=2)).isoformat(),
            "window_ended_at": (now - timedelta(hours=1)).isoformat(),
            "sample_count": 500,
        },
        "metrics": {
            "production_golden_success_rate": 0.98,
            "p95_latency_seconds": 10.0,
            "average_cost_per_success_usd": 1.0,
        },
        "raw_evidence": {
            "sha256": raw_digest,
            "uri": _digest_uri(raw_digest),
        },
        "signer": {
            "identity": SIGNER_IDENTITY,
            "issuer": SIGNER_ISSUER,
        },
        "issued_at": (now - timedelta(minutes=30)).isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
    }


def _validated(
    baseline: dict[str, Any],
    *,
    now: datetime = NOW,
    source_uri: str | None = None,
) -> dict[str, Any]:
    source_bytes = _canonical(baseline)
    source_digest = "sha256:" + hashlib.sha256(source_bytes).hexdigest()
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return validate_live_baseline(
        baseline,
        schema,
        source_bytes=source_bytes,
        source_uri=source_uri or _digest_uri(source_digest),
        signature_bundle_sha256="sha256:" + "e" * 64,
        expected_environment="production",
        expected_signer_identity=SIGNER_IDENTITY,
        expected_signer_issuer=SIGNER_ISSUER,
        maximum_age_seconds=3 * 24 * 60 * 60,
        now=now,
    )


def test_accepts_fresh_content_addressed_prior_release_baseline() -> None:
    baseline = live_baseline()

    report = _validated(baseline)

    assert report["validated"] is True
    assert report["signature_verified"] is True
    assert report["environment"] == "production"
    assert report["prior_release"] == baseline["prior_release"]
    assert report["sampling"] == baseline["sampling"]
    assert report["metrics"] == baseline["metrics"]
    assert report["raw_evidence"] == baseline["raw_evidence"]
    assert report["signer"] == baseline["signer"]
    assert report["baseline_uri"].endswith(report["baseline_sha256"])


@pytest.mark.parametrize(
    ("mutation", "error"),
    (
        (
            lambda value: value["signer"].__setitem__("identity", "https://attacker.test"),
            "LIVE_BASELINE_SIGNER_IDENTITY_MISMATCH",
        ),
        (
            lambda value: value["raw_evidence"].__setitem__(
                "uri",
                _digest_uri("sha256:" + "0" * 64),
            ),
            "LIVE_BASELINE_RAW_EVIDENCE_DIGEST_URI_MISMATCH",
        ),
        (
            lambda value: value["sampling"].__setitem__(
                "window_started_at",
                (NOW + timedelta(hours=1)).isoformat(),
            ),
            "LIVE_BASELINE_SAMPLING_TIMELINE_INVALID",
        ),
    ),
)
def test_rejects_untrusted_signer_raw_evidence_or_sampling_timeline(
    mutation: object,
    error: str,
) -> None:
    baseline = live_baseline()
    mutation(baseline)

    with pytest.raises(ValueError, match=error):
        _validated(baseline)


def test_rejects_source_digest_mismatch_or_stale_baseline() -> None:
    baseline = live_baseline()
    with pytest.raises(ValueError, match="LIVE_BASELINE_SOURCE_URI_DIGEST_MISMATCH"):
        _validated(
            baseline,
            source_uri=_digest_uri("sha256:" + "0" * 64),
        )

    stale = live_baseline(now=NOW - timedelta(days=4))
    stale["expires_at"] = (NOW + timedelta(days=1)).isoformat()
    with pytest.raises(ValueError, match="LIVE_BASELINE_STALE"):
        _validated(stale)


def test_cosign_verification_uses_exact_oidc_identity_and_issuer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "baseline.json"
    bundle = tmp_path / "baseline.json.sigstore.json"
    evidence.write_bytes(_canonical(live_baseline()))
    bundle.write_text("{}", encoding="utf-8")
    calls: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        assert kwargs["shell"] is False
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(validator_module.subprocess, "run", fake_run)

    bundle_digest = verify_cosign_signature(
        evidence_path=evidence,
        signature_bundle_path=bundle,
        expected_signer_identity=SIGNER_IDENTITY,
        expected_signer_issuer=SIGNER_ISSUER,
    )

    assert bundle_digest == "sha256:" + hashlib.sha256(b"{}").hexdigest()
    assert calls == [
        [
            "cosign",
            "verify-blob",
            "--bundle",
            str(bundle),
            "--certificate-identity",
            SIGNER_IDENTITY,
            "--certificate-oidc-issuer",
            SIGNER_ISSUER,
            str(evidence),
        ]
    ]


def test_schema_rejects_missing_release_sampling_metrics_or_evidence() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    for field in ("prior_release", "sampling", "metrics", "raw_evidence", "signer"):
        baseline = deepcopy(live_baseline())
        baseline.pop(field)
        source_bytes = _canonical(baseline)
        source_digest = "sha256:" + hashlib.sha256(source_bytes).hexdigest()
        with pytest.raises(ValueError, match="LIVE_BASELINE_SCHEMA_INVALID"):
            validate_live_baseline(
                baseline,
                schema,
                source_bytes=source_bytes,
                source_uri=_digest_uri(source_digest),
                signature_bundle_sha256="sha256:" + "e" * 64,
                expected_environment="production",
                expected_signer_identity=SIGNER_IDENTITY,
                expected_signer_issuer=SIGNER_ISSUER,
                maximum_age_seconds=3 * 24 * 60 * 60,
                now=NOW,
            )
