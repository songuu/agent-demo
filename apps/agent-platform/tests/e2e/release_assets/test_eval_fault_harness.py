from __future__ import annotations

import base64
import hashlib
from copy import deepcopy
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from evals.fault_harness import (
    canonical_json_sha256,
    finalize_fault_injection,
    prepare_fault_injection,
    validate_fault_receipt,
)
from jsonschema import Draft202012Validator

RELEASE_ID = "release-20260727"
GIT_SHA = "a" * 40
IMAGE_DIGEST = f"sha256:{'b' * 64}"
SIGNER_IDENTITY = "spiffe://agent-platform.example/staging/eval-fault-controller"
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
PUBLIC_KEY = PRIVATE_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
KEY_ID = f"sha256:{hashlib.sha256(PUBLIC_KEY).hexdigest()}"
PLATFORM_ROOT = Path(__file__).parents[3]


def _signature_value(digest: str) -> str:
    message = f"agent-platform-fault-receipt:v1\n{SIGNER_IDENTITY}\n{digest}".encode()
    return base64.b64encode(PRIVATE_KEY.sign(message)).decode()


def _receipt_payload() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "receipt_id": "fault-receipt-001",
        "injection_id": "fault-injection-001",
        "receipt_uri": (
            "https://staging.example.test/v1/admin/evals/fault-injections/"
            "fault-injection-001/receipt"
        ),
        "release_id": RELEASE_ID,
        "git_sha": GIT_SHA,
        "image_digest": IMAGE_DIGEST,
        "case_id": "candidate-live-001",
        "source_scenario_sha256": "c" * 64,
        "component": "model",
        "fault_mode": "model_fallback_recovery",
        "run_id": "run-001",
        "snapshot_sha256": "f" * 64,
        "audit_sha256": "1" * 64,
        "status": "completed",
        "expected_outcome": "recovered",
        "observed_outcome": "recovered",
        "injection_observed": True,
        "activated_at": "2026-07-27T01:00:00Z",
        "completed_at": "2026-07-27T01:01:00Z",
        "observations": {
            "model_fault_count": 1,
            "checkpoint_count": 1,
            "fallback_or_retry_count": 1,
            "unsafe_effect_count": 0,
        },
        "evidence_refs": [
            {
                "kind": "audit",
                "uri": "https://staging.example.test/v1/audit/runs/run-001",
                "sha256": "d" * 64,
            },
            {
                "kind": "metrics",
                "uri": "https://metrics.example.test/query/fault-001",
                "sha256": "e" * 64,
            },
        ],
    }


def _signed_receipt() -> dict[str, object]:
    payload = _receipt_payload()
    digest = canonical_json_sha256(payload)
    return {
        **payload,
        "receipt_sha256": digest,
        "signature": {
            "algorithm": "ed25519",
            "key_id": KEY_ID,
            "signer_identity": SIGNER_IDENTITY,
            "value": _signature_value(digest),
        },
    }


def _signed_artifact_receipt(
    fault_mode: str,
    observations: dict[str, int],
) -> dict[str, object]:
    payload = {
        **_receipt_payload(),
        "component": "artifact",
        "fault_mode": fault_mode,
        "observations": {
            "artifact_fault_count": 1,
            "integrity_check_count": 1,
            "orphan_or_corrupt_count": 0,
            "unsafe_effect_count": 0,
            **observations,
        },
        "evidence_refs": [
            {
                "kind": "audit",
                "uri": "https://staging.example.test/v1/audit/runs/run-001",
                "sha256": "d" * 64,
            },
            {
                "kind": "artifact",
                "uri": "https://staging.example.test/v1/artifacts/fault-001",
                "sha256": "e" * 64,
            },
        ],
    }
    digest = canonical_json_sha256(payload)
    return {
        **payload,
        "receipt_sha256": digest,
        "signature": {
            "algorithm": "ed25519",
            "key_id": KEY_ID,
            "signer_identity": SIGNER_IDENTITY,
            "value": _signature_value(digest),
        },
    }


def test_fault_receipt_requires_exact_binding_observations_and_ed25519_signer() -> None:
    receipt = _signed_receipt()

    validated = validate_fault_receipt(
        receipt,
        verification_public_key=PUBLIC_KEY,
        expected_signer_identity=SIGNER_IDENTITY,
        expected_release_id=RELEASE_ID,
        expected_git_sha=GIT_SHA,
        expected_image_digest=IMAGE_DIGEST,
        expected_case_id="candidate-live-001",
        expected_source_scenario_sha256="c" * 64,
        expected_component="model",
        expected_fault_mode="model_fallback_recovery",
        expected_outcome="recovered",
        expected_run_id="run-001",
        expected_snapshot_sha256="f" * 64,
        expected_audit_sha256="1" * 64,
    )

    assert validated["receipt_sha256"] == receipt["receipt_sha256"]
    assert validated["injection_observed"] is True
    schema = __import__("json").loads(
        (PLATFORM_ROOT / "evals" / "fault-receipt.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(validated)


@pytest.mark.parametrize(
    ("mutate", "error"),
    (
        (
            lambda row: row.__setitem__("release_id", "other-release"),
            "FAULT_RECEIPT_RELEASE_MISMATCH",
        ),
        (
            lambda row: row["observations"].__setitem__("model_fault_count", 0),
            "FAULT_RECEIPT_FAULT_NOT_OBSERVED",
        ),
        (
            lambda row: row["observations"].__setitem__("unsafe_effect_count", 1),
            "FAULT_RECEIPT_UNSAFE_EFFECT",
        ),
        (
            lambda row: row.__setitem__("snapshot_sha256", "0" * 64),
            "FAULT_RECEIPT_SNAPSHOT_MISMATCH",
        ),
        (
            lambda row: row["signature"].__setitem__(
                "signer_identity",
                "spiffe://agent-platform.example/staging/other-controller",
            ),
            "FAULT_RECEIPT_SIGNATURE_INVALID",
        ),
        (
            lambda row: row["signature"].__setitem__("value", "0" * 64),
            "FAULT_RECEIPT_SIGNATURE_INVALID",
        ),
    ),
)
def test_fault_receipt_tampering_or_self_report_only_evidence_fails_closed(
    mutate: object,
    error: str,
) -> None:
    receipt = deepcopy(_signed_receipt())
    mutate(receipt)

    with pytest.raises(ValueError, match=error):
        validate_fault_receipt(
            receipt,
            verification_public_key=PUBLIC_KEY,
            expected_signer_identity=SIGNER_IDENTITY,
            expected_release_id=RELEASE_ID,
            expected_git_sha=GIT_SHA,
            expected_image_digest=IMAGE_DIGEST,
            expected_case_id="candidate-live-001",
            expected_source_scenario_sha256="c" * 64,
            expected_component="model",
            expected_fault_mode="model_fallback_recovery",
            expected_outcome="recovered",
            expected_run_id="run-001",
            expected_snapshot_sha256="f" * 64,
            expected_audit_sha256="1" * 64,
        )


def test_fault_harness_client_prepares_and_finalizes_exact_staging_case() -> None:
    calls: list[tuple[str, str, dict[str, object]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = request.read()
        payload = __import__("json").loads(body)
        calls.append((request.method, request.url.path, payload))
        assert request.headers["authorization"] == "Bearer fault-token"
        if request.url.path.endswith("/fault-injections"):
            return httpx.Response(
                201,
                json={
                    "schema_version": "1.0",
                    "injection_id": "fault-injection-001",
                    "state": "armed",
                    "release_id": RELEASE_ID,
                    "case_id": "candidate-live-001",
                    "component": "model",
                    "expected_outcome": "recovered",
                },
            )
        return httpx.Response(200, json=_signed_receipt())

    with httpx.Client(
        base_url="https://staging.example.test",
        transport=httpx.MockTransport(handler),
    ) as client:
        prepared = prepare_fault_injection(
            client,
            token="fault-token",
            release_id=RELEASE_ID,
            git_sha=GIT_SHA,
            image_digest=IMAGE_DIGEST,
            case_id="candidate-live-001",
            source_scenario_sha256="c" * 64,
            component="model",
            fault_mode="model_fallback_recovery",
            expected_outcome="recovered",
        )
        receipt = finalize_fault_injection(
            client,
            token="fault-token",
            injection_id=str(prepared["injection_id"]),
            run_id="run-001",
            snapshot_sha256="f" * 64,
            audit_sha256="1" * 64,
        )

    assert prepared["state"] == "armed"
    assert receipt["receipt_id"] == "fault-receipt-001"
    assert calls[0][1] == "/v1/admin/evals/fault-injections"
    assert calls[1][1].endswith("/fault-injection-001:finalize")


@pytest.mark.parametrize(
    ("fault_mode", "observations"),
    (
        (
            "large_artifact_streaming",
            {
                "streamed_bytes": 200 * 1024 * 1024,
                "peak_buffer_bytes": 8 * 1024 * 1024,
                "stream_digest_match_count": 1,
            },
        ),
        (
            "artifact_checksum_mismatch",
            {
                "checksum_mismatch_detected_count": 1,
                "corrupt_promotion_count": 0,
            },
        ),
        (
            "malicious_archive",
            {
                "malware_detected_count": 1,
                "promoted_malware_count": 0,
                "decompression_limit_enforced_count": 1,
                "mime_mismatch_rejected_count": 1,
            },
        ),
    ),
)
def test_artifact_receipt_requires_mode_specific_operational_proof(
    fault_mode: str,
    observations: dict[str, int],
) -> None:
    receipt = _signed_artifact_receipt(fault_mode, observations)

    validate_fault_receipt(
        receipt,
        verification_public_key=PUBLIC_KEY,
        expected_signer_identity=SIGNER_IDENTITY,
        expected_release_id=RELEASE_ID,
        expected_git_sha=GIT_SHA,
        expected_image_digest=IMAGE_DIGEST,
        expected_case_id="candidate-live-001",
        expected_source_scenario_sha256="c" * 64,
        expected_component="artifact",
        expected_fault_mode=fault_mode,
        expected_outcome="recovered",
        expected_run_id="run-001",
        expected_snapshot_sha256="f" * 64,
        expected_audit_sha256="1" * 64,
    )


def test_artifact_streaming_receipt_rejects_buffering_entire_payload() -> None:
    receipt = _signed_artifact_receipt(
        "large_artifact_streaming",
        {
            "streamed_bytes": 200 * 1024 * 1024,
            "peak_buffer_bytes": 200 * 1024 * 1024,
            "stream_digest_match_count": 1,
        },
    )

    with pytest.raises(ValueError, match="FAULT_RECEIPT_OBSERVATIONS_INVALID"):
        validate_fault_receipt(
            receipt,
            verification_public_key=PUBLIC_KEY,
            expected_signer_identity=SIGNER_IDENTITY,
            expected_release_id=RELEASE_ID,
            expected_git_sha=GIT_SHA,
            expected_image_digest=IMAGE_DIGEST,
            expected_case_id="candidate-live-001",
            expected_source_scenario_sha256="c" * 64,
            expected_component="artifact",
            expected_fault_mode="large_artifact_streaming",
            expected_outcome="recovered",
            expected_run_id="run-001",
            expected_snapshot_sha256="f" * 64,
            expected_audit_sha256="1" * 64,
        )
