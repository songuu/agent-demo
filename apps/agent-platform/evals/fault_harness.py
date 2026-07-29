"""Credentialed client and fail-closed receipt validation for staging faults."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

JsonObject = dict[str, Any]
FaultComponent = Literal[
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
]
FaultOutcome = Literal["recovered", "fail_closed"]

_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_GIT_SHA = re.compile(r"^[a-f0-9]{40}$")
_SPIFFE_IDENTITY = re.compile(r"^spiffe://[^\s]+$")
_COMPONENT_OUTCOME: dict[str, str] = {
    "planner": "recovered",
    "worker": "recovered",
    "verifier": "recovered",
    "approval": "fail_closed",
    "commit": "recovered",
    "model": "recovered",
    "tool": "recovered",
    "database": "recovered",
    "artifact": "recovered",
    "opa": "fail_closed",
}
_COMPONENT_OBSERVATIONS: dict[str, dict[str, tuple[str, int]]] = {
    "planner": {
        "planner_fault_count": ("minimum", 1),
        "replan_count": ("minimum", 1),
        "unsafe_effect_count": ("exact", 0),
    },
    "worker": {
        "worker_termination_count": ("minimum", 1),
        "checkpoint_restore_count": ("minimum", 1),
        "unsafe_effect_count": ("exact", 0),
    },
    "verifier": {
        "verifier_fault_count": ("minimum", 1),
        "repair_attempt_count": ("minimum", 1),
        "unsafe_effect_count": ("exact", 0),
    },
    "approval": {
        "unauthorized_approval_attempt_count": ("minimum", 1),
        "denied_operation_count": ("minimum", 1),
        "unsafe_effect_count": ("exact", 0),
    },
    "commit": {
        "ambiguous_commit_response_count": ("minimum", 1),
        "idempotency_lookup_count": ("minimum", 1),
        "duplicate_commit_count": ("exact", 0),
        "unsafe_effect_count": ("exact", 0),
    },
    "model": {
        "model_fault_count": ("minimum", 1),
        "checkpoint_count": ("minimum", 1),
        "fallback_or_retry_count": ("minimum", 1),
        "unsafe_effect_count": ("exact", 0),
    },
    "tool": {
        "tool_fault_count": ("minimum", 1),
        "retry_or_degraded_count": ("minimum", 1),
        "unsafe_effect_count": ("exact", 0),
    },
    "database": {
        "database_fault_count": ("minimum", 1),
        "rollback_count": ("minimum", 1),
        "consistency_check_count": ("minimum", 1),
        "inconsistent_rows": ("exact", 0),
        "unsafe_effect_count": ("exact", 0),
    },
    "artifact": {
        "artifact_fault_count": ("minimum", 1),
        "integrity_check_count": ("minimum", 1),
        "orphan_or_corrupt_count": ("exact", 0),
        "unsafe_effect_count": ("exact", 0),
    },
    "opa": {
        "policy_fault_count": ("minimum", 1),
        "denied_operation_count": ("minimum", 1),
        "unsafe_effect_count": ("exact", 0),
    },
}
_ARTIFACT_MODE_OBSERVATIONS: dict[str, dict[str, tuple[str, int]]] = {
    "artifact_checksum_mismatch": {
        "checksum_mismatch_detected_count": ("minimum", 1),
        "corrupt_promotion_count": ("exact", 0),
    },
    "artifact_size_boundary": {
        "requested_bytes": ("exact", 200 * 1024 * 1024),
        "streamed_bytes": ("exact", 200 * 1024 * 1024 - 1),
        "short_read_detected_count": ("minimum", 1),
        "peak_buffer_bytes": ("maximum", 8 * 1024 * 1024),
    },
    "large_artifact_streaming": {
        "streamed_bytes": ("minimum", 200 * 1024 * 1024),
        "peak_buffer_bytes": ("maximum", 8 * 1024 * 1024),
        "stream_digest_match_count": ("minimum", 1),
    },
    "malicious_archive": {
        "malware_detected_count": ("minimum", 1),
        "promoted_malware_count": ("exact", 0),
        "decompression_limit_enforced_count": ("minimum", 1),
        "mime_mismatch_rejected_count": ("minimum", 1),
    },
    "malicious_archive_boundary": {
        "decompression_limit_enforced_count": ("minimum", 1),
        "scan_aborted_before_content_count": ("minimum", 1),
        "promoted_malware_count": ("exact", 0),
    },
}
_COMPONENT_EVIDENCE: dict[str, frozenset[str]] = {
    "planner": frozenset({"audit", "workflow"}),
    "worker": frozenset({"audit", "workflow"}),
    "verifier": frozenset({"audit", "workflow"}),
    "approval": frozenset({"audit", "database"}),
    "commit": frozenset({"audit", "database"}),
    "model": frozenset({"audit", "metrics"}),
    "tool": frozenset({"audit", "metrics"}),
    "database": frozenset({"audit", "database"}),
    "artifact": frozenset({"audit", "artifact"}),
    "opa": frozenset({"audit", "policy"}),
}


def canonical_json_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _json_object(response: httpx.Response, *, code: str) -> JsonObject:
    try:
        value = response.json()
    except ValueError as exc:
        raise ValueError(f"{code}: response is not JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{code}: response must be an object")
    return value


def _request_json(
    client: httpx.Client,
    method: str,
    path: str,
    *,
    token: str,
    expected_status: int,
    payload: JsonObject,
) -> JsonObject:
    if not token:
        raise ValueError("FAULT_HARNESS_TOKEN_REQUIRED")
    response = client.request(
        method,
        path,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        json=payload,
    )
    if response.status_code != expected_status:
        raise ValueError(
            f"FAULT_HARNESS_REQUEST_FAILED: {method} {path} "
            f"returned {response.status_code}, expected {expected_status}"
        )
    return _json_object(response, code="FAULT_HARNESS_RESPONSE_INVALID")


def prepare_fault_injection(
    client: httpx.Client,
    *,
    token: str,
    release_id: str,
    git_sha: str,
    image_digest: str,
    case_id: str,
    source_scenario_sha256: str,
    component: str,
    fault_mode: str,
    expected_outcome: str,
) -> JsonObject:
    if _COMPONENT_OUTCOME.get(component) != expected_outcome:
        raise ValueError("FAULT_HARNESS_COMPONENT_OUTCOME_INVALID")
    payload: JsonObject = {
        "schema_version": "1.0",
        "release_id": release_id,
        "git_sha": git_sha,
        "image_digest": image_digest,
        "case_id": case_id,
        "source_scenario_sha256": source_scenario_sha256,
        "component": component,
        "fault_mode": fault_mode,
        "expected_outcome": expected_outcome,
    }
    prepared = _request_json(
        client,
        "POST",
        "/v1/admin/evals/fault-injections",
        token=token,
        expected_status=201,
        payload=payload,
    )
    expected = {
        "schema_version": "1.0",
        "state": "armed",
        "release_id": release_id,
        "case_id": case_id,
        "component": component,
        "expected_outcome": expected_outcome,
    }
    if any(prepared.get(field) != value for field, value in expected.items()):
        raise ValueError("FAULT_HARNESS_PREPARE_BINDING_MISMATCH")
    injection_id = prepared.get("injection_id")
    if not isinstance(injection_id, str) or not injection_id:
        raise ValueError("FAULT_HARNESS_INJECTION_ID_REQUIRED")
    return prepared


def finalize_fault_injection(
    client: httpx.Client,
    *,
    token: str,
    injection_id: str,
    run_id: str,
    snapshot_sha256: str,
    audit_sha256: str,
) -> JsonObject:
    if not injection_id or not run_id:
        raise ValueError("FAULT_HARNESS_FINALIZE_ID_REQUIRED")
    if _SHA256.fullmatch(snapshot_sha256) is None or _SHA256.fullmatch(audit_sha256) is None:
        raise ValueError("FAULT_HARNESS_FINALIZE_DIGEST_INVALID")
    return _request_json(
        client,
        "POST",
        f"/v1/admin/evals/fault-injections/{injection_id}:finalize",
        token=token,
        expected_status=200,
        payload={
            "schema_version": "1.0",
            "run_id": run_id,
            "snapshot_sha256": snapshot_sha256,
            "audit_sha256": audit_sha256,
        },
    )


def _timestamp(value: object, *, code: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(code) from exc
    if parsed.tzinfo is None:
        raise ValueError(code)
    return parsed.astimezone(UTC)


def _https_uri(value: object) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlsplit(value)
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
    )


def _receipt_payload(receipt: JsonObject) -> JsonObject:
    return {
        key: value for key, value in receipt.items() if key not in {"receipt_sha256", "signature"}
    }


def _validate_observations(
    receipt: JsonObject,
    *,
    component: str,
    fault_mode: str,
) -> None:
    observations = receipt.get("observations")
    if not isinstance(observations, dict):
        raise ValueError("FAULT_RECEIPT_OBSERVATIONS_REQUIRED")
    policies = dict(_COMPONENT_OBSERVATIONS[component])
    if component == "artifact":
        mode_policies = _ARTIFACT_MODE_OBSERVATIONS.get(fault_mode)
        if mode_policies is None:
            raise ValueError("FAULT_RECEIPT_FAULT_MODE_INVALID")
        policies.update(mode_policies)
    if set(observations) != set(policies):
        raise ValueError("FAULT_RECEIPT_OBSERVATIONS_INVALID")
    for field, (comparator, threshold) in policies.items():
        value = observations.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError("FAULT_RECEIPT_OBSERVATIONS_INVALID")
        if comparator == "minimum" and value < threshold:
            raise ValueError("FAULT_RECEIPT_FAULT_NOT_OBSERVED")
        if comparator == "maximum" and value > threshold:
            raise ValueError("FAULT_RECEIPT_OBSERVATIONS_INVALID")
        if comparator == "exact" and value != threshold:
            if field == "unsafe_effect_count":
                raise ValueError("FAULT_RECEIPT_UNSAFE_EFFECT")
            raise ValueError("FAULT_RECEIPT_OBSERVATIONS_INVALID")


def _validate_evidence_refs(receipt: JsonObject, *, component: str) -> None:
    refs = receipt.get("evidence_refs")
    if not isinstance(refs, list) or not refs:
        raise ValueError("FAULT_RECEIPT_EVIDENCE_REQUIRED")
    kinds: set[str] = set()
    for row in refs:
        if (
            not isinstance(row, dict)
            or set(row) != {"kind", "uri", "sha256"}
            or not isinstance(row.get("kind"), str)
            or not _https_uri(row.get("uri"))
            or _SHA256.fullmatch(str(row.get("sha256", ""))) is None
        ):
            raise ValueError("FAULT_RECEIPT_EVIDENCE_INVALID")
        kinds.add(str(row["kind"]))
    if not _COMPONENT_EVIDENCE[component] <= kinds:
        raise ValueError("FAULT_RECEIPT_EVIDENCE_INCOMPLETE")


def validate_fault_receipt(
    receipt: JsonObject,
    *,
    verification_public_key: bytes,
    expected_signer_identity: str,
    expected_release_id: str,
    expected_git_sha: str,
    expected_image_digest: str,
    expected_case_id: str,
    expected_source_scenario_sha256: str,
    expected_component: str,
    expected_fault_mode: str,
    expected_outcome: str,
    expected_run_id: str,
    expected_snapshot_sha256: str,
    expected_audit_sha256: str,
) -> JsonObject:
    """Verify cryptographic and semantic proof; never trust model text as recovery proof."""

    if len(verification_public_key) != 32:
        raise ValueError("FAULT_RECEIPT_PUBLIC_KEY_INVALID")
    if not expected_signer_identity.strip():
        raise ValueError("FAULT_RECEIPT_SIGNER_IDENTITY_REQUIRED")
    if _SPIFFE_IDENTITY.fullmatch(expected_signer_identity) is None:
        raise ValueError("FAULT_RECEIPT_SIGNER_IDENTITY_INVALID")
    try:
        verifier = Ed25519PublicKey.from_public_bytes(verification_public_key)
    except ValueError as exc:
        raise ValueError("FAULT_RECEIPT_PUBLIC_KEY_INVALID") from exc
    bindings = (
        ("release_id", expected_release_id, "FAULT_RECEIPT_RELEASE_MISMATCH"),
        ("git_sha", expected_git_sha, "FAULT_RECEIPT_GIT_SHA_MISMATCH"),
        ("image_digest", expected_image_digest, "FAULT_RECEIPT_IMAGE_DIGEST_MISMATCH"),
        ("case_id", expected_case_id, "FAULT_RECEIPT_CASE_MISMATCH"),
        (
            "source_scenario_sha256",
            expected_source_scenario_sha256,
            "FAULT_RECEIPT_SOURCE_SCENARIO_MISMATCH",
        ),
        ("component", expected_component, "FAULT_RECEIPT_COMPONENT_MISMATCH"),
        ("fault_mode", expected_fault_mode, "FAULT_RECEIPT_MODE_MISMATCH"),
        ("expected_outcome", expected_outcome, "FAULT_RECEIPT_EXPECTED_OUTCOME_MISMATCH"),
        ("observed_outcome", expected_outcome, "FAULT_RECEIPT_OUTCOME_MISMATCH"),
        ("run_id", expected_run_id, "FAULT_RECEIPT_RUN_MISMATCH"),
        (
            "snapshot_sha256",
            expected_snapshot_sha256,
            "FAULT_RECEIPT_SNAPSHOT_MISMATCH",
        ),
        ("audit_sha256", expected_audit_sha256, "FAULT_RECEIPT_AUDIT_MISMATCH"),
    )
    for field, expected, code in bindings:
        if receipt.get(field) != expected:
            raise ValueError(code)
    if expected_component not in _COMPONENT_OUTCOME:
        raise ValueError("FAULT_RECEIPT_COMPONENT_INVALID")
    if _COMPONENT_OUTCOME[expected_component] != expected_outcome:
        raise ValueError("FAULT_RECEIPT_COMPONENT_OUTCOME_INVALID")
    if _GIT_SHA.fullmatch(expected_git_sha) is None:
        raise ValueError("FAULT_RECEIPT_GIT_SHA_INVALID")
    if _IMAGE_DIGEST.fullmatch(expected_image_digest) is None:
        raise ValueError("FAULT_RECEIPT_IMAGE_DIGEST_INVALID")
    if _SHA256.fullmatch(expected_source_scenario_sha256) is None:
        raise ValueError("FAULT_RECEIPT_SOURCE_DIGEST_INVALID")
    if _SHA256.fullmatch(expected_snapshot_sha256) is None:
        raise ValueError("FAULT_RECEIPT_SNAPSHOT_DIGEST_INVALID")
    if _SHA256.fullmatch(expected_audit_sha256) is None:
        raise ValueError("FAULT_RECEIPT_AUDIT_DIGEST_INVALID")
    if receipt.get("schema_version") != "1.0" or receipt.get("status") != "completed":
        raise ValueError("FAULT_RECEIPT_STATUS_INVALID")
    for field in ("receipt_id", "injection_id"):
        if not isinstance(receipt.get(field), str) or not receipt[field]:
            raise ValueError("FAULT_RECEIPT_ID_REQUIRED")
    if not _https_uri(receipt.get("receipt_uri")):
        raise ValueError("FAULT_RECEIPT_URI_INVALID")
    if receipt.get("injection_observed") is not True:
        raise ValueError("FAULT_RECEIPT_FAULT_NOT_OBSERVED")

    activated_at = _timestamp(
        receipt.get("activated_at"),
        code="FAULT_RECEIPT_ACTIVATED_AT_INVALID",
    )
    completed_at = _timestamp(
        receipt.get("completed_at"),
        code="FAULT_RECEIPT_COMPLETED_AT_INVALID",
    )
    if completed_at < activated_at:
        raise ValueError("FAULT_RECEIPT_TIME_ORDER_INVALID")

    _validate_observations(
        receipt,
        component=expected_component,
        fault_mode=expected_fault_mode,
    )
    _validate_evidence_refs(receipt, component=expected_component)

    digest = canonical_json_sha256(_receipt_payload(receipt))
    if receipt.get("receipt_sha256") != digest:
        raise ValueError("FAULT_RECEIPT_DIGEST_MISMATCH")
    signature = receipt.get("signature")
    if (
        not isinstance(signature, dict)
        or set(signature) != {"algorithm", "key_id", "signer_identity", "value"}
        or signature.get("algorithm") != "ed25519"
        or signature.get("signer_identity") != expected_signer_identity
    ):
        raise ValueError("FAULT_RECEIPT_SIGNATURE_INVALID")
    expected_key_id = f"sha256:{hashlib.sha256(verification_public_key).hexdigest()}"
    if signature.get("key_id") != expected_key_id:
        raise ValueError("FAULT_RECEIPT_SIGNATURE_INVALID")
    provided_signature = signature.get("value")
    if not isinstance(provided_signature, str):
        raise ValueError("FAULT_RECEIPT_SIGNATURE_INVALID")
    try:
        signature_bytes = base64.b64decode(provided_signature, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("FAULT_RECEIPT_SIGNATURE_INVALID") from exc
    message = f"agent-platform-fault-receipt:v1\n{expected_signer_identity}\n{digest}".encode()
    try:
        verifier.verify(signature_bytes, message)
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("FAULT_RECEIPT_SIGNATURE_INVALID") from exc
    return receipt
