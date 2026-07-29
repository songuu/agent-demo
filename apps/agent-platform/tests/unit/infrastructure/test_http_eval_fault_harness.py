from __future__ import annotations

import base64
import hashlib
import json
from copy import deepcopy

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from evals.fault_harness import canonical_json_sha256, validate_fault_receipt

from agent_platform.application.errors import PlatformError
from agent_platform.infrastructure.eval_fault_harness import HttpEvalFaultHarness

SIGNER_IDENTITY = "spiffe://agent-platform.example/staging/eval-fault-controller"
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
PUBLIC_KEY = PRIVATE_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
KEY_ID = f"sha256:{hashlib.sha256(PUBLIC_KEY).hexdigest()}"


def _signature_value(digest: str) -> str:
    message = f"agent-platform-fault-receipt:v1\n{SIGNER_IDENTITY}\n{digest}".encode()
    return base64.b64encode(PRIVATE_KEY.sign(message)).decode()


@pytest.mark.asyncio
async def test_http_eval_fault_harness_arms_finalizes_and_gets_signed_receipt() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.path.endswith(":finalize"):
            return httpx.Response(200, json={"state": "completed"})
        if request.url.path.endswith("/receipt"):
            return httpx.Response(
                200,
                json={
                    "receipt_id": "receipt-1",
                    "signature": {
                        "algorithm": "ed25519",
                        "key_id": KEY_ID,
                        "signer_identity": SIGNER_IDENTITY,
                        "value": base64.b64encode(b"a" * 64).decode(),
                    },
                },
            )
        return httpx.Response(201, json={"injection_id": "injection-1"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        harness = HttpEvalFaultHarness(
            controller_url="https://fault-controller.staging.example.test/",
            token="short-lived-token",
            client=client,
        )
        assert await harness.prepare(
            {"release_id": "release-1"},
            actor_id="reviewer-1",
            tenant_id="tenant-1",
        ) == {"injection_id": "injection-1"}
        assert await harness.finalize(
            "injection-1",
            {"run_id": "run-1"},
            actor_id="reviewer-1",
            tenant_id="tenant-1",
        ) == {"state": "completed"}
        receipt = await harness.receipt(
            "injection-1",
            actor_id="reviewer-1",
            tenant_id="tenant-1",
        )
        await harness.aclose()

    assert receipt["signature"] == {
        "algorithm": "ed25519",
        "key_id": KEY_ID,
        "signer_identity": SIGNER_IDENTITY,
        "value": base64.b64encode(b"a" * 64).decode(),
    }
    assert [request.url.path for request in calls] == [
        "/v1/fault-injections",
        "/v1/fault-injections/injection-1:finalize",
        "/v1/fault-injections/injection-1/receipt",
    ]
    for request in calls:
        assert request.headers["authorization"] == "Bearer short-lived-token"
        assert request.headers["x-agent-actor"] == "reviewer-1"
        assert request.headers["x-agent-tenant"] == "tenant-1"
    assert json.loads(calls[0].content) == {"release_id": "release-1"}


@pytest.mark.asyncio
async def test_http_eval_fault_harness_maps_controller_rejection_with_context() -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(503, json={"error": "controller unavailable"})
        )
    ) as client:
        harness = HttpEvalFaultHarness(
            controller_url="https://fault-controller.staging.example.test",
            token="short-lived-token",
            client=client,
        )
        with pytest.raises(PlatformError) as caught:
            await harness.prepare(
                {"release_id": "release-1"},
                actor_id="reviewer-1",
                tenant_id="tenant-1",
            )

    assert caught.value.code == "EVAL_FAULT_HARNESS_REJECTED"
    assert caught.value.retryable is True
    assert caught.value.context == {
        "operation": "/v1/fault-injections",
        "controller_status": 503,
    }


@pytest.mark.asyncio
async def test_http_eval_fault_harness_fails_closed_on_transport_error() -> None:
    def unavailable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("controller unavailable", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(unavailable)) as client:
        harness = HttpEvalFaultHarness(
            controller_url="https://fault-controller.staging.example.test",
            token="short-lived-token",
            client=client,
        )
        with pytest.raises(PlatformError) as caught:
            await harness.receipt(
                "injection-1",
                actor_id="reviewer-1",
                tenant_id="tenant-1",
            )

    assert caught.value.code == "EVAL_FAULT_HARNESS_UNAVAILABLE"
    assert caught.value.retryable is True
    assert caught.value.context == {"operation": "/v1/fault-injections/injection-1/receipt"}


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", ("not-json", "[]"))
async def test_http_eval_fault_harness_fails_closed_on_invalid_response(
    payload: str,
) -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                content=payload,
                headers={"content-type": "application/json"},
            )
        )
    ) as client:
        harness = HttpEvalFaultHarness(
            controller_url="https://fault-controller.staging.example.test",
            token="short-lived-token",
            client=client,
        )
        with pytest.raises(PlatformError) as caught:
            await harness.receipt(
                "injection-1",
                actor_id="reviewer-1",
                tenant_id="tenant-1",
            )

    assert caught.value.code == "EVAL_FAULT_HARNESS_RESPONSE_INVALID"
    assert caught.value.retryable is False


@pytest.mark.parametrize(
    "controller_url",
    (
        "http://fault-controller.staging.example.test",
        "https://user:secret@fault-controller.staging.example.test",
        "https://fault-controller.staging.example.test?token=secret",
    ),
)
def test_http_eval_fault_harness_rejects_insecure_controller_url(
    controller_url: str,
) -> None:
    with pytest.raises(ValueError, match="EVAL_FAULT_HARNESS_TLS_REQUIRED"):
        HttpEvalFaultHarness(
            controller_url=controller_url,
            token="short-lived-token",
        )


def test_http_eval_fault_harness_requires_token() -> None:
    with pytest.raises(ValueError, match="EVAL_FAULT_HARNESS_TOKEN_REQUIRED"):
        HttpEvalFaultHarness(
            controller_url="https://fault-controller.staging.example.test",
            token="",
        )


@pytest.mark.asyncio
async def test_http_eval_fault_harness_closes_owned_client() -> None:
    harness = HttpEvalFaultHarness(
        controller_url="https://fault-controller.staging.example.test",
        token="short-lived-token",
    )
    client = harness._client

    assert client.is_closed is False
    await harness.aclose()
    assert client.is_closed is True


@pytest.mark.asyncio
async def test_http_eval_fault_harness_receipt_is_verified_after_transport() -> None:
    payload = {
        "schema_version": "1.0",
        "receipt_id": "receipt-1",
        "injection_id": "injection-1",
        "receipt_uri": (
            "https://fault-controller.staging.example.test/v1/fault-injections/injection-1/receipt"
        ),
        "release_id": "release-1",
        "git_sha": "a" * 40,
        "image_digest": f"sha256:{'b' * 64}",
        "case_id": "case-1",
        "source_scenario_sha256": "c" * 64,
        "component": "model",
        "fault_mode": "model_fallback_recovery",
        "run_id": "run-1",
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
                "uri": "https://evidence.example.test/audit/run-1",
                "sha256": "d" * 64,
            },
            {
                "kind": "metrics",
                "uri": "https://evidence.example.test/metrics/run-1",
                "sha256": "e" * 64,
            },
        ],
    }
    digest = canonical_json_sha256(payload)
    signed_receipt = {
        **payload,
        "receipt_sha256": digest,
        "signature": {
            "algorithm": "ed25519",
            "key_id": KEY_ID,
            "signer_identity": SIGNER_IDENTITY,
            "value": _signature_value(digest),
        },
    }

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=signed_receipt))
    ) as client:
        harness = HttpEvalFaultHarness(
            controller_url="https://fault-controller.staging.example.test",
            token="short-lived-token",
            client=client,
        )
        transported = await harness.receipt(
            "injection-1",
            actor_id="reviewer-1",
            tenant_id="tenant-1",
        )

    assert (
        validate_fault_receipt(
            transported,
            verification_public_key=PUBLIC_KEY,
            expected_signer_identity=SIGNER_IDENTITY,
            expected_release_id="release-1",
            expected_git_sha="a" * 40,
            expected_image_digest=f"sha256:{'b' * 64}",
            expected_case_id="case-1",
            expected_source_scenario_sha256="c" * 64,
            expected_component="model",
            expected_fault_mode="model_fallback_recovery",
            expected_outcome="recovered",
            expected_run_id="run-1",
            expected_snapshot_sha256="f" * 64,
            expected_audit_sha256="1" * 64,
        )
        == transported
    )

    tampered = deepcopy(transported)
    tampered["signature"]["value"] = base64.b64encode(b"0" * 64).decode()
    with pytest.raises(ValueError, match="FAULT_RECEIPT_SIGNATURE_INVALID"):
        validate_fault_receipt(
            tampered,
            verification_public_key=PUBLIC_KEY,
            expected_signer_identity=SIGNER_IDENTITY,
            expected_release_id="release-1",
            expected_git_sha="a" * 40,
            expected_image_digest=f"sha256:{'b' * 64}",
            expected_case_id="case-1",
            expected_source_scenario_sha256="c" * 64,
            expected_component="model",
            expected_fault_mode="model_fallback_recovery",
            expected_outcome="recovered",
            expected_run_id="run-1",
            expected_snapshot_sha256="f" * 64,
            expected_audit_sha256="1" * 64,
        )
