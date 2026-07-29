from __future__ import annotations

import httpx
import pytest
from scripts.verify_release import _smoke_run, _verify_health

GIT_SHA = "a" * 40
IMAGE_DIGEST = "sha256:" + "b" * 64
TOOL_CATALOG_ID = "enterprise-tools-2026-07-24"
TOOL_CATALOG_DIGEST = "sha256:" + "d" * 64


def test_release_verifier_checks_identity_dependencies_and_read_only_smoke() -> None:
    seen_idempotency_key = ""

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal seen_idempotency_key
        if request.url.path == "/health":
            return httpx.Response(
                200,
                json={
                    "ok": True,
                    "release_git_sha": GIT_SHA,
                    "release_image_digest": IMAGE_DIGEST,
                    "release_identity": {
                        "tool_catalog_id": TOOL_CATALOG_ID,
                        "tool_catalog_digest": TOOL_CATALOG_DIGEST,
                    },
                    "dependencies": {
                        "database": "ok",
                        "temporal": "ok",
                        "object_store": "ok",
                        "policy": "ok",
                    },
                },
            )
        if request.url.path == "/ready":
            return httpx.Response(200, json={"ready": True})
        if request.url.path == "/v1/runs" and request.method == "POST":
            seen_idempotency_key = request.headers["Idempotency-Key"]
            assert request.headers["Authorization"] == "Bearer release-token"
            return httpx.Response(202, json={"run_id": "run-1", "status": "received"})
        if request.url.path == "/v1/runs/run-1":
            return httpx.Response(
                200,
                json={
                    "run_id": "run-1",
                    "status": "completed",
                    "result": {"summary": "verified"},
                },
            )
        return httpx.Response(404)

    with httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="https://agent.example.test",
    ) as client:
        health = _verify_health(
            client,
            expected_git_sha=GIT_SHA,
            expected_image_digest=IMAGE_DIGEST,
            expected_tool_catalog_id=TOOL_CATALOG_ID,
            expected_tool_catalog_digest=TOOL_CATALOG_DIGEST,
        )
        smoke = _smoke_run(
            client,
            token="release-token",
            expected_git_sha=GIT_SHA,
            timeout_seconds=5,
        )

    assert health["dependencies"]["temporal"] == "ok"
    assert smoke["status"] == "completed"
    assert seen_idempotency_key == f"release-smoke-{GIT_SHA}"


def test_release_verifier_fails_closed_on_digest_or_dependency_mismatch() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(
                200,
                json={
                    "ok": True,
                    "release_git_sha": GIT_SHA,
                    "release_image_digest": "sha256:" + "c" * 64,
                    "dependencies": {"database": "error:unavailable"},
                },
            )
        return httpx.Response(200, json={"ready": True})

    with httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="https://agent.example.test",
    ) as client:
        with pytest.raises(RuntimeError, match="RELEASE_IMAGE_DIGEST_MISMATCH"):
            _verify_health(
                client,
                expected_git_sha=GIT_SHA,
                expected_image_digest=IMAGE_DIGEST,
                expected_tool_catalog_id=TOOL_CATALOG_ID,
                expected_tool_catalog_digest=TOOL_CATALOG_DIGEST,
            )
