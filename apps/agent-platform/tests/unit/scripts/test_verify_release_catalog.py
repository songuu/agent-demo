from __future__ import annotations

import httpx
import pytest
from scripts.verify_release import _verify_health

GIT_SHA = "a" * 40
IMAGE_DIGEST = "sha256:" + "b" * 64
TOOL_CATALOG_ID = "enterprise-tools-2026-07-24"
TOOL_CATALOG_DIGEST = "sha256:" + "d" * 64


def _health_response(
    *,
    catalog_id: str = TOOL_CATALOG_ID,
    catalog_digest: str = TOOL_CATALOG_DIGEST,
) -> dict[str, object]:
    return {
        "ok": True,
        "release_git_sha": GIT_SHA,
        "release_image_digest": IMAGE_DIGEST,
        "release_identity": {
            "tool_catalog_id": catalog_id,
            "tool_catalog_digest": catalog_digest,
        },
        "dependencies": {"database": "ok"},
    }


@pytest.mark.parametrize(
    ("health", "error_code"),
    (
        ({**_health_response(), "release_identity": None}, "RELEASE_IDENTITY_MISSING"),
        (
            _health_response(catalog_id="unexpected-catalog"),
            "TOOL_CATALOG_ID_MISMATCH",
        ),
        (
            _health_response(catalog_digest="sha256:" + "e" * 64),
            "TOOL_CATALOG_DIGEST_MISMATCH",
        ),
    ),
)
def test_release_verifier_fails_closed_on_tool_catalog_identity(
    health: dict[str, object],
    error_code: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200, json=health)
        return httpx.Response(200, json={"ready": True})

    with httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="https://agent.example.test",
    ) as client:
        with pytest.raises(RuntimeError, match=error_code):
            _verify_health(
                client,
                expected_git_sha=GIT_SHA,
                expected_image_digest=IMAGE_DIGEST,
                expected_tool_catalog_id=TOOL_CATALOG_ID,
                expected_tool_catalog_digest=TOOL_CATALOG_DIGEST,
            )
