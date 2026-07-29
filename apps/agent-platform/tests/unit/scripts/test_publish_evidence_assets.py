from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
import pytest
from scripts.publish_evidence_assets import (
    _parse_asset_specs,
    publish_assets,
)

RELEASE_ID = "release-2026-07-27"
GIT_SHA = "a" * 40
IMAGE_DIGEST = "sha256:" + "b" * 64
ARTIFACT_ID = UUID("11111111-1111-4111-8111-111111111111")
NOW = datetime(2026, 7, 27, tzinfo=UTC)


class ArtifactBackend:
    def __init__(self, *, metadata_overrides: dict[str, Any] | None = None) -> None:
        self.metadata_overrides = metadata_overrides or {}
        self.persisted_content = b""
        self.upload_headers: httpx.Headers | None = None
        self.readback_content: bytes | None = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            self.persisted_content = request.content
            self.upload_headers = request.headers
            digest = hashlib.sha256(self.persisted_content).hexdigest()
            metadata: dict[str, Any] = {
                "artifact_id": str(ARTIFACT_ID),
                "sha256": digest,
                "size_bytes": len(self.persisted_content),
                "classification": "restricted",
                "retention_policy": "release-evidence@1:immutable:365d",
                "scan_status": "malware_clean",
                "scan_provenance": {
                    "release_binding": {
                        "release_id": RELEASE_ID,
                        "git_sha": GIT_SHA,
                        "image_digest": IMAGE_DIGEST,
                    }
                },
                "object_version_id": "version-1",
                "object_retain_until": (NOW + timedelta(days=366)).isoformat(),
                "legal_hold_status": "none",
                "expires_at": (NOW + timedelta(days=366)).isoformat(),
            }
            metadata.update(self.metadata_overrides)
            return httpx.Response(201, json=metadata)
        if request.method == "GET" and request.url.host == "artifacts.example.test":
            assert request.headers["authorization"] == "Bearer test-token"
            digest = hashlib.sha256(self.persisted_content).hexdigest()
            return httpx.Response(
                307,
                headers={
                    "Location": "https://objects.example.test/evidence",
                    "ETag": f'"sha256:{digest}"',
                    "Digest": f"sha-256={digest}",
                },
            )
        if request.method == "GET" and request.url.host == "objects.example.test":
            assert "authorization" not in request.headers
            content = (
                self.persisted_content if self.readback_content is None else self.readback_content
            )
            return httpx.Response(200, content=content)
        raise AssertionError(f"unexpected request: {request.method} {request.url}")


def _publish(path: Path, backend: ArtifactBackend) -> dict[str, Any]:
    with httpx.Client(
        transport=httpx.MockTransport(backend),
        headers={"Authorization": "Bearer test-token"},
    ) as client:
        return publish_assets(
            client=client,
            base_url="https://artifacts.example.test",
            release_id=RELEASE_ID,
            git_sha=GIT_SHA,
            image_digest=IMAGE_DIGEST,
            assets={"sbom": path},
            kind="release-evidence-component",
            minimum_retention_days=365,
            now=NOW,
        )


def test_publish_assets_binds_canonical_persisted_bytes_and_readback(
    tmp_path: Path,
) -> None:
    source = tmp_path / "sbom.spdx.json"
    source.write_text('{ "z": "e\u0301", "a": 1 }\n', encoding="utf-8")
    backend = ArtifactBackend()

    receipt = _publish(source, backend)

    expected = '{"a":1,"z":"é"}'.encode()
    expected_digest = hashlib.sha256(expected).hexdigest()
    assert backend.persisted_content == expected
    assert backend.upload_headers is not None
    assert backend.upload_headers["content-type"] == "application/json"
    assert backend.upload_headers["content-length"] == str(len(expected))
    assert receipt["verified"] is True
    assert receipt["assets"]["sbom"] == {
        "artifact_id": str(ARTIFACT_ID),
        "content_uri": (
            "https://artifacts.example.test/v1/artifacts/"
            f"{ARTIFACT_ID}/content/sha256:{expected_digest}"
        ),
        "sha256": f"sha256:{expected_digest}",
        "size_bytes": len(expected),
        "classification": "restricted",
        "release_binding": {
            "release_id": RELEASE_ID,
            "git_sha": GIT_SHA,
            "image_digest": IMAGE_DIGEST,
        },
        "retention_policy": "release-evidence@1:immutable:365d",
        "scan_status": "malware_clean",
        "object_version_id": "version-1",
        "object_retain_until": (NOW + timedelta(days=366)).isoformat(),
        "legal_hold_status": "none",
        "expires_at": (NOW + timedelta(days=366)).isoformat(),
        "readback_verified": True,
    }


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"scan_status": "pending"}, "EVIDENCE_ARTIFACT_MALWARE_GATE_FAILED"),
        ({"object_version_id": ""}, "EVIDENCE_ARTIFACT_VERSION_ID_REQUIRED"),
        (
            {"object_retain_until": (NOW + timedelta(days=364)).isoformat()},
            "EVIDENCE_ARTIFACT_RETENTION_TOO_SHORT",
        ),
        (
            {"expires_at": (NOW + timedelta(days=364)).isoformat()},
            "EVIDENCE_ARTIFACT_EXPIRY_TOO_SOON",
        ),
    ],
)
def test_publish_assets_fails_closed_on_incomplete_governance_metadata(
    tmp_path: Path,
    override: dict[str, Any],
    message: str,
) -> None:
    source = tmp_path / "evidence.json"
    source.write_text('{"ok":true}', encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        _publish(source, ArtifactBackend(metadata_overrides=override))


def test_publish_assets_rejects_content_readback_mismatch(tmp_path: Path) -> None:
    source = tmp_path / "evidence.json"
    source.write_text('{"ok":true}', encoding="utf-8")
    backend = ArtifactBackend()
    backend.readback_content = b'{"ok":false}'

    with pytest.raises(ValueError, match="EVIDENCE_ARTIFACT_READBACK_SHA256_MISMATCH"):
        _publish(source, backend)


def test_publish_assets_requires_https_and_valid_asset_specs(tmp_path: Path) -> None:
    source = tmp_path / "evidence.json"
    source.write_text('{"ok":true}', encoding="utf-8")
    backend = ArtifactBackend()
    with httpx.Client(transport=httpx.MockTransport(backend)) as client:
        with pytest.raises(ValueError, match="EVIDENCE_ARTIFACT_BASE_URL_INVALID"):
            publish_assets(
                client=client,
                base_url="http://artifacts.example.test",
                release_id=RELEASE_ID,
                git_sha=GIT_SHA,
                image_digest=IMAGE_DIGEST,
                assets={"evidence": source},
                kind="release-evidence-component",
                minimum_retention_days=365,
                now=NOW,
            )

    with pytest.raises(ValueError, match="EVIDENCE_ASSETS_REQUIRED"):
        _parse_asset_specs([])
    with pytest.raises(ValueError, match="EVIDENCE_ASSET_NAME_DUPLICATED"):
        _parse_asset_specs([f"evidence={source}", f"evidence={source}"])
