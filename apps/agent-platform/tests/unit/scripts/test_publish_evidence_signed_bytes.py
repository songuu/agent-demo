from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from scripts.publish_evidence_assets import publish_assets
from tests.unit.scripts.test_publish_evidence_assets import (
    GIT_SHA,
    IMAGE_DIGEST,
    NOW,
    RELEASE_ID,
    ArtifactBackend,
    _publish,
)


def test_final_release_evidence_requires_already_canonical_signed_bytes(
    tmp_path: Path,
) -> None:
    source = tmp_path / "release-evidence.json"
    source.write_text('{ "a": 1 }\n', encoding="utf-8")
    backend = ArtifactBackend()

    with httpx.Client(transport=httpx.MockTransport(backend)) as client:
        with pytest.raises(ValueError, match="EVIDENCE_SIGNED_ASSET_NOT_CANONICAL"):
            publish_assets(
                client=client,
                base_url="https://artifacts.example.test",
                release_id=RELEASE_ID,
                git_sha=GIT_SHA,
                image_digest=IMAGE_DIGEST,
                assets={"release_evidence": source},
                kind="release-evidence",
                minimum_retention_days=365,
                now=NOW,
            )

    assert backend.persisted_content == b""


def test_final_release_evidence_saves_exact_verified_object_readback(
    tmp_path: Path,
) -> None:
    source = tmp_path / "release-evidence.json"
    source.write_bytes(b'{"a":1}')
    readback_dir = tmp_path / "readback"
    backend = ArtifactBackend()

    with httpx.Client(
        transport=httpx.MockTransport(backend),
        headers={"Authorization": "Bearer test-token"},
    ) as client:
        receipt = publish_assets(
            client=client,
            base_url="https://artifacts.example.test",
            release_id=RELEASE_ID,
            git_sha=GIT_SHA,
            image_digest=IMAGE_DIGEST,
            assets={"release_evidence": source},
            kind="release-evidence",
            minimum_retention_days=365,
            readback_dir=readback_dir,
            now=NOW,
        )

    assert receipt["verified"] is True
    assert (readback_dir / "release_evidence").read_bytes() == source.read_bytes()


def test_publish_assets_rejects_server_release_binding_mismatch(
    tmp_path: Path,
) -> None:
    source = tmp_path / "evidence.json"
    source.write_text('{"ok":true}', encoding="utf-8")
    backend = ArtifactBackend(
        metadata_overrides={
            "scan_provenance": {
                "release_binding": {
                    "release_id": "other-release",
                    "git_sha": GIT_SHA,
                    "image_digest": IMAGE_DIGEST,
                }
            }
        }
    )

    with pytest.raises(ValueError, match="EVIDENCE_ARTIFACT_RELEASE_BINDING_MISMATCH"):
        _publish(source, backend)


def test_sigstore_bundle_is_published_as_exact_opaque_bytes(tmp_path: Path) -> None:
    source = tmp_path / "release-approvals.json.sigstore.json"
    signed_bundle = b'{\n  "bundle": "format-is-signature-relevant"\n}\n'
    source.write_bytes(signed_bundle)
    backend = ArtifactBackend()

    receipt = _publish(source, backend)

    assert receipt["verified"] is True
    assert backend.persisted_content == signed_bundle
    assert backend.upload_headers is not None
    assert backend.upload_headers["content-type"] == "application/octet-stream"


@pytest.mark.parametrize(
    "asset_name",
    (
        "canary",
        "canary_signature_bundle",
        "foundation_attestation",
        "foundation_attestation_signature_bundle",
        "release_approvals",
        "release_approvals_signature_bundle",
    ),
)
def test_signed_component_json_preserves_decomposed_unicode_exact_bytes(
    tmp_path: Path,
    asset_name: str,
) -> None:
    source = tmp_path / "signed-external-evidence.json"
    signed_source = '{"actor":"Jose\u0301"}'.encode()
    source.write_bytes(signed_source)
    backend = ArtifactBackend()

    with httpx.Client(
        transport=httpx.MockTransport(backend),
        headers={"Authorization": "Bearer test-token"},
    ) as client:
        receipt = publish_assets(
            client=client,
            base_url="https://artifacts.example.test",
            release_id=RELEASE_ID,
            git_sha=GIT_SHA,
            image_digest=IMAGE_DIGEST,
            assets={asset_name: source},
            kind="release-evidence-component",
            minimum_retention_days=365,
            now=NOW,
        )

    assert receipt["verified"] is True
    assert backend.persisted_content == signed_source
    assert backend.upload_headers is not None
    assert backend.upload_headers["content-type"] == "application/octet-stream"


def test_signed_component_json_preserves_exact_nfc_bytes(tmp_path: Path) -> None:
    source = tmp_path / "release-approvals.json"
    signed_source = '{"actor":"José"}'.encode()
    source.write_bytes(signed_source)
    backend = ArtifactBackend()

    with httpx.Client(
        transport=httpx.MockTransport(backend),
        headers={"Authorization": "Bearer test-token"},
    ) as client:
        receipt = publish_assets(
            client=client,
            base_url="https://artifacts.example.test",
            release_id=RELEASE_ID,
            git_sha=GIT_SHA,
            image_digest=IMAGE_DIGEST,
            assets={"release_approvals": source},
            kind="release-evidence-component",
            minimum_retention_days=365,
            now=NOW,
        )

    assert receipt["verified"] is True
    assert backend.persisted_content == signed_source
