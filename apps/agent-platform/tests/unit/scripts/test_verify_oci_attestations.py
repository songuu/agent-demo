from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path
from typing import Any

import pytest
from scripts.verify_oci_attestations import verify_archive


def _json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def _descriptor(payload: bytes, *, media_type: str) -> dict[str, Any]:
    return {
        "mediaType": media_type,
        "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
    }


def _archive(path: Path, *, include_sbom: bool = True) -> None:
    statements = [
        _json_bytes(
            {
                "_type": "https://in-toto.io/Statement/v1",
                "predicateType": "https://slsa.dev/provenance/v1",
                "subject": [{"digest": {"sha256": "a" * 64}}],
                "predicate": {},
            }
        )
    ]
    if include_sbom:
        statements.append(
            _json_bytes(
                {
                    "_type": "https://in-toto.io/Statement/v1",
                    "predicateType": "https://spdx.dev/Document",
                    "subject": [{"digest": {"sha256": "a" * 64}}],
                    "predicate": {},
                }
            )
        )
    layers = [
        _descriptor(payload, media_type="application/vnd.in-toto+json") for payload in statements
    ]
    manifest = _json_bytes(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.empty.v1+json",
                "digest": f"sha256:{'0' * 64}",
                "size": 2,
            },
            "layers": layers,
        }
    )
    manifest_descriptor = _descriptor(
        manifest,
        media_type="application/vnd.oci.image.manifest.v1+json",
    )
    manifest_descriptor["annotations"] = {
        "vnd.docker.reference.type": "attestation-manifest",
        "vnd.docker.reference.digest": f"sha256:{'a' * 64}",
    }
    index = _json_bytes(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [manifest_descriptor],
        }
    )
    members = {
        "index.json": index,
        f"blobs/sha256/{hashlib.sha256(manifest).hexdigest()}": manifest,
        **{
            f"blobs/sha256/{hashlib.sha256(payload).hexdigest()}": payload for payload in statements
        },
    }
    with tarfile.open(path, mode="w") as archive:
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))


def test_verify_oci_archive_requires_provenance_and_spdx_for_one_subject(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "image.oci.tar"
    _archive(archive_path)

    report = verify_archive(archive_path)

    assert report["subject_digest"] == f"sha256:{'a' * 64}"
    assert report["provenance_verified"] is True
    assert report["sbom_verified"] is True


def test_verify_oci_archive_rejects_missing_sbom_attestation(tmp_path: Path) -> None:
    archive_path = tmp_path / "image.oci.tar"
    _archive(archive_path, include_sbom=False)

    with pytest.raises(ValueError, match="OCI_SBOM_ATTESTATION_REQUIRED"):
        verify_archive(archive_path)
