"""Verify BuildKit provenance and SPDX attestations embedded in an OCI archive."""

from __future__ import annotations

import argparse
import json
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any

OCI_INDEX = "index.json"
ATTESTATION_MEDIA_TYPE = "application/vnd.in-toto+json"
PROVENANCE_PREFIX = "https://slsa.dev/provenance/"
SPDX_PREDICATE = "https://spdx.dev/Document"


def _object(payload: bytes, *, name: str) -> dict[str, Any]:
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError(f"OCI_ATTESTATION_OBJECT_REQUIRED: {name}")
    return value


def _safe_member(archive: tarfile.TarFile, name: str) -> bytes:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"OCI_ARCHIVE_PATH_UNSAFE: {name}")
    member = archive.getmember(name)
    if not member.isfile() or member.size > 16 * 1024 * 1024:
        raise ValueError(f"OCI_ARCHIVE_MEMBER_INVALID: {name}")
    extracted = archive.extractfile(member)
    if extracted is None:
        raise ValueError(f"OCI_ARCHIVE_MEMBER_UNREADABLE: {name}")
    return extracted.read()


def verify_archive(path: Path) -> dict[str, Any]:
    predicates: set[str] = set()
    subject_digests: set[str] = set()
    with tarfile.open(path, mode="r:*") as archive:
        index = _object(_safe_member(archive, OCI_INDEX), name=OCI_INDEX)
        manifests = index.get("manifests")
        if not isinstance(manifests, list) or not manifests:
            raise ValueError("OCI_INDEX_MANIFESTS_REQUIRED")
        for descriptor in manifests:
            if not isinstance(descriptor, dict):
                continue
            annotations = descriptor.get("annotations")
            if not isinstance(annotations, dict):
                continue
            if annotations.get("vnd.docker.reference.type") != "attestation-manifest":
                continue
            subject_digest = annotations.get("vnd.docker.reference.digest")
            if isinstance(subject_digest, str):
                subject_digests.add(subject_digest)
            digest = descriptor.get("digest")
            if not isinstance(digest, str) or not digest.startswith("sha256:"):
                raise ValueError("OCI_ATTESTATION_DIGEST_INVALID")
            manifest_name = f"blobs/sha256/{digest.removeprefix('sha256:')}"
            manifest = _object(
                _safe_member(archive, manifest_name),
                name=manifest_name,
            )
            layers = manifest.get("layers")
            if not isinstance(layers, list):
                continue
            for layer in layers:
                if (
                    not isinstance(layer, dict)
                    or layer.get("mediaType") != ATTESTATION_MEDIA_TYPE
                ):
                    continue
                layer_digest = layer.get("digest")
                if not isinstance(layer_digest, str) or not layer_digest.startswith(
                    "sha256:"
                ):
                    raise ValueError("OCI_ATTESTATION_LAYER_DIGEST_INVALID")
                layer_name = (
                    f"blobs/sha256/{layer_digest.removeprefix('sha256:')}"
                )
                statement = _object(
                    _safe_member(archive, layer_name),
                    name=layer_name,
                )
                predicate_type = statement.get("predicateType")
                if isinstance(predicate_type, str):
                    predicates.add(predicate_type)

    has_provenance = any(value.startswith(PROVENANCE_PREFIX) for value in predicates)
    if not has_provenance:
        raise ValueError("OCI_PROVENANCE_ATTESTATION_REQUIRED")
    if SPDX_PREDICATE not in predicates:
        raise ValueError("OCI_SBOM_ATTESTATION_REQUIRED")
    if len(subject_digests) != 1:
        raise ValueError("OCI_ATTESTATION_SUBJECT_AMBIGUOUS")
    return {
        "schema_version": "1.0",
        "subject_digest": next(iter(subject_digests)),
        "predicate_types": sorted(predicates),
        "provenance_verified": True,
        "sbom_verified": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = verify_archive(args.archive)
    except (OSError, ValueError, json.JSONDecodeError, tarfile.TarError) as exc:
        print(f"OCI attestation verification failed: {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
