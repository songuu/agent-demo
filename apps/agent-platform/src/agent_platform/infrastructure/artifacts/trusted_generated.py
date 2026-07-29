"""Fail-closed provenance for platform-owned, deterministic JSON Artifacts."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any

from agent_platform.application.errors import PlatformError
from agent_platform.application.records import ArtifactRecord
from agent_platform.domain.hashing import canonical_json
from agent_platform.infrastructure.artifacts.sanitizer import ArtifactContentSanitizer

TRUSTED_GENERATED_SCHEMA_VERSION = "1"
TRUSTED_GENERATED_SERIALIZATION = "canonical-json"
TRUSTED_GENERATED_SERIALIZATION_VERSION = "1"
TRUSTED_GENERATED_SOURCES = frozenset(
    {
        ("report", "deterministic_runtime"),
        ("tool_result", "tool_gateway"),
    }
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def build_trusted_generated_json(
    value: Any,
    *,
    kind: str,
    source: str,
) -> tuple[bytes, dict[str, Any]]:
    """Serialize a fixed platform source and attach byte-bound sanitization proof."""
    _require_allowlisted_source(kind, source)
    raw = canonical_json(value).encode("utf-8")
    sanitized = ArtifactContentSanitizer().sanitize(raw, "application/json")
    content = sanitized.content
    digest = hashlib.sha256(content).hexdigest()
    return (
        content,
        {
            "trusted_generated": {
                "schema_version": TRUSTED_GENERATED_SCHEMA_VERSION,
                "source": source,
                "source_version": "1",
                "kind": kind,
                "media_type": "application/json",
                "serialization": TRUSTED_GENERATED_SERIALIZATION,
                "serialization_version": TRUSTED_GENERATED_SERIALIZATION_VERSION,
                "sha256": digest,
                "size_bytes": len(content),
            },
            "sanitization": sanitized.provenance(),
        },
    )


def validate_trusted_generated_artifact(artifact: ArtifactRecord) -> Mapping[str, Any]:
    """Validate that trusted-generated proof binds an allowlisted canonical JSON object."""
    raw = artifact.scan_provenance.get("trusted_generated")
    sanitization = artifact.scan_provenance.get("sanitization")
    if (
        artifact.scan_status != "trusted_generated"
        or not isinstance(raw, Mapping)
        or not isinstance(sanitization, Mapping)
    ):
        raise PlatformError(
            "ARTIFACT_STORAGE_EVIDENCE_REQUIRED",
            "Artifact storage requires exact malware-clean or trusted-generated evidence",
            http_status=503,
        )

    source = raw.get("source")
    kind = raw.get("kind")
    if not isinstance(source, str) or not isinstance(kind, str):
        raise _source_denied()
    _require_allowlisted_source(kind, source, platform_error=True)
    if artifact.kind != kind or artifact.classification.value != "internal":
        raise _source_denied()

    expected_constants = {
        "schema_version": TRUSTED_GENERATED_SCHEMA_VERSION,
        "source_version": "1",
        "media_type": "application/json",
        "serialization": TRUSTED_GENERATED_SERIALIZATION,
        "serialization_version": TRUSTED_GENERATED_SERIALIZATION_VERSION,
    }
    if artifact.media_type.partition(";")[0].strip().lower() != "application/json" or any(
        raw.get(field) != value for field, value in expected_constants.items()
    ):
        raise PlatformError(
            "ARTIFACT_TRUSTED_GENERATED_PROVENANCE_INVALID",
            "Trusted-generated provenance is incomplete or unsupported",
            http_status=503,
        )

    digest = hashlib.sha256(artifact.content).hexdigest()
    if (
        artifact.sha256 != digest
        or raw.get("sha256") != digest
        or raw.get("size_bytes") != len(artifact.content)
    ):
        raise PlatformError(
            "ARTIFACT_TRUSTED_GENERATED_BINDING_INVALID",
            "Trusted-generated evidence does not bind the Artifact bytes",
            http_status=503,
        )

    try:
        normalized = ArtifactContentSanitizer().sanitize(
            artifact.content,
            "application/json",
        )
    except PlatformError as exc:
        raise PlatformError(
            "ARTIFACT_TRUSTED_GENERATED_CONTENT_INVALID",
            "Trusted-generated content is not safe canonical JSON",
            http_status=503,
        ) from exc
    if normalized.content != artifact.content:
        raise PlatformError(
            "ARTIFACT_TRUSTED_GENERATED_CONTENT_INVALID",
            "Trusted-generated content is not safe canonical JSON",
            http_status=503,
        )

    original_sha256 = sanitization.get("original_sha256")
    if (
        sanitization.get("status") != "normalized"
        or sanitization.get("method") != "canonical-json"
        or sanitization.get("version") != ArtifactContentSanitizer.VERSION
        or not isinstance(original_sha256, str)
        or _SHA256.fullmatch(original_sha256) is None
        or sanitization.get("sanitized_sha256") != digest
    ):
        raise PlatformError(
            "ARTIFACT_TRUSTED_GENERATED_SANITIZATION_INVALID",
            "Trusted-generated sanitization provenance is incomplete or unbound",
            http_status=503,
        )
    return raw


def _require_allowlisted_source(
    kind: str,
    source: str,
    *,
    platform_error: bool = False,
) -> None:
    if (kind, source) in TRUSTED_GENERATED_SOURCES:
        return
    if platform_error:
        raise _source_denied()
    raise ValueError(
        f"TRUSTED_GENERATED_SOURCE_DENIED: kind={kind!r} source={source!r} is not allowlisted"
    )


def _source_denied() -> PlatformError:
    return PlatformError(
        "ARTIFACT_TRUSTED_GENERATED_SOURCE_DENIED",
        "Trusted-generated Artifact kind and source are not allowlisted",
        http_status=503,
    )
