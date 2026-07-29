"""Ordered Artifact security pipeline: structure, sanitization, malware, storage gate."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_platform.application.errors import PlatformError
from agent_platform.infrastructure.artifacts.malware import MalwareScanner
from agent_platform.infrastructure.artifacts.sanitizer import ArtifactContentSanitizer
from agent_platform.infrastructure.artifacts.scanner import ArtifactScanner, ScanResult


@dataclass(frozen=True, slots=True)
class ArtifactSecurityResult:
    content: bytes
    media_type: str
    sha256: str
    scan_status: str
    scan_provenance: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ArtifactFileSecurityResult:
    path: Path
    size_bytes: int
    media_type: str
    sha256: str
    scan_status: str
    scan_provenance: dict[str, Any]


async def inspect_artifact_for_storage(
    content: bytes,
    media_type: str,
    *,
    structural_scanner: ArtifactScanner,
    malware_scanner: MalwareScanner,
    sanitizer: ArtifactContentSanitizer,
    environment: str,
    artifact_backend: str,
    malware_scan_mode: str,
) -> ArtifactSecurityResult:
    initial = structural_scanner.scan(content, media_type)
    sanitized = sanitizer.sanitize(content, initial.media_type)
    final = structural_scanner.scan(sanitized.content, initial.media_type)
    malware = await malware_scanner.scan(
        sanitized.content,
        media_type=final.media_type,
    )

    if malware.sha256 != final.sha256 or malware.size_bytes != final.size_bytes:
        raise PlatformError(
            "ARTIFACT_MALWARE_SCAN_BINDING_INVALID",
            "Malware scan evidence does not bind the stored Artifact bytes",
            http_status=503,
        )
    if malware.verdict == "clean":
        scan_status = "malware_clean"
    elif (
        malware.verdict == "structural_only"
        and environment in {"dev", "test"}
        and artifact_backend == "memory"
        and malware_scan_mode == "structural_only"
    ):
        scan_status = "structural_only"
    else:
        _raise_non_clean_verdict(malware.verdict)

    return ArtifactSecurityResult(
        content=sanitized.content,
        media_type=final.media_type,
        sha256=final.sha256,
        scan_status=scan_status,
        scan_provenance={
            "structural": _structural_provenance(final),
            "sanitization": sanitized.provenance(),
            "malware": malware.provenance(),
        },
    )


async def inspect_artifact_file_for_storage(
    path: Path,
    media_type: str,
    *,
    work_dir: Path,
    structural_scanner: ArtifactScanner,
    malware_scanner: MalwareScanner,
    sanitizer: ArtifactContentSanitizer,
    environment: str,
    artifact_backend: str,
    malware_scan_mode: str,
    max_in_memory_bytes: int,
) -> ArtifactFileSecurityResult:
    """Run the ordered security pipeline over staged files with bounded memory."""
    initial = await asyncio.to_thread(structural_scanner.scan_path, path, media_type)
    sanitized_path = work_dir / "sanitized.upload"
    sanitized = await asyncio.to_thread(
        sanitizer.sanitize_file,
        path,
        sanitized_path,
        initial.media_type,
        max_in_memory_bytes=max_in_memory_bytes,
    )
    final = await asyncio.to_thread(
        structural_scanner.scan_path,
        sanitized.path,
        initial.media_type,
    )
    scan_file = getattr(malware_scanner, "scan_file", None)
    if callable(scan_file):
        malware = await scan_file(
            sanitized.path,
            media_type=final.media_type,
            sha256=final.sha256,
            size_bytes=final.size_bytes,
        )
    elif final.size_bytes <= max_in_memory_bytes:
        content = await asyncio.to_thread(sanitized.path.read_bytes)
        malware = await malware_scanner.scan(content, media_type=final.media_type)
    else:
        raise PlatformError(
            "ARTIFACT_STREAMING_MALWARE_SCAN_REQUIRED",
            "Large Artifact requires a file-streaming malware scanner",
            http_status=503,
            context={"size_bytes": final.size_bytes},
        )

    if malware.sha256 != final.sha256 or malware.size_bytes != final.size_bytes:
        raise PlatformError(
            "ARTIFACT_MALWARE_SCAN_BINDING_INVALID",
            "Malware scan evidence does not bind the stored Artifact bytes",
            http_status=503,
        )
    if malware.verdict == "clean":
        scan_status = "malware_clean"
    elif (
        malware.verdict == "structural_only"
        and environment in {"dev", "test"}
        and artifact_backend == "memory"
        and malware_scan_mode == "structural_only"
    ):
        scan_status = "structural_only"
    else:
        _raise_non_clean_verdict(malware.verdict)

    return ArtifactFileSecurityResult(
        path=sanitized.path,
        size_bytes=final.size_bytes,
        media_type=final.media_type,
        sha256=final.sha256,
        scan_status=scan_status,
        scan_provenance={
            "structural": _structural_provenance(final),
            "sanitization": sanitized.provenance(),
            "malware": malware.provenance(),
        },
    )


def _structural_provenance(result: ScanResult) -> dict[str, str | int]:
    return {
        "status": result.status,
        "sha256": result.sha256,
        "size_bytes": result.size_bytes,
        "media_type": result.media_type,
        "engine": result.engine,
        "engine_version": result.engine_version,
        "active_content_status": result.active_content_status,
    }


def _raise_non_clean_verdict(verdict: str) -> None:
    errors = {
        "infected": (
            "ARTIFACT_MALWARE_DETECTED",
            "Malware scanner detected malicious content",
            422,
            False,
        ),
        "suspicious": (
            "ARTIFACT_MALWARE_SUSPICIOUS",
            "Malware scanner classified the Artifact as suspicious",
            422,
            False,
        ),
        "unknown": (
            "ARTIFACT_MALWARE_SCAN_INCONCLUSIVE",
            "Malware scanner could not establish a clean verdict",
            503,
            True,
        ),
        "structural_only": (
            "ARTIFACT_MALWARE_SCAN_REQUIRED",
            "External malware-clean evidence is required for object storage",
            503,
            False,
        ),
    }
    code, message, status, retryable = errors.get(
        verdict,
        (
            "ARTIFACT_MALWARE_SCAN_RESPONSE_INVALID",
            "Malware scanner returned an unsupported verdict",
            503,
            False,
        ),
    )
    raise PlatformError(
        code,
        message,
        retryable=retryable,
        http_status=status,
        context={"verdict": verdict},
    )
