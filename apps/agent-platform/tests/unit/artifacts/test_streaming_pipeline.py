from __future__ import annotations

import asyncio
import hashlib
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.infrastructure.artifacts.malware import MalwareScanEvidence
from agent_platform.infrastructure.artifacts.pipeline import inspect_artifact_file_for_storage
from agent_platform.infrastructure.artifacts.sanitizer import ArtifactContentSanitizer
from agent_platform.infrastructure.artifacts.scanner import ArtifactScanner
from agent_platform.infrastructure.artifacts.streaming import stream_request_to_path


async def _chunks(total: int, chunk_size: int) -> AsyncIterator[bytes]:
    remaining = total
    while remaining:
        size = min(remaining, chunk_size)
        yield b"x" * size
        remaining -= size


@pytest.mark.asyncio
async def test_request_stream_is_spooled_and_hashed_without_byte_aggregation(
    tmp_path: Path,
) -> None:
    target = tmp_path / "request.raw"

    staged = await stream_request_to_path(
        _chunks(3 * 1024 * 1024 + 9, 64 * 1024),
        target,
        max_bytes=4 * 1024 * 1024,
    )

    assert staged.path == target
    assert staged.size_bytes == 3 * 1024 * 1024 + 9
    assert staged.sha256 == hashlib.sha256(target.read_bytes()).hexdigest()
    assert staged.chunk_count == 49
    assert staged.max_chunk_bytes == 64 * 1024


@pytest.mark.asyncio
async def test_stream_limit_removes_partial_file(tmp_path: Path) -> None:
    target = tmp_path / "too-large.raw"

    with pytest.raises(PlatformError, match="ARTIFACT_SIZE_LIMIT_EXCEEDED"):
        await stream_request_to_path(
            _chunks(1025, 256),
            target,
            max_bytes=1024,
        )

    assert not target.exists()


@pytest.mark.asyncio
async def test_large_passthrough_file_uses_file_scanner_and_file_malware_boundary(
    tmp_path: Path,
) -> None:
    source = tmp_path / "upload.raw"
    source.write_bytes(b"%PDF-1.7\n" + b"x" * (2 * 1024 * 1024))
    malware = _FileOnlyMalwareScanner()

    result = await inspect_artifact_file_for_storage(
        source,
        "application/pdf",
        work_dir=tmp_path,
        structural_scanner=ArtifactScanner(max_upload_bytes=3 * 1024 * 1024),
        malware_scanner=malware,
        sanitizer=ArtifactContentSanitizer(),
        environment="prod",
        artifact_backend="s3",
        malware_scan_mode="external",
        max_in_memory_bytes=1024,
    )

    assert result.path.exists()
    assert result.size_bytes == result.path.stat().st_size
    assert result.sha256 == hashlib.sha256(result.path.read_bytes()).hexdigest()
    assert malware.file_calls == 1
    assert malware.bytes_calls == 0


class _FileOnlyMalwareScanner:
    def __init__(self) -> None:
        self.file_calls = 0
        self.bytes_calls = 0

    async def scan(self, content: bytes, *, media_type: str) -> MalwareScanEvidence:
        del content, media_type
        self.bytes_calls += 1
        raise AssertionError("large streaming upload must not use bytes malware scan")

    async def scan_file(
        self,
        path: Path,
        *,
        media_type: str,
        sha256: str,
        size_bytes: int,
    ) -> MalwareScanEvidence:
        del media_type
        self.file_calls += 1
        file_info = await asyncio.to_thread(path.stat)
        content = await asyncio.to_thread(path.read_bytes)
        assert file_info.st_size == size_bytes
        assert hashlib.sha256(content).hexdigest() == sha256
        return MalwareScanEvidence(
            request_id="scan-request-1",
            sha256=sha256,
            size_bytes=size_bytes,
            verdict="clean",
            engine="controlled-av",
            engine_version="1",
            scanned_at=datetime.now(UTC),
            evidence_id="scan-evidence-1",
        )

    async def healthcheck(self) -> str:
        return "ok"

    async def aclose(self) -> None:
        return None