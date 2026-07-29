"""Bounded request-body spooling for large Artifact uploads."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import AsyncIterable
from dataclasses import dataclass
from pathlib import Path

from agent_platform.application.errors import PlatformError


@dataclass(frozen=True, slots=True)
class StagedUpload:
    path: Path
    size_bytes: int
    sha256: str
    chunk_count: int
    max_chunk_bytes: int


async def stream_request_to_path(
    chunks: AsyncIterable[bytes],
    target: Path,
    *,
    max_bytes: int,
) -> StagedUpload:
    """Spool one request incrementally and remove partial bytes on every failure."""
    if max_bytes <= 0:
        raise ValueError("ARTIFACT_UPLOAD_LIMIT_INVALID")
    target.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    observed = 0
    chunk_count = 0
    max_chunk_bytes = 0
    handle = await asyncio.to_thread(target.open, "xb")
    try:
        async for chunk in chunks:
            if not isinstance(chunk, bytes):
                raise PlatformError(
                    "ARTIFACT_UPLOAD_CHUNK_INVALID",
                    "Artifact upload stream yielded a non-bytes chunk",
                    http_status=400,
                )
            if not chunk:
                continue
            attempted = observed + len(chunk)
            if attempted > max_bytes:
                raise PlatformError(
                    "ARTIFACT_SIZE_LIMIT_EXCEEDED",
                    "Artifact exceeds the configured upload limit",
                    http_status=413,
                    context={
                        "size_bytes": attempted,
                        "max_upload_bytes": max_bytes,
                    },
                )
            written = await asyncio.to_thread(handle.write, chunk)
            if written != len(chunk):
                raise PlatformError(
                    "ARTIFACT_UPLOAD_WRITE_INCOMPLETE",
                    "Artifact staging storage accepted an incomplete chunk",
                    retryable=True,
                    http_status=503,
                )
            digest.update(chunk)
            observed = attempted
            chunk_count += 1
            max_chunk_bytes = max(max_chunk_bytes, len(chunk))
        await asyncio.to_thread(handle.flush)
    except BaseException:
        await asyncio.to_thread(handle.close)
        await asyncio.to_thread(target.unlink, missing_ok=True)
        raise
    await asyncio.to_thread(handle.close)
    return StagedUpload(
        path=target,
        size_bytes=observed,
        sha256=digest.hexdigest(),
        chunk_count=chunk_count,
        max_chunk_bytes=max_chunk_bytes,
    )