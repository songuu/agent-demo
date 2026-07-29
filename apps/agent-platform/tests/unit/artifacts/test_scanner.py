from __future__ import annotations

import io
import zipfile

import pytest

from agent_platform.infrastructure.artifacts.scanner import ArtifactScanner


def make_zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def test_scanner_rejects_path_traversal_and_zip_bomb_ratio() -> None:
    scanner = ArtifactScanner(
        max_upload_bytes=1_000_000,
        max_archive_entries=10,
        max_uncompressed_bytes=1_000,
        max_compression_ratio=10,
    )
    with pytest.raises(ValueError, match="ARCHIVE_PATH_TRAVERSAL"):
        scanner.scan(make_zip({"../secret.txt": b"x"}), "application/zip")
    with pytest.raises(ValueError, match="ARCHIVE_UNCOMPRESSED_LIMIT"):
        scanner.scan(make_zip({"huge.txt": b"x" * 10_000}), "application/zip")


def test_scanner_rejects_executables_and_accepts_bounded_text() -> None:
    scanner = ArtifactScanner(max_upload_bytes=100)
    with pytest.raises(ValueError, match="EXECUTABLE_CONTENT_DENIED"):
        scanner.scan(b"MZ" + b"\x00" * 20, "application/octet-stream")
    result = scanner.scan(b"source-backed report", "text/plain")
    assert result.status == "structural_safe"
    assert result.size_bytes == 20
    assert len(result.sha256) == 64
