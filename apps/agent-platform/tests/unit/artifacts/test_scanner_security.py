from __future__ import annotations

import io
import zipfile

import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.infrastructure.artifacts.scanner import ArtifactScanner


def make_zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def assert_scan_error(
    scanner: ArtifactScanner,
    content: bytes,
    media_type: str,
    code: str,
) -> None:
    with pytest.raises(PlatformError) as caught:
        scanner.scan(content, media_type)
    assert caught.value.code == code
    assert 400 <= caught.value.http_status < 500


def test_scanner_normalizes_magic_and_rejects_declared_mime_mismatch() -> None:
    scanner = ArtifactScanner(max_upload_bytes=1_000)
    pdf = b"%PDF-1.7\nsource-backed"

    result = scanner.scan(pdf, "application/pdf; charset=binary")

    assert result.media_type == "application/pdf"
    assert_scan_error(scanner, pdf, "text/plain", "ARTIFACT_MEDIA_TYPE_MISMATCH")


def test_scanner_treats_octet_stream_as_generic_but_keeps_detected_type() -> None:
    scanner = ArtifactScanner(max_upload_bytes=10_000)

    result = scanner.scan(make_zip({"safe.txt": b"evidence"}), "application/octet-stream")

    assert result.media_type == "application/zip"


@pytest.mark.parametrize(
    ("entries", "code"),
    [
        ({"../escape.txt": b"x"}, "ARCHIVE_PATH_TRAVERSAL"),
        ({"C:/escape.txt": b"x"}, "ARCHIVE_PATH_TRAVERSAL"),
        ({"payload.exe": b"not-even-an-exe"}, "EXECUTABLE_CONTENT_DENIED"),
        ({"payload.txt": b"MZ" + b"\x00" * 20}, "EXECUTABLE_CONTENT_DENIED"),
    ],
)
def test_scanner_maps_archive_security_failures_to_platform_errors(
    entries: dict[str, bytes],
    code: str,
) -> None:
    scanner = ArtifactScanner(max_upload_bytes=10_000)

    assert_scan_error(scanner, make_zip(entries), "application/zip", code)


def test_scanner_rejects_invalid_zip_and_compression_bomb_with_stable_errors() -> None:
    scanner = ArtifactScanner(
        max_upload_bytes=1_000_000,
        max_uncompressed_bytes=1_000,
        max_compression_ratio=5,
    )

    assert_scan_error(scanner, b"PK\x03\x04broken", "application/zip", "ARCHIVE_INVALID")
    assert_scan_error(
        scanner,
        make_zip({"huge.txt": b"A" * 20_000}),
        "application/zip",
        "ARCHIVE_UNCOMPRESSED_LIMIT",
    )


def test_scanner_rejects_top_level_executable_and_oversize_with_stable_errors() -> None:
    scanner = ArtifactScanner(max_upload_bytes=8)

    assert_scan_error(
        scanner,
        b"\x7fELF\x02\x01",
        "application/octet-stream",
        "EXECUTABLE_CONTENT_DENIED",
    )
    assert_scan_error(
        scanner,
        b"123456789",
        "application/octet-stream",
        "ARTIFACT_SIZE_LIMIT_EXCEEDED",
    )
