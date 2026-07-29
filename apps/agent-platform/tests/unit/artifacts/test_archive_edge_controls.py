from __future__ import annotations

import io
import stat
import zipfile

import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.infrastructure.artifacts.scanner import ArtifactScanner


def archive(entries: list[tuple[zipfile.ZipInfo | str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as value:
        for name, content in entries:
            value.writestr(name, content)
    return buffer.getvalue()


@pytest.mark.parametrize(
    ("content", "code"),
    [
        (
            archive([("report.txt", b"a"), ("REPORT.TXT", b"b")]),
            "ARCHIVE_DUPLICATE_ENTRY",
        ),
        (
            archive(
                [
                    (
                        zipfile.ZipInfo("link-to-secret"),
                        b"../../secret",
                    )
                ]
            ),
            "ARCHIVE_SYMLINK_DENIED",
        ),
        (
            archive([("nested.zip", archive([("payload.exe", b"MZ")]))]),
            "ARCHIVE_NESTED_DENIED",
        ),
    ],
)
def test_archive_edge_controls_fail_closed(content: bytes, code: str) -> None:
    if code == "ARCHIVE_SYMLINK_DENIED":
        buffer = io.BytesIO()
        info = zipfile.ZipInfo("link-to-secret")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(buffer, "w") as value:
            value.writestr(info, "../../secret")
        content = buffer.getvalue()

    scanner = ArtifactScanner(max_upload_bytes=100_000)
    with pytest.raises(PlatformError) as caught:
        scanner.scan(content, "application/zip")

    assert caught.value.code == code
