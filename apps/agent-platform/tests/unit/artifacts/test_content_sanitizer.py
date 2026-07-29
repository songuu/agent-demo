from __future__ import annotations

import io
import zipfile

import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.infrastructure.artifacts.sanitizer import ArtifactContentSanitizer
from agent_platform.infrastructure.artifacts.scanner import ArtifactScanner


def make_zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def test_text_json_and_xml_are_normalized_before_storage() -> None:
    sanitizer = ArtifactContentSanitizer()

    text = sanitizer.sanitize(b"\xef\xbb\xbfCafe\xcc\x81\r\nline\r", "text/plain")
    json_result = sanitizer.sanitize(b'{ "b": 2, "a": "Cafe\\u0301" }', "application/json")
    xml = sanitizer.sanitize(
        b'<?xml version="1.0"?><root>value</root>',
        "application/xml",
    )

    assert text.content == "Café\nline\n".encode()
    assert text.status == "normalized"
    assert json_result.content == '{"a":"Café","b":2}'.encode()
    assert json_result.status == "normalized"
    assert xml.content == b"<root>value</root>"
    assert xml.status == "normalized"


@pytest.mark.parametrize(
    ("content", "media_type"),
    [
        (b'{"key": 1, "key": 2}', "application/json"),
        (b'{"value": NaN}', "application/json"),
        (b'<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root/>', "application/xml"),
    ],
)
def test_ambiguous_or_active_structured_content_is_not_sanitized(
    content: bytes,
    media_type: str,
) -> None:
    sanitizer = ArtifactContentSanitizer()

    with pytest.raises(PlatformError, match="ARTIFACT_CONTENT_SANITIZATION_FAILED"):
        sanitizer.sanitize(content, media_type)


@pytest.mark.parametrize(
    ("content", "media_type"),
    [
        (b"%PDF-1.7\n1 0 obj<</OpenAction 2 0 R/JavaScript(foo)>>", "application/pdf"),
        (
            make_zip(
                {
                    "[Content_Types].xml": b"<Types/>",
                    "word/document.xml": b"<document/>",
                    "word/vbaProject.bin": b"macro",
                }
            ),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ),
    ],
)
def test_structural_scanner_blocks_pdf_or_office_active_content(
    content: bytes,
    media_type: str,
) -> None:
    scanner = ArtifactScanner(max_upload_bytes=100_000)

    with pytest.raises(PlatformError, match="ARTIFACT_ACTIVE_CONTENT_DENIED"):
        scanner.scan(content, media_type)
