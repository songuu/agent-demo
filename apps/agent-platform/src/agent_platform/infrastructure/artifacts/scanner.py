from __future__ import annotations

import hashlib
import io
import json
import re
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from agent_platform.application.errors import PlatformError

_MEDIA_TYPE_PATTERN = re.compile(
    r"^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$",
    re.ASCII,
)
_ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_EXECUTABLE_SIGNATURES = (b"MZ", b"\x7fELF", b"#!")
_EXECUTABLE_SUFFIXES = frozenset(
    {
        ".app",
        ".bat",
        ".cmd",
        ".com",
        ".dll",
        ".exe",
        ".jar",
        ".msi",
        ".ps1",
        ".scr",
        ".sh",
    }
)
_MEDIA_TYPE_ALIASES = {
    "application/x-zip-compressed": "application/zip",
    "application/x-pdf": "application/pdf",
}
_ZIP_MEDIA_TYPES = frozenset(
    {
        "application/zip",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    }
)
_STRUCTURAL_SCANNER_VERSION = "2"
_PDF_ACTIVE_CONTENT = re.compile(
    rb"/(?:JavaScript|JS|Launch|EmbeddedFile|OpenAction|AA|RichMedia)\b",
    re.IGNORECASE,
)
_OFFICE_RELATIONSHIP_ACTIVE = re.compile(
    rb"""(?:TargetMode\s*=\s*["']External["']|"""
    rb"""relationships/(?:oleObject|package|attachedTemplate)|"""
    rb"""schemas\.microsoft\.com/office/vbaProject|macroEnabled|activeX)""",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class ScanResult:
    status: str
    sha256: str
    size_bytes: int
    media_type: str
    engine: str = "local-structural-policy"
    engine_version: str = _STRUCTURAL_SCANNER_VERSION
    active_content_status: str = "not_applicable"


class ArtifactScanError(PlatformError, ValueError):
    """Public API error that preserves the scanner's legacy ValueError contract."""


class ArtifactScanner:
    def __init__(
        self,
        *,
        max_upload_bytes: int = 200 * 1024 * 1024,
        max_archive_entries: int = 1_000,
        max_uncompressed_bytes: int = 500 * 1024 * 1024,
        max_compression_ratio: int = 100,
    ) -> None:
        limits = {
            "max_upload_bytes": max_upload_bytes,
            "max_archive_entries": max_archive_entries,
            "max_uncompressed_bytes": max_uncompressed_bytes,
            "max_compression_ratio": max_compression_ratio,
        }
        if any(value <= 0 for value in limits.values()):
            raise ValueError(f"ARTIFACT_SCAN_LIMIT_INVALID: {limits!r}")
        self.max_upload_bytes = max_upload_bytes
        self.max_archive_entries = max_archive_entries
        self.max_uncompressed_bytes = max_uncompressed_bytes
        self.max_compression_ratio = max_compression_ratio

    def scan(self, content: bytes, media_type: str) -> ScanResult:
        declared_type = self._normalize_media_type(media_type)
        if len(content) > self.max_upload_bytes:
            raise self._error(
                "ARTIFACT_SIZE_LIMIT_EXCEEDED",
                "Artifact exceeds the configured upload limit",
                http_status=413,
                size_bytes=len(content),
                max_upload_bytes=self.max_upload_bytes,
            )
        if self._has_executable_signature(content):
            raise self._error(
                "EXECUTABLE_CONTENT_DENIED",
                "Executable Artifact content is not accepted",
            )
        if content.startswith(b"%PDF-") and _PDF_ACTIVE_CONTENT.search(content):
            raise self._error(
                "ARTIFACT_ACTIVE_CONTENT_DENIED",
                "PDF active content is not accepted",
            )

        detected_type = self._detect_media_type(content)
        if detected_type == "application/zip":
            detected_type = self._scan_zip(content)
        resolved_type = self._resolve_media_type(declared_type, detected_type)
        active_content_status = (
            "checked"
            if resolved_type == "application/pdf" or resolved_type in _ZIP_MEDIA_TYPES
            else "not_applicable"
        )
        return ScanResult(
            status="structural_safe",
            sha256=hashlib.sha256(content).hexdigest(),
            size_bytes=len(content),
            media_type=resolved_type,
            active_content_status=active_content_status,
        )

    def scan_path(self, path: Path, media_type: str) -> ScanResult:
        """Inspect and hash a staged file with bounded reads."""
        declared_type = self._normalize_media_type(media_type)
        try:
            size_bytes = path.stat().st_size
        except OSError as exc:
            raise self._error(
                "ARTIFACT_STAGED_FILE_UNAVAILABLE",
                "Staged Artifact cannot be inspected",
                http_status=503,
            ) from exc
        if size_bytes > self.max_upload_bytes:
            raise self._error(
                "ARTIFACT_SIZE_LIMIT_EXCEEDED",
                "Artifact exceeds the configured upload limit",
                http_status=413,
                size_bytes=size_bytes,
                max_upload_bytes=self.max_upload_bytes,
            )

        digest = hashlib.sha256()
        prefix = b""
        pdf_window = b""
        try:
            with path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    if not prefix:
                        prefix = chunk[: 64 * 1024]
                    digest.update(chunk)
                    if prefix.startswith(b"%PDF-"):
                        inspection = pdf_window + chunk
                        if _PDF_ACTIVE_CONTENT.search(inspection):
                            raise self._error(
                                "ARTIFACT_ACTIVE_CONTENT_DENIED",
                                "PDF active content is not accepted",
                            )
                        pdf_window = inspection[-128:]
        except OSError as exc:
            raise self._error(
                "ARTIFACT_STAGED_FILE_UNAVAILABLE",
                "Staged Artifact cannot be inspected",
                http_status=503,
            ) from exc

        if self._has_executable_signature(prefix):
            raise self._error(
                "EXECUTABLE_CONTENT_DENIED",
                "Executable Artifact content is not accepted",
            )
        detected_type = self._detect_media_type(prefix)
        if detected_type == "application/zip":
            detected_type = self._scan_zip_path(path)
        resolved_type = self._resolve_media_type(declared_type, detected_type)
        active_content_status = (
            "checked"
            if resolved_type == "application/pdf" or resolved_type in _ZIP_MEDIA_TYPES
            else "not_applicable"
        )
        return ScanResult(
            status="structural_safe",
            sha256=digest.hexdigest(),
            size_bytes=size_bytes,
            media_type=resolved_type,
            active_content_status=active_content_status,
        )

    def _scan_zip(self, content: bytes) -> str:
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                return self._scan_zip_archive(archive)
        except PlatformError:
            raise
        except (
            zipfile.BadZipFile,
            zipfile.LargeZipFile,
            RuntimeError,
            NotImplementedError,
            OSError,
        ) as exc:
            raise self._error(
                "ARCHIVE_INVALID",
                "Archive is invalid or cannot be inspected",
            ) from exc

    def _scan_zip_path(self, path: Path) -> str:
        try:
            with zipfile.ZipFile(path) as archive:
                return self._scan_zip_archive(archive)
        except PlatformError:
            raise
        except (
            zipfile.BadZipFile,
            zipfile.LargeZipFile,
            RuntimeError,
            NotImplementedError,
            OSError,
        ) as exc:
            raise self._error(
                "ARCHIVE_INVALID",
                "Archive is invalid or cannot be inspected",
            ) from exc

    def _scan_zip_archive(self, archive: zipfile.ZipFile) -> str:
        infos = archive.infolist()
        if len(infos) > self.max_archive_entries:
            raise self._error(
                "ARCHIVE_ENTRY_LIMIT",
                "Archive contains too many entries",
                entry_count=len(infos),
                max_archive_entries=self.max_archive_entries,
            )
        uncompressed = 0
        compressed = 0
        normalized_names: set[str] = set()
        for info in infos:
            normalized_name = self._validate_archive_path(info.filename)
            collision_key = normalized_name.casefold()
            if collision_key in normalized_names:
                raise self._error(
                    "ARCHIVE_DUPLICATE_ENTRY",
                    "Archive contains colliding entry names",
                )
            normalized_names.add(collision_key)
            if info.flag_bits & 0x1:
                raise self._error(
                    "ARCHIVE_ENCRYPTED_DENIED",
                    "Encrypted archives cannot be inspected safely",
                )
            mode = info.external_attr >> 16
            if stat.S_IFMT(mode) == stat.S_IFLNK:
                raise self._error(
                    "ARCHIVE_SYMLINK_DENIED",
                    "Archive symbolic links are not accepted",
                )
            if not info.is_dir() and (
                PurePosixPath(normalized_name).suffix.lower() in _EXECUTABLE_SUFFIXES
                or mode & 0o111
            ):
                raise self._error(
                    "EXECUTABLE_CONTENT_DENIED",
                    "Archive contains an executable entry",
                )
            if self._is_office_active_path(normalized_name):
                raise self._error(
                    "ARTIFACT_ACTIVE_CONTENT_DENIED",
                    "Office active content is not accepted",
                )

            uncompressed += info.file_size
            compressed += max(info.compress_size, 1)
            if uncompressed > self.max_uncompressed_bytes:
                raise self._error(
                    "ARCHIVE_UNCOMPRESSED_LIMIT",
                    "Archive exceeds the uncompressed size limit",
                    uncompressed_bytes=uncompressed,
                    max_uncompressed_bytes=self.max_uncompressed_bytes,
                )
            if info.file_size / max(info.compress_size, 1) > self.max_compression_ratio:
                raise self._error(
                    "ARCHIVE_COMPRESSION_RATIO_LIMIT",
                    "Archive entry exceeds the compression ratio limit",
                )
            if not info.is_dir():
                inspect_markup = (
                    normalized_name.casefold().endswith(".rels")
                    or normalized_name.casefold() == "[content_types].xml"
                )
                with archive.open(info) as entry:
                    inspection = entry.read(
                        min(info.file_size, 1_048_577) if inspect_markup else 4
                    )
                    prefix = inspection[:4]
                    if prefix.startswith(_ZIP_SIGNATURES):
                        raise self._error(
                            "ARCHIVE_NESTED_DENIED",
                            "Nested archives cannot be inspected safely",
                        )
                    if self._has_executable_signature(prefix):
                        raise self._error(
                            "EXECUTABLE_CONTENT_DENIED",
                            "Archive contains executable content",
                        )
                    if inspect_markup and (
                        len(inspection) > 1_048_576
                        or _OFFICE_RELATIONSHIP_ACTIVE.search(inspection)
                    ):
                        raise self._error(
                            "ARTIFACT_ACTIVE_CONTENT_DENIED",
                            "Office external or embedded active content is not accepted",
                        )
        if uncompressed / max(compressed, 1) > self.max_compression_ratio:
            raise self._error(
                "ARCHIVE_COMPRESSION_RATIO_LIMIT",
                "Archive exceeds the compression ratio limit",
            )
        return self._zip_media_type(normalized_names)

    @classmethod
    def _normalize_media_type(cls, value: str) -> str:
        normalized = value.partition(";")[0].strip().lower()
        normalized = _MEDIA_TYPE_ALIASES.get(normalized, normalized)
        if not _MEDIA_TYPE_PATTERN.fullmatch(normalized):
            raise cls._error(
                "ARTIFACT_MEDIA_TYPE_INVALID",
                "Artifact Content-Type is invalid",
                http_status=415,
            )
        return normalized

    @classmethod
    def _resolve_media_type(cls, declared: str, detected: str) -> str:
        if declared == "application/octet-stream":
            return detected
        if detected == "application/octet-stream":
            return declared
        if declared == detected:
            return detected
        if detected == "text/plain" and declared.startswith("text/"):
            return declared
        if declared == "application/zip" and detected in _ZIP_MEDIA_TYPES:
            return detected
        raise cls._error(
            "ARTIFACT_MEDIA_TYPE_MISMATCH",
            "Declared Artifact Content-Type does not match file content",
            http_status=415,
            declared_media_type=declared,
            detected_media_type=detected,
        )

    @staticmethod
    def _detect_media_type(content: bytes) -> str:
        if content.startswith(_ZIP_SIGNATURES):
            return "application/zip"
        if content.startswith(b"%PDF-"):
            return "application/pdf"
        if content.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if content.startswith(b"\xff\xd8\xff"):
            return "image/jpeg"
        if content.startswith((b"GIF87a", b"GIF89a")):
            return "image/gif"
        if content.startswith(b"\x1f\x8b"):
            return "application/gzip"
        stripped = content.lstrip()
        if stripped.startswith((b"{", b"[")):
            try:
                json.loads(content.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass
            else:
                return "application/json"
        if stripped.startswith(b"<?xml"):
            return "application/xml"
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            return "application/octet-stream"
        if all(character >= " " or character in "\t\r\n" for character in text):
            return "text/plain"
        return "application/octet-stream"

    @staticmethod
    def _has_executable_signature(content: bytes) -> bool:
        return content.startswith(_EXECUTABLE_SIGNATURES)

    @staticmethod
    def _is_office_active_path(value: str) -> bool:
        for part in PurePosixPath(value).parts:
            normalized = part.casefold()
            if normalized in {"activex", "embeddings", "vbaproject.bin"} or normalized.startswith(
                "oleobject"
            ):
                return True
        return False

    @classmethod
    def _validate_archive_path(cls, value: str) -> str:
        normalized = value.replace("\\", "/")
        path = PurePosixPath(normalized)
        drive_prefixed = bool(re.match(r"^[A-Za-z]:", normalized, re.ASCII))
        if (
            not normalized
            or "\x00" in normalized
            or path.is_absolute()
            or drive_prefixed
            or ".." in path.parts
        ):
            raise cls._error(
                "ARCHIVE_PATH_TRAVERSAL",
                "Archive entry escapes the extraction root",
            )
        return path.as_posix()

    @staticmethod
    def _zip_media_type(names: set[str]) -> str:
        if "[content_types].xml" in names:
            if any(name.startswith("word/") for name in names):
                return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            if any(name.startswith("xl/") for name in names):
                return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            if any(name.startswith("ppt/") for name in names):
                return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        return "application/zip"

    @staticmethod
    def _error(
        code: str,
        message: str,
        *,
        http_status: int = 422,
        **context: int | str,
    ) -> ArtifactScanError:
        return ArtifactScanError(
            code,
            message,
            http_status=http_status,
            context=context,
        )
