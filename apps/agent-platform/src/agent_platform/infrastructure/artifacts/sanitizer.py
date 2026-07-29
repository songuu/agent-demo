"""Deterministic content normalization applied before malware scanning."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import defusedxml.ElementTree as ElementTree

from agent_platform.application.errors import PlatformError

_SAFE_TEXT_TYPES = frozenset({"text/plain", "text/csv", "text/markdown"})
_OOXML_TYPES = frozenset(
    {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    }
)
_XML_ACTIVE_MARKUP = re.compile(
    r"<!DOCTYPE|<!ENTITY|<\?xml-stylesheet|<\?(?!xml(?:\s|\?>))",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class SanitizationResult:
    content: bytes
    status: str
    method: str
    version: str
    original_sha256: str
    sanitized_sha256: str

    def provenance(self) -> dict[str, str]:
        return {
            "status": self.status,
            "method": self.method,
            "version": self.version,
            "original_sha256": self.original_sha256,
            "sanitized_sha256": self.sanitized_sha256,
        }


@dataclass(frozen=True, slots=True)
class FileSanitizationResult:
    path: Path
    size_bytes: int
    status: str
    method: str
    version: str
    original_sha256: str
    sanitized_sha256: str

    def provenance(self) -> dict[str, str]:
        return {
            "status": self.status,
            "method": self.method,
            "version": self.version,
            "original_sha256": self.original_sha256,
            "sanitized_sha256": self.sanitized_sha256,
        }


class ArtifactContentSanitizer:
    VERSION = "1"

    def sanitize(self, content: bytes, media_type: str) -> SanitizationResult:
        normalized_type = media_type.partition(";")[0].strip().lower()
        try:
            if normalized_type in _SAFE_TEXT_TYPES:
                sanitized = self._normalize_text(content)
                return self._result(content, sanitized, "normalized", "utf8-nfc-lines")
            if normalized_type == "application/json":
                sanitized = self._normalize_json(content)
                return self._result(content, sanitized, "normalized", "canonical-json")
            if normalized_type in {"application/xml", "text/xml"}:
                sanitized = self._normalize_xml(content)
                return self._result(content, sanitized, "normalized", "restricted-xml")
            if normalized_type == "application/pdf" or normalized_type in _OOXML_TYPES:
                return self._result(
                    content,
                    content,
                    "active_content_checked",
                    "structural-deny-active-content",
                )
            if normalized_type.startswith("text/"):
                raise ValueError("unsupported active text media type")
            return self._result(content, content, "not_applicable", "none")
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ElementTree.ParseError,
            ValueError,
        ) as exc:
            raise PlatformError(
                "ARTIFACT_CONTENT_SANITIZATION_FAILED",
                "Artifact content could not be normalized safely",
                http_status=422,
                context={"media_type": normalized_type},
            ) from exc

    def sanitize_file(
        self,
        source: Path,
        destination: Path,
        media_type: str,
        *,
        max_in_memory_bytes: int,
    ) -> FileSanitizationResult:
        """Sanitize a staged file without materializing large pass-through types."""
        if max_in_memory_bytes <= 0:
            raise ValueError("ARTIFACT_SANITIZATION_LIMIT_INVALID")
        normalized_type = media_type.partition(";")[0].strip().lower()
        try:
            size_bytes = source.stat().st_size
            if size_bytes <= max_in_memory_bytes:
                original = source.read_bytes()
                result = self.sanitize(original, normalized_type)
                destination.write_bytes(result.content)
                return FileSanitizationResult(
                    path=destination,
                    size_bytes=len(result.content),
                    status=result.status,
                    method=result.method,
                    version=result.version,
                    original_sha256=result.original_sha256,
                    sanitized_sha256=result.sanitized_sha256,
                )

            requires_transform = (
                normalized_type in _SAFE_TEXT_TYPES
                or normalized_type in {"application/json", "application/xml", "text/xml"}
                or normalized_type.startswith("text/")
            )
            if requires_transform:
                raise PlatformError(
                    "ARTIFACT_STREAMING_SANITIZATION_UNSUPPORTED",
                    "Large Artifact media type requires a non-streaming normalization",
                    http_status=422,
                    context={
                        "media_type": normalized_type,
                        "size_bytes": size_bytes,
                        "max_in_memory_bytes": max_in_memory_bytes,
                    },
                )

            status = (
                "active_content_checked"
                if normalized_type == "application/pdf" or normalized_type in _OOXML_TYPES
                else "not_applicable"
            )
            method = (
                "structural-deny-active-content" if status == "active_content_checked" else "none"
            )
            digest = hashlib.sha256()
            copied = 0
            with source.open("rb") as reader, destination.open("xb") as writer:
                while chunk := reader.read(1024 * 1024):
                    writer.write(chunk)
                    digest.update(chunk)
                    copied += len(chunk)
            sha256 = digest.hexdigest()
            return FileSanitizationResult(
                path=destination,
                size_bytes=copied,
                status=status,
                method=method,
                version=self.VERSION,
                original_sha256=sha256,
                sanitized_sha256=sha256,
            )
        except PlatformError:
            destination.unlink(missing_ok=True)
            raise
        except OSError as exc:
            destination.unlink(missing_ok=True)
            raise PlatformError(
                "ARTIFACT_SANITIZATION_IO_FAILED",
                "Artifact staging storage failed during sanitization",
                retryable=True,
                http_status=503,
            ) from exc

    @classmethod
    def _normalize_text(cls, content: bytes) -> bytes:
        text = cls._normalized_unicode(content)
        if any(ord(character) < 32 and character not in "\t\n" for character in text):
            raise ValueError("text contains disallowed control characters")
        return text.encode("utf-8")

    @classmethod
    def _normalize_json(cls, content: bytes) -> bytes:
        text = cls._normalized_unicode(content)

        def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                normalized_key = unicodedata.normalize("NFC", key)
                if normalized_key in result:
                    raise ValueError("duplicate JSON key")
                result[normalized_key] = value
            return result

        def reject_constant(value: str) -> None:
            raise ValueError(f"non-finite JSON constant: {value}")

        value = json.loads(
            text,
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_constant,
        )
        normalized = cls._normalize_json_strings(value)
        return json.dumps(
            normalized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

    @classmethod
    def _normalize_xml(cls, content: bytes) -> bytes:
        text = cls._normalized_unicode(content)
        if _XML_ACTIVE_MARKUP.search(text):
            raise ValueError("active XML markup is denied")
        # The upload-size gate and active-markup rejection run before this parser.
        root = ElementTree.fromstring(text)
        return cast(
            bytes,
            ElementTree.tostring(
                root,
                encoding="utf-8",
                short_empty_elements=True,
            ),
        )

    @staticmethod
    def _normalized_unicode(content: bytes) -> str:
        decoded = content.decode("utf-8-sig")
        lines = decoded.replace("\r\n", "\n").replace("\r", "\n")
        return unicodedata.normalize("NFC", lines)

    @classmethod
    def _normalize_json_strings(cls, value: Any) -> Any:
        if isinstance(value, str):
            return unicodedata.normalize("NFC", value)
        if isinstance(value, list):
            return [cls._normalize_json_strings(item) for item in value]
        if isinstance(value, dict):
            return {key: cls._normalize_json_strings(item) for key, item in value.items()}
        return value

    @classmethod
    def _result(
        cls,
        original: bytes,
        sanitized: bytes,
        status: str,
        method: str,
    ) -> SanitizationResult:
        return SanitizationResult(
            content=sanitized,
            status=status,
            method=method,
            version=cls.VERSION,
            original_sha256=hashlib.sha256(original).hexdigest(),
            sanitized_sha256=hashlib.sha256(sanitized).hexdigest(),
        )
