"""Tenant-safe cache primitives for non-authoritative read projections only."""

from __future__ import annotations

import asyncio
import copy
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent_platform.application.errors import PlatformError
from agent_platform.domain.hashing import canonical_json, payload_hash

CacheKind = Literal["read_result", "artifact_metadata", "capability_catalog"]
_ALLOWED_KINDS = {"read_result", "artifact_metadata", "capability_catalog"}
_FORBIDDEN_KEYS = {
    "access_token",
    "action_id",
    "approval_id",
    "api_key",
    "approval",
    "authorization",
    "client_secret",
    "commit_receipt",
    "cookie",
    "credential",
    "idempotency_key",
    "password",
    "prepared_action",
    "private_key",
    "receipt_id",
    "refresh_token",
    "secret",
    "token",
}
_FORBIDDEN_TYPES = {
    "ActionRecord",
    "ApprovalRecord",
    "CommitReceipt",
    "CompensationReceipt",
    "PreparedAction",
}


class CacheKey(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(min_length=1, max_length=256)
    namespace: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,127}$")
    data_scope_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool_id: str = Field(min_length=1, max_length=256)
    tool_version: str = Field(min_length=1, max_length=256)
    model_id: str = Field(min_length=1, max_length=256)
    model_revision: str = Field(min_length=1, max_length=256)
    prompt_id: str = Field(min_length=1, max_length=256)
    prompt_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    input_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    freshness_token: str = Field(min_length=1, max_length=512)

    @field_validator(
        "tenant_id",
        "tool_id",
        "tool_version",
        "model_id",
        "model_revision",
        "prompt_id",
        "freshness_token",
    )
    @classmethod
    def _reject_blank_dimension(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("CACHE_KEY_DIMENSION_REQUIRED")
        return normalized

    @classmethod
    def build(
        cls,
        *,
        tenant_id: str,
        namespace: str,
        data_scope: Any,
        tool_id: str,
        tool_version: str,
        model_id: str,
        model_revision: str,
        prompt_id: str,
        prompt_digest: str,
        input_data: Any,
        freshness_token: str,
    ) -> CacheKey:
        if data_scope is None:
            raise ValueError("CACHE_DATA_SCOPE_REQUIRED: cache keys require an explicit data scope")
        return cls(
            tenant_id=tenant_id,
            namespace=namespace,
            data_scope_hash=payload_hash(data_scope),
            tool_id=tool_id,
            tool_version=tool_version,
            model_id=model_id,
            model_revision=model_revision,
            prompt_id=prompt_id,
            prompt_digest=prompt_digest,
            input_hash=payload_hash(input_data),
            freshness_token=freshness_token,
        )

    @property
    def digest(self) -> str:
        return payload_hash(self.model_dump(mode="python"))


@dataclass(frozen=True, slots=True)
class _CacheEntry:
    tenant_id: str
    kind: CacheKind
    value: Any
    expires_at: float
    size_bytes: int


def _sensitive_path(value: Any, *, path: str = "value") -> str | None:
    type_name = type(value).__name__
    if type_name in _FORBIDDEN_TYPES or "Credential" in type_name:
        return f"{path}<{type(value).__name__}>"
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if (
                normalized in _FORBIDDEN_KEYS
                or normalized.endswith("_password")
                or normalized.endswith("_secret")
                or normalized.endswith("_token")
                or normalized.endswith("_credential")
            ):
                return f"{path}.{key}"
            nested = _sensitive_path(item, path=f"{path}.{key}")
            if nested:
                return nested
    elif isinstance(value, (list, tuple, set, frozenset)):
        for index, item in enumerate(value):
            nested = _sensitive_path(item, path=f"{path}[{index}]")
            if nested:
                return nested
    return None


class SafeCache:
    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_entry_bytes: int = 1_000_000,
        max_ttl_seconds: int = 3_600,
    ) -> None:
        if max_entry_bytes < 1 or max_ttl_seconds < 1:
            raise ValueError("CACHE_LIMIT_INVALID: cache limits must be positive")
        self._clock = clock
        self._max_entry_bytes = max_entry_bytes
        self._max_ttl_seconds = max_ttl_seconds
        self._entries: dict[str, _CacheEntry] = {}
        self._lock = asyncio.Lock()

    async def put(
        self,
        key: CacheKey,
        *,
        tenant_id: str,
        kind: CacheKind | str,
        value: Any,
        ttl_seconds: int,
    ) -> None:
        self._require_tenant(key, tenant_id)
        if kind not in _ALLOWED_KINDS:
            raise PlatformError(
                "CACHE_KIND_FORBIDDEN",
                (
                    "CACHE_KIND_FORBIDDEN: actions, approvals, receipts, "
                    "and credentials are not cached"
                ),
            )
        sensitive = _sensitive_path(value)
        if sensitive:
            raise PlatformError(
                "CACHE_SENSITIVE_VALUE_FORBIDDEN",
                "CACHE_SENSITIVE_VALUE_FORBIDDEN: authoritative or secret value detected",
                context={"path": sensitive},
            )
        if ttl_seconds < 1 or ttl_seconds > self._max_ttl_seconds:
            raise PlatformError(
                "CACHE_TTL_INVALID",
                "CACHE_TTL_INVALID: TTL is outside the configured hard limit",
            )
        encoded = canonical_json(value).encode("utf-8")
        if len(encoded) > self._max_entry_bytes:
            raise PlatformError(
                "CACHE_ENTRY_TOO_LARGE",
                "CACHE_ENTRY_TOO_LARGE: value must be stored as an Artifact",
                http_status=413,
            )
        entry = _CacheEntry(
            tenant_id=tenant_id,
            kind=kind,  # type: ignore[arg-type]
            value=copy.deepcopy(value),
            expires_at=self._clock() + ttl_seconds,
            size_bytes=len(encoded),
        )
        async with self._lock:
            self._entries[key.digest] = entry

    async def get(self, key: CacheKey, *, tenant_id: str) -> Any | None:
        self._require_tenant(key, tenant_id)
        digest = key.digest
        async with self._lock:
            entry = self._entries.get(digest)
            if entry is None:
                return None
            if self._clock() >= entry.expires_at:
                self._entries.pop(digest, None)
                return None
            return copy.deepcopy(entry.value)

    async def invalidate_tenant(self, tenant_id: str) -> int:
        async with self._lock:
            digests = [
                digest for digest, entry in self._entries.items() if entry.tenant_id == tenant_id
            ]
            for digest in digests:
                self._entries.pop(digest, None)
            return len(digests)

    @staticmethod
    def _require_tenant(key: CacheKey, tenant_id: str) -> None:
        if key.tenant_id != tenant_id:
            raise PlatformError(
                "CACHE_TENANT_MISMATCH",
                "CACHE_TENANT_MISMATCH: cache key and caller tenants differ",
                http_status=403,
            )
