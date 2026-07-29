"""Hash-bound, immutable production tool catalog loading."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from agent_platform.application.errors import PlatformError
from agent_platform.application.reliability import SharedReliabilityControl
from agent_platform.domain.enums import ToolEffect
from agent_platform.tools.adapters.enterprise_gateway import (
    EnterpriseGatewayReliabilityConfig,
    EnterpriseToolGatewayAdapter,
)
from agent_platform.tools.models import RegisteredTool, ToolDefinition
from agent_platform.tools.registry import ToolRegistry

_MAX_CATALOG_BYTES = 2 * 1024 * 1024
_CATALOG_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ENTERPRISE_ADAPTER = re.compile(r"^enterprise\.[a-z0-9][a-z0-9_.-]{2,127}$")


class _ToolCatalogDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    catalog_id: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,127}$")
    tools: tuple[ToolDefinition, ...] = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def validate_production_definitions(self) -> _ToolCatalogDocument:
        versions: set[tuple[str, str]] = set()
        for definition in self.tools:
            key = (definition.name, definition.version)
            if key in versions:
                raise ValueError("TOOL_CATALOG_DUPLICATE_VERSION")
            versions.add(key)
            if not _ENTERPRISE_ADAPTER.fullmatch(definition.adapter_ref):
                raise ValueError("PRODUCTION_ADAPTER_REF_REQUIRED")
        return self


@dataclass(frozen=True, slots=True)
class ProductionToolCatalog:
    catalog_id: str
    digest: str
    definitions: tuple[ToolDefinition, ...]


def load_production_tool_catalog(
    path: str | Path,
    *,
    expected_sha256: str,
) -> ProductionToolCatalog:
    if not _CATALOG_DIGEST.fullmatch(expected_sha256):
        raise PlatformError(
            "TOOL_CATALOG_DIGEST_REQUIRED",
            "A sha256-bound production tool catalog is required",
            http_status=500,
        )
    resolved = Path(path).expanduser().resolve(strict=True)
    if resolved.stat().st_size > _MAX_CATALOG_BYTES:
        raise PlatformError(
            "TOOL_CATALOG_TOO_LARGE",
            "Production tool catalog exceeds the bounded size",
            http_status=500,
        )
    raw = resolved.read_bytes()
    actual_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(actual_digest, expected_sha256):
        raise PlatformError(
            "TOOL_CATALOG_DIGEST_MISMATCH",
            "Production tool catalog does not match the configured digest",
            http_status=500,
            context={"actual_digest": actual_digest},
        )
    try:
        parsed = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
        document = _ToolCatalogDocument.model_validate(parsed)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError) as exc:
        code = _validation_error_code(exc)
        raise PlatformError(
            code,
            "Production tool catalog failed strict validation",
            http_status=500,
        ) from exc
    return ProductionToolCatalog(
        catalog_id=document.catalog_id,
        digest=actual_digest,
        definitions=document.tools,
    )


def build_enterprise_registry(
    catalog: ProductionToolCatalog,
    *,
    client: httpx.AsyncClient,
    gateway_url: str,
    reliability: EnterpriseGatewayReliabilityConfig | None = None,
    shared_control: SharedReliabilityControl | None = None,
) -> ToolRegistry:
    registry = ToolRegistry()
    for definition in catalog.definitions:
        registry.register(
            RegisteredTool(
                definition=definition,
                adapter=EnterpriseToolGatewayAdapter(
                    definition=definition,
                    client=client,
                    gateway_url=gateway_url,
                    catalog_digest=catalog.digest,
                    reliability=reliability,
                    shared_control=shared_control,
                ),
            ),
            expose_to_agent=definition.effect != ToolEffect.COMMIT,
        )
    return registry


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"TOOL_CATALOG_DUPLICATE_KEY:{key}")
        result[key] = value
    return result


def _validation_error_code(exc: Exception) -> str:
    rendered = str(exc)
    for code in (
        "TOOL_CATALOG_DUPLICATE_VERSION",
        "PRODUCTION_ADAPTER_REF_REQUIRED",
        "TOOL_CATALOG_DUPLICATE_KEY",
    ):
        if code in rendered:
            return code
    return "TOOL_CATALOG_INVALID"
