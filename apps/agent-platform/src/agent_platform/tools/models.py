from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agent_platform.application.ports import ToolAdapter
from agent_platform.domain.enums import RiskLevel, ToolEffect


class ToolDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,127}$")
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    description: str = Field(min_length=1, max_length=1_000)
    capability_name: str
    effect: ToolEffect
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    risk: RiskLevel
    required_scopes: frozenset[str] = frozenset()
    commit_scopes: frozenset[str] = frozenset()
    supported_data_classes: frozenset[str] = frozenset()
    allowed_network_targets: tuple[str, ...] = ()
    timeout_seconds: int = Field(ge=1, le=300)
    max_result_bytes: int = Field(ge=1, le=50_000_000)
    idempotency: str
    approval_policy: str
    adapter_ref: str
    enabled: bool = True
    deprecation_at: datetime | None = None

    @model_validator(mode="after")
    def require_strict_input_schema(self) -> ToolDefinition:
        if self.input_schema.get("type") != "object":
            raise ValueError("TOOL_SCHEMA_OBJECT_REQUIRED")
        if self.input_schema.get("additionalProperties") is not False:
            raise ValueError("TOOL_SCHEMA_MUST_FORBID_ADDITIONAL_PROPERTIES")
        return self


@dataclass(frozen=True, slots=True)
class RegisteredTool:
    definition: ToolDefinition
    adapter: ToolAdapter


@dataclass(frozen=True, slots=True)
class ToolContext:
    run_id: UUID
    task_id: str
    plan_version: int
    tenant_id: str
    principal_id: str
    principal_scopes: frozenset[str]
    allowed_capabilities: frozenset[str]
    data_scope: dict[str, Any]
    correlation_id: str


class ToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    data: Any | None = None
    summary: str
    row_count: int | None = None
    result_hash: str
    result_bytes: int = Field(default=0, ge=0)
    artifact_id: UUID | None = None
    truncated: bool = False
    tool_name: str
    tool_version: str


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    reason_codes: tuple[str, ...]
    approval_required: bool
    policy_version: str
    credential_scopes: frozenset[str]
    expires_at: datetime
    required_approvals: int = 1
    restricted_data_scope: dict[str, Any] | None = None
