"""Registered-only MCP access with certificate binding and output taint."""

from __future__ import annotations

from typing import Any, Protocol, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agent_platform.application.errors import Conflict, PlatformError
from agent_platform.domain.enums import ToolEffect, TrustLevel
from agent_platform.domain.hashing import canonical_json, payload_hash

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_TOOL_NAME_PATTERN = r"^[a-z][a-z0-9_.-]{2,127}$"


class McpObserver(Protocol):
    def record_mcp_server(
        self,
        *,
        server: str,
        healthy: bool,
        result_bytes: int = 0,
    ) -> None: ...


class McpTool(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=_TOOL_NAME_PATTERN)
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    capability_name: str = Field(pattern=_TOOL_NAME_PATTERN)
    effect: ToolEffect
    enabled: bool = True

    @model_validator(mode="after")
    def reject_commit(self) -> Self:
        if self.effect is ToolEffect.COMMIT:
            raise ValueError("MCP_COMMIT_TOOL_FORBIDDEN: Commit is never exposed through MCP")
        return self


class McpServerRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    server_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,63}$")
    tenant_id: str = Field(min_length=1, max_length=256)
    base_url: str = Field(min_length=1, max_length=2_048)
    certificate_organization: str = Field(min_length=1, max_length=256)
    certificate_fingerprint_sha256: str = Field(pattern=_SHA256_PATTERN)
    ca_bundle_ref: str = Field(min_length=1, max_length=1_024)
    client_certificate_ref: str = Field(min_length=1, max_length=1_024)
    tools: tuple[McpTool, ...] = Field(min_length=1, max_length=100)
    max_output_bytes: int = Field(default=1_000_000, ge=1, le=50_000_000)

    @model_validator(mode="after")
    def validate_registration_boundary(self) -> Self:
        parsed = urlsplit(self.base_url)
        if parsed.scheme != "https":
            raise ValueError("MCP_HTTPS_REQUIRED: MCP servers must use HTTPS")
        if (
            not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "MCP_URL_INVALID: registration URL cannot contain credentials, query, or fragment"
            )
        if parsed.hostname.lower() == "localhost":
            raise ValueError("MCP_URL_INVALID: localhost is not a managed MCP endpoint")
        if not self.ca_bundle_ref.startswith(("configmap://", "secret://")):
            raise ValueError(
                "MCP_CERTIFICATE_REF_REQUIRED: CA must use a managed config or secret reference"
            )
        if not self.client_certificate_ref.startswith("secret://"):
            raise ValueError(
                "MCP_CERTIFICATE_REF_REQUIRED: client certificate must use a secret reference"
            )
        if "BEGIN " in self.ca_bundle_ref or "BEGIN " in self.client_certificate_ref:
            raise ValueError(
                "MCP_CERTIFICATE_REF_REQUIRED: certificate material cannot be embedded"
            )
        identities = [(tool.name, tool.version) for tool in self.tools]
        if len(identities) != len(set(identities)):
            raise ValueError("MCP_DUPLICATE_TOOL: tool name/version pairs must be unique")
        return self


class McpAuthorizedCall(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    server_id: str
    tenant_id: str
    task_id: str
    endpoint: str
    tool: McpTool
    max_output_bytes: int


class McpOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    data: Any
    trust: TrustLevel = TrustLevel.UNTRUSTED
    taint: frozenset[str] = frozenset({"external", "mcp"})
    content_hash: str = Field(pattern=_SHA256_PATTERN)
    size_bytes: int = Field(ge=0)
    server_id: str
    tool_name: str

    @model_validator(mode="after")
    def preserve_untrusted_taint(self) -> Self:
        if self.trust is not TrustLevel.UNTRUSTED or not {"external", "mcp"} <= self.taint:
            raise ValueError("MCP_OUTPUT_TAINT_REQUIRED: external MCP output stays untrusted")
        return self


class McpRegistry:
    """Admin-provisioned registry; runtime calls accept server IDs, never URLs."""

    def __init__(self, observability: McpObserver | None = None) -> None:
        self._servers: dict[tuple[str, str], McpServerRegistration] = {}
        self._observability = observability

    def register(self, registration: McpServerRegistration) -> None:
        key = (registration.tenant_id, registration.server_id)
        if key in self._servers:
            raise Conflict(
                "MCP_SERVER_ALREADY_REGISTERED",
                "MCP server registrations are immutable",
                tenant_id=registration.tenant_id,
                server_id=registration.server_id,
            )
        self._servers[key] = registration

    def resolve(self, server_id: str, tenant_id: str) -> McpServerRegistration:
        registration = self._servers.get((tenant_id, server_id))
        if registration is None:
            # The same result prevents cross-tenant registration discovery.
            raise PlatformError(
                "MCP_SERVER_NOT_FOUND",
                "MCP_SERVER_NOT_FOUND: server is not registered for this tenant",
                http_status=404,
            )
        return registration

    def authorize_call(
        self,
        *,
        server_id: str,
        tenant_id: str,
        tool_name: str,
        task_id: str,
        allowed_capabilities: set[str] | frozenset[str],
    ) -> McpAuthorizedCall:
        registration = self.resolve(server_id, tenant_id)
        candidates = [
            tool
            for tool in registration.tools
            if tool.name == tool_name
            and tool.enabled
            and tool.effect is not ToolEffect.COMMIT
            and tool.capability_name in allowed_capabilities
        ]
        if not candidates:
            raise PlatformError(
                "MCP_TOOL_NOT_AUTHORIZED",
                "MCP_TOOL_NOT_AUTHORIZED: tool is unavailable to this task",
                http_status=403,
                context={
                    "server_id": server_id,
                    "task_id": task_id,
                    "tool_name": tool_name,
                },
            )
        tool = max(
            candidates,
            key=lambda item: tuple(int(part) for part in item.version.split(".")),
        )
        return McpAuthorizedCall(
            server_id=server_id,
            tenant_id=tenant_id,
            task_id=task_id,
            endpoint=registration.base_url.rstrip("/"),
            tool=tool,
            max_output_bytes=registration.max_output_bytes,
        )

    def verify_peer_certificate(
        self,
        *,
        server_id: str,
        tenant_id: str,
        organization: str,
        fingerprint_sha256: str,
    ) -> None:
        registration = self.resolve(server_id, tenant_id)
        if (
            organization != registration.certificate_organization
            or fingerprint_sha256 != registration.certificate_fingerprint_sha256
        ):
            if self._observability is not None:
                self._observability.record_mcp_server(
                    server=server_id,
                    healthy=False,
                )
            raise PlatformError(
                "MCP_CERTIFICATE_IDENTITY_MISMATCH",
                "MCP_CERTIFICATE_IDENTITY_MISMATCH: peer certificate is not registered",
                http_status=502,
                context={"server_id": server_id},
            )
        if self._observability is not None:
            self._observability.record_mcp_server(
                server=server_id,
                healthy=True,
            )

    def normalize_output(self, call: McpAuthorizedCall, data: Any) -> McpOutput:
        registration = self.resolve(call.server_id, call.tenant_id)
        registered_endpoint = registration.base_url.rstrip("/")
        if (
            call.endpoint != registered_endpoint
            or call.tool not in registration.tools
            or call.max_output_bytes != registration.max_output_bytes
        ):
            raise PlatformError(
                "MCP_CALL_NOT_REGISTERED",
                "MCP_CALL_NOT_REGISTERED: call does not match the managed registration",
                http_status=403,
            )
        encoded = canonical_json(data).encode("utf-8")
        if self._observability is not None:
            self._observability.record_mcp_server(
                server=call.server_id,
                healthy=True,
                result_bytes=len(encoded),
            )
        if len(encoded) > call.max_output_bytes:
            raise PlatformError(
                "MCP_OUTPUT_LIMIT_EXCEEDED",
                "MCP_OUTPUT_LIMIT_EXCEEDED: output must be artifactized",
                http_status=413,
                context={
                    "server_id": call.server_id,
                    "tool_name": call.tool.name,
                    "size_bytes": len(encoded),
                    "max_output_bytes": call.max_output_bytes,
                },
            )
        return McpOutput(
            data=data,
            content_hash=payload_hash(data),
            size_bytes=len(encoded),
            server_id=call.server_id,
            tool_name=call.tool.name,
        )
