"""Production adapter for a workload-identity protected enterprise tool gateway."""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from agent_platform.application.errors import PlatformError
from agent_platform.application.records import ActionRecord
from agent_platform.application.reliability import (
    BackpressureGate,
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
    SharedReliabilityControl,
)
from agent_platform.domain.hashing import payload_hash
from agent_platform.infrastructure.credential_broker import WorkloadCredentialGrant
from agent_platform.tools.models import ToolDefinition

_CATALOG_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_PROTOCOL_RESPONSE_BYTES = 50_100_000


class EnterpriseGatewayReliabilityConfig(BaseModel):
    """Bound concurrency and isolate failures for one tool/endpoint pair."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_in_flight: int = Field(default=20, ge=1, le=1_000)
    max_queued: int = Field(default=100, ge=0, le=10_000)
    queue_timeout_seconds: float = Field(default=5, gt=0, le=300)
    circuit_failure_threshold: int = Field(default=5, ge=1, le=100)
    circuit_recovery_timeout_seconds: float = Field(default=30, gt=0, le=3_600)


@dataclass(frozen=True, slots=True)
class AdapterInvocationResult(Mapping[str, Any]):
    """Separate provider evidence from tool data so schemas stay business-owned."""

    data: Any
    provider_request_id: str

    def __getitem__(self, key: str) -> Any:
        return self._mapping()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._mapping())

    def __len__(self) -> int:
        return len(self._mapping())

    def _mapping(self) -> Mapping[str, Any]:
        if not isinstance(self.data, Mapping):
            raise TypeError("ADAPTER_INVOCATION_RESULT_MAPPING_REQUIRED")
        return self.data


class _ProviderResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol_version: Literal["1.0"]
    request_id: str = Field(min_length=36, max_length=36)
    catalog_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    definition_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    tool_name: str
    tool_version: str
    operation: Literal["read", "preview", "lookup", "commit", "verify", "compensate"]
    status: Literal["succeeded", "not_found"]
    provider_request_id: str = Field(min_length=1, max_length=1_024)
    completed_at: datetime
    result: Any | None = None

    @field_validator("completed_at")
    @classmethod
    def completed_at_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("TOOL_PROVIDER_COMPLETED_AT_TIMEZONE_REQUIRED")
        return value.astimezone(UTC)


class EnterpriseToolGatewayAdapter:
    """Call one fixed internal gateway endpoint; catalog data never controls the URL."""

    def __init__(
        self,
        *,
        definition: ToolDefinition,
        client: httpx.AsyncClient,
        gateway_url: str,
        catalog_digest: str,
        reliability: EnterpriseGatewayReliabilityConfig | None = None,
        shared_control: SharedReliabilityControl | None = None,
    ) -> None:
        normalized_url = gateway_url.strip().rstrip("/")
        parsed = urlsplit(normalized_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("TOOL_GATEWAY_TLS_REQUIRED")
        if not _CATALOG_DIGEST.fullmatch(catalog_digest):
            raise ValueError("TOOL_CATALOG_DIGEST_INVALID")
        if not definition.adapter_ref.startswith("enterprise."):
            raise ValueError("PRODUCTION_ADAPTER_REF_REQUIRED")
        if "authorization" in client.headers or "cookie" in client.headers:
            raise ValueError("TOOL_GATEWAY_AMBIENT_CREDENTIAL_FORBIDDEN")
        self._definition = definition
        self._client = client
        self._operation_url = f"{normalized_url}/v1/tool-operations"
        self._catalog_digest = catalog_digest
        self._definition_hash = "sha256:" + payload_hash(definition.model_dump(mode="json"))
        self._shared_control = shared_control
        self._shared_scope = f"tool:{normalized_url}:{definition.name}:{definition.version}"
        reliability_config = reliability or EnterpriseGatewayReliabilityConfig()
        self._backpressure = BackpressureGate(
            max_in_flight=reliability_config.max_in_flight,
            max_queued=reliability_config.max_queued,
            queue_timeout_seconds=reliability_config.queue_timeout_seconds,
        )
        self._circuit = CircuitBreaker(
            CircuitBreakerConfig(
                failure_threshold=reliability_config.circuit_failure_threshold,
                recovery_timeout_seconds=(reliability_config.circuit_recovery_timeout_seconds),
            ),
            is_failure=self._is_provider_failure,
        )

    @property
    def circuit_state(self) -> CircuitState:
        return self._circuit.state

    async def read(
        self,
        args: Mapping[str, Any],
        credential: Any,
    ) -> AdapterInvocationResult:
        response = await self._invoke(
            "read",
            credential,
            arguments=dict(args),
        )
        self._validate_result(response.result)
        return AdapterInvocationResult(
            data=response.result,
            provider_request_id=response.provider_request_id,
        )

    async def preview(
        self,
        args: Mapping[str, Any],
        credential: Any,
    ) -> AdapterInvocationResult:
        response = await self._invoke(
            "preview",
            credential,
            arguments=dict(args),
        )
        self._require_mapping_result(response)
        self._validate_result(response.result)
        return AdapterInvocationResult(
            data=response.result,
            provider_request_id=response.provider_request_id,
        )

    async def lookup_by_idempotency_key(
        self,
        idempotency_key: str,
        credential: Any,
    ) -> Any | None:
        response = await self._invoke(
            "lookup",
            credential,
            idempotency_key=self._require_idempotency_key(idempotency_key),
        )
        if response.status == "not_found":
            if response.result is not None:
                raise self._protocol_error("TOOL_PROVIDER_NOT_FOUND_RESULT_FORBIDDEN")
            return None
        if response.result is None:
            return None
        self._require_mapping_result(response)
        return self._with_provider_request_id(
            response.result,
            response.provider_request_id,
        )

    async def commit(
        self,
        payload: Mapping[str, Any],
        credential: Any,
        idempotency_key: str,
    ) -> Any:
        response = await self._invoke(
            "commit",
            credential,
            arguments=dict(payload),
            idempotency_key=self._require_idempotency_key(idempotency_key),
        )
        self._require_mapping_result(response)
        self._validate_result(response.result)
        return self._with_provider_request_id(
            response.result,
            response.provider_request_id,
        )

    async def verify(
        self,
        action: ActionRecord,
        receipt: Any,
        credential: Any,
    ) -> Any:
        response = await self._invoke(
            "verify",
            credential,
            action=self._action_binding(action),
            receipt=receipt,
        )
        self._require_mapping_result(response)
        return self._with_provider_request_id(
            response.result,
            response.provider_request_id,
        )

    async def compensate(
        self,
        action: ActionRecord,
        receipt: Any,
        credential: Any,
    ) -> Any:
        response = await self._invoke(
            "compensate",
            credential,
            action=self._action_binding(action),
            receipt=receipt,
        )
        self._require_mapping_result(response)
        return self._with_provider_request_id(
            response.result,
            response.provider_request_id,
        )

    async def _invoke(
        self,
        operation: Literal[
            "read",
            "preview",
            "lookup",
            "commit",
            "verify",
            "compensate",
        ],
        credential: Any,
        **operation_payload: Any,
    ) -> _ProviderResponse:
        grant = self._require_grant(credential)
        self._require_operation_scopes(operation, grant)
        self._require_action_subject(operation_payload.get("action"), grant)
        request_id = str(uuid4())
        request_body = {
            "protocol_version": "1.0",
            "request_id": request_id,
            "requested_at": datetime.now(UTC).isoformat(),
            "catalog_digest": self._catalog_digest,
            "tool": {
                "name": self._definition.name,
                "version": self._definition.version,
                "adapter_ref": self._definition.adapter_ref,
                "definition_hash": self._definition_hash,
            },
            "operation": operation,
            "credential_grant": {
                "tenant_id": grant.tenant_id,
                "principal_id": grant.principal_id,
                "scopes": sorted(grant.scopes),
                "secret_reference": grant.secret_reference,
                "issued_at": grant.issued_at.isoformat(),
                "expires_at": grant.expires_at.isoformat(),
            },
            **operation_payload,
        }

        async def invoke_provider() -> _ProviderResponse:
            return await self._exchange(
                request_id=request_id,
                operation=operation,
                request_body=request_body,
            )

        if self._shared_control is not None:
            return await self._shared_control.call(
                self._shared_scope,
                invoke_provider,
                is_failure=self._is_provider_failure,
            )

        async def invoke_with_local_admission() -> _ProviderResponse:
            async with self._backpressure.slot():
                return await invoke_provider()

        return await self._circuit.call(invoke_with_local_admission)

    async def _exchange(
        self,
        *,
        request_id: str,
        operation: str,
        request_body: Mapping[str, Any],
    ) -> _ProviderResponse:
        try:
            response = await self._client.post(
                self._operation_url,
                json=request_body,
                headers={
                    "Accept": "application/json",
                    "X-Request-ID": request_id,
                },
            )
        except httpx.TimeoutException as exc:
            raise PlatformError(
                "TOOL_PROVIDER_TIMEOUT",
                "Enterprise tool gateway timed out",
                retryable=True,
                http_status=504,
                context={"tool_name": self._definition.name, "operation": operation},
            ) from exc
        except httpx.HTTPError as exc:
            raise PlatformError(
                "TOOL_PROVIDER_UNAVAILABLE",
                "Enterprise tool gateway could not be reached",
                retryable=True,
                http_status=503,
                context={"tool_name": self._definition.name, "operation": operation},
            ) from exc

        if response.status_code == 429 or response.status_code >= 500:
            raise PlatformError(
                "TOOL_PROVIDER_UNAVAILABLE",
                "Enterprise tool gateway is unavailable",
                retryable=True,
                http_status=503,
                context={
                    "tool_name": self._definition.name,
                    "operation": operation,
                    "provider_status": response.status_code,
                },
            )
        if not 200 <= response.status_code < 300:
            raise PlatformError(
                "TOOL_PROVIDER_REJECTED",
                "Enterprise tool gateway rejected the operation",
                http_status=502,
                context={
                    "tool_name": self._definition.name,
                    "operation": operation,
                    "provider_status": response.status_code,
                },
            )
        if len(response.content) > _MAX_PROTOCOL_RESPONSE_BYTES:
            raise self._protocol_error("TOOL_PROVIDER_RESPONSE_TOO_LARGE")
        try:
            envelope = _ProviderResponse.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise self._protocol_error("TOOL_PROVIDER_RESPONSE_INVALID") from exc
        self._validate_binding(envelope, request_id=request_id, operation=operation)
        return envelope

    @staticmethod
    def _is_provider_failure(error: Exception) -> bool:
        if not isinstance(error, PlatformError):
            return True
        return error.code.startswith("TOOL_PROVIDER_") and error.code != ("TOOL_PROVIDER_REJECTED")

    def _validate_binding(
        self,
        response: _ProviderResponse,
        *,
        request_id: str,
        operation: str,
    ) -> None:
        if (
            response.request_id != request_id
            or response.catalog_digest != self._catalog_digest
            or response.definition_hash != self._definition_hash
            or response.tool_name != self._definition.name
            or response.tool_version != self._definition.version
            or response.operation != operation
        ):
            raise self._protocol_error("TOOL_PROVIDER_BINDING_MISMATCH")
        now = datetime.now(UTC)
        if response.completed_at < now - timedelta(minutes=10):
            raise self._protocol_error("TOOL_PROVIDER_RESPONSE_STALE")
        if response.completed_at > now + timedelta(seconds=30):
            raise self._protocol_error("TOOL_PROVIDER_RESPONSE_FROM_FUTURE")

    def _validate_result(self, result: Any) -> None:
        errors = sorted(
            Draft202012Validator(self._definition.output_schema).iter_errors(result),
            key=lambda item: item.path,
        )
        if errors:
            raise PlatformError(
                "TOOL_PROVIDER_OUTPUT_SCHEMA_FAILED",
                "Enterprise tool result does not match its registered output schema",
                http_status=502,
                context={
                    "tool_name": self._definition.name,
                    "violations": [
                        {
                            "path": ".".join(str(part) for part in error.path),
                            "message": error.message,
                        }
                        for error in errors
                    ],
                },
            )

    @staticmethod
    def _require_grant(credential: Any) -> WorkloadCredentialGrant:
        if not isinstance(credential, WorkloadCredentialGrant):
            raise PlatformError(
                "WORKLOAD_CREDENTIAL_GRANT_REQUIRED",
                "Production adapters require a workload credential grant",
                http_status=500,
            )
        now = datetime.now(UTC)
        if credential.expires_at.tzinfo is None or credential.issued_at.tzinfo is None:
            raise PlatformError(
                "WORKLOAD_CREDENTIAL_GRANT_INVALID",
                "The workload credential grant must use timezone-aware timestamps",
                http_status=500,
            )
        if credential.expires_at <= now:
            raise PlatformError(
                "WORKLOAD_CREDENTIAL_GRANT_EXPIRED",
                "The workload credential grant has expired",
                http_status=503,
            )
        lifetime = credential.expires_at - credential.issued_at
        if (
            credential.issued_at > now + timedelta(seconds=30)
            or lifetime <= timedelta(0)
            or lifetime > timedelta(seconds=300)
            or not credential.tenant_id.strip()
            or not credential.principal_id.strip()
            or not credential.secret_reference.strip()
        ):
            raise PlatformError(
                "WORKLOAD_CREDENTIAL_GRANT_INVALID",
                "The workload credential grant is incomplete or outside its bounded lifetime",
                http_status=500,
            )
        return credential

    def _require_operation_scopes(
        self,
        operation: str,
        grant: WorkloadCredentialGrant,
    ) -> None:
        required = (
            self._definition.required_scopes
            if operation in {"read", "preview"}
            else self._definition.commit_scopes
        )
        if required and not required.issubset(grant.scopes):
            raise PlatformError(
                "WORKLOAD_CREDENTIAL_SCOPE_DENIED",
                "The workload credential grant lacks the registered operation scopes",
                http_status=403,
                context={"tool_name": self._definition.name, "operation": operation},
            )

    @staticmethod
    def _require_action_subject(
        action: Any,
        grant: WorkloadCredentialGrant,
    ) -> None:
        if action is None:
            return
        if not isinstance(action, Mapping):
            raise PlatformError(
                "ACTION_PROVIDER_BINDING_INVALID",
                "Provider action binding must be an object",
                http_status=500,
            )
        if (
            action.get("tenant_id") != grant.tenant_id
            or action.get("principal_id") != grant.principal_id
        ):
            raise PlatformError(
                "ACTION_PROVIDER_SUBJECT_MISMATCH",
                "Provider action binding does not match the credential subject",
                http_status=403,
            )

    @staticmethod
    def _require_idempotency_key(value: str) -> str:
        normalized = value.strip()
        if not normalized or len(normalized) > 512:
            raise PlatformError(
                "IDEMPOTENCY_KEY_INVALID",
                "The idempotency key must contain 1 to 512 characters",
            )
        return normalized

    @staticmethod
    def _action_binding(action: Any) -> dict[str, Any]:
        required = (
            "action_id",
            "run_id",
            "tenant_id",
            "principal_id",
            "tool_name",
            "tool_version",
            "payload_hash",
            "idempotency_key",
        )
        missing = [name for name in required if not hasattr(action, name)]
        if missing:
            raise PlatformError(
                "ACTION_PROVIDER_BINDING_INVALID",
                "Action is missing fields required for provider verification",
                http_status=500,
                context={"missing": missing},
            )
        return {name: str(getattr(action, name)) for name in required}

    @staticmethod
    def _require_mapping_result(response: _ProviderResponse) -> None:
        if not isinstance(response.result, Mapping):
            raise PlatformError(
                "TOOL_PROVIDER_RESULT_MAPPING_REQUIRED",
                "Enterprise action operations must return an object",
                http_status=502,
            )

    def _protocol_error(self, code: str) -> PlatformError:
        return PlatformError(
            code,
            "Enterprise tool gateway returned an untrusted protocol response",
            http_status=502,
            context={"tool_name": self._definition.name},
        )

    def _with_provider_request_id(
        self,
        result: Any,
        provider_request_id: str,
    ) -> dict[str, Any]:
        if not isinstance(result, Mapping):
            raise self._protocol_error("TOOL_PROVIDER_RESULT_MAPPING_REQUIRED")
        existing = result.get("provider_request_id")
        if existing is not None and existing != provider_request_id:
            raise self._protocol_error("TOOL_PROVIDER_REQUEST_ID_CONFLICT")
        return {**dict(result), "provider_request_id": provider_request_id}
