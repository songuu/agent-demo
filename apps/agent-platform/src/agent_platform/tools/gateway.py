from __future__ import annotations

import asyncio
import hashlib
import json
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from time import monotonic
from typing import Any, Literal
from uuid import UUID, uuid4

from jsonschema import Draft202012Validator

from agent_platform.application.errors import Forbidden, PlatformError
from agent_platform.application.records import (
    ActionRecord,
    ArtifactRecord,
    AuditEvent,
    ToolInvocationRecord,
)
from agent_platform.application.trajectory_monitor import (
    TrajectoryCandidate,
    TrajectoryCheck,
    inspect_trajectory_content,
)
from agent_platform.domain.enums import ActionStatus, ToolEffect
from agent_platform.domain.events import RunEventType
from agent_platform.domain.hashing import business_idempotency_key, canonical_json, payload_hash
from agent_platform.infrastructure.artifacts.trusted_generated import (
    build_trusted_generated_json,
)
from agent_platform.infrastructure.observability.runtime import RuntimeObservability
from agent_platform.tools.adapters.enterprise_gateway import AdapterInvocationResult
from agent_platform.tools.models import (
    PolicyDecision,
    ToolContext,
    ToolDefinition,
    ToolResult,
)
from agent_platform.tools.registry import ToolRegistry


class ToolGateway:
    def __init__(
        self,
        registry: ToolRegistry,
        policy: Any,
        credentials: Any,
        actions: Any,
        artifact_store: Any,
        *,
        capabilities: Any | None = None,
        kill_switches: Any | None = None,
        audit: Any | None = None,
        trajectory_guard: Any | None = None,
        observability: RuntimeObservability | None = None,
    ) -> None:
        self._registry = registry
        self._policy = policy
        self._credentials = credentials
        self._actions = actions
        self._artifact_store = artifact_store
        self._capabilities = capabilities
        self._kill_switches = kill_switches
        self._audit = audit
        self._trajectory = trajectory_guard
        self._observability = observability

    async def call_read(
        self,
        context: ToolContext,
        name: str,
        args: dict[str, Any],
    ) -> ToolResult:
        tool = await self._registry.resolve(name, context.tenant_id)
        definition = tool.definition
        if definition.effect != ToolEffect.READ:
            raise PlatformError("READ_EFFECT_REQUIRED", "Tool is not read-only", http_status=403)
        await self._require_operational(
            context,
            definition.capability_name,
            operation="read",
        )
        trajectory = await self._trajectory_preflight(
            context,
            definition,
            args,
            boundary="tool",
        )
        try:
            self._authorize_capability(context, definition.capability_name)
            self._validate_args(definition.input_schema, args)
            policy_request = self._policy_request(context, definition, args, "execute")
            decision = await self._policy.authorize_tool(policy_request)
            decision_id = self._policy_decision_id(policy_request, decision)
            self._record_policy("execute", decision)
            self._require_allowed(decision)
            credential = await self._credentials.issue(
                context.tenant_id,
                context.principal_id,
                self._scoped_credentials(
                    context,
                    definition.required_scopes,
                    decision,
                ),
                min(definition.timeout_seconds + 5, 300),
            )
        except Exception as exc:
            await self._record_trajectory_exception(trajectory, exc)
            raise

        invocation_id = uuid4()
        started = monotonic()
        span = (
            self._observability.span(
                "agent.tool.call",
                {
                    "correlation_id": context.correlation_id,
                    "run_id": str(context.run_id),
                    "plan_version": context.plan_version,
                    "task_id": context.task_id,
                    "tool_invocation_id": str(invocation_id),
                    "tenant_id_hash": self._observability.tenant_hash(context.tenant_id),
                    "tool": definition.name,
                    "version": definition.version,
                    "effect": definition.effect.value,
                },
            )
            if self._observability is not None
            else nullcontext()
        )
        try:
            with span:
                async with asyncio.timeout(definition.timeout_seconds):
                    raw = await tool.adapter.read(args, credential)
                raw, provider_request_id = self._unwrap_adapter_result(raw)
                result = await self._normalize_result(context, definition, raw)
        except TimeoutError as exc:
            duration = monotonic() - started
            self._record_tool(definition, "timeout", duration)
            await self._record_trajectory_exception(trajectory, exc, error_code="TOOL_TIMEOUT")
            await self._record_invocation(
                context,
                definition,
                args,
                decision,
                decision_id,
                invocation_id,
                status="failed",
                duration_seconds=duration,
                error_code="TOOL_TIMEOUT",
            )
            raise PlatformError(
                "TOOL_TIMEOUT",
                f"Tool {definition.name} exceeded its hard timeout",
                retryable=True,
                http_status=504,
            ) from exc
        except Exception as exc:
            duration = monotonic() - started
            error_code = str(getattr(exc, "code", type(exc).__name__))
            self._record_tool(definition, "error", duration)
            await self._record_trajectory_exception(
                trajectory,
                exc,
                error_code=error_code,
            )
            await self._record_invocation(
                context,
                definition,
                args,
                decision,
                decision_id,
                invocation_id,
                status="failed",
                duration_seconds=duration,
                error_code=error_code,
            )
            raise
        duration = monotonic() - started
        self._record_tool(
            definition,
            "success",
            duration,
            result_bytes=result.result_bytes,
        )
        await self._record_invocation(
            context,
            definition,
            args,
            decision,
            decision_id,
            invocation_id,
            status="succeeded",
            duration_seconds=duration,
            result=result,
            provider_request_id=provider_request_id,
        )
        await self._record_trajectory_success(
            trajectory,
            produced_untrusted_content=True,
        )
        return result

    async def prepare(
        self,
        context: ToolContext,
        name: str,
        args: dict[str, Any],
    ) -> ActionRecord:
        tool = await self._registry.resolve(name, context.tenant_id)
        definition = tool.definition
        if definition.effect != ToolEffect.PREPARE:
            raise PlatformError(
                "PREPARE_EFFECT_REQUIRED",
                "Tool cannot prepare an action",
                http_status=403,
            )
        await self._require_operational(
            context,
            definition.capability_name,
            operation="prepare",
        )
        trajectory = await self._trajectory_preflight(
            context,
            definition,
            args,
            boundary="prepare",
        )
        try:
            self._authorize_capability(context, definition.capability_name)
            self._validate_args(definition.input_schema, args)
            policy_request = self._policy_request(context, definition, args, "prepare")
            decision: PolicyDecision = await self._policy.authorize_tool(policy_request)
            decision_id = self._policy_decision_id(policy_request, decision)
            self._record_policy("prepare", decision)
            self._require_allowed(decision)
            credential = await self._credentials.issue(
                context.tenant_id,
                context.principal_id,
                self._scoped_credentials(
                    context,
                    definition.required_scopes,
                    decision,
                ),
                min(definition.timeout_seconds + 5, 300),
            )
        except Exception as exc:
            await self._record_trajectory_exception(trajectory, exc)
            raise

        invocation_id = uuid4()
        started = monotonic()
        span = (
            self._observability.span(
                "agent.tool.prepare",
                {
                    "correlation_id": context.correlation_id,
                    "run_id": str(context.run_id),
                    "plan_version": context.plan_version,
                    "task_id": context.task_id,
                    "tool_invocation_id": str(invocation_id),
                    "tenant_id_hash": self._observability.tenant_hash(context.tenant_id),
                    "tool": definition.name,
                    "version": definition.version,
                    "effect": definition.effect.value,
                },
            )
            if self._observability is not None
            else nullcontext()
        )
        try:
            with span:
                async with asyncio.timeout(definition.timeout_seconds):
                    raw_preview = await tool.adapter.preview(args, credential)
                raw_preview, provider_request_id = self._unwrap_adapter_result(raw_preview)
                preview = dict(raw_preview)
        except TimeoutError as exc:
            duration = monotonic() - started
            self._record_tool(definition, "timeout", duration)
            await self._record_trajectory_exception(trajectory, exc, error_code="TOOL_TIMEOUT")
            await self._record_invocation(
                context,
                definition,
                args,
                decision,
                decision_id,
                invocation_id,
                status="failed",
                duration_seconds=duration,
                error_code="TOOL_TIMEOUT",
            )
            raise PlatformError(
                "TOOL_TIMEOUT",
                f"Tool {definition.name} exceeded its hard timeout",
                retryable=True,
                http_status=504,
            ) from exc
        except Exception as exc:
            duration = monotonic() - started
            error_code = str(getattr(exc, "code", type(exc).__name__))
            self._record_tool(definition, "error", duration)
            await self._record_trajectory_exception(
                trajectory,
                exc,
                error_code=error_code,
            )
            await self._record_invocation(
                context,
                definition,
                args,
                decision,
                decision_id,
                invocation_id,
                status="failed",
                duration_seconds=duration,
                error_code=error_code,
            )
            raise

        duration = monotonic() - started
        self._record_tool(
            definition,
            "success",
            duration,
            result_bytes=len(canonical_json(preview).encode("utf-8")),
        )
        try:
            canonical_payload = json.loads(canonical_json(args))
            digest = payload_hash(canonical_payload)
            action = ActionRecord(
                action_id=uuid4(),
                run_id=context.run_id,
                tenant_id=context.tenant_id,
                principal_id=context.principal_id,
                action_type=definition.capability_name,
                tool_name=definition.name,
                tool_version=definition.version,
                canonical_payload=canonical_payload,
                payload_hash=digest,
                preview=preview,
                risk=definition.risk,
                approval_policy=definition.approval_policy,
                required_approvals=(
                    max(decision.required_approvals, 1) if decision.approval_required else 0
                ),
                idempotency_key=business_idempotency_key(
                    tenant_id=context.tenant_id,
                    action_type=definition.capability_name,
                    payload=canonical_payload,
                    business_window=str(context.run_id),
                ),
                policy_version=decision.policy_version,
                expires_at=min(
                    decision.expires_at,
                    datetime.now(UTC) + timedelta(hours=24),
                ),
                status=(
                    ActionStatus.PENDING_APPROVAL
                    if decision.approval_required
                    else ActionStatus.APPROVED
                ),
            )
            invocation = self._invocation_record(
                context,
                definition,
                args,
                decision,
                decision_id,
                invocation_id,
                status="succeeded",
                duration_seconds=duration,
                result_hash=payload_hash(preview),
                provider_request_id=provider_request_id,
            )
            event = AuditEvent(
                event_type=(
                    RunEventType.ACTION_APPROVAL_REQUIRED.value
                    if decision.approval_required
                    else RunEventType.ACTION_PREPARED.value
                ),
                payload={
                    "run_id": str(action.run_id),
                    "action_id": str(action.action_id),
                    "task_id": context.task_id,
                    "plan_version": context.plan_version,
                    "tool_invocation_id": str(invocation.invocation_id),
                    "tool_name": definition.name,
                    "tool_version": definition.version,
                    "policy_decision_id": decision_id,
                    "policy_version": decision.policy_version,
                    "payload_hash": action.payload_hash,
                    "risk": action.risk.value,
                    "expires_at": action.expires_at.isoformat(),
                    "preview_locator": {
                        "storage": "action_record",
                        "action_id": str(action.action_id),
                        "field": "preview",
                    },
                    "preview_hash": invocation.result_hash,
                    "provider_request_id": invocation.provider_request_id,
                    "status": action.status.value,
                    "trajectory_candidate_id": (
                        str(trajectory.candidate_id) if trajectory is not None else None
                    ),
                },
                correlation_id=context.correlation_id,
                actor_type="agent",
                actor_id=context.principal_id,
                task_id=context.task_id,
                action_id=action.action_id,
            )
            atomic_create = getattr(self._actions, "create_once_with_event", None)
            if self._audit is not None and callable(atomic_create):
                stored, _, _ = await atomic_create(action, event, invocation)
            else:
                stored, _ = await self._actions.create_once(action)
                if self._audit is not None:
                    await self._audit.record_tool(invocation, event)
            if not isinstance(stored, ActionRecord):
                raise TypeError("ACTION_REPOSITORY_RETURNED_INVALID_RECORD")
        except Exception as exc:
            await self._record_trajectory_exception(trajectory, exc)
            raise
        if self._observability is not None:
            self._observability.record_action(
                action_type=stored.action_type,
                risk=stored.risk.value,
                status=stored.status.value,
            )
        await self._record_trajectory_success(trajectory)
        return stored

    async def _trajectory_preflight(
        self,
        context: ToolContext,
        definition: ToolDefinition,
        args: dict[str, Any],
        *,
        boundary: Literal["tool", "prepare"],
    ) -> TrajectoryCheck | None:
        guard = self._trajectory
        if guard is None:
            return None
        signals = inspect_trajectory_content(args)
        classifications = {str(value) for value in context.data_scope.get("classifications", ())}
        check: TrajectoryCheck = await guard.preflight(
            run_id=context.run_id,
            tenant_id=context.tenant_id,
            candidate=TrajectoryCandidate(
                boundary=boundary,
                task_id=context.task_id,
                plan_version=context.plan_version,
                operation_name=definition.name,
                capability=definition.capability_name,
                args_hash=payload_hash(args),
                data_scope_hash=payload_hash(context.data_scope),
                planned=definition.capability_name in context.allowed_capabilities,
                injection_indicators=signals.injection_indicators,
                content_signal_hash=signals.content_signal_hash,
                credential_access_attempts=signals.credential_access_attempts,
                sensitive_data_egress=(
                    boundary == "prepare" and bool(classifications & {"restricted", "secret"})
                ),
                principal_id=context.principal_id,
                principal_scopes=context.principal_scopes,
                requested_data_scope=context.data_scope,
            ),
            correlation_id=context.correlation_id,
            actor_type="agent",
            actor_id=context.principal_id,
        )
        return check

    async def _record_trajectory_success(
        self,
        check: TrajectoryCheck | None,
        *,
        produced_untrusted_content: bool = False,
    ) -> None:
        guard = self._trajectory
        if check is None or guard is None:
            return
        await guard.record_outcome(
            check,
            status="succeeded",
            produced_untrusted_content=produced_untrusted_content,
        )

    async def _record_trajectory_exception(
        self,
        check: TrajectoryCheck | None,
        exc: Exception,
        *,
        error_code: str | None = None,
    ) -> None:
        guard = self._trajectory
        if check is None or guard is None:
            return
        code = error_code or str(getattr(exc, "code", type(exc).__name__))
        validation_codes = {
            "SCHEMA_VALIDATION_FAILED",
            "READ_EFFECT_REQUIRED",
            "PREPARE_EFFECT_REQUIRED",
        }
        scope_codes = {
            "TOOL_CAPABILITY_DENIED",
            "DATA_SCOPE_DENIED",
            "FORBIDDEN",
            "ACTION_COMMIT_DENIED",
        }
        if code in validation_codes:
            await guard.record_outcome(
                check,
                status="denied",
                error_code=code,
                denial_kind="validation",
            )
            return
        if code in scope_codes or isinstance(exc, Forbidden):
            await guard.record_outcome(
                check,
                status="denied",
                error_code=code,
                denial_kind="scope",
            )
            return
        if isinstance(exc, PlatformError) and exc.http_status == 403:
            await guard.record_outcome(
                check,
                status="denied",
                error_code=code,
                denial_kind="policy",
            )
            return
        await guard.record_outcome(
            check,
            status="failed",
            error_code=code,
        )

    @staticmethod
    def _unwrap_adapter_result(raw: Any) -> tuple[Any, str | None]:
        if isinstance(raw, AdapterInvocationResult):
            return raw.data, raw.provider_request_id
        return raw, None

    @staticmethod
    def _policy_decision_id(
        request: dict[str, Any],
        decision: PolicyDecision,
    ) -> str:
        return payload_hash(
            {
                "request": request,
                "allowed": decision.allowed,
                "reason_codes": decision.reason_codes,
                "policy_version": decision.policy_version,
                "credential_scopes": sorted(decision.credential_scopes),
            }
        )

    @staticmethod
    def _invocation_record(
        context: ToolContext,
        definition: ToolDefinition,
        args: dict[str, Any],
        decision: PolicyDecision,
        decision_id: str,
        invocation_id: UUID,
        *,
        status: str,
        duration_seconds: float,
        result_hash: str | None = None,
        result_artifact_id: Any | None = None,
        error_code: str | None = None,
        provider_request_id: str | None = None,
    ) -> ToolInvocationRecord:
        completed_at = datetime.now(UTC)
        return ToolInvocationRecord(
            invocation_id=invocation_id,
            run_id=context.run_id,
            tenant_id=context.tenant_id,
            plan_version=context.plan_version,
            task_id=context.task_id,
            tool_name=definition.name,
            tool_version=definition.version,
            effect=definition.effect,
            args_hash=payload_hash(args),
            args_redacted={key: "[REDACTED]" for key in sorted(args)},
            data_scope_hash=payload_hash(context.data_scope),
            policy_decision_id=decision_id,
            policy_version=decision.policy_version,
            status=status,
            result_hash=result_hash,
            result_artifact_id=result_artifact_id,
            error_code=error_code,
            provider_request_id=provider_request_id,
            latency_ms=max(int(duration_seconds * 1000), 0),
            created_at=completed_at - timedelta(seconds=max(duration_seconds, 0.0)),
            completed_at=completed_at,
        )

    async def _record_invocation(
        self,
        context: ToolContext,
        definition: ToolDefinition,
        args: dict[str, Any],
        decision: PolicyDecision,
        decision_id: str,
        invocation_id: UUID,
        *,
        status: str,
        duration_seconds: float,
        result: ToolResult | None = None,
        error_code: str | None = None,
        provider_request_id: str | None = None,
    ) -> None:
        if self._audit is None:
            return
        invocation = self._invocation_record(
            context,
            definition,
            args,
            decision,
            decision_id,
            invocation_id,
            status=status,
            duration_seconds=duration_seconds,
            result_hash=result.result_hash if result is not None else None,
            result_artifact_id=result.artifact_id if result is not None else None,
            error_code=error_code,
            provider_request_id=provider_request_id,
        )
        await self._audit.record_tool(
            invocation,
            AuditEvent(
                event_type=("tool.completed" if status == "succeeded" else "tool.failed"),
                payload={
                    "tool_invocation_id": str(invocation.invocation_id),
                    "task_id": context.task_id,
                    "plan_version": context.plan_version,
                    "tool_name": definition.name,
                    "tool_version": definition.version,
                    "effect": definition.effect.value,
                    "args_hash": invocation.args_hash,
                    "data_scope_hash": invocation.data_scope_hash,
                    "policy_decision_id": decision_id,
                    "policy_version": decision.policy_version,
                    "status": status,
                    "provider_request_id": invocation.provider_request_id,
                    "result_hash": invocation.result_hash,
                    "result_artifact_id": (
                        str(invocation.result_artifact_id)
                        if invocation.result_artifact_id is not None
                        else None
                    ),
                    "error_code": error_code,
                },
                correlation_id=context.correlation_id,
                actor_type="agent",
                actor_id=context.principal_id,
                task_id=context.task_id,
            ),
        )

    def _record_policy(self, phase: str, decision: PolicyDecision) -> None:
        if self._observability is not None:
            self._observability.record_policy(
                phase=phase,
                allowed=decision.allowed,
                reason_codes=decision.reason_codes,
            )

    def _record_tool(
        self,
        definition: ToolDefinition,
        status: str,
        duration_seconds: float,
        *,
        result_bytes: int = 0,
    ) -> None:
        if self._observability is not None:
            self._observability.record_tool(
                tool=definition.name,
                version=definition.version,
                effect=definition.effect.value,
                status=status,
                duration_seconds=duration_seconds,
                result_bytes=result_bytes,
            )

    def _authorize_capability(self, context: ToolContext, capability: str) -> None:
        if capability not in context.allowed_capabilities:
            raise Forbidden("TOOL_CAPABILITY_DENIED", "Capability is not in the Task contract")

    async def _require_operational(
        self,
        context: ToolContext,
        capability: str,
        *,
        operation: str,
    ) -> None:
        if self._capabilities is not None:
            records = await self._capabilities.list(context.tenant_id)
            record = next((item for item in records if item.name == capability), None)
            if record is None or not record.enabled:
                raise PlatformError(
                    "CAPABILITY_DISABLED",
                    f"Capability {capability} is disabled",
                    http_status=503,
                    context={"capability": capability},
                )
        if self._kill_switches is not None:
            configured = context.data_scope.get("use_case")
            use_case = (
                configured
                if isinstance(configured, str) and configured.strip()
                else context.task_id
            )
            await self._kill_switches.require_allowed(
                tenant_id=context.tenant_id,
                use_case=use_case,
                capability=capability,
                operation=operation,
            )

    @staticmethod
    def _validate_args(schema: dict[str, Any], args: dict[str, Any]) -> None:
        errors = sorted(Draft202012Validator(schema).iter_errors(args), key=lambda item: item.path)
        if errors:
            locations = [
                {"path": ".".join(str(part) for part in error.path), "message": error.message}
                for error in errors
            ]
            raise PlatformError(
                "SCHEMA_VALIDATION_FAILED",
                "Tool arguments do not match the strict schema",
                context={"violations": locations},
            )

    @staticmethod
    def _require_allowed(decision: PolicyDecision) -> None:
        if not decision.allowed:
            raise Forbidden(
                "DATA_SCOPE_DENIED",
                f"Policy denied the request: {','.join(decision.reason_codes)}",
            )

    @staticmethod
    def _scoped_credentials(
        context: ToolContext,
        required: frozenset[str],
        decision: PolicyDecision,
    ) -> frozenset[str]:
        granted = context.principal_scopes & required & decision.credential_scopes
        if required and granted != required:
            raise Forbidden("FORBIDDEN", "Required credential scopes are not available")
        return granted

    @staticmethod
    def _policy_request(
        context: ToolContext, definition: Any, args: dict[str, Any], phase: str
    ) -> dict[str, Any]:
        return {
            "principal": {
                "tenant_id": context.tenant_id,
                "user_id": context.principal_id,
                "scopes": sorted(context.principal_scopes),
            },
            "run": {
                "run_id": str(context.run_id),
                "allowed_capabilities": sorted(context.allowed_capabilities),
            },
            "task": {
                "task_id": context.task_id,
                "plan_version": context.plan_version,
                "allowed_capabilities": sorted(context.allowed_capabilities),
            },
            "tool": {
                "name": definition.name,
                "version": definition.version,
                "capability_name": definition.capability_name,
                "effect": definition.effect.value,
                "risk": definition.risk.value,
                "enabled": definition.enabled,
                "required_scopes": sorted(definition.required_scopes),
                "supported_data_classes": sorted(definition.supported_data_classes),
            },
            "request": {
                "args_hash": payload_hash(args),
                "data_scope": context.data_scope,
                "classifications": context.data_scope.get(
                    "classifications",
                    ["internal"],
                ),
                "phase": phase,
            },
            "kill_switch": {"mode": "none"},
            "caller": "agent",
        }

    async def _normalize_result(
        self, context: ToolContext, definition: Any, raw: Any
    ) -> ToolResult:
        encoded, scan_provenance = build_trusted_generated_json(
            raw,
            kind="tool_result",
            source="tool_gateway",
        )
        digest = hashlib.sha256(encoded).hexdigest()
        row_count = len(raw) if isinstance(raw, list) else None
        if isinstance(raw, dict) and isinstance(raw.get("items"), list):
            row_count = len(raw["items"])
        if len(encoded) <= definition.max_result_bytes:
            return ToolResult(
                data=raw,
                summary=(
                    f"{definition.name} returned "
                    f"{row_count if row_count is not None else 1} item(s)"
                ),
                row_count=row_count,
                result_hash=digest,
                result_bytes=len(encoded),
                tool_name=definition.name,
                tool_version=definition.version,
            )
        artifact = ArtifactRecord(
            artifact_id=uuid4(),
            tenant_id=context.tenant_id,
            run_id=context.run_id,
            kind="tool_result",
            media_type="application/json",
            content=encoded,
            sha256=digest,
            classification="internal",
            created_by=context.principal_id,
            retention_policy="tool-raw-short@1:artifact:90d",
            expires_at=datetime.now(UTC) + timedelta(days=90),
            scan_status="trusted_generated",
            scan_provenance=scan_provenance,
        )
        await self._artifact_store.put(artifact)
        return ToolResult(
            summary=f"{definition.name} result exceeded inline limit and was stored as an Artifact",
            row_count=row_count,
            result_hash=digest,
            result_bytes=len(encoded),
            artifact_id=artifact.artifact_id,
            truncated=True,
            tool_name=definition.name,
            tool_version=definition.version,
        )
