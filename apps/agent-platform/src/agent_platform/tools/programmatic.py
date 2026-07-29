"""Bounded Programmatic Tool Calling for read-only, typed call plans."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent_platform.application.errors import PlatformError
from agent_platform.domain.enums import ToolEffect
from agent_platform.domain.hashing import canonical_json, payload_hash
from agent_platform.tools.models import ToolContext, ToolDefinition

ResolveTool = Callable[[str, str], Awaitable[ToolDefinition]]
InvokeTool = Callable[[ToolDefinition, dict[str, Any]], Awaitable[Any]]


class ProgrammaticCall(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    call_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    tool_name: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,127}$")
    args: dict[str, Any] = Field(default_factory=dict)


class ProgrammaticPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    waves: tuple[tuple[ProgrammaticCall, ...], ...] = Field(min_length=1)

    @field_validator("waves")
    @classmethod
    def reject_empty_waves(
        cls,
        waves: tuple[tuple[ProgrammaticCall, ...], ...],
    ) -> tuple[tuple[ProgrammaticCall, ...], ...]:
        if any(not wave for wave in waves):
            raise ValueError("PTC_EMPTY_LOOP_FORBIDDEN: every loop must contain a call")
        return waves


class ProgrammaticLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_calls: int = Field(default=20, ge=1, le=100)
    max_loops: int = Field(default=5, ge=1, le=20)
    max_concurrency: int = Field(default=4, ge=1, le=16)
    max_duration_seconds: float = Field(default=60, ge=0.001, le=300)
    max_output_bytes: int = Field(default=1_000_000, ge=1, le=50_000_000)


class ProgrammaticOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    call_id: str
    tool_name: str
    data: Any
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)


class ProgrammaticResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    outputs: tuple[ProgrammaticOutput, ...]
    call_count: int = Field(ge=0)
    loop_count: int = Field(ge=0)
    total_output_bytes: int = Field(ge=0)


class ProgrammaticReadExecutor:
    def __init__(
        self,
        resolve: ResolveTool,
        invoke: InvokeTool,
        *,
        limits: ProgrammaticLimits | None = None,
    ) -> None:
        self._resolve = resolve
        self._invoke = invoke
        self._limits = limits or ProgrammaticLimits()

    async def execute(
        self,
        plan: ProgrammaticPlan,
        context: ToolContext,
    ) -> ProgrammaticResult:
        calls = [call for wave in plan.waves for call in wave]
        if len(calls) > self._limits.max_calls:
            raise PlatformError(
                "PTC_CALL_LIMIT_EXCEEDED",
                "PTC_CALL_LIMIT_EXCEEDED: call plan exceeds its hard limit",
            )
        if len(plan.waves) > self._limits.max_loops:
            raise PlatformError(
                "PTC_LOOP_LIMIT_EXCEEDED",
                "PTC_LOOP_LIMIT_EXCEEDED: loop count exceeds its hard limit",
            )
        call_ids = [call.call_id for call in calls]
        if len(call_ids) != len(set(call_ids)):
            raise PlatformError(
                "PTC_DUPLICATE_CALL_ID",
                "PTC_DUPLICATE_CALL_ID: call IDs must be unique",
            )

        deadline = (
            asyncio.get_running_loop().time() + self._limits.max_duration_seconds
        )
        resolved: dict[str, ToolDefinition] = {}
        for call in calls:
            try:
                async with asyncio.timeout_at(deadline):
                    definition = await self._resolve(call.tool_name, context.tenant_id)
            except (KeyError, LookupError) as exc:
                if call.tool_name not in context.allowed_capabilities:
                    raise PlatformError(
                        "PTC_CAPABILITY_DENIED",
                        "PTC_CAPABILITY_DENIED: tool is outside the Task contract",
                        http_status=403,
                        context={
                            "task_id": context.task_id,
                            "tool_name": call.tool_name,
                        },
                    ) from exc
                raise PlatformError(
                    "PTC_TOOL_NOT_FOUND",
                    "PTC_TOOL_NOT_FOUND: registered read tool was not found",
                    http_status=404,
                ) from exc
            except TimeoutError as exc:
                raise PlatformError(
                    "PTC_DURATION_EXCEEDED",
                    "PTC_DURATION_EXCEEDED: resolution exceeded the hard deadline",
                    http_status=504,
                ) from exc
            if definition.effect is not ToolEffect.READ:
                raise PlatformError(
                    "PTC_READ_EFFECT_REQUIRED",
                    "PTC_READ_EFFECT_REQUIRED: only read tools are permitted",
                    http_status=403,
                    context={"tool_name": call.tool_name},
                )
            if definition.capability_name not in context.allowed_capabilities:
                raise PlatformError(
                    "PTC_CAPABILITY_DENIED",
                    "PTC_CAPABILITY_DENIED: capability is outside the Task contract",
                    http_status=403,
                    context={
                        "task_id": context.task_id,
                        "capability": definition.capability_name,
                    },
                )
            schema_errors = sorted(
                Draft202012Validator(definition.input_schema).iter_errors(call.args),
                key=lambda item: list(item.path),
            )
            if schema_errors:
                raise PlatformError(
                    "PTC_SCHEMA_VALIDATION_FAILED",
                    "PTC_SCHEMA_VALIDATION_FAILED: arguments violate the strict schema",
                    context={
                        "call_id": call.call_id,
                        "violations": [error.message for error in schema_errors],
                    },
                )
            resolved[call.call_id] = definition

        semaphore = asyncio.Semaphore(self._limits.max_concurrency)
        outputs: list[ProgrammaticOutput] = []
        total_bytes = 0

        async def execute_call(call: ProgrammaticCall) -> ProgrammaticOutput:
            definition = resolved[call.call_id]
            async with semaphore:
                try:
                    async with asyncio.timeout(definition.timeout_seconds):
                        data = await self._invoke(definition, dict(call.args))
                except TimeoutError as exc:
                    raise PlatformError(
                        "PTC_TOOL_TIMEOUT",
                        "PTC_TOOL_TIMEOUT: read tool exceeded its timeout",
                        retryable=True,
                        http_status=504,
                        context={"tool_name": call.tool_name},
                    ) from exc
            encoded = canonical_json(data).encode("utf-8")
            if len(encoded) > min(
                self._limits.max_output_bytes,
                definition.max_result_bytes,
            ):
                raise PlatformError(
                    "PTC_OUTPUT_LIMIT_EXCEEDED",
                    "PTC_OUTPUT_LIMIT_EXCEEDED: a call output exceeded the hard limit",
                    http_status=413,
                )
            return ProgrammaticOutput(
                call_id=call.call_id,
                tool_name=call.tool_name,
                data=data,
                content_hash=payload_hash(data),
                size_bytes=len(encoded),
            )

        try:
            async with asyncio.timeout_at(deadline):
                for wave in plan.waves:
                    wave_outputs = await asyncio.gather(
                        *(execute_call(call) for call in wave)
                    )
                    wave_size = sum(item.size_bytes for item in wave_outputs)
                    if total_bytes + wave_size > self._limits.max_output_bytes:
                        raise PlatformError(
                            "PTC_OUTPUT_LIMIT_EXCEEDED",
                            "PTC_OUTPUT_LIMIT_EXCEEDED: aggregate output exceeded the hard limit",
                            http_status=413,
                        )
                    outputs.extend(wave_outputs)
                    total_bytes += wave_size
        except TimeoutError as exc:
            raise PlatformError(
                "PTC_DURATION_EXCEEDED",
                "PTC_DURATION_EXCEEDED: program exceeded its hard deadline",
                retryable=False,
                http_status=504,
            ) from exc

        return ProgrammaticResult(
            outputs=tuple(outputs),
            call_count=len(calls),
            loop_count=len(plan.waves),
            total_output_bytes=total_bytes,
        )
