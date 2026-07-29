"""Release-bound, staging-only API for externally controlled fault exercises."""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal, cast

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, ConfigDict, Field

from agent_platform.api.auth import require_step_up
from agent_platform.api.dependencies import RequestIdentity, current_identity
from agent_platform.application.errors import Forbidden, PlatformError

router = APIRouter(prefix="/v1/admin/evals", tags=["evaluation"])
Identity = Annotated[RequestIdentity, Depends(current_identity)]
FaultComponent = Literal[
    "planner",
    "worker",
    "verifier",
    "approval",
    "commit",
    "model",
    "tool",
    "database",
    "artifact",
    "opa",
]
FaultOutcome = Literal["recovered", "fail_closed"]
_COMPONENT_OUTCOME: dict[str, str] = {
    "planner": "recovered",
    "worker": "recovered",
    "verifier": "recovered",
    "approval": "fail_closed",
    "commit": "recovered",
    "model": "recovered",
    "tool": "recovered",
    "database": "recovered",
    "artifact": "recovered",
    "opa": "fail_closed",
}
_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")


class FaultPrepareRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"]
    release_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    git_sha: str = Field(pattern=r"^[a-f0-9]{40}$")
    image_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    case_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    source_scenario_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    component: FaultComponent
    fault_mode: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    expected_outcome: FaultOutcome


class FaultPreparedResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"]
    injection_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    state: Literal["armed"]
    release_id: str
    case_id: str
    component: FaultComponent
    expected_outcome: FaultOutcome


class FaultFinalizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"]
    run_id: str = Field(min_length=1, max_length=200)
    snapshot_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    audit_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


def _authorize(request: Request, identity: RequestIdentity, *, write: bool) -> Any:
    settings = request.app.state.container.settings
    if settings.environment != "staging":
        raise Forbidden(
            "EVAL_FAULT_INJECTION_STAGING_ONLY",
            "Fault injection is available only in the isolated staging environment",
        )
    required_scope = "eval:fault:inject" if write else "eval:fault:read"
    if required_scope not in identity.principal.scopes:
        raise Forbidden(
            "EVAL_FAULT_SCOPE_REQUIRED",
            f"Required scope is missing: {required_scope}",
        )
    if "admin" not in identity.principal.roles:
        raise Forbidden(
            "EVAL_FAULT_ADMIN_REQUIRED",
            "Fault injection requires an explicit staging administrator role",
        )
    require_step_up(identity.principal)
    harness = getattr(request.app.state.container, "fault_injection_harness", None)
    if harness is None:
        raise PlatformError(
            "EVAL_FAULT_HARNESS_NOT_CONFIGURED",
            "The isolated staging fault controller is not configured",
            retryable=False,
            http_status=503,
        )
    return harness


def _exact_prepared(
    value: object,
    *,
    request: FaultPrepareRequest,
) -> FaultPreparedResponse:
    try:
        prepared = FaultPreparedResponse.model_validate(value)
    except ValueError as exc:
        raise PlatformError(
            "EVAL_FAULT_PREPARE_RESPONSE_INVALID",
            "The fault controller returned an invalid activation response",
            retryable=False,
            http_status=502,
        ) from exc
    if (
        prepared.release_id != request.release_id
        or prepared.case_id != request.case_id
        or prepared.component != request.component
        or prepared.expected_outcome != request.expected_outcome
    ):
        raise PlatformError(
            "EVAL_FAULT_PREPARE_BINDING_MISMATCH",
            "The fault activation response is not bound to the exact release case",
            retryable=False,
            http_status=502,
        )
    return prepared


@router.post(
    "/fault-injections",
    response_model=FaultPreparedResponse,
    status_code=status.HTTP_201_CREATED,
)
async def prepare_fault_injection(
    body: FaultPrepareRequest,
    request: Request,
    identity: Identity,
) -> FaultPreparedResponse:
    harness = _authorize(request, identity, write=True)
    settings = request.app.state.container.settings
    if (
        body.git_sha != settings.release_git_sha
        or body.image_digest != settings.release_image_digest
    ):
        raise Forbidden(
            "EVAL_FAULT_RELEASE_IDENTITY_MISMATCH",
            "Fault injection must target the exact staging git SHA and image digest",
        )
    if _COMPONENT_OUTCOME[body.component] != body.expected_outcome:
        raise Forbidden(
            "EVAL_FAULT_OUTCOME_INVALID",
            "The requested outcome does not match the release fault policy",
        )
    prepared = await harness.prepare(
        body.model_dump(mode="json"),
        actor_id=identity.principal.user_id,
        tenant_id=identity.principal.tenant_id,
    )
    return _exact_prepared(prepared, request=body)


@router.post("/fault-injections/{injection_id}:finalize")
async def finalize_fault_injection(
    injection_id: str,
    body: FaultFinalizeRequest,
    request: Request,
    identity: Identity,
) -> dict[str, object]:
    if _ID_PATTERN.fullmatch(injection_id) is None:
        raise Forbidden("EVAL_FAULT_INJECTION_ID_INVALID", "Invalid injection identifier")
    harness = _authorize(request, identity, write=True)
    receipt = await harness.finalize(
        injection_id,
        body.model_dump(mode="json"),
        actor_id=identity.principal.user_id,
        tenant_id=identity.principal.tenant_id,
    )
    if receipt.get("injection_id") != injection_id:
        raise PlatformError(
            "EVAL_FAULT_RECEIPT_BINDING_MISMATCH",
            "The fault receipt is not bound to the finalized injection",
            retryable=False,
            http_status=502,
        )
    return cast(dict[str, object], receipt)


@router.get("/fault-injections/{injection_id}/receipt")
async def get_fault_injection_receipt(
    injection_id: str,
    request: Request,
    identity: Identity,
) -> dict[str, object]:
    if _ID_PATTERN.fullmatch(injection_id) is None:
        raise Forbidden("EVAL_FAULT_INJECTION_ID_INVALID", "Invalid injection identifier")
    harness = _authorize(request, identity, write=False)
    receipt = await harness.receipt(
        injection_id,
        actor_id=identity.principal.user_id,
        tenant_id=identity.principal.tenant_id,
    )
    if receipt.get("injection_id") != injection_id:
        raise PlatformError(
            "EVAL_FAULT_RECEIPT_BINDING_MISMATCH",
            "The fault receipt is not bound to the requested injection",
            retryable=False,
            http_status=502,
        )
    return cast(dict[str, object], receipt)
