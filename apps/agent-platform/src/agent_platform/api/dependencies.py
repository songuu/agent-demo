from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Annotated, cast

from fastapi import Depends, Request

from agent_platform.api.auth import JwtAuthenticator
from agent_platform.application.errors import PlatformError
from agent_platform.domain.enums import DataClassification
from agent_platform.domain.models import DataScope, Principal
from agent_platform.infrastructure.quota import QuotaDimension


@dataclass(frozen=True, slots=True)
class RequestIdentity:
    principal: Principal
    data_scope: DataScope


def container(request: Request) -> object:
    return request.app.state.container


def authenticator(request: Request) -> JwtAuthenticator:
    return cast(JwtAuthenticator, request.app.state.container.authenticator)


async def current_identity(
    request: Request,
    auth: Annotated[JwtAuthenticator, Depends(authenticator)],
) -> RequestIdentity:
    principal = await auth.authenticate(request)
    authenticated_scope = getattr(request.state, "authenticated_data_scope", None)
    if isinstance(authenticated_scope, DataScope):
        if authenticated_scope.tenant_id != principal.tenant_id:
            raise RuntimeError("AUTHENTICATED_DATA_SCOPE_TENANT_MISMATCH")
        identity = RequestIdentity(principal=principal, data_scope=authenticated_scope)
    else:
        resources: set[str] = set()
        for scope in principal.scopes:
            prefix = scope.split(":", 1)[0]
            if prefix in {"knowledge", "artifact", "email", "web", "memory"}:
                resources.add(prefix)
        if "admin" in principal.roles:
            resources.update({"knowledge", "artifact", "email", "web", "memory"})
        if not resources:
            resources.add("knowledge")
        classifications = {
            DataClassification.PUBLIC,
            DataClassification.INTERNAL,
        }
        # Restricted/secret access is never inferred from role; it requires an
        # authenticated data_scope claim in the production identity adapter.
        identity = RequestIdentity(
            principal=principal,
            data_scope=DataScope(
                tenant_id=principal.tenant_id,
                resource_types=frozenset(resources),
                classifications=frozenset(classifications),
            ),
        )
    await _consume_authenticated_quota(request, identity)
    return identity


async def _consume_authenticated_quota(
    request: Request,
    identity: RequestIdentity,
) -> None:
    runtime_container = request.app.state.container
    limiter = getattr(runtime_container, "quota_limiter", None)
    settings = getattr(runtime_container, "settings", None)
    if limiter is None:
        if (
            getattr(settings, "environment", "dev") in {"staging", "prod"}
            and getattr(settings, "quota_backend", "memory") == "redis"
        ):
            raise PlatformError(
                "QUOTA_BACKEND_UNAVAILABLE",
                "The shared quota backend is unavailable",
                retryable=True,
                http_status=503,
            )
        return

    source_host = str(getattr(request.state, "source_host", "unknown"))
    decision = await limiter.consume(
        (
            QuotaDimension(
                name="user",
                value=f"{identity.principal.tenant_id}\0{identity.principal.user_id}",
                limit=getattr(settings, "user_requests_per_minute", 120),
                window_seconds=60,
            ),
            QuotaDimension(
                name="tenant",
                value=identity.principal.tenant_id,
                limit=getattr(settings, "tenant_requests_per_minute", 1_200),
                window_seconds=60,
            ),
            QuotaDimension(
                name="use_case",
                value=_request_use_case(request),
                limit=getattr(settings, "use_case_requests_per_minute", 300),
                window_seconds=60,
            ),
            QuotaDimension(
                name="ip",
                value=source_host,
                limit=getattr(settings, "ip_requests_per_minute", 120),
                window_seconds=60,
            ),
        )
    )
    if not decision.allowed:
        raise PlatformError(
            "RATE_LIMITED",
            "Request quota is temporarily exhausted",
            retryable=True,
            http_status=429,
            context={
                "dimension": decision.limited_dimension,
                "retry_after_seconds": decision.retry_after_seconds,
            },
        )


def _request_use_case(request: Request) -> str:
    raw_body = getattr(request, "_body", b"")
    if raw_body:
        try:
            body = json.loads(raw_body)
        except (TypeError, ValueError, json.JSONDecodeError):
            body = None
        if isinstance(body, dict):
            constraints = body.get("constraints")
            if isinstance(constraints, dict):
                configured = constraints.get("use_case")
                if isinstance(configured, str) and configured.strip():
                    return configured.strip()
    route = request.scope.get("route")
    route_name = getattr(route, "name", None)
    if isinstance(route_name, str) and route_name.strip():
        return route_name
    return request.url.path
