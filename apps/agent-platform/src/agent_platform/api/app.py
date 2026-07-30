from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from agent_platform.api.frontend_assets import (
    frontend_page,
    frontend_script,
    frontend_stylesheet,
)
from agent_platform.api.middleware import MIDDLEWARE_ORDER, SecurityEnvelopeMiddleware
from agent_platform.api.routes_actions import router as actions_router
from agent_platform.api.routes_artifacts import router as artifacts_router
from agent_platform.api.routes_capabilities import router as capabilities_router
from agent_platform.api.routes_evaluations import router as evaluations_router
from agent_platform.api.routes_governance import router as governance_router
from agent_platform.api.routes_runs import router as runs_router
from agent_platform.application.errors import PlatformError
from agent_platform.config import Settings, get_settings
from agent_platform.container import Container, build_container
from agent_platform.domain.errors import DomainInvariantError


def create_app(
    settings: Settings | None = None,
    *,
    container: Container | None = None,
) -> FastAPI:
    runtime_settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        owns_container = container is None
        app.state.accepting_requests = True
        app.state.container = container or await build_container(runtime_settings)
        await app.state.container.healthcheck()
        try:
            yield
        finally:
            app.state.accepting_requests = False
            if owns_container:
                await app.state.container.aclose()

    app = FastAPI(
        title="GPT-5.6 Agent Platform API",
        version="1.0.0",
        description=(
            "Deterministic control plane, bounded Agent runtime, and "
            "Prepare/Approve/Commit/Verify transaction boundary."
        ),
        lifespan=lifespan,
        openapi_url="/openapi.json",
        docs_url="/docs",
        redoc_url=None,
    )
    app.state.middleware_order = MIDDLEWARE_ORDER
    if container is not None:
        app.state.container = container
        app.state.accepting_requests = True
    app.add_middleware(
        SecurityEnvelopeMiddleware,
        max_request_bytes=runtime_settings.max_request_bytes,
        artifact_max_upload_bytes=runtime_settings.artifact_max_upload_bytes,
        trusted_proxy_cidrs=runtime_settings.trusted_proxy_cidrs,
    )
    app.include_router(runs_router)
    app.include_router(actions_router)
    app.include_router(artifacts_router)
    app.include_router(capabilities_router)
    app.include_router(governance_router)
    app.include_router(evaluations_router)

    @app.exception_handler(PlatformError)
    async def platform_error_handler(request: Request, exc: PlatformError) -> JSONResponse:
        return _error_response(
            request,
            status_code=exc.http_status,
            code=exc.code,
            message=exc.message,
            retryable=exc.retryable,
            details=exc.context,
        )

    @app.exception_handler(DomainInvariantError)
    async def domain_error_handler(request: Request, exc: DomainInvariantError) -> JSONResponse:
        return _error_response(
            request,
            status_code=409,
            code=exc.code,
            message=exc.message,
            retryable=False,
            details=exc.context,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        details = {
            "violations": [
                {
                    "path": ".".join(str(part) for part in item["loc"]),
                    "type": item["type"],
                    "message": item["msg"],
                }
                for item in exc.errors()
            ]
        }
        return _error_response(
            request,
            status_code=422,
            code="SCHEMA_VALIDATION_FAILED",
            message="Request does not match the public API schema",
            retryable=False,
            details=details,
        )

    @app.get("/", include_in_schema=False)
    async def root() -> Response:
        return frontend_page()

    @app.get("/assets/app.css", include_in_schema=False)
    async def frontend_css() -> Response:
        return frontend_stylesheet()

    @app.get("/assets/app.js", include_in_schema=False)
    async def frontend_javascript() -> Response:
        return frontend_script()

    @app.get("/health", tags=["operations"])
    async def health(request: Request) -> dict[str, Any]:
        return {
            "ok": True,
            "service": runtime_settings.service_name,
            "release_git_sha": runtime_settings.release_git_sha,
            "release_image_digest": runtime_settings.release_image_digest,
            "release_identity": getattr(
                request.app.state.container,
                "release_identity",
                {},
            ),
            "dependencies": await request.app.state.container.healthcheck(),
        }

    @app.get("/ready", tags=["operations"], response_model=None)
    async def ready(request: Request) -> Response | dict[str, bool]:
        if not request.app.state.accepting_requests:
            return JSONResponse({"ready": False}, status_code=503)
        dependencies = await request.app.state.container.healthcheck()
        ready_now = all(status == "ok" for status in dependencies.values())
        if not ready_now:
            return JSONResponse(
                {"ready": False, "dependencies": dependencies},
                status_code=503,
            )
        return {"ready": True}

    @app.get("/metrics", include_in_schema=False)
    async def metrics(request: Request) -> Response:
        collector = getattr(request.app.state.container, "operational_metrics", None)
        if collector is not None:
            await collector.collect()
        registry = request.app.state.container.metrics.registry
        return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)

    return app


def _error_response(
    request: Request,
    *,
    status_code: int,
    code: str,
    message: str,
    retryable: bool,
    details: dict[str, Any],
) -> JSONResponse:
    correlation_id = getattr(request.state, "correlation_id", "unavailable")
    headers = {"X-Correlation-ID": correlation_id}
    retry_after = details.get("retry_after_seconds")
    if status_code == 429 and isinstance(retry_after, int) and retry_after > 0:
        headers["Retry-After"] = str(retry_after)
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "retryable": retryable,
                "correlation_id": correlation_id,
                "details": details,
            }
        },
        headers=headers,
    )


app = create_app()
