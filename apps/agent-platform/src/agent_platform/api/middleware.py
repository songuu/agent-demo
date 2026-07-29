from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable, Sequence
from ipaddress import ip_address, ip_network
from typing import Any
from uuid import uuid4

import structlog
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from opentelemetry import context as otel_context
from opentelemetry.propagate import extract
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import ClientDisconnect

from agent_platform.application.errors import PlatformError
from agent_platform.infrastructure.quota import QuotaDimension

CORRELATION_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{8,128}$")

MIDDLEWARE_ORDER = (
    "correlation",
    "trusted_proxy",
    "body_content_type",
    "authentication",
    "tenant",
    "rate_quota",
    "idempotency",
    "authorization",
    "trace_log",
    "exception_mapping",
)


class SecurityEnvelopeMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: Any,
        *,
        max_request_bytes: int,
        artifact_max_upload_bytes: int | None = None,
        requests_per_minute: int = 120,
        trusted_proxy_cidrs: Sequence[str] = (),
    ) -> None:
        super().__init__(app)
        self._max_request_bytes = max_request_bytes
        self._artifact_max_upload_bytes = artifact_max_upload_bytes or max_request_bytes
        self._requests_per_minute = requests_per_minute
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._trusted_proxy_networks = tuple(
            ip_network(cidr, strict=False) for cidr in trusted_proxy_cidrs
        )

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        supplied = request.headers.get("x-correlation-id", "")
        correlation_id = supplied if CORRELATION_PATTERN.fullmatch(supplied) else f"c-{uuid4()}"
        request.state.correlation_id = correlation_id
        is_artifact_upload = request.method == "POST" and request.url.path.rstrip("/").endswith(
            "/v1/artifacts"
        )
        body_limit = (
            self._artifact_max_upload_bytes if is_artifact_upload else self._max_request_bytes
        )

        content_length = request.headers.get("content-length")
        if content_length:
            try:
                declared_length = int(content_length)
                exceeds_limit = declared_length > body_limit
                if declared_length < 0:
                    raise ValueError
            except ValueError:
                return self._error_response(
                    correlation_id,
                    PlatformError(
                        "INVALID_CONTENT_LENGTH",
                        "Content-Length must be an integer",
                        http_status=400,
                    ),
                )
            if exceeds_limit:
                return self._error_response(
                    correlation_id,
                    PlatformError(
                        "REQUEST_TOO_LARGE",
                        "Request exceeds the configured body limit",
                        http_status=413,
                    ),
                )
        has_body = content_length not in {None, "0"} or bool(
            request.headers.get("transfer-encoding")
        )
        if request.method in {"POST", "PUT", "PATCH"} and has_body:
            content_type = request.headers.get("content-type", "")
            valid_content_type = (
                bool(content_type) and not content_type.startswith("multipart/form-data")
                if is_artifact_upload
                else (
                    content_type.startswith("application/json")
                    or content_type.startswith("multipart/form-data")
                    or content_type.startswith("application/octet-stream")
                )
            )
            if not valid_content_type:
                return self._error_response(
                    correlation_id,
                    PlatformError(
                        "UNSUPPORTED_MEDIA_TYPE",
                        "Write requests require JSON, multipart, or octet-stream content",
                        http_status=415,
                    ),
                )
            if content_type.startswith("application/json"):
                chunks: list[bytes] = []
                observed_bytes = 0
                try:
                    async for chunk in request.stream():
                        observed_bytes += len(chunk)
                        if observed_bytes > body_limit:
                            return self._error_response(
                                correlation_id,
                                PlatformError(
                                    "REQUEST_TOO_LARGE",
                                    "Request exceeds the configured body limit",
                                    http_status=413,
                                ),
                            )
                        chunks.append(chunk)
                except ClientDisconnect:
                    return self._error_response(
                        correlation_id,
                        PlatformError(
                            "REQUEST_BODY_DISCONNECTED",
                            "Request body ended before it was complete",
                            retryable=True,
                            http_status=400,
                        ),
                    )
                request._body = b"".join(chunks)

        source_host = self._source_host(request)
        request.state.source_host = source_host
        container = getattr(request.app.state, "container", None)
        limiter = getattr(container, "quota_limiter", None)
        runtime_settings = getattr(container, "settings", None)
        if limiter is not None:
            try:
                decision = await limiter.consume(
                    (
                        QuotaDimension(
                            name="pre_auth_ip",
                            value=source_host,
                            limit=getattr(
                                runtime_settings,
                                "pre_auth_ip_requests_per_minute",
                                self._requests_per_minute,
                            ),
                            window_seconds=60,
                        ),
                    )
                )
            except PlatformError as exc:
                return self._error_response(correlation_id, exc)
            if not decision.allowed:
                return self._error_response(
                    correlation_id,
                    PlatformError(
                        "RATE_LIMITED",
                        "Request quota is temporarily exhausted",
                        retryable=True,
                        http_status=429,
                        context={
                            "dimension": decision.limited_dimension,
                            "retry_after_seconds": decision.retry_after_seconds,
                        },
                    ),
                )
        elif (
            getattr(runtime_settings, "environment", "dev") in {"staging", "prod"}
            and getattr(runtime_settings, "quota_backend", "memory") == "redis"
        ):
            return self._error_response(
                correlation_id,
                PlatformError(
                    "QUOTA_BACKEND_UNAVAILABLE",
                    "The shared quota backend is unavailable",
                    retryable=True,
                    http_status=503,
                ),
            )
        else:
            now = time.monotonic()
            bucket = self._requests[f"source:{source_host}"]
            while bucket and bucket[0] < now - 60:
                bucket.popleft()
            if len(bucket) >= self._requests_per_minute:
                return self._error_response(
                    correlation_id,
                    PlatformError(
                        "RATE_LIMITED",
                        "Request quota is temporarily exhausted",
                        retryable=True,
                        http_status=429,
                        context={
                            "dimension": "pre_auth_ip",
                            "retry_after_seconds": 60,
                        },
                    ),
                )
            bucket.append(now)
        parent_context = extract(request.headers)
        context_token = otel_context.attach(parent_context)
        try:
            with structlog.contextvars.bound_contextvars(correlation_id=correlation_id):
                observability = getattr(container, "observability", None)
                if observability is None:
                    response = await call_next(request)
                else:
                    with observability.span(
                        "agent.api.request",
                        {
                            "correlation_id": correlation_id,
                            "http_method": request.method,
                        },
                    ) as current_span:
                        response = await call_next(request)
                        route = getattr(request.scope.get("route"), "path", request.url.path)
                        current_span.set_attribute("http.route", route)
                        current_span.set_attribute(
                            "http.response.status_code",
                            response.status_code,
                        )
        finally:
            otel_context.detach(context_token)
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    def _source_host(self, request: Request) -> str:
        peer_host = request.client.host if request.client is not None else "unknown"
        try:
            peer = ip_address(peer_host)
        except ValueError:
            return peer_host
        if not any(peer in network for network in self._trusted_proxy_networks):
            return peer.compressed
        forwarded_for = request.headers.get("x-forwarded-for", "")
        try:
            hops = [ip_address(raw.strip()) for raw in forwarded_for.split(",") if raw.strip()]
        except ValueError:
            return peer.compressed
        for hop in reversed(hops):
            if not any(hop in network for network in self._trusted_proxy_networks):
                return hop.compressed
        return peer.compressed

    @staticmethod
    def _error_response(
        correlation_id: str,
        error: PlatformError,
    ) -> JSONResponse:
        headers = {
            "X-Correlation-ID": correlation_id,
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        }
        retry_after = error.context.get("retry_after_seconds")
        if error.http_status == 429 and isinstance(retry_after, int) and retry_after > 0:
            headers["Retry-After"] = str(retry_after)
        return JSONResponse(
            status_code=error.http_status,
            content={
                "error": {
                    "code": error.code,
                    "message": error.message,
                    "retryable": error.retryable,
                    "correlation_id": correlation_id,
                    "details": error.context,
                }
            },
            headers=headers,
        )
