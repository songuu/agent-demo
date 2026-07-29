"""Stable application errors mapped to the public API contract."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class PlatformError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool = False,
        http_status: int = 400,
        context: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
        self.http_status = http_status
        self.context = dict(context or {})

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class NotFound(PlatformError):
    def __init__(self, resource: str, resource_id: str) -> None:
        # Cross-tenant reads intentionally share this response to avoid existence leaks.
        super().__init__(
            "NOT_FOUND",
            f"{resource} was not found",
            http_status=404,
            context={"resource": resource, "resource_id": resource_id},
        )


class Conflict(PlatformError):
    def __init__(self, code: str, message: str, **context: Any) -> None:
        super().__init__(code, message, http_status=409, context=context)


class Forbidden(PlatformError):
    def __init__(self, code: str = "FORBIDDEN", message: str = "Access denied") -> None:
        super().__init__(code, message, http_status=403)


class Unauthenticated(PlatformError):
    def __init__(self, message: str = "Authentication is required") -> None:
        super().__init__("UNAUTHENTICATED", message, http_status=401)


class StaleActionHash(Conflict):
    def __init__(self, action_id: str) -> None:
        super().__init__(
            "STALE_ACTION_HASH",
            "The approval payload no longer matches the prepared action",
            action_id=action_id,
        )


class UnknownOutcome(PlatformError):
    def __init__(self, action_id: str, provider_request_id: str | None = None) -> None:
        super().__init__(
            "COMMIT_OUTCOME_UNKNOWN",
            "The external side effect outcome is unknown and requires reconciliation",
            retryable=False,
            http_status=503,
            context={
                "action_id": action_id,
                "provider_request_id": provider_request_id,
            },
        )


class WorkflowSignalFailed(PlatformError):
    def __init__(self, resource: str, resource_id: str, signal: str) -> None:
        super().__init__(
            "WORKFLOW_SIGNAL_FAILED",
            "The durable state was saved, but workflow notification failed; retry the request",
            retryable=True,
            http_status=503,
            context={
                "resource": resource,
                "resource_id": resource_id,
                "signal": signal,
            },
        )
