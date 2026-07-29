"""Outbound adapter for the isolated staging fault-injection controller."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import httpx

from agent_platform.application.errors import PlatformError

JsonObject = dict[str, Any]


class HttpEvalFaultHarness:
    """Call a separately authorized controller; the Agent runtime never gets this client."""

    def __init__(
        self,
        *,
        controller_url: str,
        token: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        normalized = controller_url.strip().rstrip("/")
        parsed = urlsplit(normalized)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("EVAL_FAULT_HARNESS_TLS_REQUIRED")
        if not token:
            raise ValueError("EVAL_FAULT_HARNESS_TOKEN_REQUIRED")
        self._controller_url = normalized
        self._token = token
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(60),
            follow_redirects=False,
        )
        self._owns_client = client is None

    async def prepare(
        self,
        payload: JsonObject,
        *,
        actor_id: str,
        tenant_id: str,
    ) -> JsonObject:
        return await self._request(
            "POST",
            "/v1/fault-injections",
            expected_status=201,
            payload=payload,
            actor_id=actor_id,
            tenant_id=tenant_id,
        )

    async def finalize(
        self,
        injection_id: str,
        payload: JsonObject,
        *,
        actor_id: str,
        tenant_id: str,
    ) -> JsonObject:
        return await self._request(
            "POST",
            f"/v1/fault-injections/{injection_id}:finalize",
            expected_status=200,
            payload=payload,
            actor_id=actor_id,
            tenant_id=tenant_id,
        )

    async def receipt(
        self,
        injection_id: str,
        *,
        actor_id: str,
        tenant_id: str,
    ) -> JsonObject:
        return await self._request(
            "GET",
            f"/v1/fault-injections/{injection_id}/receipt",
            expected_status=200,
            payload=None,
            actor_id=actor_id,
            tenant_id=tenant_id,
        )

    async def _request(
        self,
        method: str,
        path: str,
        *,
        expected_status: int,
        payload: JsonObject | None,
        actor_id: str,
        tenant_id: str,
    ) -> JsonObject:
        try:
            response = await self._client.request(
                method,
                f"{self._controller_url}{path}",
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "X-Agent-Actor": actor_id,
                    "X-Agent-Tenant": tenant_id,
                },
                json=payload,
            )
        except httpx.HTTPError as exc:
            raise PlatformError(
                "EVAL_FAULT_HARNESS_UNAVAILABLE",
                "The isolated staging fault controller is unavailable",
                retryable=True,
                http_status=503,
                context={"operation": path},
            ) from exc
        if response.status_code != expected_status:
            raise PlatformError(
                "EVAL_FAULT_HARNESS_REJECTED",
                "The isolated staging fault controller rejected the operation",
                retryable=response.status_code >= 500,
                http_status=503,
                context={
                    "operation": path,
                    "controller_status": response.status_code,
                },
            )
        try:
            value = response.json()
        except ValueError as exc:
            raise PlatformError(
                "EVAL_FAULT_HARNESS_RESPONSE_INVALID",
                "The staging fault controller returned invalid JSON",
                retryable=False,
                http_status=502,
                context={"operation": path},
            ) from exc
        if not isinstance(value, dict):
            raise PlatformError(
                "EVAL_FAULT_HARNESS_RESPONSE_INVALID",
                "The staging fault controller response must be an object",
                retryable=False,
                http_status=502,
                context={"operation": path},
            )
        return value

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
