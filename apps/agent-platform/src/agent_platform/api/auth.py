from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, cast

import httpx
import jwt
from fastapi import Request

from agent_platform.application.errors import Forbidden, Unauthenticated
from agent_platform.config import Settings
from agent_platform.domain.models import DataScope, Principal


@dataclass(slots=True)
class CachedJwks:
    value: dict[str, Any]
    expires_at: float


class JwtAuthenticator:
    def __init__(
        self,
        settings: Settings,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._settings = settings
        self._client = client or httpx.AsyncClient(timeout=5.0)
        self._jwks: CachedJwks | None = None

    async def authenticate(self, request: Request) -> Principal:
        if self._settings.auth_disabled:
            if self._settings.environment not in {"dev", "test"}:
                raise Unauthenticated("Header identity is disabled outside dev/test")
            request.state.authenticated_data_scope = None
            return self._development_principal(request)

        authorization = request.headers.get("authorization", "")
        if not authorization.startswith("Bearer "):
            raise Unauthenticated()
        token = authorization.removeprefix("Bearer ").strip()
        try:
            jwk_data, algorithm = self._select_signing_jwk(token, await self._get_jwks())
            claims = jwt.decode(
                token,
                jwt.PyJWK.from_dict(jwk_data, algorithm=algorithm),
                algorithms=[algorithm],
                audience=self._settings.jwt_audience,
                issuer=self._settings.jwt_issuer,
                options={"require": ["exp", "sub"]},
            )
        except (jwt.PyJWTError, TypeError, ValueError) as exc:
            raise Unauthenticated("Bearer token validation failed") from exc
        nonce_header = request.headers.get("x-auth-nonce")
        if claims.get("nonce") is not None and claims["nonce"] != nonce_header:
            raise Unauthenticated("JWT nonce does not match the authenticated request")
        principal, data_scope = self._claims_to_principal_and_scope(claims)
        request.state.authenticated_data_scope = data_scope
        return principal

    def _development_principal(self, request: Request) -> Principal:
        tenant_id = request.headers.get("x-agent-tenant", "test-tenant")
        user_id = request.headers.get("x-agent-user", "test-user")
        roles = frozenset(
            item.strip()
            for item in request.headers.get("x-agent-roles", "analyst,approver,admin").split(",")
            if item.strip()
        )
        scopes = frozenset(
            item.strip()
            for item in request.headers.get(
                "x-agent-scopes",
                "runs:create,runs:read,runs:control,knowledge:read,artifact:write,"
                "email:prepare,email:commit,actions:approve,admin:capabilities",
            ).split(",")
            if item.strip()
        )
        return Principal(
            user_id=user_id,
            tenant_id=tenant_id,
            roles=roles,
            scopes=scopes,
            auth_strength=request.headers.get("x-agent-auth-strength", "mfa"),
            session_id=request.headers.get("x-agent-session", "test-session"),
        )

    @staticmethod
    def _select_signing_jwk(
        token: str,
        jwks: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        algorithm = header.get("alg")
        if not isinstance(kid, str) or not kid:
            raise jwt.InvalidTokenError("JWT header is missing kid")
        if algorithm not in {"RS256", "ES256"}:
            raise jwt.InvalidTokenError("JWT algorithm is not allowed")

        keys = jwks.get("keys")
        if not isinstance(keys, list):
            raise jwt.InvalidTokenError("JWKS keys are missing")
        matches = [key for key in keys if isinstance(key, dict) and key.get("kid") == kid]
        if len(matches) != 1:
            raise jwt.InvalidTokenError("JWT kid must select exactly one signing key")
        selected = cast(dict[str, Any], matches[0])
        if selected.get("alg") not in {None, algorithm}:
            raise jwt.InvalidTokenError("JWK algorithm does not match the JWT header")
        if selected.get("use") not in {None, "sig"}:
            raise jwt.InvalidTokenError("JWK is not a signing key")
        key_ops = selected.get("key_ops")
        if key_ops is not None and (not isinstance(key_ops, list) or "verify" not in key_ops):
            raise jwt.InvalidTokenError("JWK is not authorized for verification")
        return selected, algorithm

    async def _get_jwks(self) -> dict[str, Any]:
        if self._jwks is not None and self._jwks.expires_at > time.monotonic():
            return self._jwks.value
        url = self._settings.jwt_jwks_url
        if not url:
            if not self._settings.jwt_issuer:
                raise Unauthenticated("JWT issuer is not configured")
            url = f"{self._settings.jwt_issuer.rstrip('/')}/.well-known/jwks.json"
        try:
            response = await self._client.get(url)
            response.raise_for_status()
            value = cast(dict[str, Any], response.json())
        except (httpx.HTTPError, ValueError) as exc:
            raise Unauthenticated("Identity key service is unavailable") from exc
        self._jwks = CachedJwks(value=value, expires_at=time.monotonic() + 300)
        return value

    @staticmethod
    def _claims_to_principal_and_scope(
        claims: dict[str, Any],
    ) -> tuple[Principal, DataScope]:
        tenant_id = claims.get("tenant_id")
        if not tenant_id:
            raise Unauthenticated("JWT is missing tenant_id")
        scope_claim = claims.get("scope", claims.get("scopes", []))
        scopes = (
            frozenset(scope_claim.split())
            if isinstance(scope_claim, str)
            else frozenset(scope_claim)
        )
        roles = frozenset(claims.get("roles", []))
        data_scope_claim = claims.get("data_scope", {})
        data_scope = DataScope(
            tenant_id=tenant_id,
            resource_types=frozenset(data_scope_claim.get("resource_types", {"knowledge"})),
            resource_ids=frozenset(data_scope_claim.get("resource_ids", [])),
            row_filter=data_scope_claim.get("row_filter", {}),
            allowed_fields=frozenset(data_scope_claim.get("allowed_fields", [])),
            classifications=frozenset(data_scope_claim.get("classifications", {"internal"})),
        )
        principal = Principal(
            user_id=str(claims["sub"]),
            tenant_id=str(tenant_id),
            roles=roles,
            scopes=scopes,
            auth_strength=claims.get("auth_strength", claims.get("acr", "password")),
            delegation_id=claims.get("delegation_id"),
            session_id=claims.get("sid"),
        )
        return principal, data_scope


def require_scope(principal: Principal, scope: str) -> None:
    if scope not in principal.scopes and "admin" not in principal.roles:
        raise Forbidden("FORBIDDEN", f"Required scope is missing: {scope}")


def require_step_up(principal: Principal) -> None:
    if principal.auth_strength not in {"mfa", "phishing_resistant"}:
        raise Forbidden("STEP_UP_AUTH_REQUIRED", "Step-up authentication is required")
