from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import SecretStr

from agent_platform.api import auth as auth_module
from agent_platform.api.auth import (
    CachedJwks,
    JwtAuthenticator,
    require_scope,
    require_step_up,
)
from agent_platform.api.dependencies import (
    _request_use_case,
    current_identity,
)
from agent_platform.application.errors import Forbidden, PlatformError, Unauthenticated
from agent_platform.config import Settings
from agent_platform.domain.enums import DataClassification
from agent_platform.domain.models import DataScope, Principal
from agent_platform.infrastructure.quota import QuotaDimension


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "auth_disabled": False,
        "environment": "test",
        "jwt_jwks_url": "https://identity.example.test/jwks.json",
        "jwt_issuer": "https://identity.example.test",
        "jwt_audience": "agent-platform",
    }
    values.update(overrides)
    return cast(Settings, SimpleNamespace(**values))


def _request(
    *,
    headers: dict[str, str] | None = None,
    container: object | None = None,
    body: bytes = b"",
    route_name: str | None = None,
    path: str = "/v1/runs",
) -> SimpleNamespace:
    state = SimpleNamespace(source_host="203.0.113.8")
    route = SimpleNamespace(name=route_name) if route_name is not None else None
    return SimpleNamespace(
        headers=headers or {},
        state=state,
        app=SimpleNamespace(state=SimpleNamespace(container=container)),
        _body=body,
        scope={"route": route},
        url=SimpleNamespace(path=path),
    )


def _principal(
    *,
    tenant_id: str = "tenant-a",
    scopes: frozenset[str] = frozenset({"knowledge:read"}),
    roles: frozenset[str] = frozenset(),
    auth_strength: str = "mfa",
) -> Principal:
    return Principal(
        user_id="user-1",
        tenant_id=tenant_id,
        scopes=scopes,
        roles=roles,
        auth_strength=auth_strength,
    )


@pytest.mark.asyncio
async def test_development_identity_is_header_bound_and_forbidden_outside_test() -> None:
    request = _request(
        headers={
            "x-agent-tenant": "tenant-a",
            "x-agent-user": "developer-1",
            "x-agent-roles": "analyst, admin",
            "x-agent-scopes": "runs:read, knowledge:read",
            "x-agent-auth-strength": "phishing_resistant",
            "x-agent-session": "session-1",
        }
    )
    authenticator = JwtAuthenticator(_settings(auth_disabled=True))

    principal = await authenticator.authenticate(request)

    assert principal.tenant_id == "tenant-a"
    assert principal.user_id == "developer-1"
    assert principal.roles == frozenset({"analyst", "admin"})
    assert principal.scopes == frozenset({"runs:read", "knowledge:read"})
    assert principal.auth_strength == "phishing_resistant"
    assert principal.session_id == "session-1"
    assert request.state.authenticated_data_scope is None

    with pytest.raises(Unauthenticated, match="disabled outside dev/test"):
        await JwtAuthenticator(_settings(auth_disabled=True, environment="prod")).authenticate(
            _request()
        )


@pytest.mark.asyncio
async def test_development_console_token_is_required_when_configured() -> None:
    authenticator = JwtAuthenticator(
        _settings(
            auth_disabled=True,
            development_console_token=SecretStr("development-console-token-with-at-least-32-bytes"),
        )
    )

    with pytest.raises(Unauthenticated, match="console token"):
        await authenticator.authenticate(_request())
    with pytest.raises(Unauthenticated, match="console token"):
        await authenticator.authenticate(
            _request(headers={"authorization": "Bearer incorrect-token"})
        )

    principal = await authenticator.authenticate(
        _request(
            headers={"authorization": ("Bearer development-console-token-with-at-least-32-bytes")}
        )
    )

    assert principal.user_id == "single-node-console"
    assert principal.tenant_id == "single-node"
    assert principal.roles == frozenset({"admin", "approver"})
    assert principal.auth_strength == "mfa"


@pytest.mark.asyncio
async def test_bearer_auth_validates_claims_nonce_and_authenticated_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    claims = {
        "sub": "subject-1",
        "tenant_id": "tenant-a",
        "scope": "runs:read memory:read",
        "roles": ["analyst"],
        "auth_strength": "mfa",
        "nonce": "nonce-1",
        "data_scope": {
            "resource_types": ["knowledge", "memory"],
            "resource_ids": ["project-a"],
            "allowed_fields": ["title"],
            "classifications": ["internal"],
        },
    }
    decode_calls: list[dict[str, object]] = []

    def decode(token: str, jwks: object, **kwargs: object) -> dict[str, Any]:
        decode_calls.append({"token": token, "jwks": jwks, **kwargs})
        return claims

    monkeypatch.setattr(
        auth_module.jwt,
        "get_unverified_header",
        lambda _: {"kid": "key-1", "alg": "RS256"},
    )
    monkeypatch.setattr(
        auth_module.jwt.PyJWK,
        "from_dict",
        staticmethod(lambda value, algorithm=None: {"value": value, "algorithm": algorithm}),
    )
    monkeypatch.setattr(auth_module.jwt, "decode", decode)
    authenticator = JwtAuthenticator(_settings())
    authenticator._jwks = CachedJwks(
        value={
            "keys": [
                {
                    "kid": "key-1",
                    "alg": "RS256",
                    "use": "sig",
                    "key_ops": ["verify"],
                }
            ]
        },
        expires_at=time.monotonic() + 60,
    )
    request = _request(
        headers={
            "authorization": "Bearer signed-token",
            "x-auth-nonce": "nonce-1",
        }
    )

    principal = await authenticator.authenticate(request)

    assert principal.user_id == "subject-1"
    assert principal.scopes == frozenset({"runs:read", "memory:read"})
    assert request.state.authenticated_data_scope.resource_ids == frozenset({"project-a"})
    assert decode_calls[0]["audience"] == "agent-platform"
    assert decode_calls[0]["issuer"] == "https://identity.example.test"
    assert decode_calls[0]["algorithms"] == ["RS256"]
    assert decode_calls[0]["options"] == {"require": ["exp", "sub"]}

    with pytest.raises(Unauthenticated, match="nonce"):
        await authenticator.authenticate(
            _request(
                headers={
                    "authorization": "Bearer signed-token",
                    "x-auth-nonce": "different",
                }
            )
        )


@pytest.mark.asyncio
async def test_bearer_auth_fails_closed_for_missing_or_invalid_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authenticator = JwtAuthenticator(_settings())
    authenticator._jwks = CachedJwks(
        value={"keys": [{"kid": "key-1", "alg": "RS256"}]},
        expires_at=time.monotonic() + 60,
    )

    with pytest.raises(Unauthenticated):
        await authenticator.authenticate(_request())

    monkeypatch.setattr(
        auth_module.jwt,
        "get_unverified_header",
        lambda _: {"kid": "key-1", "alg": "RS256"},
    )
    monkeypatch.setattr(
        auth_module.jwt.PyJWK,
        "from_dict",
        staticmethod(lambda value, algorithm=None: {"value": value, "algorithm": algorithm}),
    )

    def reject(*args: object, **kwargs: object) -> object:
        raise jwt.PyJWTError("invalid signature")

    monkeypatch.setattr(auth_module.jwt, "decode", reject)
    with pytest.raises(Unauthenticated, match="validation failed"):
        await authenticator.authenticate(_request(headers={"authorization": "Bearer invalid"}))


@pytest.mark.asyncio
async def test_bearer_auth_verifies_a_real_rs256_jwk_and_required_claims() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = cast(
        dict[str, Any],
        jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True),
    )
    public_jwk.update(
        {
            "kid": "release-key-1",
            "alg": "RS256",
            "use": "sig",
            "key_ops": ["verify"],
        }
    )
    token = jwt.encode(
        {
            "sub": "subject-1",
            "tenant_id": "tenant-a",
            "aud": "agent-platform",
            "iss": "https://identity.example.test",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "scope": "runs:read",
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "release-key-1"},
    )
    authenticator = JwtAuthenticator(_settings())
    authenticator._jwks = CachedJwks(
        value={"keys": [public_jwk]},
        expires_at=time.monotonic() + 60,
    )

    principal = await authenticator.authenticate(
        _request(headers={"authorization": f"Bearer {token}"})
    )

    assert principal.user_id == "subject-1"
    assert principal.tenant_id == "tenant-a"
    assert principal.scopes == frozenset({"runs:read"})


def test_jwt_signing_key_selection_is_exact_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid = {
        "keys": [
            {
                "kid": "key-1",
                "alg": "RS256",
                "use": "sig",
                "key_ops": ["verify"],
            }
        ]
    }
    monkeypatch.setattr(
        auth_module.jwt,
        "get_unverified_header",
        lambda _: {"kid": "key-1", "alg": "RS256"},
    )

    selected, algorithm = JwtAuthenticator._select_signing_jwk("token", valid)

    assert selected == valid["keys"][0]
    assert algorithm == "RS256"

    for jwks in (
        {"keys": []},
        {"keys": [valid["keys"][0], valid["keys"][0]]},
        {"keys": [{**valid["keys"][0], "alg": "ES256"}]},
        {"keys": [{**valid["keys"][0], "use": "enc"}]},
        {"keys": [{**valid["keys"][0], "key_ops": ["sign"]}]},
    ):
        with pytest.raises(jwt.PyJWTError):
            JwtAuthenticator._select_signing_jwk("token", jwks)

    monkeypatch.setattr(
        auth_module.jwt,
        "get_unverified_header",
        lambda _: {"kid": "key-1", "alg": "HS256"},
    )
    with pytest.raises(jwt.PyJWTError):
        JwtAuthenticator._select_signing_jwk("token", valid)


@pytest.mark.asyncio
async def test_jwks_is_discovered_cached_and_transport_failures_are_closed() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json={"keys": [{"kid": "key-1"}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        authenticator = JwtAuthenticator(
            _settings(jwt_jwks_url="", jwt_issuer="https://issuer.example.test/"),
            client=client,
        )
        first = await authenticator._get_jwks()
        second = await authenticator._get_jwks()

    assert first == second == {"keys": [{"kid": "key-1"}]}
    assert calls == ["https://issuer.example.test/.well-known/jwks.json"]

    missing = JwtAuthenticator(_settings(jwt_jwks_url="", jwt_issuer=""))
    with pytest.raises(Unauthenticated, match="issuer is not configured"):
        await missing._get_jwks()

    def unavailable(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(unavailable)) as client:
        failing = JwtAuthenticator(_settings(), client=client)
        with pytest.raises(Unauthenticated, match="key service"):
            await failing._get_jwks()

    def invalid_json(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not-json", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(invalid_json)) as client:
        malformed = JwtAuthenticator(_settings(), client=client)
        with pytest.raises(Unauthenticated, match="key service"):
            await malformed._get_jwks()


def test_claim_conversion_and_authorization_guards_fail_closed() -> None:
    with pytest.raises(Unauthenticated, match="tenant_id"):
        JwtAuthenticator._claims_to_principal_and_scope({"sub": "subject-1"})

    principal, scope = JwtAuthenticator._claims_to_principal_and_scope(
        {
            "sub": "subject-1",
            "tenant_id": "tenant-a",
            "scopes": ["runs:read"],
            "roles": ["analyst"],
        }
    )
    assert principal.auth_strength == "password"
    assert scope.resource_types == frozenset({"knowledge"})

    with pytest.raises(Forbidden, match="Required scope"):
        require_scope(principal, "runs:create")
    with pytest.raises(Forbidden, match="STEP_UP_AUTH_REQUIRED"):
        require_step_up(principal)

    admin = principal.model_copy(
        update={"roles": frozenset({"admin"}), "auth_strength": "phishing_resistant"}
    )
    require_scope(admin, "any:scope")
    require_step_up(admin)


class _Authenticator:
    def __init__(self, principal: Principal) -> None:
        self.principal = principal

    async def authenticate(self, request: object) -> Principal:
        return self.principal


class _Limiter:
    def __init__(self, *, allowed: bool) -> None:
        self.allowed = allowed
        self.dimensions: tuple[QuotaDimension, ...] = ()

    async def consume(self, dimensions: tuple[QuotaDimension, ...]) -> SimpleNamespace:
        self.dimensions = dimensions
        return SimpleNamespace(
            allowed=self.allowed,
            limited_dimension=None if self.allowed else "tenant",
            retry_after_seconds=0 if self.allowed else 17,
        )


@pytest.mark.asyncio
async def test_current_identity_uses_authenticated_scope_and_shared_quota() -> None:
    principal = _principal(scopes=frozenset({"memory:read", "artifact:write"}))
    limiter = _Limiter(allowed=True)
    settings = SimpleNamespace(
        environment="prod",
        quota_backend="redis",
        user_requests_per_minute=10,
        tenant_requests_per_minute=20,
        use_case_requests_per_minute=30,
        ip_requests_per_minute=40,
    )
    request = _request(
        container=SimpleNamespace(quota_limiter=limiter, settings=settings),
        body=b'{"constraints":{"use_case":"release-evaluation"}}',
    )
    request.state.authenticated_data_scope = DataScope(
        tenant_id="tenant-a",
        resource_types=frozenset({"memory"}),
        classifications=frozenset({DataClassification.INTERNAL}),
    )

    identity = await current_identity(request, _Authenticator(principal))

    assert identity.data_scope.resource_types == frozenset({"memory"})
    assert [item.name for item in limiter.dimensions] == [
        "user",
        "tenant",
        "use_case",
        "ip",
    ]
    assert limiter.dimensions[2].value == "release-evaluation"

    request.state.authenticated_data_scope = DataScope(
        tenant_id="tenant-b",
        resource_types=frozenset({"memory"}),
    )
    with pytest.raises(RuntimeError, match="TENANT_MISMATCH"):
        await current_identity(request, _Authenticator(principal))


@pytest.mark.asyncio
async def test_current_identity_infers_only_non_sensitive_scope_and_fails_on_quota() -> None:
    principal = _principal(
        scopes=frozenset({"artifact:write"}),
        roles=frozenset({"admin"}),
    )
    limiter = _Limiter(allowed=False)
    request = _request(
        container=SimpleNamespace(
            quota_limiter=limiter,
            settings=SimpleNamespace(environment="prod", quota_backend="redis"),
        ),
        route_name="create_run",
    )

    with pytest.raises(PlatformError) as caught:
        await current_identity(request, _Authenticator(principal))

    assert caught.value.code == "RATE_LIMITED"
    assert caught.value.context == {
        "dimension": "tenant",
        "retry_after_seconds": 17,
    }

    without_backend = _request(
        container=SimpleNamespace(
            quota_limiter=None,
            settings=SimpleNamespace(environment="prod", quota_backend="redis"),
        )
    )
    with pytest.raises(PlatformError, match="QUOTA_BACKEND_UNAVAILABLE"):
        await current_identity(without_backend, _Authenticator(principal))


def test_use_case_derivation_is_bounded_and_deterministic() -> None:
    assert (
        _request_use_case(_request(body=b'{"constraints":{"use_case":"  governed-release  "}}'))
        == "governed-release"
    )
    assert _request_use_case(_request(body=b"not-json", route_name="list_runs")) == "list_runs"
    assert _request_use_case(_request(path="/v1/fallback")) == "/v1/fallback"
