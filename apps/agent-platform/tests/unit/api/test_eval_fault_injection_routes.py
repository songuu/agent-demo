from __future__ import annotations

from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from agent_platform.api.app import create_app
from agent_platform.config import Settings
from agent_platform.container import build_container
from agent_platform.domain.models import Principal

GIT_SHA = "a" * 40
IMAGE_DIGEST = f"sha256:{'b' * 64}"


class FakeAuthenticator:
    def __init__(
        self,
        *,
        scopes: frozenset[str] = frozenset({"eval:fault:inject", "eval:fault:read"}),
        roles: frozenset[str] = frozenset({"admin"}),
        auth_strength: str = "mfa",
    ) -> None:
        self._principal = Principal(
            user_id="release-evaluator",
            tenant_id="staging-eval",
            scopes=scopes,
            roles=roles,
            auth_strength=auth_strength,
        )

    async def authenticate(self, request: object) -> Principal:
        return self._principal


class FakeHarness:
    def __init__(self) -> None:
        self.prepared: list[dict[str, object]] = []
        self.finalized: list[tuple[str, dict[str, object]]] = []

    async def prepare(
        self,
        payload: dict[str, object],
        *,
        actor_id: str,
        tenant_id: str,
    ) -> dict[str, object]:
        assert actor_id == "release-evaluator"
        assert tenant_id == "staging-eval"
        self.prepared.append(payload)
        return {
            "schema_version": "1.0",
            "injection_id": "fault-001",
            "state": "armed",
            "release_id": payload["release_id"],
            "case_id": payload["case_id"],
            "component": payload["component"],
            "expected_outcome": payload["expected_outcome"],
        }

    async def finalize(
        self,
        injection_id: str,
        payload: dict[str, object],
        *,
        actor_id: str,
        tenant_id: str,
    ) -> dict[str, object]:
        self.finalized.append((injection_id, payload))
        return {
            "injection_id": injection_id,
            "receipt_sha256": "c" * 64,
            "receipt_uri": f"https://staging.example.test/receipts/{injection_id}",
        }

    async def receipt(
        self,
        injection_id: str,
        *,
        actor_id: str,
        tenant_id: str,
    ) -> dict[str, object]:
        return {
            "injection_id": injection_id,
            "receipt_sha256": "c" * 64,
            "receipt_uri": f"https://staging.example.test/receipts/{injection_id}",
        }


def _settings() -> Settings:
    return Settings(
        environment="test",
        database_dsn=SecretStr("postgresql+asyncpg://test:test@localhost/test"),
        auth_disabled=True,
        release_git_sha=GIT_SHA,
        release_image_digest=IMAGE_DIGEST,
    )


async def _client(
    *,
    environment: str = "staging",
    authenticator: Any | None = None,
    harness: Any | None = None,
) -> tuple[httpx.AsyncClient, Any]:
    settings = _settings()
    container = await build_container(settings)
    container.settings.environment = environment
    container.authenticator = authenticator or FakeAuthenticator()
    container.fault_injection_harness = harness
    app = create_app(settings, container=container)
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    )
    return client, container


def _prepare_body() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "release_id": "release-20260727",
        "git_sha": GIT_SHA,
        "image_digest": IMAGE_DIGEST,
        "case_id": "golden-model-live-001",
        "source_scenario_sha256": "d" * 64,
        "component": "model",
        "fault_mode": "model_fallback_recovery",
        "expected_outcome": "recovered",
    }


@pytest.mark.asyncio
async def test_fault_api_arms_and_finalizes_exact_release_bound_staging_fault() -> None:
    harness = FakeHarness()
    client, container = await _client(harness=harness)
    try:
        prepared = await client.post(
            "/v1/admin/evals/fault-injections",
            json=_prepare_body(),
        )
        finalized = await client.post(
            "/v1/admin/evals/fault-injections/fault-001:finalize",
            json={
                "schema_version": "1.0",
                "run_id": "run-001",
                "snapshot_sha256": "e" * 64,
                "audit_sha256": "f" * 64,
            },
        )
    finally:
        await client.aclose()
        await container.aclose()

    assert prepared.status_code == 201
    assert prepared.json()["state"] == "armed"
    assert finalized.status_code == 200
    assert finalized.json()["injection_id"] == "fault-001"
    assert harness.prepared[0]["git_sha"] == GIT_SHA
    assert harness.finalized[0][1]["run_id"] == "run-001"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("environment", "authenticator", "expected_code"),
    (
        ("prod", FakeAuthenticator(), "EVAL_FAULT_INJECTION_STAGING_ONLY"),
        (
            "staging",
            FakeAuthenticator(scopes=frozenset({"eval:fault:read"})),
            "EVAL_FAULT_SCOPE_REQUIRED",
        ),
        (
            "staging",
            FakeAuthenticator(roles=frozenset({"qa"})),
            "EVAL_FAULT_ADMIN_REQUIRED",
        ),
        (
            "staging",
            FakeAuthenticator(auth_strength="password"),
            "STEP_UP_AUTH_REQUIRED",
        ),
    ),
)
async def test_fault_api_rejects_non_staging_or_insufficient_authority(
    environment: str,
    authenticator: FakeAuthenticator,
    expected_code: str,
) -> None:
    client, container = await _client(
        environment=environment,
        authenticator=authenticator,
        harness=FakeHarness(),
    )
    try:
        response = await client.post(
            "/v1/admin/evals/fault-injections",
            json=_prepare_body(),
        )
    finally:
        await client.aclose()
        await container.aclose()

    assert response.status_code == 403
    assert response.json()["error"]["code"] == expected_code


@pytest.mark.asyncio
async def test_fault_api_rejects_release_drift_and_missing_controller() -> None:
    client, container = await _client(harness=FakeHarness())
    drifted = _prepare_body()
    drifted["git_sha"] = "0" * 40
    try:
        mismatch = await client.post(
            "/v1/admin/evals/fault-injections",
            json=drifted,
        )
    finally:
        await client.aclose()
        await container.aclose()

    client, container = await _client(harness=None)
    try:
        unavailable = await client.post(
            "/v1/admin/evals/fault-injections",
            json=_prepare_body(),
        )
    finally:
        await client.aclose()
        await container.aclose()

    assert mismatch.status_code == 403
    assert mismatch.json()["error"]["code"] == "EVAL_FAULT_RELEASE_IDENTITY_MISMATCH"
    assert unavailable.status_code == 503
    assert unavailable.json()["error"]["code"] == "EVAL_FAULT_HARNESS_NOT_CONFIGURED"
