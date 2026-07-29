from __future__ import annotations

from decimal import Decimal
from uuid import uuid4

import httpx
import pytest
from pydantic import SecretStr

from agent_platform.api.app import create_app
from agent_platform.api.auth import JwtAuthenticator
from agent_platform.application.errors import PlatformError
from agent_platform.application.records import RunRecord
from agent_platform.config import Settings
from agent_platform.container import build_container
from agent_platform.domain.enums import RiskLevel
from agent_platform.domain.models import (
    DataScope,
    Principal,
    SuccessCriterion,
    TaskContract,
)
from agent_platform.infrastructure.artifacts.s3_store import S3ArtifactStore
from agent_platform.infrastructure.kill_switch import KillSwitchScope
from agent_platform.tools.models import ToolContext


def settings() -> Settings:
    return Settings(
        environment="test",
        database_dsn=SecretStr("postgresql+asyncpg://test:test@localhost/test"),
        openai_api_key=SecretStr(""),
        auth_disabled=True,
        workflow_backend="inline",
        persistence_backend="memory",
        artifact_backend="memory",
        policy_backend="builtin",
    )


@pytest.mark.asyncio
async def test_container_owns_isolated_metrics_and_governance_services() -> None:
    first = await build_container(settings())
    second = await build_container(settings())
    try:
        assert first.metrics.registry is not second.metrics.registry
        assert first.memory_vault is not second.memory_vault
        assert first.kill_switches is not second.kill_switches
        assert first.webhook_registry is not second.webhook_registry
    finally:
        await first.aclose()
        await second.aclose()


def test_production_claim_data_scope_is_not_added_to_strict_principal() -> None:
    principal, data_scope = JwtAuthenticator._claims_to_principal_and_scope(
        {
            "sub": "user-1",
            "tenant_id": "tenant-a",
            "roles": ["analyst"],
            "scope": "runs:create knowledge:read",
            "auth_strength": "mfa",
            "data_scope": {
                "resource_types": ["knowledge"],
                "resource_ids": ["document-1"],
                "classifications": ["confidential"],
            },
        }
    )

    assert principal.tenant_id == "tenant-a"
    assert "data_scope" not in type(principal).model_fields
    assert data_scope.tenant_id == "tenant-a"
    assert data_scope.resource_ids == frozenset({"document-1"})
    assert {item.value for item in data_scope.classifications} == {"confidential"}


@pytest.mark.asyncio
async def test_middleware_returns_stable_json_for_its_own_rejections() -> None:
    container = await build_container(settings())
    app = create_app(settings(), container=container)
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://test",
        ) as client:
            unsupported = await client.post(
                "/v1/runs",
                content=b"not-json",
                headers={
                    "Content-Type": "text/plain",
                    "X-Correlation-ID": "middleware-media-1",
                },
            )
            assert unsupported.status_code == 415
            assert unsupported.json()["error"] == {
                "code": "UNSUPPORTED_MEDIA_TYPE",
                "message": ("Write requests require JSON, multipart, or octet-stream content"),
                "retryable": False,
                "correlation_id": "middleware-media-1",
                "details": {},
            }

            oversized = await client.post(
                "/v1/runs",
                content=b"{}",
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(settings().max_request_bytes + 1),
                    "X-Correlation-ID": "middleware-size-1",
                },
            )
            assert oversized.status_code == 413
            assert oversized.json()["error"]["code"] == "REQUEST_TOO_LARGE"
            assert oversized.headers["x-correlation-id"] == "middleware-size-1"
    finally:
        await container.aclose()


@pytest.mark.asyncio
async def test_capability_change_and_kill_switch_reach_live_gateway() -> None:
    container = await build_container(settings())
    contract = TaskContract(
        goal="Search the approved knowledge scope",
        success_criteria=[
            SuccessCriterion(
                id="sc-1",
                description="Return bounded knowledge evidence",
                verification="evidence",
                evidence_required=True,
            )
        ],
        principal=Principal(
            user_id="user-1",
            tenant_id="tenant-a",
            roles={"analyst"},
            scopes={"knowledge:read"},
            auth_strength="mfa",
        ),
        data_scope=DataScope(
            tenant_id="tenant-a",
            resource_types={"knowledge"},
        ),
        risk=RiskLevel.MEDIUM,
        allowed_capabilities={"knowledge.search"},
        constraints={"use_case": "market-report"},
        max_cost_usd=Decimal("1"),
        max_duration_seconds=30,
        max_tool_calls=5,
        max_parallelism=1,
        max_replans=1,
    )
    context = ToolContext(
        run_id=uuid4(),
        task_id="research",
        plan_version=1,
        tenant_id="tenant-a",
        principal_id="user-1",
        principal_scopes=frozenset({"knowledge:read"}),
        allowed_capabilities=frozenset({"knowledge.search"}),
        data_scope=contract.data_scope.model_dump(mode="json"),
        correlation_id="governance-gateway-1",
    )
    try:
        await container.store.runs.create_once(
            RunRecord(
                run_id=context.run_id,
                tenant_id=context.tenant_id,
                principal_id=context.principal_id,
                contract=contract,
                idempotency_key="governance-gateway-run",
                request_hash="governance-gateway-request",
                workflow_id="governance-gateway-workflow",
            )
        )
        result = await container.gateway.call_read(
            context, "knowledge.search", {"query": "SG", "limit": 2}
        )
        assert result.row_count

        await container.store.capabilities.set_enabled(
            "tenant-a", "knowledge.search", False, "incident"
        )
        with pytest.raises(PlatformError) as disabled:
            await container.gateway.call_read(
                context, "knowledge.search", {"query": "SG", "limit": 2}
            )
        assert disabled.value.code == "CAPABILITY_DISABLED"

        await container.store.capabilities.set_enabled(
            "tenant-a", "knowledge.search", True, "recovered"
        )
        switch = await container.kill_switches.activate(
            scope=KillSwitchScope.CAPABILITY,
            scope_id="knowledge.search",
            mode="all",
            reason="containment",
            changed_by="operator",
            incident_id="INC-1",
        )
        with pytest.raises(PlatformError) as killed:
            await container.gateway.call_read(
                context, "knowledge.search", {"query": "SG", "limit": 2}
            )
        assert killed.value.code == "CAPABILITY_KILL_SWITCH_ACTIVE"

        await container.kill_switches.deactivate(
            switch.switch_id,
            changed_by="operator",
            reason="recovered",
        )
        recovered = await container.gateway.call_read(
            context, "knowledge.search", {"query": "SG", "limit": 2}
        )
        assert recovered.row_count
    finally:
        await container.aclose()


class FakeS3Client:
    def __init__(self, key: str) -> None:
        self.key = key
        self.deleted: list[str] = []

    def list_objects_v2(self, **kwargs: object) -> dict[str, object]:
        return {"Contents": [{"Key": self.key}]}

    def delete_object(self, **kwargs: object) -> None:
        self.deleted.append(str(kwargs["Key"]))


@pytest.mark.asyncio
async def test_s3_delete_uses_the_discovered_bound_object_key() -> None:
    artifact_id = uuid4()
    actual_key = f"prod/tenant/tenant-a/run/real-run-id/artifacts/{artifact_id}"
    client = FakeS3Client(actual_key)
    store = S3ArtifactStore(
        client=client,
        bucket="artifacts",
        kms_key_id=None,
        environment="prod",
    )

    await store.delete(artifact_id, "tenant-a")

    assert client.deleted == [actual_key]
