from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import httpx
import pytest
from pydantic import SecretStr

from agent_platform.config import Settings
from agent_platform.infrastructure.persistence.postgres_kill_switch import (
    PostgresKillSwitchRegistry,
)
from agent_platform.infrastructure.persistence.postgres_memory_vault import (
    MemoryContentCipher,
    PostgresMemoryVault,
)
from agent_platform.infrastructure.persistence.postgres_webhook_registry import (
    PostgresWebhookEndpointRegistry,
    SecretBroker,
)
from agent_platform.infrastructure.persistence.production_store import (
    ActionPayloadCipher,
    PostgresPlatformStore,
)
from agent_platform.infrastructure.persistence.session import AsyncSessionFactory
from agent_platform.infrastructure.policy.port_adapter import OpaPolicyPortAdapter
from agent_platform.infrastructure.production_resources import (
    ProductionSharedResources,
    build_agent_openai_client,
    build_agent_worker_resources,
    build_commit_worker_resources,
    build_production_shared_resources,
)
from agent_platform.tools.registry import ToolRegistry


def _settings() -> Settings:
    return Settings(
        environment="test",
        database_dsn=SecretStr(
            "postgresql+asyncpg://agent_api:local-only@localhost:5432/agent_platform"
        ),
        persistence_backend="postgres",
        artifact_backend="s3",
        policy_backend="opa",
        artifact_bucket="agent-platform-test",
        opa_url="http://opa.test:8181",
    )


@pytest.mark.asyncio
async def test_shared_builder_closes_only_the_opa_client_it_owns() -> None:
    shared = await build_production_shared_resources(
        _settings(),
        s3_client=object(),
        action_payload_cipher=cast(ActionPayloadCipher, object()),
        memory_cipher=cast(MemoryContentCipher, object()),
        secret_broker=cast(SecretBroker, object()),
    )
    owned_client = shared.owned_opa_http_client
    assert owned_client is not None
    assert shared.policy._engine._fail_closed is True

    await shared.aclose()

    assert owned_client.is_closed

    injected_client = httpx.AsyncClient(base_url="http://opa.test:8181")
    injected = await build_production_shared_resources(
        _settings(),
        s3_client=object(),
        action_payload_cipher=cast(ActionPayloadCipher, object()),
        memory_cipher=cast(MemoryContentCipher, object()),
        secret_broker=cast(SecretBroker, object()),
        opa_http_client=injected_client,
    )
    assert injected.owned_opa_http_client is None

    await injected.aclose()

    assert not injected_client.is_closed
    await injected_client.aclose()


@pytest.mark.asyncio
async def test_agent_model_client_is_role_guarded_and_uses_gateway() -> None:
    with pytest.raises(RuntimeError, match="AGENT_WORKER_ROLE_REQUIRED"):
        build_agent_openai_client(_settings())

    settings = _settings().model_copy(
        update={
            "process_role": "agent-worker",
            "openai_api_key": SecretStr("agent-worker-test-key"),
            "openai_base_url": "http://model-gateway.agent-platform.svc:8080/v1",
        }
    )
    client = build_agent_openai_client(settings)
    try:
        assert str(client.base_url) == "http://model-gateway.agent-platform.svc:8080/v1/"
    finally:
        await client.close()


def _shared_resources() -> ProductionSharedResources:
    sentinel = cast(Any, object())
    store = cast(
        PostgresPlatformStore,
        SimpleNamespace(
            runs=sentinel,
            actions=sentinel,
            artifacts=sentinel,
            capabilities=sentinel,
        ),
    )
    return ProductionSharedResources(
        session_factory=cast(AsyncSessionFactory, sentinel),
        management_session_factory=None,
        store=store,
        policy=cast(OpaPolicyPortAdapter, sentinel),
        memory_vault=cast(PostgresMemoryVault, sentinel),
        webhook_registry=cast(PostgresWebhookEndpointRegistry, sentinel),
        kill_switches=cast(PostgresKillSwitchRegistry, sentinel),
        health=sentinel,
    )


def test_agent_and_commit_builders_keep_privileged_dependencies_separate() -> None:
    shared = _shared_resources()
    runtime = object()
    agent_credentials = object()
    business_credentials = object()

    agent = build_agent_worker_resources(
        shared,
        runtime=runtime,
        agent_tool_registry=ToolRegistry(),
        agent_credential_broker=agent_credentials,
        workflow_control=object(),
    )
    commit = build_commit_worker_resources(
        shared,
        commit_tool_registry=ToolRegistry(),
        business_credential_broker=business_credentials,
    )

    assert agent.runtime is runtime
    assert agent.gateway._credentials is agent_credentials
    assert not hasattr(agent, "commit_service")
    assert not hasattr(agent, "business_credential_broker")

    assert commit.commit_service._credentials is business_credentials
    assert not hasattr(commit, "runtime")
    assert not hasattr(commit, "gateway")
    assert not hasattr(commit, "agent_credential_broker")
