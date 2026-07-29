"""Production resource builders with explicit Agent/Commit privilege separation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpx

from agent_platform.application.commit_service import CommitService
from agent_platform.application.run_service import RunService
from agent_platform.application.trajectory_monitor import TrajectoryGuard
from agent_platform.config import Settings
from agent_platform.infrastructure.artifacts.addressable_s3_store import (
    AddressableS3ArtifactStore,
)
from agent_platform.infrastructure.dependency_health import (
    DependencyHealthChecker,
    database_probe,
    opa_probe,
    s3_probe,
)
from agent_platform.infrastructure.observability.runtime import RuntimeObservability
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
from agent_platform.infrastructure.persistence.session import (
    AsyncSessionFactory,
    create_session_factory,
    dispose_session_factory,
)
from agent_platform.infrastructure.policy.engine import OpaPolicyEngine
from agent_platform.infrastructure.policy.port_adapter import OpaPolicyPortAdapter
from agent_platform.tools.gateway import ToolGateway
from agent_platform.tools.registry import ToolRegistry

if TYPE_CHECKING:
    from openai import AsyncOpenAI


@dataclass(slots=True)
class ProductionSharedResources:
    """Owned resources shared within one process, never across process roles."""

    session_factory: AsyncSessionFactory
    management_session_factory: AsyncSessionFactory | None
    store: PostgresPlatformStore
    policy: OpaPolicyPortAdapter
    memory_vault: PostgresMemoryVault
    webhook_registry: PostgresWebhookEndpointRegistry
    kill_switches: PostgresKillSwitchRegistry
    health: DependencyHealthChecker
    owned_opa_http_client: httpx.AsyncClient | None = None

    async def aclose(self) -> None:
        await self.policy.aclose()
        if self.owned_opa_http_client is not None:
            await self.owned_opa_http_client.aclose()
        await dispose_session_factory(self.session_factory)
        if (
            self.management_session_factory is not None
            and self.management_session_factory is not self.session_factory
        ):
            await dispose_session_factory(self.management_session_factory)


@dataclass(frozen=True, slots=True)
class AgentWorkerResources:
    """Agent-plane dependencies: model runtime plus read/prepare credentials."""

    store: PostgresPlatformStore
    runtime: Any
    gateway: ToolGateway
    run_service: RunService
    policy: OpaPolicyPortAdapter
    kill_switches: PostgresKillSwitchRegistry
    trajectory_guard: TrajectoryGuard


@dataclass(frozen=True, slots=True)
class CommitWorkerResources:
    """Commit-plane dependencies; intentionally has no runtime or gateway."""

    store: PostgresPlatformStore
    commit_service: CommitService
    policy: OpaPolicyPortAdapter
    kill_switches: PostgresKillSwitchRegistry
    trajectory_guard: TrajectoryGuard


async def build_production_shared_resources(
    settings: Settings,
    *,
    s3_client: Any,
    action_payload_cipher: ActionPayloadCipher,
    memory_cipher: MemoryContentCipher,
    secret_broker: SecretBroker,
    management_database_dsn: str | None = None,
    opa_http_client: httpx.AsyncClient | None = None,
) -> ProductionSharedResources:
    """Build resources common to API/Agent/Commit processes without OpenAI."""
    if settings.persistence_backend != "postgres":
        raise RuntimeError("PRODUCTION_POSTGRES_BACKEND_REQUIRED")
    if settings.artifact_backend != "s3":
        raise RuntimeError("PRODUCTION_S3_BACKEND_REQUIRED")
    if settings.policy_backend != "opa":
        raise RuntimeError("PRODUCTION_OPA_BACKEND_REQUIRED")

    factory = create_session_factory(settings.database_dsn.get_secret_value())
    management_factory = (
        create_session_factory(management_database_dsn)
        if management_database_dsn is not None
        else None
    )
    content_store = AddressableS3ArtifactStore(
        client=s3_client,
        bucket=settings.artifact_bucket,
        staging_bucket=settings.artifact_staging_bucket,
        kms_key_id=settings.artifact_kms_key,
        environment=settings.environment,
        allow_unencrypted_local=settings.artifact_allow_unencrypted_local,
    )
    store = PostgresPlatformStore(
        factory,
        action_payload_cipher=action_payload_cipher,
        artifact_content_store=content_store,
    )
    owned_opa_http_client = (
        httpx.AsyncClient(
            base_url=settings.opa_url.rstrip("/"),
            timeout=httpx.Timeout(2.0),
        )
        if opa_http_client is None
        else None
    )
    policy_http_client = opa_http_client or owned_opa_http_client
    if policy_http_client is None:  # Defensive: narrows the optional type.
        raise RuntimeError("OPA_HTTP_CLIENT_REQUIRED")
    opa_engine = OpaPolicyEngine(
        base_url=settings.opa_url,
        client=policy_http_client,
        fail_closed=settings.policy_fail_closed,
    )
    policy = OpaPolicyPortAdapter(opa_engine)
    memory_vault = PostgresMemoryVault(factory, cipher=memory_cipher)
    webhook_registry = PostgresWebhookEndpointRegistry(
        factory,
        secret_broker=secret_broker,
    )
    kill_switches = PostgresKillSwitchRegistry(
        factory,
        environment=settings.environment,
        management_factory=management_factory,
    )
    health_probes = {
        "database": database_probe(factory),
        "opa": opa_probe(policy_http_client),
        "s3": s3_probe(
            s3_client,
            settings.artifact_bucket,
            require_governance=settings.environment in {"staging", "prod"},
            expected_kms_key=settings.artifact_kms_key,
        ),
    }
    if settings.environment in {"staging", "prod"}:
        staging_bucket = (settings.artifact_staging_bucket or "").strip()
        if not staging_bucket:
            raise RuntimeError("ARTIFACT_STAGING_BUCKET_REQUIRED")
        health_probes["s3-staging"] = s3_probe(
            s3_client,
            staging_bucket,
            require_staging_controls=True,
            expected_kms_key=settings.artifact_kms_key,
        )
    health = DependencyHealthChecker(health_probes)
    return ProductionSharedResources(
        session_factory=factory,
        management_session_factory=management_factory,
        store=store,
        policy=policy,
        memory_vault=memory_vault,
        webhook_registry=webhook_registry,
        kill_switches=kill_switches,
        health=health,
        owned_opa_http_client=owned_opa_http_client,
    )


def build_agent_openai_client(settings: Settings) -> AsyncOpenAI:
    """Create the model client only inside the Agent worker process."""
    if settings.process_role != "agent-worker":
        raise RuntimeError("AGENT_WORKER_ROLE_REQUIRED")
    api_key = settings.openai_api_key.get_secret_value()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY_REQUIRED")
    if settings.environment == "prod" and not settings.openai_base_url:
        raise RuntimeError("MODEL_GATEWAY_URL_REQUIRED")

    # Keep the import role-local so Commit/API control-plane processes neither
    # import nor initialize the OpenAI client.
    from openai import AsyncOpenAI

    return AsyncOpenAI(
        api_key=api_key,
        base_url=settings.openai_base_url,
        project=settings.openai_project,
    )


def build_agent_worker_resources(
    shared: ProductionSharedResources,
    *,
    runtime: Any,
    agent_tool_registry: ToolRegistry,
    agent_credential_broker: Any,
    workflow_control: Any,
    capacity_cost: Any | None = None,
    trajectory_guard: TrajectoryGuard | None = None,
    observability: RuntimeObservability | None = None,
) -> AgentWorkerResources:
    """Build the Agent plane without business commit credentials."""
    guard = trajectory_guard or TrajectoryGuard(
        shared.store.runs,
        kill_switches=shared.kill_switches,
        observability=observability,
    )
    gateway = ToolGateway(
        agent_tool_registry,
        shared.policy,
        agent_credential_broker,
        shared.store.actions,
        shared.store.artifacts,
        capabilities=shared.store.capabilities,
        kill_switches=shared.kill_switches,
        audit=getattr(shared.store, "audit", None),
        trajectory_guard=guard,
        observability=observability,
    )
    run_service = RunService(
        shared.store.runs,
        shared.store.actions,
        workflow_control,
        capabilities=shared.store.capabilities,
        kill_switches=shared.kill_switches,
        observability=observability,
        capacity_cost=capacity_cost,
    )
    return AgentWorkerResources(
        store=shared.store,
        runtime=runtime,
        gateway=gateway,
        run_service=run_service,
        policy=shared.policy,
        kill_switches=shared.kill_switches,
        trajectory_guard=guard,
    )


def build_commit_worker_resources(
    shared: ProductionSharedResources,
    *,
    commit_tool_registry: ToolRegistry,
    business_credential_broker: Any,
    observability: RuntimeObservability | None = None,
) -> CommitWorkerResources:
    """Build the Commit plane without OpenAI, model runtime, or Agent gateway."""
    guard = TrajectoryGuard(
        shared.store.runs,
        kill_switches=shared.kill_switches,
        observability=observability,
    )
    commit_service = CommitService(
        shared.store.actions,
        shared.store.runs,
        commit_tool_registry,
        shared.policy,
        business_credential_broker,
        trajectory_guard=guard,
        kill_switches=shared.kill_switches,
        observability=observability,
    )
    return CommitWorkerResources(
        store=shared.store,
        commit_service=commit_service,
        policy=shared.policy,
        trajectory_guard=guard,
        kill_switches=shared.kill_switches,
    )
