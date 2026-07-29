"""Role-aware production composition roots.

The API, Agent worker, and Commit worker deliberately build separate object
graphs.  In particular, only the Agent process constructs an OpenAI client and
only the Commit process constructs the business credential broker.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import boto3
import httpx
from botocore.config import Config as BotoConfig  # type: ignore[import-untyped]
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import Tracer
from prometheus_client import CollectorRegistry
from redis import asyncio as redis_async
from temporalio.client import Client
from temporalio.contrib.opentelemetry import TracingInterceptor

from agent_platform.agents.context_builder import ContextBuilder
from agent_platform.agents.deterministic_runtime import DeterministicAgentRuntime
from agent_platform.agents.factory import AgentFactory
from agent_platform.agents.model_reliability import (
    ModelReliabilityConfig,
    ModelReliabilityRegistry,
)
from agent_platform.agents.model_router import ModelPolicy
from agent_platform.agents.openai_runtime import (
    ModelPriceCatalog,
    OpenAIAgentRuntime,
    SdkRunner,
)
from agent_platform.agents.prompt_registry import PromptRegistry
from agent_platform.api.auth import JwtAuthenticator
from agent_platform.application.action_service import ActionService
from agent_platform.application.records import CapabilityRecord
from agent_platform.application.run_service import RunService
from agent_platform.application.trajectory_monitor import TrajectoryGuard
from agent_platform.config import AWS_MANAGER_BACKEND, Settings
from agent_platform.infrastructure.artifacts.factory import (
    build_malware_scanner,
    malware_scanner_health,
)
from agent_platform.infrastructure.artifacts.malware import MalwareScanner
from agent_platform.infrastructure.artifacts.sanitizer import ArtifactContentSanitizer
from agent_platform.infrastructure.artifacts.scanner import ArtifactScanner
from agent_platform.infrastructure.capacity_cost import (
    AuditCostReconciler,
    CapacityControlConfig,
    CapacityCostController,
    CostRateCatalog,
    RedisSharedReliability,
    SharedReliabilityConfig,
    TemporalQueueBacklogProbe,
)
from agent_platform.infrastructure.credential_broker import ReferencedCredentialBroker
from agent_platform.infrastructure.credentials import EphemeralCredentialBroker
from agent_platform.infrastructure.eval_fault_harness import HttpEvalFaultHarness
from agent_platform.infrastructure.observability.logging import configure_logging
from agent_platform.infrastructure.observability.metrics import PlatformMetrics
from agent_platform.infrastructure.observability.operational_metrics import (
    OperationalMetricsCollector,
)
from agent_platform.infrastructure.observability.runtime import RuntimeObservability
from agent_platform.infrastructure.observability.temporal_metrics import (
    record_temporal_queue_metrics,
)
from agent_platform.infrastructure.observability.tracing import configure_tracing
from agent_platform.infrastructure.persistence.capacity_repository import (
    PostgresCapacityCostRepository,
)
from agent_platform.infrastructure.persistence.postgres_memory_vault import (
    AesGcmMemoryContentCipher,
)
from agent_platform.infrastructure.persistence.production_store import (
    AesGcmActionPayloadCipher,
)
from agent_platform.infrastructure.production_resources import (
    ProductionSharedResources,
    build_agent_openai_client,
    build_agent_worker_resources,
    build_commit_worker_resources,
    build_production_shared_resources,
)
from agent_platform.infrastructure.quota import RedisQuotaLimiter
from agent_platform.infrastructure.secret_broker import (
    AwsSecretsManagerBroker,
    DirectorySecretBroker,
)
from agent_platform.tools.adapters.enterprise_gateway import (
    EnterpriseGatewayReliabilityConfig,
)
from agent_platform.tools.catalog import build_reference_registry
from agent_platform.tools.models import ToolDefinition
from agent_platform.tools.production_catalog import (
    ProductionToolCatalog,
    build_enterprise_registry,
    load_production_tool_catalog,
)
from agent_platform.workflows.activities import ActivityDependencies
from agent_platform.workflows.temporal_starter import TemporalWorkflowStarter


@dataclass(slots=True)
class ApiProcessResources:
    """API control plane with no model runtime or business credentials."""

    settings: Settings
    store: Any
    run_service: RunService
    action_service: ActionService
    artifact_scanner: ArtifactScanner
    artifact_malware_scanner: MalwareScanner
    artifact_sanitizer: ArtifactContentSanitizer
    authenticator: JwtAuthenticator
    metrics: PlatformMetrics
    observability: RuntimeObservability
    memory_vault: Any
    kill_switches: Any
    webhook_registry: Any
    recovery_workflow: TemporalWorkflowStarter
    foundation: ProductionProcessFoundation
    temporal_client: Client
    trace_provider: TracerProvider
    operational_metrics: OperationalMetricsCollector | None = None
    quota_limiter: RedisQuotaLimiter | None = None
    quota_client: Any | None = None
    tool_catalog: ProductionToolCatalog | None = None
    fault_injection_harness: HttpEvalFaultHarness | None = None

    @property
    def release_identity(self) -> dict[str, str]:
        if self.tool_catalog is None:
            return {}
        return {
            "tool_catalog_id": self.tool_catalog.catalog_id,
            "tool_catalog_digest": self.tool_catalog.digest,
        }

    async def healthcheck(self) -> dict[str, str]:
        dependency_health = await self.foundation.shared.health.check()
        statuses = dict(dependency_health.statuses)
        try:
            healthy = await self.temporal_client.service_client.check_health()
            statuses["temporal"] = "ok" if healthy else "error:unhealthy"
        except Exception as exc:
            statuses["temporal"] = f"error:{type(exc).__name__}"
        if hasattr(self.temporal_client, "workflow_service"):
            try:
                await record_temporal_queue_metrics(
                    self.temporal_client,
                    namespace=self.settings.temporal_namespace,
                    task_queues=(
                        self.settings.temporal_task_queue,
                        self.settings.temporal_commit_task_queue,
                    ),
                    observability=self.observability,
                )
                statuses["temporal_queue_telemetry"] = "ok"
            except Exception as exc:
                statuses["temporal_queue_telemetry"] = f"error:{type(exc).__name__}"
        if self.operational_metrics is not None:
            refreshed = await self.operational_metrics.collect()
            statuses["operational_metrics"] = "ok" if refreshed else "error:refresh_failed"
        statuses["artifact_malware_scanner"] = await malware_scanner_health(
            self.artifact_malware_scanner
        )
        if self.quota_client is not None:
            try:
                statuses["quota_redis"] = "ok" if await self.quota_client.ping() else "error"
            except Exception as exc:
                statuses["quota_redis"] = f"error:{type(exc).__name__}"
        self.observability.record_dependency_health(statuses)
        return statuses

    async def aclose(self) -> None:
        await self.artifact_malware_scanner.aclose()
        if self.fault_injection_harness is not None:
            await self.fault_injection_harness.aclose()
        if self.quota_client is not None:
            await _close_client(self.quota_client)
        await self.foundation.aclose()
        self.trace_provider.shutdown()


@dataclass(slots=True)
class ProductionProcessFoundation:
    """Owned shared infrastructure for exactly one OS process."""

    shared: ProductionSharedResources
    s3_client: Any
    secrets_client: Any | None = None

    async def aclose(self) -> None:
        await self.shared.aclose()
        await _close_client(self.s3_client)
        if self.secrets_client is not None:
            await _close_client(self.secrets_client)


@dataclass(slots=True)
class BootstrappedWorkerResources:
    """Concrete implementation of the worker resource protocol."""

    dependencies: ActivityDependencies
    metrics_registry: CollectorRegistry
    foundation: ProductionProcessFoundation
    temporal_client: Client
    trace_provider: TracerProvider
    openai_client: Any | None = None
    tool_gateway_client: httpx.AsyncClient | None = None
    tool_gateway_health_url: str | None = None
    control_client: Any | None = None

    async def healthcheck(self) -> dict[str, str]:
        dependency_health = await self.foundation.shared.health.check()
        statuses = dict(dependency_health.statuses)
        try:
            healthy = await self.temporal_client.service_client.check_health()
            statuses["temporal"] = "ok" if healthy else "error:unhealthy"
        except Exception as exc:
            statuses["temporal"] = f"error:{type(exc).__name__}"
        if self.tool_gateway_client is not None and self.tool_gateway_health_url:
            try:
                response = await self.tool_gateway_client.get(self.tool_gateway_health_url)
                statuses["tool_gateway"] = (
                    "ok"
                    if 200 <= response.status_code < 300
                    else f"error:http-{response.status_code}"
                )
            except Exception as exc:
                statuses["tool_gateway"] = f"error:{type(exc).__name__}"
        if self.control_client is not None:
            try:
                healthy = await self.control_client.ping()
                statuses["shared_control"] = "ok" if healthy else "error:unhealthy"
            except Exception as exc:
                statuses["shared_control"] = f"error:{type(exc).__name__}"
        if self.dependencies.observability is not None:
            self.dependencies.observability.record_dependency_health(statuses)
        return statuses

    async def aclose(self) -> None:
        if self.openai_client is not None:
            await _close_client(self.openai_client)
        if self.tool_gateway_client is not None:
            await self.tool_gateway_client.aclose()
        if self.control_client is not None:
            await _close_client(self.control_client)
        await self.foundation.aclose()
        self.trace_provider.shutdown()


async def build_api_process(
    settings: Settings,
    *,
    temporal_client: Client | None = None,
) -> ApiProcessResources:
    """Build the distributed API control plane without worker privileges."""

    if settings.process_role != "api":
        raise RuntimeError("API_PROCESS_ROLE_REQUIRED")
    configure_logging(
        json_logs=settings.environment != "dev",
        service_name=settings.service_name,
    )
    trace_provider = configure_tracing(
        service_name=settings.service_name,
        environment=settings.environment,
        endpoint=settings.otlp_endpoint,
        capture_content=settings.trace_content_capture,
        set_global=False,
    )
    metrics = PlatformMetrics()
    observability = RuntimeObservability(
        metrics,
        environment=settings.environment,
        tracer=trace_provider.get_tracer("agent_platform.runtime"),
    )
    foundation = await build_production_process_foundation(settings)
    management_sessions = getattr(
        foundation.shared,
        "management_session_factory",
        None,
    )
    operational_metrics = (
        OperationalMetricsCollector(
            management_sessions,
            metrics,
            environment=settings.environment,
        )
        if management_sessions is not None
        else None
    )
    malware_scanner: MalwareScanner | None = None
    quota_client: Any | None = None
    try:
        malware_scanner = build_malware_scanner(settings)
        quota_client, quota_limiter = _build_quota_limiter(settings)
        tool_catalog = _load_production_catalog(settings)
        client = temporal_client or await _connect_temporal(
            settings,
            tracer=trace_provider.get_tracer("agent_platform.temporal"),
        )
        workflow = _temporal_workflow(settings, client, foundation.shared)
        capacity_cost = _build_capacity_cost_controller(
            settings,
            foundation.shared,
            temporal_client=client,
            reconciler=None,
        )
        run_service = RunService(
            foundation.shared.store.runs,
            foundation.shared.store.actions,
            workflow,
            capabilities=foundation.shared.store.capabilities,
            kill_switches=foundation.shared.kill_switches,
            observability=observability,
            capacity_cost=capacity_cost,
        )
        action_service = ActionService(
            foundation.shared.store.actions,
            workflow,
            observability=observability,
        )
        definitions = (
            tool_catalog.definitions
            if tool_catalog is not None
            else build_reference_registry().definitions()
        )
        await _register_capabilities(foundation.shared.store, definitions)
        fault_injection_harness = (
            HttpEvalFaultHarness(
                controller_url=settings.eval_fault_harness_url,
                token=settings.eval_fault_harness_token.get_secret_value(),
            )
            if settings.environment == "staging" and settings.eval_fault_harness_url
            else None
        )
        return ApiProcessResources(
            settings=settings,
            store=foundation.shared.store,
            run_service=run_service,
            action_service=action_service,
            artifact_scanner=ArtifactScanner(
                max_upload_bytes=settings.artifact_max_upload_bytes,
            ),
            artifact_malware_scanner=malware_scanner,
            artifact_sanitizer=ArtifactContentSanitizer(),
            authenticator=JwtAuthenticator(settings),
            metrics=metrics,
            observability=observability,
            memory_vault=foundation.shared.memory_vault,
            kill_switches=foundation.shared.kill_switches,
            webhook_registry=foundation.shared.webhook_registry,
            recovery_workflow=workflow,
            foundation=foundation,
            temporal_client=client,
            trace_provider=trace_provider,
            operational_metrics=operational_metrics,
            quota_limiter=quota_limiter,
            quota_client=quota_client,
            tool_catalog=tool_catalog,
            fault_injection_harness=fault_injection_harness,
        )
    except Exception:
        if malware_scanner is not None:
            await malware_scanner.aclose()
        if quota_client is not None:
            await _close_client(quota_client)
        await foundation.aclose()
        trace_provider.shutdown()
        raise


async def build_production_process_foundation(
    settings: Settings,
) -> ProductionProcessFoundation:
    """Build PostgreSQL, S3, OPA, and governance adapters for one process."""

    s3_client = _build_s3_client(settings)
    secrets_client: Any | None = None
    if settings.secret_backend == AWS_MANAGER_BACKEND:
        secrets_client = boto3.client(
            "secretsmanager",
            region_name=settings.artifact_region or "us-east-1",
        )
        secret_broker: Any = AwsSecretsManagerBroker(
            secrets_client,
            prefix=settings.secrets_manager_prefix,
        )
    else:
        configured_root = settings.webhook_secret_dir.strip()
        secret_root = (
            Path(configured_root)
            if configured_root
            else Path(tempfile.gettempdir()) / "agent-platform-secrets" / settings.process_role
        )
        secret_broker = DirectorySecretBroker(secret_root)

    try:
        shared = await build_production_shared_resources(
            settings,
            s3_client=s3_client,
            action_payload_cipher=AesGcmActionPayloadCipher(
                _encryption_key(
                    settings,
                    settings.action_payload_encryption_key.get_secret_value(),
                    "action-payload",
                )
            ),
            memory_cipher=AesGcmMemoryContentCipher(
                _encryption_key(
                    settings,
                    settings.memory_encryption_key.get_secret_value(),
                    "memory-content",
                )
            ),
            secret_broker=secret_broker,
            management_database_dsn=_management_dsn(settings),
        )
    except Exception:
        await _close_client(s3_client)
        if secrets_client is not None:
            await _close_client(secrets_client)
        raise
    return ProductionProcessFoundation(
        shared=shared,
        s3_client=s3_client,
        secrets_client=secrets_client,
    )


async def build_agent_worker_process(
    settings: Settings,
    temporal_client: Client,
    *,
    configured_trace_provider: TracerProvider | None = None,
) -> BootstrappedWorkerResources:
    """Build the bounded Agent plane without business commit credentials."""

    if settings.process_role != "agent-worker":
        raise RuntimeError("AGENT_WORKER_ROLE_REQUIRED")
    configure_logging(
        json_logs=settings.environment != "dev",
        service_name=f"{settings.service_name}-agent-worker",
    )
    trace_provider = configured_trace_provider or configure_tracing(
        service_name=f"{settings.service_name}-agent-worker",
        environment=settings.environment,
        endpoint=settings.otlp_endpoint,
        capture_content=settings.trace_content_capture,
        set_global=False,
    )
    metrics = PlatformMetrics()
    observability = RuntimeObservability(
        metrics,
        environment=settings.environment,
        tracer=trace_provider.get_tracer("agent_platform.runtime"),
    )
    foundation = await build_production_process_foundation(settings)
    openai_client: Any | None = None
    tool_gateway_client: httpx.AsyncClient | None = None
    control_client: Any | None = None
    try:
        control_client, _ = _build_quota_limiter(settings)
        model_shared_control = _build_shared_reliability(
            settings,
            control_client,
            resource="model",
        )
        tool_shared_control = _build_shared_reliability(
            settings,
            control_client,
            resource="tool",
        )
        cost_reconciler = _build_cost_reconciler(
            settings,
            getattr(foundation.shared.store, "audit", None),
        )
        capacity_cost = _build_capacity_cost_controller(
            settings,
            foundation.shared,
            temporal_client=temporal_client,
            reconciler=cost_reconciler,
        )
        workflow = _temporal_workflow(settings, temporal_client, foundation.shared)
        trajectory_guard = TrajectoryGuard(
            foundation.shared.store.runs,
            kill_switches=foundation.shared.kill_switches,
            observability=observability,
        )
        registry, tool_gateway_client, _ = await _build_runtime_tool_registry(
            settings,
            shared_control=tool_shared_control,
        )
        agent_credentials = (
            ReferencedCredentialBroker(settings.agent_credential_ref)
            if settings.agent_credential_ref.strip()
            else EphemeralCredentialBroker()
        )
        if settings.openai_api_key.get_secret_value():
            openai_client = build_agent_openai_client(settings)
            runtime: Any = OpenAIAgentRuntime(
                factory=AgentFactory(
                    model_policy=ModelPolicy(settings.model_allowlist),
                    prompts=PromptRegistry(Path(settings.prompt_registry_path)),
                ),
                runner=SdkRunner(
                    client=openai_client,
                    store_model_content=settings.store_model_content,
                ),
                context_builder=ContextBuilder(),
                memory_vault=foundation.shared.memory_vault,
                known_capabilities=_known_capabilities(registry.definitions()),
                pricing=ModelPriceCatalog.from_path(
                    settings.model_pricing_catalog_path,
                    allowed_models=settings.model_allowlist,
                ),
                trajectory_guard=trajectory_guard,
                observability=observability,
                model_project_id=settings.openai_project or "development",
                model_reliability=ModelReliabilityRegistry(
                    ModelReliabilityConfig(
                        max_in_flight=settings.model_max_in_flight,
                        max_queued=settings.model_max_queued,
                        queue_timeout_seconds=settings.model_queue_timeout_seconds,
                        circuit_failure_threshold=(settings.model_circuit_failure_threshold),
                        circuit_recovery_timeout_seconds=(settings.model_circuit_recovery_seconds),
                    ),
                    max_keys=len(settings.model_allowlist),
                    shared_control=model_shared_control,
                ),
            )
        elif settings.environment in {"dev", "test"}:
            runtime = DeterministicAgentRuntime()
        else:
            raise RuntimeError("OPENAI_API_KEY_REQUIRED")

        resources = build_agent_worker_resources(
            foundation.shared,
            runtime=runtime,
            agent_tool_registry=registry,
            agent_credential_broker=agent_credentials,
            workflow_control=workflow,
            capacity_cost=capacity_cost,
            trajectory_guard=trajectory_guard,
            observability=observability,
        )
        return BootstrappedWorkerResources(
            dependencies=ActivityDependencies(
                store=resources.store,
                runtime=resources.runtime,
                gateway=resources.gateway,
                run_service=resources.run_service,
                commit_service=None,
                trajectory_guard=trajectory_guard,
                observability=observability,
            ),
            metrics_registry=metrics.registry,
            foundation=foundation,
            temporal_client=temporal_client,
            trace_provider=trace_provider,
            openai_client=openai_client,
            tool_gateway_client=tool_gateway_client,
            tool_gateway_health_url=settings.tool_gateway_health_url,
            control_client=control_client,
        )
    except Exception:
        if openai_client is not None:
            await _close_client(openai_client)
        if tool_gateway_client is not None:
            await tool_gateway_client.aclose()
        if control_client is not None:
            await _close_client(control_client)
        await foundation.aclose()
        trace_provider.shutdown()
        raise


async def build_commit_worker_process(
    settings: Settings,
    temporal_client: Client,
    *,
    configured_trace_provider: TracerProvider | None = None,
) -> BootstrappedWorkerResources:
    """Build the isolated transaction plane without model/runtime access."""

    if settings.process_role != "commit-worker":
        raise RuntimeError("COMMIT_WORKER_ROLE_REQUIRED")
    configure_logging(
        json_logs=settings.environment != "dev",
        service_name=f"{settings.service_name}-commit-worker",
    )
    trace_provider = configured_trace_provider or configure_tracing(
        service_name=f"{settings.service_name}-commit-worker",
        environment=settings.environment,
        endpoint=settings.otlp_endpoint,
        capture_content=settings.trace_content_capture,
        set_global=False,
    )
    metrics = PlatformMetrics()
    observability = RuntimeObservability(
        metrics,
        environment=settings.environment,
        tracer=trace_provider.get_tracer("agent_platform.runtime"),
    )
    foundation = await build_production_process_foundation(settings)
    tool_gateway_client: httpx.AsyncClient | None = None
    control_client: Any | None = None
    try:
        control_client, _ = _build_quota_limiter(settings)
        tool_shared_control = _build_shared_reliability(
            settings,
            control_client,
            resource="tool",
        )
        workflow = _temporal_workflow(settings, temporal_client, foundation.shared)

        registry, tool_gateway_client, _ = await _build_runtime_tool_registry(
            settings,
            shared_control=tool_shared_control,
        )
        business_credentials = (
            ReferencedCredentialBroker(settings.business_credential_ref)
            if settings.business_credential_ref.strip()
            else EphemeralCredentialBroker()
        )
        resources = build_commit_worker_resources(
            foundation.shared,
            commit_tool_registry=registry,
            business_credential_broker=business_credentials,
            observability=observability,
        )
        run_service = RunService(
            resources.store.runs,
            resources.store.actions,
            workflow,
            capabilities=resources.store.capabilities,
            kill_switches=resources.kill_switches,
            observability=observability,
        )
        return BootstrappedWorkerResources(
            dependencies=ActivityDependencies(
                store=resources.store,
                runtime=None,
                gateway=None,
                run_service=run_service,
                commit_service=resources.commit_service,
                commit_scopes=_commit_scopes(registry.definitions()),
                trajectory_guard=resources.trajectory_guard,
                observability=observability,
            ),
            metrics_registry=metrics.registry,
            foundation=foundation,
            temporal_client=temporal_client,
            trace_provider=trace_provider,
            tool_gateway_client=tool_gateway_client,
            tool_gateway_health_url=settings.tool_gateway_health_url,
            control_client=control_client,
        )
    except Exception:
        if tool_gateway_client is not None:
            await tool_gateway_client.aclose()
        if control_client is not None:
            await _close_client(control_client)
        await foundation.aclose()
        trace_provider.shutdown()
        raise


def _load_production_catalog(settings: Settings) -> ProductionToolCatalog | None:
    if not settings.tool_catalog_path.strip():
        if settings.environment in {"dev", "test"}:
            return None
        raise RuntimeError("TOOL_CATALOG_PATH_REQUIRED")
    return load_production_tool_catalog(
        settings.tool_catalog_path,
        expected_sha256=settings.tool_catalog_sha256,
    )


async def _build_runtime_tool_registry(
    settings: Settings,
    *,
    shared_control: RedisSharedReliability | None = None,
) -> tuple[Any, httpx.AsyncClient | None, ProductionToolCatalog | None]:
    catalog = _load_production_catalog(settings)
    if catalog is None:
        return build_reference_registry(), None, None
    gateway_url = settings.tool_gateway_url
    proxy_url = settings.tool_gateway_egress_proxy_url
    if not gateway_url or not proxy_url:
        raise RuntimeError("TOOL_GATEWAY_CONFIGURATION_REQUIRED")
    client = httpx.AsyncClient(
        proxy=proxy_url,
        trust_env=False,
        follow_redirects=False,
        timeout=httpx.Timeout(settings.tool_gateway_timeout_seconds),
        limits=httpx.Limits(
            max_connections=settings.tool_gateway_max_in_flight,
            max_keepalive_connections=settings.tool_gateway_max_in_flight,
        ),
    )
    try:
        registry = build_enterprise_registry(
            catalog,
            client=client,
            gateway_url=gateway_url,
            reliability=EnterpriseGatewayReliabilityConfig(
                max_in_flight=settings.tool_gateway_max_in_flight,
                max_queued=settings.tool_gateway_max_queued,
                queue_timeout_seconds=settings.tool_gateway_queue_timeout_seconds,
                circuit_failure_threshold=settings.tool_gateway_circuit_failure_threshold,
                circuit_recovery_timeout_seconds=(settings.tool_gateway_circuit_recovery_seconds),
            ),
            shared_control=shared_control,
        )
    except Exception:
        await client.aclose()
        raise
    return registry, client, catalog


def _capacity_control_config(settings: Settings) -> CapacityControlConfig:
    return CapacityControlConfig(
        tenant_max_active_runs=settings.tenant_max_active_runs,
        queue_backlog_soft_limit=settings.queue_backlog_soft_limit,
        queue_oldest_age_soft_limit_seconds=(settings.queue_oldest_age_soft_limit_seconds),
        critical_queue_multiplier=settings.critical_queue_multiplier,
        reservation_grace_seconds=settings.capacity_reservation_grace_seconds,
        tenant_daily_budget_usd=settings.tenant_daily_budget_usd,
        tenant_monthly_budget_usd=settings.tenant_monthly_budget_usd,
    )


def _build_capacity_cost_controller(
    settings: Settings,
    shared: ProductionSharedResources,
    *,
    temporal_client: Client,
    reconciler: AuditCostReconciler | None,
) -> CapacityCostController | None:
    if settings.environment in {"dev", "test"}:
        return None
    config = _capacity_control_config(settings)
    repository = PostgresCapacityCostRepository(
        shared.session_factory,
        config=config,
    )
    return CapacityCostController(
        repository,
        queue_probe=TemporalQueueBacklogProbe(
            temporal_client,
            namespace=settings.temporal_namespace,
            task_queue=settings.temporal_task_queue,
        ),
        key_hmac_secret=_encryption_key(
            settings,
            settings.quota_key_hmac_secret.get_secret_value(),
            "quota-key-hmac",
        ),
        config=config,
        reconciler=reconciler,
    )


def _build_cost_reconciler(
    settings: Settings,
    audit: Any,
) -> AuditCostReconciler | None:
    configured_path = settings.cost_rate_catalog_path.strip()
    if not configured_path:
        if settings.environment in {"dev", "test"}:
            return None
        raise RuntimeError("COST_RATE_CATALOG_PATH_REQUIRED")
    catalog = CostRateCatalog.from_path(
        configured_path,
        expected_sha256=settings.cost_rate_catalog_sha256,
    )
    return AuditCostReconciler(audit, catalog)


def _build_shared_reliability(
    settings: Settings,
    client: Any | None,
    *,
    resource: str,
) -> RedisSharedReliability | None:
    if client is None:
        return None
    if resource == "model":
        config = SharedReliabilityConfig(
            max_in_flight=settings.model_max_in_flight,
            max_queued=settings.model_max_queued,
            queue_timeout_seconds=settings.model_queue_timeout_seconds,
            circuit_failure_threshold=settings.model_circuit_failure_threshold,
            circuit_recovery_seconds=settings.model_circuit_recovery_seconds,
        )
    elif resource == "tool":
        config = SharedReliabilityConfig(
            max_in_flight=settings.tool_gateway_max_in_flight,
            max_queued=settings.tool_gateway_max_queued,
            queue_timeout_seconds=settings.tool_gateway_queue_timeout_seconds,
            circuit_failure_threshold=settings.tool_gateway_circuit_failure_threshold,
            circuit_recovery_seconds=settings.tool_gateway_circuit_recovery_seconds,
        )
    else:
        raise ValueError("SHARED_RELIABILITY_RESOURCE_INVALID")
    return RedisSharedReliability(
        client,
        key_hmac_secret=_encryption_key(
            settings,
            settings.quota_key_hmac_secret.get_secret_value(),
            "quota-key-hmac",
        ),
        config=config,
        namespace=f"agent-platform:{resource}-reliability:v1",
    )


def _build_quota_limiter(
    settings: Settings,
) -> tuple[Any | None, RedisQuotaLimiter | None]:
    if settings.quota_backend != "redis":
        return None, None
    # redis-py currently exposes from_url without complete typing metadata.
    redis_from_url: Any = redis_async.from_url
    client = redis_from_url(
        settings.quota_redis_url.get_secret_value(),
        decode_responses=False,
        socket_connect_timeout=3,
        socket_timeout=3,
        health_check_interval=30,
    )
    limiter = RedisQuotaLimiter(
        client,
        key_hmac_secret=_encryption_key(
            settings,
            settings.quota_key_hmac_secret.get_secret_value(),
            "quota-key-hmac",
        ),
    )
    return client, limiter


async def _connect_temporal(
    settings: Settings,
    *,
    tracer: Tracer,
) -> Client:
    return await Client.connect(
        settings.temporal_address,
        namespace=settings.temporal_namespace,
        api_key=settings.temporal_api_key.get_secret_value() or None,
        tls=settings.temporal_tls,
        interceptors=(TracingInterceptor(tracer),),
    )


async def _register_capabilities(
    store: Any,
    definitions: tuple[object, ...],
) -> None:
    register = getattr(store.capabilities, "register", None)
    if not callable(register):
        return
    for candidate in definitions:
        if not isinstance(candidate, ToolDefinition):
            raise TypeError("TOOL_REGISTRY_DEFINITION_INVALID")
        await register(
            "*",
            CapabilityRecord(
                name=candidate.capability_name,
                version=candidate.version,
                effect=candidate.effect.value,
                risk=candidate.risk.value,
            ),
        )
    await register(
        "*",
        CapabilityRecord(
            name="artifact.create",
            version="1.0.0",
            effect="prepare",
            risk="medium",
        ),
    )


def _temporal_workflow(
    settings: Settings,
    client: Client,
    shared: ProductionSharedResources,
) -> TemporalWorkflowStarter:
    async def resolve_action_workflow(action_id: Any, tenant_id: str) -> str:
        action = await shared.store.actions.get(action_id, tenant_id)
        run = await shared.store.runs.get(action.run_id, tenant_id)
        return str(run.workflow_id)

    return TemporalWorkflowStarter(
        client=client,
        task_queue=settings.temporal_task_queue,
        commit_task_queue=settings.temporal_commit_task_queue,
        action_workflow_resolver=resolve_action_workflow,
        default_run_timeout_seconds=settings.default_run_timeout_seconds,
    )


def _build_s3_client(settings: Settings) -> Any:
    options: dict[str, Any] = {
        "region_name": settings.artifact_region or "us-east-1",
    }
    if settings.artifact_endpoint_url:
        options["endpoint_url"] = settings.artifact_endpoint_url
        options["config"] = BotoConfig(s3={"addressing_style": "path"})
    return boto3.client("s3", **options)


def _management_dsn(settings: Settings) -> str | None:
    if settings.process_role != "api":
        return None
    value = settings.management_database_dsn.get_secret_value().strip()
    return value or None


def _encryption_key(settings: Settings, encoded: str, purpose: str) -> bytes:
    if encoded:
        key = base64.b64decode(encoded, validate=True)
        if len(key) != 32:
            raise ValueError(f"{purpose.upper().replace('-', '_')}_KEY_INVALID")
        return key
    if settings.environment not in {"dev", "test"}:
        raise RuntimeError(f"{purpose.upper().replace('-', '_')}_KEY_REQUIRED")
    # Development-only deterministic keys make local restarts readable while
    # production validation requires injected random 256-bit keys.
    return hashlib.sha256(f"agent-platform-local:{purpose}".encode()).digest()


def _known_capabilities(definitions: tuple[object, ...]) -> frozenset[str]:
    return frozenset(
        definition.capability_name
        for definition in definitions
        if isinstance(definition, ToolDefinition)
    ) | frozenset({"artifact.create"})


def _commit_scopes(definitions: tuple[object, ...]) -> frozenset[str]:
    return frozenset(
        scope
        for definition in definitions
        if isinstance(definition, ToolDefinition)
        for scope in definition.commit_scopes
    )


async def _close_client(client: Any) -> None:
    close = getattr(client, "aclose", None) or getattr(client, "close", None)
    if not callable(close):
        return
    result = close()
    if inspect.isawaitable(result):
        await result
