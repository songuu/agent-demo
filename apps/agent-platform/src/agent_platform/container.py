from __future__ import annotations

import asyncio
import hashlib
import inspect
from dataclasses import dataclass
from typing import Any

from agent_platform.agents.deterministic_runtime import DeterministicAgentRuntime
from agent_platform.api.auth import JwtAuthenticator
from agent_platform.application.action_service import ActionService
from agent_platform.application.commit_service import CommitService
from agent_platform.application.records import CapabilityRecord
from agent_platform.application.run_service import RunService
from agent_platform.application.trajectory_monitor import TrajectoryGuard
from agent_platform.config import Settings
from agent_platform.infrastructure.artifacts.factory import (
    build_malware_scanner,
    malware_scanner_health,
)
from agent_platform.infrastructure.artifacts.malware import MalwareScanner
from agent_platform.infrastructure.artifacts.sanitizer import ArtifactContentSanitizer
from agent_platform.infrastructure.artifacts.scanner import ArtifactScanner
from agent_platform.infrastructure.credentials import EphemeralCredentialBroker
from agent_platform.infrastructure.kill_switch import KillSwitchRegistry
from agent_platform.infrastructure.memory_store import InMemoryPlatformStore
from agent_platform.infrastructure.memory_vault import MemoryVault
from agent_platform.infrastructure.observability.metrics import PlatformMetrics
from agent_platform.infrastructure.observability.runtime import RuntimeObservability
from agent_platform.infrastructure.webhook_registry import WebhookEndpointRegistry
from agent_platform.tools.catalog import build_reference_registry
from agent_platform.tools.gateway import ToolGateway
from agent_platform.tools.models import ToolDefinition
from agent_platform.tools.policy import BuiltinPolicyEngine
from agent_platform.workflows.inline import InlineWorkflowStarter


@dataclass(slots=True)
class Container:
    settings: Settings
    store: Any
    tool_registry: Any
    policy: Any
    credentials: Any
    gateway: ToolGateway
    commit_service: CommitService
    workflow: Any
    run_service: RunService
    action_service: ActionService
    artifact_scanner: ArtifactScanner
    artifact_malware_scanner: MalwareScanner
    artifact_sanitizer: ArtifactContentSanitizer
    authenticator: JwtAuthenticator
    metrics: PlatformMetrics
    observability: RuntimeObservability
    memory_vault: MemoryVault
    kill_switches: KillSwitchRegistry
    webhook_registry: WebhookEndpointRegistry
    trajectory_guard: TrajectoryGuard
    fault_injection_harness: Any | None = None
    quota_limiter: Any | None = None
    recovery_workflow: Any | None = None
    dependency_health: Any | None = None
    temporal_client: Any | None = None
    operational_metrics: Any | None = None
    owned_resources: tuple[Any, ...] = ()

    async def healthcheck(self) -> dict[str, str]:
        if self.dependency_health is not None:
            result = await self.dependency_health.check()
            statuses = dict(getattr(result, "statuses", result))
            if self.temporal_client is not None:
                try:
                    healthy = await self.temporal_client.service_client.check_health()
                    statuses["temporal"] = "ok" if healthy else "unhealthy"
                except Exception as exc:
                    statuses["temporal"] = f"error:{type(exc).__name__}"
            statuses["artifact_malware_scanner"] = await self._malware_health()
            self.observability.record_dependency_health(statuses)
            return statuses
        statuses = {
            "api": "ok",
            "database": "ok",
            "workflow": "ok",
            "policy": "ok",
            "artifact": "ok",
            "artifact_malware_scanner": await self._malware_health(),
        }
        self.observability.record_dependency_health(statuses)
        return statuses

    async def _malware_health(self) -> str:
        if (
            self.settings.environment in {"dev", "test"}
            and self.settings.artifact_malware_scan_mode == "structural_only"
        ):
            return "ok"
        return await malware_scanner_health(self.artifact_malware_scanner)

    async def aclose(self) -> None:
        tasks = list(getattr(self.workflow, "_tasks", {}).values())
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for resource in reversed(self.owned_resources):
            close = getattr(resource, "aclose", None) or getattr(resource, "close", None)
            if close is None:
                continue
            result = close()
            if inspect.isawaitable(result):
                await result


async def build_container(settings: Settings) -> Any:
    distributed = (
        settings.persistence_backend == "postgres",
        settings.workflow_backend == "temporal",
        settings.artifact_backend == "s3",
        settings.policy_backend == "opa",
    )
    if any(distributed):
        if not all(distributed):
            raise RuntimeError("DISTRIBUTED_BACKENDS_MUST_BE_CONFIGURED_TOGETHER")
        from agent_platform.bootstrap import build_api_process

        return await build_api_process(settings)

    if settings.environment not in {"dev", "test"}:
        raise RuntimeError("MEMORY_KEY_PROVIDER_REQUIRED")

    store = InMemoryPlatformStore()
    registry = build_reference_registry()
    kill_switches = KillSwitchRegistry(environment=settings.environment)
    memory_vault = MemoryVault(
        encryption_key=hashlib.sha256(b"agent-platform-dev-test-memory-key").digest()
    )
    webhook_registry = WebhookEndpointRegistry()
    policy = BuiltinPolicyEngine()
    credentials = EphemeralCredentialBroker()
    metrics = PlatformMetrics()
    observability = RuntimeObservability(
        metrics,
        environment=settings.environment,
    )
    trajectory_guard = TrajectoryGuard(
        store.runs,
        kill_switches=kill_switches,
        observability=observability,
    )
    gateway = ToolGateway(
        registry,
        policy,
        credentials,
        store.actions,
        store.artifacts,
        capabilities=store.capabilities,
        kill_switches=kill_switches,
        audit=store.audit,
        trajectory_guard=trajectory_guard,
        observability=observability,
    )
    commit_service = CommitService(
        store.actions,
        store.runs,
        registry,
        policy,
        credentials,
        kill_switches=kill_switches,
        trajectory_guard=trajectory_guard,
        observability=observability,
    )
    workflow = InlineWorkflowStarter(
        store=store,
        runtime=DeterministicAgentRuntime(),
        gateway=gateway,
        commit_service=commit_service,
    )
    run_service = RunService(
        store.runs,
        store.actions,
        workflow,
        capabilities=store.capabilities,
        kill_switches=kill_switches,
        observability=observability,
    )
    workflow.bind(run_service)
    action_service = ActionService(
        store.actions,
        workflow,
        observability=observability,
    )
    for candidate in registry.definitions():
        if not isinstance(candidate, ToolDefinition):
            raise TypeError("TOOL_REGISTRY_DEFINITION_INVALID")
        definition = candidate
        await store.capabilities.register(
            "*",
            CapabilityRecord(
                name=definition.capability_name,
                version=definition.version,
                effect=definition.effect.value,
                risk=definition.risk.value,
            ),
        )
    await store.capabilities.register(
        "*",
        CapabilityRecord(
            name="artifact.create",
            version="1.0.0",
            effect="prepare",
            risk="medium",
        ),
    )
    malware_scanner = build_malware_scanner(settings)
    return Container(
        settings=settings,
        store=store,
        tool_registry=registry,
        policy=policy,
        credentials=credentials,
        gateway=gateway,
        commit_service=commit_service,
        workflow=workflow,
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
        memory_vault=memory_vault,
        kill_switches=kill_switches,
        webhook_registry=webhook_registry,
        trajectory_guard=trajectory_guard,
        owned_resources=(malware_scanner,),
    )
