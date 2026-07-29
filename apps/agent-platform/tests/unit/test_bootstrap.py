from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from agent_platform import bootstrap
from agent_platform.agents.deterministic_runtime import DeterministicAgentRuntime
from agent_platform.config import Settings
from agent_platform.tools.catalog import build_reference_registry


class _Foundation:
    def __init__(self) -> None:
        store = SimpleNamespace(
            runs=object(),
            actions=object(),
            artifacts=object(),
            capabilities=object(),
        )
        self.shared = SimpleNamespace(
            store=store,
            policy=object(),
            kill_switches=object(),
        )
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


class _TemporalClient:
    pass


def _distributed_settings(role: str) -> Settings:
    return Settings(
        environment="dev",
        process_role=role,
        auth_disabled=True,
        persistence_backend="postgres",
        workflow_backend="temporal",
        artifact_backend="s3",
        policy_backend="opa",
        artifact_region="us-east-1",
    )


def test_reference_registry_declares_distinct_prepare_and_commit_scopes() -> None:
    definitions = build_reference_registry().definitions()

    assert bootstrap._known_capabilities(definitions) == frozenset(
        {"artifact.create", "email.prepare", "knowledge.search"}
    )
    assert bootstrap._commit_scopes(definitions) == frozenset({"email:commit"})


@pytest.mark.asyncio
async def test_commit_bootstrap_has_no_model_runtime_or_agent_gateway(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    foundation = _Foundation()

    async def build_foundation(_: Settings) -> Any:
        return foundation

    def build_commit(shared: Any, **_: Any) -> Any:
        return SimpleNamespace(
            store=shared.store,
            commit_service=object(),
            kill_switches=shared.kill_switches,
            trajectory_guard=object(),
        )

    def fail_if_model_client_is_built(_: Settings) -> None:
        raise AssertionError("Commit worker must not initialize an OpenAI client")

    monkeypatch.setattr(bootstrap, "build_production_process_foundation", build_foundation)
    monkeypatch.setattr(bootstrap, "build_commit_worker_resources", build_commit)
    monkeypatch.setattr(bootstrap, "build_agent_openai_client", fail_if_model_client_is_built)

    resources = await bootstrap.build_commit_worker_process(
        _distributed_settings("commit-worker"),
        _TemporalClient(),  # type: ignore[arg-type]
    )

    assert resources.dependencies.runtime is None
    assert resources.dependencies.gateway is None
    assert resources.dependencies.commit_service is not None
    assert resources.dependencies.commit_scopes == frozenset({"email:commit"})


@pytest.mark.asyncio
async def test_agent_bootstrap_uses_deterministic_runtime_only_in_local_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    foundation = _Foundation()

    async def build_foundation(_: Settings) -> Any:
        return foundation

    def build_agent(shared: Any, *, runtime: Any, **_: Any) -> Any:
        return SimpleNamespace(
            store=shared.store,
            runtime=runtime,
            gateway=object(),
            run_service=object(),
        )

    monkeypatch.setattr(bootstrap, "build_production_process_foundation", build_foundation)
    monkeypatch.setattr(bootstrap, "build_agent_worker_resources", build_agent)

    resources = await bootstrap.build_agent_worker_process(
        _distributed_settings("agent-worker"),
        _TemporalClient(),  # type: ignore[arg-type]
    )

    assert isinstance(resources.dependencies.runtime, DeterministicAgentRuntime)
    assert resources.dependencies.commit_service is None


@pytest.mark.asyncio
async def test_worker_bootstrap_rejects_the_wrong_process_role_before_io() -> None:
    settings = _distributed_settings("api")

    with pytest.raises(RuntimeError, match="AGENT_WORKER_ROLE_REQUIRED"):
        await bootstrap.build_agent_worker_process(
            settings,
            _TemporalClient(),  # type: ignore[arg-type]
        )
    with pytest.raises(RuntimeError, match="COMMIT_WORKER_ROLE_REQUIRED"):
        await bootstrap.build_commit_worker_process(
            settings,
            _TemporalClient(),  # type: ignore[arg-type]
        )
