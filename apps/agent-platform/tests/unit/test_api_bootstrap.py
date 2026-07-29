from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import SecretStr

from agent_platform import bootstrap
from agent_platform.config import Settings
from agent_platform.container import build_container


class _Health:
    async def check(self) -> Any:
        return SimpleNamespace(
            ready=True,
            statuses={"database": "ok", "opa": "ok", "s3": "ok"},
        )


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
            memory_vault=object(),
            webhook_registry=object(),
            kill_switches=object(),
            health=_Health(),
        )
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


class _TemporalService:
    async def check_health(self) -> bool:
        return True


class _TemporalClient:
    service_client = _TemporalService()


def _api_settings() -> Settings:
    return Settings(
        environment="dev",
        process_role="api",
        auth_disabled=True,
        persistence_backend="postgres",
        workflow_backend="temporal",
        artifact_backend="s3",
        policy_backend="opa",
        artifact_region="us-east-1",
    )


@pytest.mark.asyncio
async def test_api_bootstrap_builds_control_plane_without_worker_privileges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    foundation = _Foundation()

    async def build_foundation(_: Settings) -> Any:
        return foundation

    monkeypatch.setattr(bootstrap, "build_production_process_foundation", build_foundation)

    container = await bootstrap.build_api_process(
        _api_settings(),
        temporal_client=_TemporalClient(),  # type: ignore[arg-type]
    )

    assert container.settings.process_role == "api"
    assert container.run_service is not None
    assert container.action_service is not None
    assert not hasattr(container, "runtime")
    assert not hasattr(container, "gateway")
    assert not hasattr(container, "commit_service")
    assert not hasattr(container, "credentials")
    assert await container.healthcheck() == {
        "database": "ok",
        "opa": "ok",
        "s3": "ok",
        "temporal": "ok",
        "artifact_malware_scanner": "error:policy-fail-closed:structural-only",
    }

    await container.aclose()
    assert foundation.closed is True


@pytest.mark.asyncio
async def test_api_bootstrap_owns_staging_fault_harness_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    foundation = _Foundation()
    created: list[Any] = []
    malware_scanner = bootstrap.build_malware_scanner(_api_settings())

    async def build_foundation(_: Settings) -> Any:
        return foundation

    class FaultHarness:
        def __init__(self, *, controller_url: str, token: str) -> None:
            self.controller_url = controller_url
            self.token = token
            self.closed = False
            created.append(self)

        async def aclose(self) -> None:
            self.closed = True

    monkeypatch.setattr(bootstrap, "build_production_process_foundation", build_foundation)
    monkeypatch.setattr(bootstrap, "HttpEvalFaultHarness", FaultHarness)
    monkeypatch.setattr(bootstrap, "build_malware_scanner", lambda _: malware_scanner)
    monkeypatch.setattr(bootstrap, "_load_production_catalog", lambda _: None)
    monkeypatch.setattr(
        bootstrap,
        "_build_capacity_cost_controller",
        lambda *_args, **_kwargs: None,
    )
    settings = _api_settings().model_copy(
        update={
            "environment": "staging",
            "eval_fault_harness_url": "https://fault-controller.staging.example.test",
            "eval_fault_harness_token": SecretStr("short-lived-token"),
        }
    )

    container = await bootstrap.build_api_process(
        settings,
        temporal_client=_TemporalClient(),  # type: ignore[arg-type]
    )

    assert container.fault_injection_harness is created[0]
    assert created[0].controller_url == "https://fault-controller.staging.example.test"
    assert created[0].token == "short-lived-token"

    await container.aclose()
    assert created[0].closed is True


@pytest.mark.asyncio
async def test_distributed_api_container_delegates_to_role_composition_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = object()

    async def build_api(settings: Settings) -> Any:
        assert settings.process_role == "api"
        return sentinel

    monkeypatch.setattr(bootstrap, "build_api_process", build_api)

    assert await build_container(_api_settings()) is sentinel


@pytest.mark.asyncio
async def test_api_bootstrap_rejects_wrong_role_before_io() -> None:
    settings = _api_settings().model_copy(update={"process_role": "agent-worker"})

    with pytest.raises(RuntimeError, match="API_PROCESS_ROLE_REQUIRED"):
        await bootstrap.build_api_process(
            settings,
            temporal_client=_TemporalClient(),  # type: ignore[arg-type]
        )
