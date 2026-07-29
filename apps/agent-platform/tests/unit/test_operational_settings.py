from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from agent_platform import bootstrap
from agent_platform.config import Settings


def test_activity_concurrency_is_bounded_at_the_configuration_boundary() -> None:
    assert Settings(environment="test", auth_disabled=True).max_concurrent_activities == 20

    with pytest.raises(ValidationError):
        Settings(
            environment="test",
            auth_disabled=True,
            max_concurrent_activities=0,
        )


def test_production_rejects_trace_content_capture() -> None:
    with pytest.raises(
        ValidationError,
        match="PRODUCTION_TRACE_CONTENT_CAPTURE_FORBIDDEN",
    ):
        Settings(
            environment="prod",
            process_role="agent-worker",
            trace_content_capture=True,
        )


@pytest.mark.parametrize("environment", ["staging", "prod"])
@pytest.mark.parametrize("enable_admin_api", [False, True])
def test_staging_and_prod_api_require_management_dsn_independent_of_admin_api(
    environment: str,
    enable_admin_api: bool,
) -> None:
    with pytest.raises(
        ValidationError,
        match="PRODUCTION_MANAGEMENT_DATABASE_DSN_REQUIRED",
    ):
        Settings(
            environment=environment,
            process_role="api",
            enable_admin_api=enable_admin_api,
            management_database_dsn="",
        )


def test_management_dsn_is_not_disabled_with_admin_api() -> None:
    settings = Settings(
        environment="test",
        process_role="api",
        auth_disabled=True,
        enable_admin_api=False,
        management_database_dsn="postgresql+asyncpg://manager:test@localhost/agent",
    )

    assert (
        bootstrap._management_dsn(settings) == "postgresql+asyncpg://manager:test@localhost/agent"
    )


@pytest.mark.asyncio
async def test_agent_bootstrap_passes_explicit_trace_capture_to_observability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[bool] = []

    class _TraceProvider:
        def get_tracer(self, _: str) -> object:
            return object()

        def shutdown(self) -> None:
            return None

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

        async def aclose(self) -> None:
            return None

    def configure_tracing(**kwargs: Any) -> _TraceProvider:
        captured.append(bool(kwargs["capture_content"]))
        return _TraceProvider()

    async def build_foundation(_: Settings) -> _Foundation:
        return _Foundation()

    def build_agent(shared: Any, *, runtime: Any, **_: Any) -> Any:
        return SimpleNamespace(
            store=shared.store,
            runtime=runtime,
            gateway=object(),
            run_service=object(),
        )

    monkeypatch.setattr(bootstrap, "configure_tracing", configure_tracing)
    monkeypatch.setattr(
        bootstrap,
        "build_production_process_foundation",
        build_foundation,
    )
    monkeypatch.setattr(bootstrap, "build_agent_worker_resources", build_agent)

    resources = await bootstrap.build_agent_worker_process(
        Settings(
            environment="test",
            process_role="agent-worker",
            auth_disabled=True,
            persistence_backend="postgres",
            workflow_backend="temporal",
            artifact_backend="s3",
            policy_backend="opa",
            artifact_region="us-east-1",
            trace_content_capture=True,
        ),
        object(),  # type: ignore[arg-type]
    )

    assert captured == [True]
    await resources.aclose()
