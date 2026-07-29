from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import any_, literal, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine
from testcontainers.postgres import PostgresContainer

from agent_platform.application.errors import NotFound, PlatformError
from agent_platform.infrastructure.kill_switch import KillSwitchScope
from agent_platform.infrastructure.persistence.models import (
    MemoryRecord,
    WebhookEndpoint,
)
from agent_platform.infrastructure.persistence.postgres_kill_switch import (
    PostgresKillSwitchRegistry,
)
from agent_platform.infrastructure.persistence.postgres_memory_vault import (
    AesGcmMemoryContentCipher,
    PostgresMemoryVault,
)
from agent_platform.infrastructure.persistence.postgres_webhook_registry import (
    PostgresWebhookEndpointRegistry,
)
from agent_platform.infrastructure.persistence.session import (
    AsyncSessionFactory,
    create_session_factory,
    dispose_session_factory,
    tenant_session,
)

pytestmark = pytest.mark.integration
PROJECT_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True, slots=True)
class GovernanceDatabaseUrls:
    application: str
    management: str


class FakeSecretBroker:
    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}

    async def put(self, reference_hint: str, secret: bytes) -> str:
        reference = f"secret://{reference_hint}"
        self.values[reference] = secret
        return reference

    async def get(self, reference: str) -> bytes:
        try:
            return self.values[reference]
        except KeyError as exc:
            raise RuntimeError("secret unavailable") from exc

    async def delete(self, reference: str) -> None:
        self.values.pop(reference, None)


async def _provision_roles(admin_url: str) -> GovernanceDatabaseUrls:
    admin = make_url(admin_url)
    application = admin.set(
        username="agent_governance_test",
        password="agent-governance-test",
    )
    management = admin.set(
        username="agent_governance_manager",
        password="agent-governance-manager",
    )
    engine = create_async_engine(admin_url)
    try:
        async with engine.begin() as connection:
            await connection.execute(text("CREATE ROLE agent_platform_admin NOLOGIN"))
            await connection.execute(
                text(
                    "CREATE ROLE agent_governance_test LOGIN PASSWORD "
                    "'agent-governance-test' NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE NOINHERIT NOBYPASSRLS"
                )
            )
            await connection.execute(
                text(
                    "CREATE ROLE agent_governance_manager LOGIN PASSWORD "
                    "'agent-governance-manager' NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE INHERIT NOBYPASSRLS"
                )
            )
            await connection.execute(text("GRANT agent_platform_admin TO agent_governance_manager"))
            for role in ("agent_governance_test", "agent_governance_manager"):
                await connection.execute(
                    text(f'GRANT CONNECT ON DATABASE "{admin.database}" TO {role}')
                )
                await connection.execute(text(f"GRANT USAGE ON SCHEMA public TO {role}"))
                await connection.execute(
                    text(
                        "GRANT SELECT, INSERT, UPDATE, DELETE "
                        f"ON ALL TABLES IN SCHEMA public TO {role}"
                    )
                )
                await connection.execute(
                    text(f"GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO {role}")
                )
                await connection.execute(
                    text(f"GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO {role}")
                )
    finally:
        await engine.dispose()
    return GovernanceDatabaseUrls(
        application=application.render_as_string(hide_password=False),
        management=management.render_as_string(hide_password=False),
    )


@pytest.fixture(scope="module")
def governance_database_urls() -> Iterator[GovernanceDatabaseUrls]:
    with PostgresContainer("postgres:16-alpine") as postgres:
        admin_url = postgres.get_connection_url(driver="asyncpg")
        environment = dict(os.environ)
        environment["AGENT_DATABASE_URL"] = admin_url
        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=PROJECT_ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        yield asyncio.run(_provision_roles(admin_url))


@pytest.fixture
async def governance_factories(
    governance_database_urls: GovernanceDatabaseUrls,
) -> AsyncIterator[tuple[AsyncSessionFactory, AsyncSessionFactory]]:
    application = create_session_factory(
        governance_database_urls.application,
        pool_size=5,
    )
    management = create_session_factory(
        governance_database_urls.management,
        pool_size=2,
    )
    try:
        yield application, management
    finally:
        await dispose_session_factory(application)
        await dispose_session_factory(management)


@pytest.mark.asyncio
async def test_memory_is_encrypted_tenant_scoped_and_corrected_atomically(
    governance_factories: tuple[AsyncSessionFactory, AsyncSessionFactory],
) -> None:
    application, _ = governance_factories
    vault = PostgresMemoryVault(
        application,
        cipher=AesGcmMemoryContentCipher(b"m" * 32),
    )
    now = datetime.now(UTC)
    original = await vault.write(
        tenant_id="tenant-a",
        subject_type="project",
        subject_id="project-1",
        memory_type="preference",
        content="Use verified evidence",
        owner_id="owner-1",
        classification="internal",
        write_policy="explicit_approval",
        approved=True,
        confidence=Decimal("0.9"),
        source_refs=("run-1",),
        valid_until=now + timedelta(days=1),
        now=now,
    )

    async with tenant_session(application, "tenant-a") as session:
        ciphertext = await session.scalar(
            select(MemoryRecord.content_encrypted).where(
                MemoryRecord.memory_id == original.memory_id
            )
        )
    assert ciphertext is not None
    assert b"Use verified evidence" not in ciphertext
    assert (await vault.list_visible("tenant-a", "owner-1"))[0].content == ("Use verified evidence")
    assert await vault.list_visible("tenant-a", "another-owner") == ()
    with pytest.raises(NotFound):
        await vault.get(original.memory_id, "tenant-b")

    with pytest.raises(ValueError, match="CONTENT_REQUIRED"):
        await vault.correct(
            original.memory_id,
            tenant_id="tenant-a",
            actor_id="editor-1",
            content=" ",
            reason="Invalid empty correction",
            now=now + timedelta(minutes=1),
        )
    assert (await vault.get(original.memory_id, "tenant-a")).superseded_by is None

    replacement = await vault.correct(
        original.memory_id,
        tenant_id="tenant-a",
        actor_id="editor-1",
        content="Use directly verified evidence",
        reason="Clarify evidence quality",
        now=now + timedelta(minutes=2),
    )
    visible = await vault.list_visible(
        "tenant-a",
        "owner-1",
        now=now + timedelta(minutes=3),
    )
    assert [item.content for item in visible] == ["Use directly verified evidence"]
    assert (await vault.get(original.memory_id, "tenant-a")).superseded_by == (
        replacement.memory_id
    )
    assert [
        event.event_type for event in await vault.lifecycle("tenant-a", original.memory_id)
    ] == ["created", "superseded"]
    assert [
        event.event_type for event in await vault.lifecycle("tenant-a", replacement.memory_id)
    ] == ["corrected"]

    await vault.delete(
        replacement.memory_id,
        tenant_id="tenant-a",
        actor_id="owner-1",
        reason="No longer applicable",
        now=now + timedelta(minutes=3),
    )
    assert (
        await vault.list_visible(
            "tenant-a",
            "owner-1",
            now=now + timedelta(minutes=4),
        )
        == ()
    )
    assert [
        event.event_type for event in await vault.lifecycle("tenant-a", replacement.memory_id)
    ] == ["corrected", "deleted"]


@pytest.mark.asyncio
async def test_webhook_registry_persists_only_secret_reference_and_is_idempotent(
    governance_factories: tuple[AsyncSessionFactory, AsyncSessionFactory],
) -> None:
    application, _ = governance_factories
    broker = FakeSecretBroker()
    registry = PostgresWebhookEndpointRegistry(
        application,
        secret_broker=broker,
    )
    supplied_secret = b"s" * 32
    view, returned_secret = await registry.register(
        tenant_id="tenant-a",
        endpoint_name="audit",
        url="https://hooks.example.com/agent",
        event_types=frozenset({"run.completed"}),
        signing_secret=supplied_secret,
    )
    duplicate, duplicate_secret = await registry.register(
        tenant_id="tenant-a",
        endpoint_name="audit",
        url="https://hooks.example.com/changed",
        event_types=frozenset({"run.failed"}),
        signing_secret=b"x" * 32,
    )

    assert returned_secret == supplied_secret
    assert duplicate == view
    assert duplicate_secret == b""
    assert await registry.list("tenant-b") == ()
    with pytest.raises(NotFound):
        await registry.delivery_endpoint(view.endpoint_id, "tenant-b")
    async with tenant_session(application, "tenant-a") as session:
        reference = await session.scalar(
            select(WebhookEndpoint.signing_secret_ref).where(
                WebhookEndpoint.endpoint_id == view.endpoint_id
            )
        )
    assert isinstance(reference, str)
    assert reference.startswith("secret://")
    assert supplied_secret.decode() not in reference
    async with tenant_session(application, "tenant-a") as session:
        matching_endpoint_ids = tuple(
            await session.scalars(
                select(WebhookEndpoint.endpoint_id).where(
                    literal("run.completed") == any_(WebhookEndpoint.event_types)
                )
            )
        )
    assert view.endpoint_id in matching_endpoint_ids

    rotated, rotated_secret = await registry.rotate_secret(
        view.endpoint_id,
        "tenant-a",
    )
    assert rotated.secret_version == 2
    assert rotated_secret != supplied_secret
    delivery = await registry.delivery_endpoint(view.endpoint_id, "tenant-a")
    assert delivery.signing_secret == rotated_secret
    disabled = await registry.set_enabled(
        view.endpoint_id,
        "tenant-a",
        enabled=False,
    )
    assert disabled.enabled is False


@pytest.mark.asyncio
async def test_kill_switch_uses_tenant_rls_and_dedicated_management_role(
    governance_factories: tuple[AsyncSessionFactory, AsyncSessionFactory],
) -> None:
    application, management = governance_factories
    registry = PostgresKillSwitchRegistry(
        application,
        environment="prod",
        management_factory=management,
    )
    tenant_switch = await registry.activate(
        scope=KillSwitchScope.TENANT,
        scope_id="tenant-a",
        mode="writes",
        reason="Tenant incident",
        changed_by="secops",
        incident_id="INC-1",
    )
    with pytest.raises(PlatformError) as blocked:
        await registry.require_allowed(
            tenant_id="tenant-a",
            use_case="report",
            capability="email.prepare",
            operation="commit",
        )
    assert blocked.value.code == "TENANT_KILL_SWITCH_ACTIVE"
    await registry.require_allowed(
        tenant_id="tenant-b",
        use_case="report",
        capability="email.prepare",
        operation="commit",
    )

    global_switch = await registry.activate(
        scope=KillSwitchScope.GLOBAL,
        scope_id="*",
        mode="all",
        reason="Global incident",
        changed_by="secops",
        incident_id="INC-2",
    )
    with pytest.raises(PlatformError) as globally_blocked:
        await registry.require_allowed(
            tenant_id="tenant-b",
            use_case="report",
            capability="email.prepare",
            operation="prepare",
        )
    assert globally_blocked.value.code == "GLOBAL_KILL_SWITCH_ACTIVE"
    await registry.require_allowed(
        tenant_id="tenant-b",
        use_case="report",
        capability="email.prepare",
        operation="query",
    )
    assert {item.switch_id for item in await registry.active()} == {
        tenant_switch.switch_id,
        global_switch.switch_id,
    }

    await registry.deactivate(
        tenant_switch.switch_id,
        changed_by="secops",
        reason="Tenant recovered",
    )
    await registry.deactivate(
        global_switch.switch_id,
        changed_by="secops",
        reason="Global recovered",
    )
    assert await registry.active() == ()
    assert [item.action for item in await registry.audit_log()] == [
        "activated",
        "activated",
        "deactivated",
        "deactivated",
    ]

    fail_closed = PostgresKillSwitchRegistry(application, environment="prod")
    with pytest.raises(PlatformError) as missing_role:
        await fail_closed.activate(
            scope=KillSwitchScope.GLOBAL,
            scope_id="*",
            mode="all",
            reason="Should fail",
            changed_by="secops",
            incident_id=f"INC-{uuid4()}",
        )
    assert missing_role.value.code == "KILL_SWITCH_MANAGEMENT_ROLE_REQUIRED"
