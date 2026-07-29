from __future__ import annotations

import secrets
from uuid import uuid4

import pytest

from agent_platform.application.errors import NotFound
from agent_platform.infrastructure.webhook_registry import WebhookEndpointRegistry


async def test_register_is_idempotent_and_list_is_tenant_scoped_and_sorted() -> None:
    registry = WebhookEndpointRegistry()
    audit_secret = b"audit-secret"
    metrics_secret = b"metrics-secret"

    metrics, returned_metrics_secret = await registry.register(
        tenant_id="tenant-a",
        endpoint_name="metrics",
        url="https://metrics.example.com/events",
        event_types=frozenset({"run.completed"}),
        signing_secret=metrics_secret,
    )
    audit, returned_audit_secret = await registry.register(
        tenant_id="tenant-a",
        endpoint_name="audit",
        url="https://audit.example.com/events",
        event_types=frozenset({"action.committed"}),
        signing_secret=audit_secret,
    )
    await registry.register(
        tenant_id="tenant-b",
        endpoint_name="other",
        url="https://other.example.com/events",
        event_types=frozenset({"run.completed"}),
        signing_secret=b"other-secret",
    )

    duplicate, duplicate_secret = await registry.register(
        tenant_id="tenant-a",
        endpoint_name="audit",
        url="https://replacement.example.com/events",
        event_types=frozenset({"replacement"}),
        signing_secret=b"replacement-secret",
    )

    assert returned_metrics_secret == metrics_secret
    assert returned_audit_secret == audit_secret
    assert duplicate == audit
    assert duplicate_secret == b""
    assert await registry.list("tenant-a") == (audit, metrics)
    assert await registry.list("missing-tenant") == ()


async def test_registry_generates_rotates_and_materializes_delivery_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = iter((b"generated-secret", b"rotated-secret"))
    monkeypatch.setattr(secrets, "token_bytes", lambda _size: next(generated))
    registry = WebhookEndpointRegistry()

    view, initial_secret = await registry.register(
        tenant_id="tenant-a",
        endpoint_name="audit",
        url="https://audit.example.com/events",
        event_types=frozenset({"action.committed"}),
    )
    disabled = await registry.set_enabled(
        view.endpoint_id,
        "tenant-a",
        enabled=False,
    )
    rotated, rotated_secret = await registry.rotate_secret(
        view.endpoint_id,
        "tenant-a",
    )
    delivery = await registry.delivery_endpoint(view.endpoint_id, "tenant-a")

    assert initial_secret == b"generated-secret"
    assert disabled.enabled is False
    assert rotated.secret_version == 2
    assert rotated.enabled is False
    assert rotated_secret == b"rotated-secret"
    assert delivery.endpoint_id == view.endpoint_id
    assert delivery.tenant_id == "tenant-a"
    assert delivery.url == "https://audit.example.com/events"
    assert delivery.event_types == frozenset({"action.committed"})
    assert delivery.signing_secret == rotated_secret
    assert delivery.enabled is False


@pytest.mark.parametrize("operation", ["set_enabled", "rotate_secret", "delivery"])
async def test_registry_hides_missing_and_cross_tenant_endpoints(
    operation: str,
) -> None:
    registry = WebhookEndpointRegistry()
    view, _ = await registry.register(
        tenant_id="tenant-a",
        endpoint_name="audit",
        url="https://audit.example.com/events",
        event_types=frozenset({"action.committed"}),
        signing_secret=b"audit-secret",
    )

    endpoint_id = uuid4() if operation == "set_enabled" else view.endpoint_id
    tenant_id = "tenant-a" if operation == "set_enabled" else "tenant-b"
    with pytest.raises(NotFound) as raised:
        if operation == "set_enabled":
            await registry.set_enabled(endpoint_id, tenant_id, enabled=False)
        elif operation == "rotate_secret":
            await registry.rotate_secret(endpoint_id, tenant_id)
        else:
            await registry.delivery_endpoint(endpoint_id, tenant_id)

    assert raised.value.code == "NOT_FOUND"
    assert raised.value.context["resource"] == "webhook endpoint"
    assert raised.value.context["resource_id"] == str(endpoint_id)
