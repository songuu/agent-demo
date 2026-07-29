from __future__ import annotations

from typing import Any

import pytest
from tests.unit.tools.test_gateway import (
    FakeAdapter,
    FakeCredentials,
    FakePolicy,
    context,
    definition,
)

from agent_platform.application.records import AuditEvent, ToolInvocationRecord
from agent_platform.domain.enums import ToolEffect
from agent_platform.infrastructure.memory_store import InMemoryPlatformStore
from agent_platform.tools.adapters.enterprise_gateway import AdapterInvocationResult
from agent_platform.tools.gateway import ToolGateway
from agent_platform.tools.models import RegisteredTool
from agent_platform.tools.registry import ToolRegistry


class EvidenceAdapter(FakeAdapter):
    async def read(self, args: object, credential: object) -> AdapterInvocationResult:
        self.read_calls += 1
        return AdapterInvocationResult(
            data={"items": [{"title": "source"}]},
            provider_request_id="provider-read-42",
        )

    async def preview(
        self,
        args: object,
        credential: object,
    ) -> AdapterInvocationResult:
        self.preview_calls += 1
        return AdapterInvocationResult(
            data={"normalized": args, "side_effect": "none_until_commit"},
            provider_request_id="provider-preview-42",
        )


class RecordingAudit:
    def __init__(self) -> None:
        self.records: list[tuple[ToolInvocationRecord, AuditEvent]] = []

    async def record_tool(
        self,
        invocation: ToolInvocationRecord,
        event: AuditEvent,
    ) -> None:
        self.records.append((invocation, event))


class NonAtomicActions:
    def __init__(self, delegate: Any) -> None:
        self._delegate = delegate

    async def create_once(self, action: Any) -> Any:
        return await self._delegate.create_once(action)


@pytest.mark.asyncio
async def test_read_unwraps_provider_evidence_without_polluting_business_data() -> None:
    store = InMemoryPlatformStore()
    registry = ToolRegistry()
    registry.register(RegisteredTool(definition(), EvidenceAdapter()))
    audit = RecordingAudit()
    gateway = ToolGateway(
        registry,
        FakePolicy(),
        FakeCredentials(),
        store.actions,
        store.artifacts,
        audit=audit,
    )

    result = await gateway.call_read(context(), "knowledge.search", {"query": "x"})

    assert result.data == {"items": [{"title": "source"}]}
    assert "provider_request_id" not in result.data
    invocation, event = audit.records[0]
    assert invocation.provider_request_id == "provider-read-42"
    assert event.payload["provider_request_id"] == "provider-read-42"


@pytest.mark.asyncio
async def test_prepare_persists_provider_evidence_in_action_audit() -> None:
    store = InMemoryPlatformStore()
    registry = ToolRegistry()
    registry.register(
        RegisteredTool(
            definition("email.prepare", effect=ToolEffect.PREPARE),
            EvidenceAdapter(),
        )
    )
    audit = RecordingAudit()
    gateway = ToolGateway(
        registry,
        FakePolicy(approval_required=True),
        FakeCredentials(),
        NonAtomicActions(store.actions),
        store.artifacts,
        audit=audit,
    )

    await gateway.prepare(
        context(),
        "email.prepare",
        {"query": "approved draft"},
    )

    invocation, prepared_event = audit.records[0]

    assert invocation.provider_request_id == "provider-preview-42"
    assert prepared_event.payload["provider_request_id"] == "provider-preview-42"
