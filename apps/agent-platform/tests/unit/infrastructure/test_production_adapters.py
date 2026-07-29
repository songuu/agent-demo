from __future__ import annotations

import asyncio
from uuid import uuid4

import httpx
import pytest
from cryptography.exceptions import InvalidTag

from agent_platform.application.records import ArtifactRecord
from agent_platform.infrastructure.artifacts.addressable_s3_store import (
    AddressableS3ArtifactStore,
)
from agent_platform.infrastructure.dependency_health import (
    DependencyHealthChecker,
)
from agent_platform.infrastructure.persistence.production_store import (
    AesGcmActionPayloadCipher,
)
from agent_platform.infrastructure.policy.engine import OpaPolicyEngine
from agent_platform.infrastructure.policy.port_adapter import OpaPolicyPortAdapter


class FakeS3Client:
    def __init__(self) -> None:
        self.presign: tuple[str, dict[str, str], int] | None = None

    def generate_presigned_url(
        self,
        operation_name: str,
        *,
        Params: dict[str, str],
        ExpiresIn: int,
    ) -> str:
        self.presign = operation_name, Params, ExpiresIn
        return "https://objects.example.test/presigned"


@pytest.mark.asyncio
async def test_addressable_s3_uri_and_presign_use_the_same_object_key() -> None:
    client = FakeS3Client()
    store = AddressableS3ArtifactStore(
        client=client,
        bucket="artifact-bucket",
        kms_key_id="kms-key",
        environment="prod",
    )
    artifact = ArtifactRecord(
        artifact_id=uuid4(),
        tenant_id="tenant-a",
        run_id=uuid4(),
        kind="report",
        media_type="application/pdf",
        content=b"pdf",
        sha256="a" * 64,
        classification="internal",
        created_by="user-1",
        object_version_id="version-7",
    )

    uri = store.uri_for(artifact)
    download = await store.create_download(
        artifact,
        principal_id="user-1",
        tenant_id="tenant-a",
        purpose="user-download",
        expires_in_seconds=300,
    )

    expected_key = f"prod/tenant/tenant-a/run/{artifact.run_id}/artifacts/{artifact.artifact_id}"
    assert uri == f"s3://artifact-bucket/{expected_key}"
    assert download.artifact_id == artifact.artifact_id
    assert client.presign is not None
    assert client.presign[0] == "get_object"
    assert client.presign[1]["Key"] == expected_key
    assert client.presign[1]["VersionId"] == "version-7"
    assert client.presign[2] == 300
    with pytest.raises(ValueError, match="TENANT_MISMATCH"):
        await store.create_download(
            artifact,
            principal_id="user-1",
            tenant_id="tenant-b",
            purpose="user-download",
            expires_in_seconds=300,
        )


def test_action_payload_cipher_authenticates_payload_and_tenant_context() -> None:
    cipher = AesGcmActionPayloadCipher(b"k" * 32)
    plaintext = b'{"subject":"approved"}'
    associated_data = b"tenant-a:action-1"

    ciphertext = cipher.encrypt(plaintext, associated_data=associated_data)

    assert plaintext not in ciphertext
    assert cipher.decrypt(ciphertext, associated_data=associated_data) == plaintext
    with pytest.raises(InvalidTag):
        cipher.decrypt(ciphertext, associated_data=b"tenant-b:action-1")


@pytest.mark.asyncio
async def test_opa_port_maps_tool_and_action_decisions_without_scope_expansion() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path.endswith("/tool/result"):
            return httpx.Response(
                200,
                json={
                    "result": {
                        "allowed": True,
                        "reason_codes": [],
                        "approval_required": True,
                        "data_scope": {"tenant_id": "tenant-a", "rows": ["1"]},
                        "policy_version": "bundle-7",
                    }
                },
            )
        return httpx.Response(
            200,
            json={
                "result": {
                    "allowed": True,
                    "reason_codes": [],
                    "policy_version": "bundle-7",
                }
            },
        )

    client = httpx.AsyncClient(
        base_url="http://opa.test",
        transport=httpx.MockTransport(handler),
    )
    adapter = OpaPolicyPortAdapter(OpaPolicyEngine(base_url="http://opa.test", client=client))
    try:
        tool = await adapter.authorize_tool(
            {
                "principal": {
                    "tenant_id": "tenant-a",
                    "scopes": ["email.send", "admin"],
                },
                "tool": {
                    "risk": "critical",
                    "required_scopes": ["email.send", "missing"],
                },
                "request": {"data_scope": {"tenant_id": "tenant-a"}},
            }
        )
        action = await adapter.authorize_action(
            {
                "principal": {
                    "tenant_id": "tenant-a",
                    "scopes": ["email.send"],
                },
                "action": {"tenant_id": "tenant-a"},
            }
        )
    finally:
        await client.aclose()

    assert calls == ["/v1/data/agent/tool/result", "/v1/data/agent/action/result"]
    assert tool.allowed is True
    assert tool.credential_scopes == frozenset({"email.send"})
    assert tool.required_approvals == 2
    assert tool.restricted_data_scope == {
        "tenant_id": "tenant-a",
        "rows": ["1"],
    }
    assert action.allowed is True
    assert action.approval_required is False
    assert action.credential_scopes == frozenset({"email.send"})


@pytest.mark.asyncio
async def test_dependency_health_reports_each_failure_without_hiding_healthy_probes() -> None:
    async def healthy() -> None:
        return None

    async def broken() -> None:
        raise ConnectionError("unavailable")

    async def slow() -> None:
        await asyncio.sleep(0.05)

    report = await DependencyHealthChecker(
        {"database": healthy, "opa": broken, "temporal": slow},
        timeout_seconds=0.01,
    ).check()

    assert report.ready is False
    assert report.statuses == {
        "database": "ok",
        "opa": "error:ConnectionError",
        "temporal": "timeout",
    }
