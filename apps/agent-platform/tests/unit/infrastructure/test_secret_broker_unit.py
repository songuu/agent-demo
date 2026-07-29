from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from agent_platform.infrastructure.secret_broker import (
    AwsSecretsManagerBroker,
    DirectorySecretBroker,
)


class _ResourceExists(Exception):
    pass


class _AwsClient:
    def __init__(self) -> None:
        self.exceptions = SimpleNamespace(ResourceExistsException=_ResourceExists)
        self.create_response: dict[str, Any] = {"ARN": "arn:secret:created"}
        self.put_response: dict[str, Any] = {"ARN": "arn:secret:updated"}
        self.get_response: dict[str, Any] = {"SecretBinary": b"resolved-secret"}
        self.create_raises = False
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def create_secret(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("create_secret", kwargs))
        if self.create_raises:
            raise _ResourceExists
        return self.create_response

    def put_secret_value(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("put_secret_value", kwargs))
        return self.put_response

    def get_secret_value(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("get_secret_value", kwargs))
        return self.get_response

    def delete_secret(self, **kwargs: Any) -> None:
        self.calls.append(("delete_secret", kwargs))


@pytest.mark.asyncio
async def test_directory_secret_broker_round_trips_and_deletes_atomically(
    tmp_path: Path,
) -> None:
    broker = DirectorySecretBroker(tmp_path / "secrets")

    reference = await broker.put("tenant-a/webhook-1", b"0123456789abcdef")

    assert reference.startswith("file-secret://")
    assert await broker.get(reference) == b"0123456789abcdef"
    assert not list((tmp_path / "secrets").glob("*.tmp"))
    await broker.delete(reference)
    with pytest.raises(KeyError, match="SECRET_REFERENCE_NOT_FOUND"):
        await broker.get(reference)
    await broker.delete(reference)


@pytest.mark.asyncio
async def test_directory_secret_broker_rejects_invalid_input_and_reference(
    tmp_path: Path,
) -> None:
    broker = DirectorySecretBroker(tmp_path / "secrets")
    for hint, secret in (("", b"value"), ("hint", b"")):
        with pytest.raises(ValueError, match="SECRET_BROKER_INPUT_REQUIRED"):
            await broker.put(hint, secret)
    for reference in ("", "file-secret://short", "../secret"):
        with pytest.raises(ValueError, match="SECRET_REFERENCE_INVALID"):
            await broker.get(reference)
    with pytest.raises(ValueError, match="SECRET_REFERENCE_PATH_INVALID"):
        broker._path("../outside")


def test_directory_secret_broker_requires_directory(tmp_path: Path) -> None:
    target = tmp_path / "not-a-directory"
    target.write_bytes(b"value")
    with pytest.raises(FileExistsError):
        DirectorySecretBroker(target)


@pytest.mark.asyncio
async def test_aws_secret_broker_create_update_read_and_delete() -> None:
    client = _AwsClient()
    broker = AwsSecretsManagerBroker(client, prefix="/agent-platform/webhooks/")

    created = await broker.put("tenant-a/webhook-1", b"0123456789abcdef")
    assert created == "arn:secret:created"
    assert client.calls[0][0] == "create_secret"
    assert client.calls[0][1]["Name"].startswith("agent-platform/webhooks/")

    client.create_raises = True
    updated = await broker.put("tenant-a/webhook-1", b"fedcba9876543210")
    assert updated == "arn:secret:updated"
    assert client.calls[-1][0] == "put_secret_value"

    assert await broker.get(created) == b"resolved-secret"
    client.get_response = {"SecretBinary": "text-secret"}
    assert await broker.get(created) == b"text-secret"
    await broker.delete(created)
    assert client.calls[-1] == (
        "delete_secret",
        {"SecretId": created, "RecoveryWindowInDays": 7},
    )


@pytest.mark.asyncio
async def test_aws_secret_broker_validates_configuration_input_and_response() -> None:
    client = _AwsClient()
    with pytest.raises(ValueError, match="SECRET_BROKER_PREFIX_REQUIRED"):
        AwsSecretsManagerBroker(client, prefix=" / ")
    broker = AwsSecretsManagerBroker(client, prefix="agent-platform")
    for hint, secret in (("", b"value"), ("hint", b"")):
        with pytest.raises(ValueError, match="SECRET_BROKER_INPUT_REQUIRED"):
            await broker.put(hint, secret)

    client.create_response = {}
    generated = await broker.put("tenant-a/webhook-1", b"value")
    assert generated.startswith("agent-platform/")

    client.get_response = {"SecretString": "unsupported"}
    with pytest.raises(ValueError, match="SECRET_BROKER_VALUE_INVALID"):
        await broker.get(generated)
