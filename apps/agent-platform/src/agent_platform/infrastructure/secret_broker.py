from __future__ import annotations

import asyncio
import hashlib
import os
import re
from pathlib import Path
from typing import Any
from uuid import uuid4

_FILE_REFERENCE = re.compile(r"^file-secret://(?P<digest>[0-9a-f]{64})$")


class DirectorySecretBroker:
    """Local-only SecretBroker with atomic, owner-readable files."""

    def __init__(self, root: Path) -> None:
        self._root = root.resolve()
        self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not self._root.is_dir():
            raise ValueError("SECRET_BROKER_DIRECTORY_REQUIRED")

    async def put(self, reference_hint: str, secret: bytes) -> str:
        if not reference_hint.strip() or not secret:
            raise ValueError("SECRET_BROKER_INPUT_REQUIRED")
        digest = hashlib.sha256(reference_hint.encode()).hexdigest()
        destination = self._path(digest)
        await asyncio.to_thread(self._atomic_write, destination, secret)
        return f"file-secret://{digest}"

    async def get(self, reference: str) -> bytes:
        path = self._reference_path(reference)
        try:
            return await asyncio.to_thread(path.read_bytes)
        except FileNotFoundError as exc:
            raise KeyError("SECRET_REFERENCE_NOT_FOUND") from exc

    async def delete(self, reference: str) -> None:
        path = self._reference_path(reference)
        await asyncio.to_thread(path.unlink, missing_ok=True)

    def _reference_path(self, reference: str) -> Path:
        match = _FILE_REFERENCE.fullmatch(reference)
        if match is None:
            raise ValueError("SECRET_REFERENCE_INVALID")
        return self._path(match.group("digest"))

    def _path(self, digest: str) -> Path:
        path = (self._root / digest).resolve()
        if path.parent != self._root:
            raise ValueError("SECRET_REFERENCE_PATH_INVALID")
        return path

    @staticmethod
    def _atomic_write(destination: Path, secret: bytes) -> None:
        temporary = destination.with_name(f".{destination.name}.{uuid4().hex}.tmp")
        descriptor = os.open(
            temporary,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(secret)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)


class AwsSecretsManagerBroker:
    """AWS Secrets Manager adapter; PostgreSQL stores only returned references."""

    def __init__(self, client: Any, *, prefix: str) -> None:
        normalized = prefix.strip().strip("/")
        if not normalized:
            raise ValueError("SECRET_BROKER_PREFIX_REQUIRED")
        self._client = client
        self._prefix = normalized

    async def put(self, reference_hint: str, secret: bytes) -> str:
        if not reference_hint.strip() or not secret:
            raise ValueError("SECRET_BROKER_INPUT_REQUIRED")
        digest = hashlib.sha256(reference_hint.encode()).hexdigest()
        name = f"{self._prefix}/{digest}"
        try:
            response = await asyncio.to_thread(
                self._client.create_secret,
                Name=name,
                SecretBinary=secret,
                Description="Agent Platform managed webhook signing secret",
            )
        except self._client.exceptions.ResourceExistsException:
            response = await asyncio.to_thread(
                self._client.put_secret_value,
                SecretId=name,
                SecretBinary=secret,
            )
        reference = response.get("ARN") or response.get("Name") or name
        return str(reference)

    async def get(self, reference: str) -> bytes:
        response = await asyncio.to_thread(
            self._client.get_secret_value,
            SecretId=reference,
        )
        value = response.get("SecretBinary")
        if isinstance(value, str):
            return value.encode()
        if isinstance(value, bytes):
            return value
        raise ValueError("SECRET_BROKER_VALUE_INVALID")

    async def delete(self, reference: str) -> None:
        await asyncio.to_thread(
            self._client.delete_secret,
            SecretId=reference,
            RecoveryWindowInDays=7,
        )
