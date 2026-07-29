"""Bounded readiness probes for production dependencies."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx
from sqlalchemy import text

from agent_platform.infrastructure.persistence.session import AsyncSessionFactory

type HealthProbe = Callable[[], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class DependencyHealth:
    ready: bool
    statuses: dict[str, str]


class DependencyHealthChecker:
    """Run independent dependency probes with one fail-fast timeout per probe."""

    def __init__(
        self,
        probes: Mapping[str, HealthProbe],
        *,
        timeout_seconds: float = 2.0,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("HEALTHCHECK_TIMEOUT_MUST_BE_POSITIVE")
        self._probes = dict(probes)
        self._timeout_seconds = timeout_seconds

    async def check(self) -> DependencyHealth:
        names = tuple(sorted(self._probes))
        results = await asyncio.gather(*(self._check_one(self._probes[name]) for name in names))
        statuses = dict(zip(names, results, strict=True))
        return DependencyHealth(
            ready=all(value == "ok" for value in statuses.values()),
            statuses=statuses,
        )

    async def _check_one(self, probe: HealthProbe) -> str:
        try:
            async with asyncio.timeout(self._timeout_seconds):
                await probe()
        except TimeoutError:
            return "timeout"
        except Exception as exc:
            return f"error:{type(exc).__name__}"
        return "ok"


def database_probe(factory: AsyncSessionFactory) -> HealthProbe:
    async def probe() -> None:
        async with factory() as session:
            value = await session.scalar(text("SELECT 1"))
            if value != 1:
                raise RuntimeError("DATABASE_HEALTHCHECK_INVALID_RESPONSE")

    return probe


def opa_probe(client: httpx.AsyncClient) -> HealthProbe:
    async def probe() -> None:
        response = await client.get("/health")
        response.raise_for_status()

    return probe


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def s3_probe(
    client: Any,
    bucket: str,
    *,
    require_governance: bool = False,
    require_staging_controls: bool = False,
    expected_kms_key: str | None = None,
    max_staging_expiration_days: int = 2,
) -> HealthProbe:
    if require_governance and require_staging_controls:
        raise ValueError("S3_PROBE_CONTROL_MODE_CONFLICT")
    if max_staging_expiration_days <= 0:
        raise ValueError("S3_STAGING_EXPIRATION_BOUND_INVALID")

    async def probe() -> None:
        await asyncio.to_thread(client.head_bucket, Bucket=bucket)
        if not require_governance and not require_staging_controls:
            return

        if require_governance or require_staging_controls:
            versioning = _mapping(
                await asyncio.to_thread(client.get_bucket_versioning, Bucket=bucket)
            )
            if versioning.get("Status") != "Enabled":
                raise RuntimeError("S3_VERSIONING_REQUIRED")

        if not expected_kms_key:
            raise RuntimeError("S3_KMS_KEY_REFERENCE_REQUIRED")
        encryption = _mapping(await asyncio.to_thread(client.get_bucket_encryption, Bucket=bucket))
        encryption_rules = _mapping(encryption.get("ServerSideEncryptionConfiguration")).get(
            "Rules"
        )
        kms_enabled = False
        if isinstance(encryption_rules, list):
            for raw_rule in encryption_rules:
                rule = _mapping(raw_rule)
                default = _mapping(rule.get("ApplyServerSideEncryptionByDefault"))
                if (
                    default.get("SSEAlgorithm") == "aws:kms"
                    and default.get("KMSMasterKeyID") == expected_kms_key
                    and rule.get("BucketKeyEnabled") is True
                ):
                    kms_enabled = True
                    break
        if not kms_enabled:
            raise RuntimeError("S3_KMS_ENCRYPTION_REQUIRED")

        lifecycle = _mapping(
            await asyncio.to_thread(
                client.get_bucket_lifecycle_configuration,
                Bucket=bucket,
            )
        )
        lifecycle_rules = lifecycle.get("Rules")
        enabled_rules = (
            [
                _mapping(rule)
                for rule in lifecycle_rules
                if _mapping(rule).get("Status") == "Enabled"
            ]
            if isinstance(lifecycle_rules, list)
            else []
        )
        if not enabled_rules:
            raise RuntimeError("S3_LIFECYCLE_REQUIRED")
        if require_staging_controls:
            if not any(
                isinstance(_mapping(rule.get("Expiration")).get("Days"), int)
                and 0 < int(_mapping(rule.get("Expiration"))["Days"]) <= max_staging_expiration_days
                for rule in enabled_rules
            ):
                raise RuntimeError("S3_STAGING_SHORT_LIFECYCLE_REQUIRED")
            if not any(
                isinstance(
                    _mapping(rule.get("AbortIncompleteMultipartUpload")).get("DaysAfterInitiation"),
                    int,
                )
                and 0
                < int(_mapping(rule.get("AbortIncompleteMultipartUpload"))["DaysAfterInitiation"])
                <= max_staging_expiration_days
                for rule in enabled_rules
            ):
                raise RuntimeError("S3_STAGING_ABORT_INCOMPLETE_MULTIPART_REQUIRED")
            if not any(
                isinstance(
                    _mapping(rule.get("NoncurrentVersionExpiration")).get("NoncurrentDays"),
                    int,
                )
                and 0
                < int(_mapping(rule.get("NoncurrentVersionExpiration"))["NoncurrentDays"])
                <= 7
                for rule in enabled_rules
            ):
                raise RuntimeError("S3_STAGING_NONCURRENT_LIFECYCLE_REQUIRED")

        public_access = _mapping(
            await asyncio.to_thread(client.get_public_access_block, Bucket=bucket)
        )
        public_access_config = _mapping(public_access.get("PublicAccessBlockConfiguration"))
        public_access_controls = (
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        )
        if not all(public_access_config.get(key) is True for key in public_access_controls):
            raise RuntimeError("S3_PUBLIC_ACCESS_BLOCK_REQUIRED")

        try:
            object_lock = _mapping(
                await asyncio.to_thread(
                    client.get_object_lock_configuration,
                    Bucket=bucket,
                )
            )
        except Exception as exc:
            error = _mapping(_mapping(getattr(exc, "response", None)).get("Error"))
            if not (
                require_staging_controls
                and str(error.get("Code", ""))
                in {"ObjectLockConfigurationNotFoundError", "NoSuchObjectLockConfiguration"}
            ):
                raise
            object_lock = {}
        object_lock_config = _mapping(object_lock.get("ObjectLockConfiguration"))
        if require_staging_controls:
            if object_lock_config.get("ObjectLockEnabled") == "Enabled":
                raise RuntimeError("S3_STAGING_OBJECT_LOCK_FORBIDDEN")
            return

        if object_lock_config.get("ObjectLockEnabled") != "Enabled":
            raise RuntimeError("S3_OBJECT_LOCK_REQUIRED")
        default_retention = _mapping(
            _mapping(object_lock_config.get("Rule")).get("DefaultRetention")
        )
        if default_retention:
            retention_value = default_retention.get("Days") or default_retention.get("Years")
            if not (
                default_retention.get("Mode") in {"GOVERNANCE", "COMPLIANCE"}
                and isinstance(retention_value, int)
                and retention_value > 0
            ):
                raise RuntimeError("S3_OBJECT_LOCK_DEFAULT_INVALID")

    return probe


def temporal_probe(client: Any) -> HealthProbe:
    async def probe() -> None:
        healthy = await client.service_client.check_health()
        if not healthy:
            raise RuntimeError("TEMPORAL_HEALTHCHECK_FAILED")

    return probe
