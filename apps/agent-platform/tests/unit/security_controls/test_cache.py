from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_platform.application.errors import PlatformError
from agent_platform.infrastructure.cache import CacheKey, SafeCache


def key(**overrides: object) -> CacheKey:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "namespace": "tool-result",
        "data_scope": {"tenant_id": "tenant-a", "resources": ["doc-1"]},
        "tool_id": "knowledge.search",
        "tool_version": "3.1.0",
        "model_id": "openai:gpt-5.6",
        "model_revision": "2026-07-15",
        "prompt_id": "research.answer",
        "prompt_digest": "a" * 64,
        "input_data": {"query": "bounded agents"},
        "freshness_token": "etag-42",
    }
    values.update(overrides)
    return CacheKey.build(**values)


def test_cache_key_binds_every_execution_and_freshness_dimension() -> None:
    base = key()
    variants = [
        key(tenant_id="tenant-b"),
        key(namespace="artifact-metadata"),
        key(data_scope={"tenant_id": "tenant-a", "resources": ["doc-2"]}),
        key(tool_id="knowledge.lookup"),
        key(tool_version="3.2.0"),
        key(model_id="openai:gpt-5.6-mini"),
        key(model_revision="2026-07-16"),
        key(prompt_id="research.answer.v2"),
        key(prompt_digest="b" * 64),
        key(input_data={"query": "different"}),
        key(freshness_token="etag-43"),
    ]
    assert len({base.digest, *(item.digest for item in variants)}) == 12


@pytest.mark.parametrize(
    "field",
    [
        "tenant_id",
        "namespace",
        "data_scope_hash",
        "tool_id",
        "tool_version",
        "model_id",
        "model_revision",
        "prompt_id",
        "prompt_digest",
        "input_hash",
        "freshness_token",
    ],
)
def test_cache_key_rejects_a_missing_persisted_dimension(field: str) -> None:
    payload = key().model_dump(mode="python")
    payload.pop(field)

    with pytest.raises(ValidationError, match=field):
        CacheKey.model_validate(payload)


@pytest.mark.parametrize(
    "field",
    [
        "tenant_id",
        "tool_id",
        "tool_version",
        "model_id",
        "model_revision",
        "prompt_id",
        "freshness_token",
    ],
)
def test_cache_key_rejects_blank_identity_or_version_dimensions(field: str) -> None:
    payload = key().model_dump(mode="python")
    payload[field] = "   "

    with pytest.raises(ValidationError, match=field):
        CacheKey.model_validate(payload)


def test_cache_key_rejects_missing_data_scope() -> None:
    with pytest.raises(ValueError, match="CACHE_DATA_SCOPE_REQUIRED"):
        key(data_scope=None)


@pytest.mark.asyncio
async def test_safe_cache_is_tenant_bound_expires_and_returns_copies() -> None:
    now = [10.0]
    cache = SafeCache(clock=lambda: now[0])
    cache_key = key()
    value = {"items": [{"source_id": "doc-1"}]}
    await cache.put(
        cache_key,
        tenant_id="tenant-a",
        kind="read_result",
        value=value,
        ttl_seconds=5,
    )
    value["items"][0]["source_id"] = "mutated"

    cached = await cache.get(cache_key, tenant_id="tenant-a")
    assert cached == {"items": [{"source_id": "doc-1"}]}
    with pytest.raises(PlatformError, match="CACHE_TENANT_MISMATCH"):
        await cache.get(cache_key, tenant_id="tenant-b")

    now[0] = 16.0
    assert await cache.get(cache_key, tenant_id="tenant-a") is None


@pytest.mark.asyncio
async def test_safe_cache_rejects_actions_and_credentials() -> None:
    cache = SafeCache()
    with pytest.raises(PlatformError, match="CACHE_KIND_FORBIDDEN"):
        await cache.put(
            key(),
            tenant_id="tenant-a",
            kind="action",
            value={"action_id": "a1"},
            ttl_seconds=5,
        )
    with pytest.raises(PlatformError, match="CACHE_SENSITIVE_VALUE_FORBIDDEN"):
        await cache.put(
            key(),
            tenant_id="tenant-a",
            kind="read_result",
            value={"nested": {"access_token": "secret"}},
            ttl_seconds=5,
        )
