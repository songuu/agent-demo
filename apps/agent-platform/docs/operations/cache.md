# Cache operating boundary

## Current status

Application caching is **disabled by construction**. `SafeCache` and `CacheKey`
are security primitives only; no API, workflow, model router, or tool execution
path constructs or injects a production cache instance. There is intentionally
no `CACHE_ENABLED` setting while that wiring does not exist. Prometheus cache
rules therefore must not be interpreted as evidence that application caching is
active.

## Cache-key contract

Every future cache call site must build the key from all of these dimensions:

- `tenant_id` and the canonical `data_scope_hash`;
- `tool_id` and `tool_version`;
- `model_id` and `model_revision`;
- `prompt_id` and the immutable `prompt_digest`;
- the canonical `input_hash`;
- a source-specific `freshness_token`.

`namespace` remains an additional projection boundary. Missing dimensions,
blank identities or versions, a missing data scope, malformed digests, and
unknown fields are rejected. Changing any dimension produces a different
digest.

Only non-authoritative read projections may be cached. Actions, approvals,
prepared actions, commit or compensation receipts, credentials, secrets, and
oversized values remain forbidden by `SafeCache`.

## Enablement gate

Do not add an enable flag until a production change also provides:

1. an owned cache backend and lifecycle injection at the real read call site;
2. immutable tool, model, and prompt version metadata at that call site;
3. tenant-scoped invalidation and source freshness handling;
4. hit, miss, rejection, latency, and eviction telemetry sourced from real
   operations;
5. cross-tenant, version-change, expiry, backend-failure, and rollback tests.

Until all five controls ship and are verified together, the supported
configuration is fixed at `cache.enabled = false`.
