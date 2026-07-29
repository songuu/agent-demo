# Agent Platform deployment assets

- `docker/`: local Compose and the reproducible multi-stage image build.
- `helm/agent-platform/`: production workload, identity, network, scaling, and
  disruption baselines.
- `kustomize/`: namespace-level default-deny and environment overlays.
- `terraform/`: provider-neutral, fail-closed external foundation release
  contract and Kubernetes namespace, with mock-plan tests.
- `observability/`: OTel Collector, Prometheus recording/alert rules, and six
  Grafana dashboards.
- `ci/`: PR gates, release evidence, and the canary progression contract.

Production uses an immutable application digest, a digest-pinned base image
passed through `PYTHON_BASE_IMAGE`, cloud Secret Manager references, managed HA
data services, and an approved release evidence bundle. The local Compose file
is deliberately excluded from production promotion.

The selected cloud foundation is intentionally external to this root module.
It must publish a signed, content-addressed Terraform plan identity plus typed
resource, secret, KMS, and workload-identity references. CI validates those
references and the production preconditions without fabricating a provider
apply when AWS, Google Cloud, Azure, or another provider has not been selected.

## Local stack verification

```powershell
docker compose --profile local -f deploy/docker/docker-compose.yml config
docker compose --profile local -f deploy/docker/docker-compose.yml build
docker compose --profile local -f deploy/docker/docker-compose.yml up -d
docker compose --profile local -f deploy/docker/docker-compose.yml ps
```

The local stack pins Postgres, Redis, Temporal, MinIO, OPA, and MinIO Client versions. Redis is deliberately plaintext and local-only in this dev profile; staging and production must use the TLS endpoint referenced by the Helm Secret.
An idempotent local-only init container restricts the webhook-secret volume to
UID/GID 10001 before API or outbox starts. API and outbox share only that
volume. Agent receives only
the read/prepare credential reference; commit receives only the business commit
reference. Retention is a one-shot service and therefore disables the inherited
API image healthcheck.

## Constrained single-node verification

The existing SPIFFE host can run a bounded development verification profile
when no production cluster is available. This path preserves the complete local
service graph but is explicitly not staging, production, HA, or release
evidence:

```powershell
pnpm deploy:agent-platform:single-node
pnpm deploy:agent-platform:single-node -- --apply
```

The deploy command requires a clean, pushed Git commit, builds the immutable
application image locally, streams it to the server without a remote tarball,
and merges `docker-compose.single-node.yml` after the local Compose file.
Credentials are generated once into a mode-`0600` remote environment file;
release Git SHA and the loaded Docker image ID are injected and read back by the
smoke test. The default release ID is `git-<full-sha>` for both manual and
workflow execution. A first install verifies that exact SHA on the remote
branch and atomically promotes its temporary clone, so retrying the same pushed
commit reuses the same release. Because this host has no transactional database
rollback plan, the script refuses an in-place upgrade to a different release.

All service ports are loopback-only. Authentication is intentionally disabled
inside this dev profile, so Nginx exposes only the base path, `/health`, and
`/ready`; every public `/v1/*` route returns `404`. Functional verification runs
through loopback on the host. The deployer owns and byte-compares a marked
Nginx block, rejects duplicate routes outside it, and verifies a forged-role
public `/v1/runs` request returns exactly `404` before switching `current`.
`/ready` intentionally returns `503` with exactly
`artifact_malware_scanner=error:policy-fail-closed:structural-only`, because no
external malware scanner is available. A successful constrained deployment
therefore means `/health=200`, that exact known readiness block, a completed
Temporal run, event readback, and Artifact readback. Before switching `current`,
the deployer also requires Postgres, Redis, Temporal, MinIO, API, Agent, Commit,
and Outbox to be healthy; OPA and Retention to be running; and MinIO init,
migration, and webhook-secret init to have exited successfully. It does not mean
the service is production-ready.

Local service and smoke gates run before the Nginx block is installed. A failed
first-install gate can leave loopback-only containers for diagnosis, but does
not switch `current` or expose the API. A later public-verification failure can
leave only the fail-closed health/readiness/404 Nginx block; `current` remains
unchanged and `/v1/*` remains denied.

The current MinIO service has no KMS backend and rejects both KMS and SSE-S3
requests. This override explicitly sets
`AGENT_ARTIFACT_ALLOW_UNENCRYPTED_LOCAL=true`; configuration validation rejects
that flag outside `dev` and rejects combining it with any KMS key. Artifact and
retention-archive objects in this profile consequently have no server-side
at-rest encryption. This is a known data-protection gap, not a production
exception. The retention worker remains running and performs its bounded sweep
once per day.

The profile caps the complete stack at 2 CPUs and 1760 MiB of container memory
with bounded swap. The deploy preflight and post-start checks refuse hosts below
the configured disk or memory-plus-swap thresholds. These controls reduce blast
radius; they do not satisfy the production prerequisites below.

## Production prerequisites

The cloud foundation must provide all of the following before Helm install:

1. Digest-pinned application and base images.
2. Managed PostgreSQL DSNs for `api`, `management`, `worker`, `commit`,
   `outbox`, `retention`, and `migration` roles. The outbox and retention roles
   require the documented BYPASSRLS maintenance grants; other roles must not.
3. Managed Temporal with TLS enabled, S3-compatible object storage with
   versioning/KMS, OPA, OpenTelemetry, DNS, and cloud Secret Manager.
4. Workload-identity annotations under `serviceAccounts.*.annotations`; do not
   inject cloud access keys into Pods.
5. Six identity-aware egress proxies labelled `control-egress-proxy`,
   `artifact-scan-egress-proxy`, `agent-egress-proxy`, `commit-egress-proxy`,
   `delivery-egress-proxy`, and `retention-egress-proxy` in namespace
   `platform`. Their ACLs must match the workload name. The malware scanner
   proxy may reach only the configured HTTPS scanning service. The Agent and
   Commit proxies may reach only the configured HTTPS Tool Gateway. The model
   gateway must be labelled `model-gateway` and expose TLS on port 443.
   A TLS Redis proxy labelled `quota-redis-proxy` must run in namespace `data`
   on port 6380; only the API plane receives egress permission to it.
6. Kubernetes Secrets containing only bootstrap references and encrypted
   runtime configuration:
   - database keys: `api-dsn`, `management-dsn`, `worker-dsn`, `commit-dsn`,
     `outbox-dsn`, `retention-dsn`, `migration-dsn`;
   - crypto keys: independent `action-payload-encryption-key` and
     `memory-encryption-key` (base64-encoded 32-byte values);
   - Agent provider keys `api-key` and explicit `project-id`, plus the read/prepare `broker-ref`;
   - Commit `broker-ref`;
   - quota keys `redis-url` (a `rediss://` URL for the TLS Redis proxy) and
     `key-hmac-secret` (an independent base64-encoded 32-byte HMAC key).
7. An immutable ConfigMap named by
   `config.modelPricingCatalogConfigMapName`. Its configured key must contain a
   versioned USD catalog for every allow-listed model:

   ```json
   {
     "schema_version": "1.0",
     "catalog_version": "billing-provider-version",
     "currency": "USD",
     "models": {
       "approved-model-id": {
         "input_usd_per_million_tokens": "0",
         "cached_input_usd_per_million_tokens": "0",
         "output_usd_per_million_tokens": "0"
       }
     }
   }
   ```

   Replace the example values with approved provider rates. Use a new immutable
   ConfigMap name for every catalog revision so the Pod template annotation
   triggers a controlled rollout; do not silently edit a released catalog.

8. The chart packages `deploy/catalogs/tool-catalog.v1.json` into an immutable,
   digest-versioned ConfigMap mounted read-only into API, Agent, and Commit.
   Release automation must pass the identity extracted from that exact file:

   ```text
   --set-string global.toolCatalogId="${TOOL_CATALOG_ID}"
   --set-string global.toolCatalogDigest="${TOOL_CATALOG_DIGEST}"
   ```

   Rendering fails when either value differs from the packaged bytes. Update the
   canonical catalog and chart copy together; the deployment tests enforce exact
   byte parity. Agent and Commit call the fixed HTTPS Tool Gateway through their
   dedicated explicit proxies. Queue and circuit limits are configured under
   `toolGateway`; they are not catalog-controlled.
The chart deliberately does not mount webhook signing secrets. API and outbox
resolve opaque references through the configured external Secret Manager.
Outbox webhook delivery uses `AGENT_WEBHOOK_EGRESS_PROXY_URL` explicitly and
does not trust ambient proxy variables.

Staging and production require `AGENT_ARTIFACT_MALWARE_SCAN_MODE=external`, an
HTTPS scan/health endpoint, and the explicit
`AGENT_ARTIFACT_MALWARE_EGRESS_PROXY_URL`. Scanner authentication belongs to
the proxy workload identity; do not mount a long-lived scanner API key. Scan
responses must bind the one-time request id, SHA-256, byte size, verdict,
engine/version, UTC scan time, and evidence id. Timeout, 5xx, stale/replayed
evidence, invalid responses, or any verdict other than exact `clean` block S3
storage. `/ready` reports scanner transport failure as
`error:scanner-unavailable:*` and a non-production scanning policy as
`error:policy-fail-closed:*`.

The only production storage exception is platform-owned canonical JSON from
the fixed `report/deterministic_runtime` and `tool_result/tool_gateway`
allowlist. Those bytes carry hash-, size-, serializer-, and sanitization-bound
`trusted_generated` provenance; they are never labelled malware-clean. API
uploads cannot supply or override this provenance. Missing, unknown, forged, or
non-allowlisted evidence fails closed before S3 write.

The static sandbox smoke Job is disabled by default. Real sandbox Jobs are
created from the validated `build_sandbox_resources` contract with a
digest-pinned runner image and registered command. If the optional smoke Job is
enabled, it only imports and validates that packaged contract; it does not run a
user task.

## Render and release gates

```powershell
helm lint deploy/helm/agent-platform
helm template agent-platform deploy/helm/agent-platform --namespace agent-platform
kubectl kustomize deploy/kustomize/overlays/staging
kubectl kustomize deploy/kustomize/overlays/prod
```

Replace every placeholder value, supply provider-specific ServiceAccount
annotations, and validate rendered manifests with the cluster policy engine
before install. A process becoming `Running` is not release completion: verify
`/ready`, worker readiness, Temporal task-queue polling, a full
Prepare → Approve → Commit → Verify flow, PostgreSQL/event/outbox readback,
Artifact upload/download, webhook delivery, retention output, metrics, traces,
recent logs, and rollback evidence independently.
