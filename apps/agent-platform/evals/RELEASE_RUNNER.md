# Release Eval Runner

## Offline hard-control preflight

`run_release_evals.py` is credential-free. It executes every versioned local
dataset against deterministic platform controls, including policy, trajectory,
budget, transaction-recovery, tenant-isolation, and per-criterion verification
checks.

Run it from `apps/agent-platform`:

```powershell
.\.venv\Scripts\python.exe evals\run_release_evals.py `
  --mode offline `
  --output .artifacts\offline-release-evals.json
```

Exit code `0` proves only the offline hard controls passed. The report
deliberately keeps `full_release_ready=false`; it never invents model quality,
production baselines, or human-review evidence.

## Credentialed staging quality gate

`run_live_release_evals.py` requires at least 50 semantically independent,
versioned Golden, Edge, Adversarial, and Production-sample source scenarios.
Source case IDs, complete semantic fingerprints, and input fingerprints must all
be unique. Each source scenario produces exactly one high/critical candidate
run; changing an ID or execution ordinal cannot manufacture review population.
The runner executes those cases through the deployed staging API, binds both
fingerprints into the immutable audit constraints, and then applies
`release-policy.json`. Every live dataset row also declares an
`expected_capability_trajectory`: a contiguous ordered capability list with
canonical arguments and mandatory audit-receipt fields. The runner hashes arguments
with the same canonicalizer used by the tool gateway and rejects missing/extra calls,
wrong order, wrong arguments, status drift, or missing result/provider receipts.
Incident-derived
coverage remains bound to the passed offline hard-control artifact and is carried
into the OPS-03 summary. The normal runner bearer token must be tenant-scoped and limited to
`runs:create`, `runs:read`, and `audit:read`. Fault exercises use a separate
short-lived token with `eval:fault:inject`/`eval:fault:read`, the staging
`admin` role, and MFA; neither token may be shared with the Agent runtime.

```powershell
$env:AGENT_PLATFORM_RELEASE_TOKEN = "<short-lived-staging-token>"
$env:AGENT_PLATFORM_HUMAN_REVIEW_TOKEN = "<short-lived-review-token>"
$env:AGENT_PLATFORM_EVAL_FAULT_TOKEN = "<short-lived-staging-fault-token>"
$env:AGENT_PLATFORM_EVAL_FAULT_RECEIPT_PUBLIC_KEY_B64 = "<base64-encoded-ed25519-public-key>"
$env:AGENT_PLATFORM_EVAL_FAULT_RECEIPT_SIGNER_IDENTITY = "<fixed-controller-signer-id>"
.\.venv\Scripts\python.exe evals\run_live_release_evals.py `
  --base-url "https://agent-platform-staging.example.com" `
  --release-id "<release-id>" `
  --git-sha "<40-character-git-sha>" `
  --image-digest "sha256:<64-hex-image-digest>" `
  --offline-results .artifacts\offline-release-evals.json `
  --baseline .artifacts\approved-production-baseline.json `
  --baseline-validation .artifacts\approved-production-baseline-validation.json `
  --review-service-url "https://review.example.com/v1/release-reviews" `
  --candidate-manifest-output .artifacts\candidate-manifest.json `
  --candidate-results-output .artifacts\candidate-results.json `
  --human-review-output .artifacts\human-review-evidence.json `
  --output .artifacts\live-release-evals.json
```

The approved baseline is canonical JSON published as a signed, content-addressed
object. It binds a real prior production release, the measurement population and
window, the three raw release metrics, and the immutable raw-observation object:

```json
{
  "schema_version": "1.0",
  "kind": "live-release-baseline",
  "environment": "production",
  "prior_release": {
    "release_id": "release-2026-07-20",
    "git_sha": "<40-lowercase-hex>",
    "image_digest": "sha256:<64-lowercase-hex>"
  },
  "sampling": {
    "window_started_at": "2026-07-19T00:00:00Z",
    "window_ended_at": "2026-07-20T00:00:00Z",
    "sample_count": 500
  },
  "metrics": {
    "production_golden_success_rate": 0.98,
    "p95_latency_seconds": 45.0,
    "average_cost_per_success_usd": 1.25
  },
  "raw_evidence": {
    "sha256": "sha256:<64-lowercase-hex>",
    "uri": "https://evidence.example/production/sha256:<same-64-lowercase-hex>"
  },
  "signer": {
    "identity": "https://github.com/example/platform/.github/workflows/publish-live-baseline.yml@refs/heads/main",
    "issuer": "https://token.actions.githubusercontent.com"
  },
  "issued_at": "2026-07-20T01:00:00Z",
  "expires_at": "2026-07-27T01:00:00Z"
}
```

The `agent-platform-staging` Environment supplies
`AGENT_PLATFORM_STAGING_LIVE_BASELINE_URI`,
`AGENT_PLATFORM_STAGING_LIVE_BASELINE_SIGNER_IDENTITY`, and
`AGENT_PLATFORM_STAGING_LIVE_BASELINE_SIGNER_ISSUER`. The URI must be
credential-free HTTPS ending in `/sha256:<64>`; the workflow downloads that exact
object and `${URI}.sigstore.json`, checks the raw byte digest, and verifies the
exact Cosign OIDC identity and issuer. `validate_live_baseline.py` independently
re-verifies the signature, enforces `live-baseline.schema.json`, canonical bytes,
production environment, raw-evidence digest URI, timeline, expiry, and a seven-day
freshness limit, then writes `live-baseline-validation.json`. B64 baseline payloads
are prohibited. The live runner refuses an unvalidated or swapped baseline and
binds both the baseline byte digest and validation-receipt digest into candidate
artifacts and `live-release-evals.json`.

The external human-review evidence must bind 50–100 unique candidate case/run
pairs. Every candidate and review row carries the same `use_case`, `risk`,
`dataset`, and `category`; `risk` must be `high` or `critical`. The validator
requires the declared population size to equal the exact high-risk candidate
population and verifies value coverage plus joint stratified distribution across
`use_case`, `risk`, and `dataset`. Reusing two runs with different sample IDs is
rejected. The JSON Schema and semantic validator also require authenticated
reviewers, fresh HTTPS provenance, full rubric scores, and zero major/critical
findings. Reviewers receive the complete immutable review subject: final result,
claims, evidence, audit and Artifact references, executed grader results, fault
receipt, normalized expected/observed tool trajectories, and a trajectory binding
covering release ID, git SHA, image digest, candidate/source case, run, source/input
digests, and both trajectory digests. Each external review row must return the exact
`review_subject_sha256`; any field-level tampering changes the digest and blocks
the release.

Every dataset grader label is resolved through the closed
`evals/graders/registry.py` registry. Unknown labels, unknown expected fields,
missing HTTPS/SHA-256 observation sources, or unexecuted hard assertions fail
closed. Fault categories are armed through the authenticated staging-only API,
executed against the release-bound run, and finalized into an Ed25519-signed receipt
conforming to `evals/fault-receipt.schema.json`, bound to release ID, git SHA,
image digest, source scenario, component, mode,
outcome, run, snapshot, and audit. Artifact modes additionally prove the 200 MB
streaming/short-read boundary, <=8 MB peak buffer, checksum rejection, and
malware/decompression/MIME controls.

The staging API process reaches the isolated controller only when
`AGENT_EVAL_FAULT_HARNESS_URL` and `AGENT_EVAL_FAULT_HARNESS_TOKEN` are both set.
The URL must be credential-free HTTPS; production configuration rejects either
setting. The release evaluator independently verifies the signed receipt with
`AGENT_PLATFORM_EVAL_FAULT_RECEIPT_PUBLIC_KEY_B64` and requires the exact
`AGENT_PLATFORM_EVAL_FAULT_RECEIPT_SIGNER_IDENTITY`. The controller's private
signing key is never present in the release job or Agent workload.

The `agent-platform-staging` GitHub Environment must provide these release-job
secrets:

- `AGENT_PLATFORM_EVAL_FAULT_TOKEN`: short-lived inbound token used only by the
  evaluator to call the staging fault API.

It must also provide
`AGENT_PLATFORM_EVAL_FAULT_RECEIPT_PUBLIC_KEY_B64`,
`AGENT_PLATFORM_EVAL_FAULT_RECEIPT_SIGNER_IDENTITY`,
`AGENT_PLATFORM_EVAL_FAULT_HARNESS_URL`,
`AGENT_PLATFORM_EVAL_FAULT_HARNESS_SECRET_NAME`, and
`AGENT_PLATFORM_EVAL_FAULT_HARNESS_TOKEN_KEY` as Environment variables. The
named Kubernetes Secret must already exist in the staging namespace; its named
key contains the API process's outbound controller token. Helm injects the
credential-free URL and the token `secretKeyRef` only into the staging API
Deployment; shared worker configuration contains neither. The workflow never
copies either token or any private signing material into Helm values, a
ConfigMap, an artifact, or a command-line argument.
Missing inputs,
non-HTTPS controller URLs, missing chart values, or a missing Secret/key abort
the atomic staging deployment.

The release job passes one `RELEASE_ID`, `GITHUB_SHA`, and `IMAGE_DIGEST` to the
live evaluator, and deploys that same SHA/digest through Helm. The staging API
rejects a fault request whose SHA or digest differs from its runtime settings;
controller activation and the signed receipt must retain the exact release ID,
SHA, digest, case, and fault plan or promotion stops.

The live gate fails closed unless every normal case completes and every safety
case either completes safely or reaches an audit-proven controlled stop. Empty,
uncertainty, safety, capability, action, memory, classification, and criterion
fields are recomputed from the staging snapshot and immutable audit export;
none are synthesized constants. Cost/latency baselines and external review
provenance remain separately identified. Exit code `0` means the live gate
passed, `2` means release policy blocked promotion, and `3` means the runner or
its inputs failed.

Never place tokens, raw prompts, model responses, or review identities in the
release report. The pipeline stores the bounded metrics and artifact references;
the source systems retain detailed evidence under their own access controls.
