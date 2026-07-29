# Terraform deployment contract

This provider-neutral root module is a fail-closed release contract. It does not
pretend to provision a cloud foundation when no cloud provider has been selected.
Instead, a provider-specific foundation pipeline supplies a signed,
content-addressed plan identity and typed, non-secret references. The module
binds those inputs plus a verified foundation attestation to the exact environment,
release id, Git SHA, immutable application image, and release evidence before Helm
deployment.

The contract covers:

- managed multi-zone PostgreSQL HA, PITR, TLS, RLS, role isolation, connection
  pooling, restore evidence, and the platform RPO/RTO;
- separate final and multipart-staging Artifact buckets, independent KMS
  references, versioning, lifecycle controls, public-access blocking, TLS, and
  final-only per-object Object Lock;
- managed/HA Temporal with TLS, isolated namespaces, history retention/archive,
  worker versioning, and alerts;
- signed, content-addressed, fail-closed OPA bundles with rollback identity and
  two-person approval evidence;
- default-deny identity-aware egress proxy references; and
- Secret Manager, independent KMS keys, Workload Identity, rotation, audit, and
  JIT administration.

`resource://`, `secretref://`, `kmsref://`, and `identityref://` values are
canonical opaque identifiers. The module accepts no DSN, token, or raw-key
field, and validates every reference scheme. A provider adapter may map AWS
ARNs, Google Cloud resource names, Azure resource IDs, or equivalent identifiers
into these forms. The signed provider plan and its policy gate must also reject
a secret that has merely been mislabeled with a reference prefix; Terraform
cannot infer string provenance. Runtime workloads resolve valid references with
Workload Identity, so secret values do not enter Terraform state.

The selected cloud foundation remains responsible for actual provider resources,
DNS, and provider-specific policy. Its reviewed plan must be exported to
`foundation_plan` with a semantic module version, exact plan SHA-256, a
content-addressed HTTPS/OCI URI, detached signature bundle, signer identity, and
issuer. Production apply is intentionally outside this module. Before Helm, the
production workflow must fetch a canonical JSON attestation from an immutable
`/sha256:<digest>` HTTPS URI, verify its Sigstore bundle against the configured
identity and issuer, and validate either a completed Terraform apply plus cloud
readback or a read-only cloud API resource attestation. The attestation must bind
`release_id`, `git_sha`, `image_digest`, Terraform `1.9.8`, real provider resource
IDs, regions, approvals, and every critical foundation control. Missing cloud
credentials or evidence fails closed; mock plans never satisfy this production gate.

## Deterministic validation

Terraform and the Kubernetes provider are pinned in `versions.tf` and
`.terraform.lock.hcl`. The test suite uses Terraform mock providers, so plans
exercise every precondition without needing a live Kubernetes cluster or cloud
account:

```powershell
terraform -chdir=deploy/terraform fmt -check -recursive
terraform -chdir=deploy/terraform init -backend=false -input=false -lockfile=readonly
terraform -chdir=deploy/terraform validate
terraform -chdir=deploy/terraform test
```

The tests include valid staging and production plans plus fail-closed production
cases for an unsigned/mismatched plan, release-mismatched foundation attestation,
PostgreSQL without PITR, unlocked final Artifact storage, locked multipart staging,
Temporal without TLS, OPA fail-open, permissive egress, and incomplete Secret
Manager references. These are deterministic contract tests, not evidence that any
cloud resources exist; only the signed production attestation provides that readback.
