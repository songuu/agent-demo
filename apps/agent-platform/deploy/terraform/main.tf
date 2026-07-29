locals {
  release_environment = contains(["staging", "prod"], var.environment)

  required_database_roles = toset([
    "api",
    "commit",
    "management",
    "migration",
    "outbox",
    "retention",
    "worker",
  ])
  required_egress_proxies = toset([
    "agent",
    "artifact-scan",
    "commit",
    "control",
    "delivery",
    "quota-redis",
    "retention",
  ])
  required_workload_identities = toset([
    "agent-worker",
    "api",
    "commit-worker",
    "migration",
    "outbox",
    "retention",
  ])
  required_secret_references = toset([
    "action-payload-encryption",
    "agent-broker",
    "commit-broker",
    "database-api",
    "database-commit",
    "database-management",
    "database-migration",
    "database-outbox",
    "database-retention",
    "database-worker",
    "memory-encryption",
    "openai",
    "quota-redis",
    "webhook-signing",
  ])
  required_kms_key_references = toset([
    "action-payload",
    "artifact",
    "memory",
    "release-evidence",
  ])
}

resource "kubernetes_namespace_v1" "agent_platform" {
  metadata {
    name = var.namespace
    labels = {
      environment                          = var.environment
      "app.kubernetes.io/part-of"          = "agent-platform"
      "pod-security.kubernetes.io/enforce" = "restricted"
      "pod-security.kubernetes.io/audit"   = "restricted"
      "pod-security.kubernetes.io/warn"    = "restricted"
    }
  }
}

resource "terraform_data" "release_contract" {
  input = {
    schema_version          = "1.0"
    environment             = var.environment
    namespace               = kubernetes_namespace_v1.agent_platform.metadata[0].name
    release_id              = var.release_id
    git_sha                 = var.git_sha
    image_digest            = var.image_digest
    foundation_attestation  = var.foundation_attestation
    foundation_plan         = var.foundation_plan
    postgres                = var.postgres
    artifact_storage        = var.artifact_storage
    artifact_bucket         = var.artifact_storage.final.bucket_reference
    artifact_staging_bucket = var.artifact_storage.staging.bucket_reference
    artifact_prefix         = var.artifact_storage.prefix
    temporal                = var.temporal
    temporal_namespace      = var.temporal.namespace
    opa_bundle              = var.opa_bundle
    opa_bundle_uri          = var.opa_bundle.uri
    egress                  = var.egress
    secret_manager          = var.secret_manager
    otlp_endpoint           = var.otlp_endpoint
    release_evidence_uri    = var.release_evidence_uri
  }

  lifecycle {
    precondition {
      condition = (
        var.foundation_attestation.environment == var.environment &&
        var.foundation_attestation.release_id == var.release_id &&
        var.foundation_attestation.git_sha == var.git_sha &&
        var.foundation_attestation.image_digest == var.image_digest &&
        (!local.release_environment || var.foundation_attestation.validated) &&
        var.foundation_plan.environment == var.environment &&
        var.postgres.environment == var.environment &&
        var.artifact_storage.final.environment == var.environment &&
        var.artifact_storage.staging.environment == var.environment &&
        var.temporal.environment == var.environment &&
        var.opa_bundle.environment == var.environment &&
        var.egress.environment == var.environment &&
        var.secret_manager.environment == var.environment
      )
      error_message = "all external foundation contracts and the verified attestation must bind the exact environment, release, Git SHA, and image digest"
    }

    precondition {
      condition = (
        !local.release_environment ||
        startswith(var.namespace, "agent-platform-${var.environment}")
      )
      error_message = "staging and prod must use an environment-isolated Kubernetes namespace"
    }

    precondition {
      condition = (
        !local.release_environment ||
        (
          var.postgres.managed &&
          var.postgres.high_availability &&
          var.postgres.multi_zone &&
          var.postgres.pitr_enabled &&
          var.postgres.backup_retention_days >= 7 &&
          var.postgres.rpo_minutes <= 5 &&
          var.postgres.rto_minutes <= 30 &&
          var.postgres.tls_required &&
          var.postgres.rls_enabled &&
          var.postgres.connection_pooling_enabled
        )
      )
      error_message = "staging and prod PostgreSQL must be managed, multi-zone HA, TLS/RLS/pool enabled, PITR protected, and meet RPO<=5m/RTO<=30m"
    }

    precondition {
      condition = (
        length(
          setsubtract(local.required_database_roles, toset(keys(var.postgres.role_secret_references)))
        ) == 0 &&
        length(distinct(values(var.postgres.role_secret_references))) == length(values(var.postgres.role_secret_references))
      )
      error_message = "PostgreSQL role secret references must cover every role and remain distinct"
    }

    precondition {
      condition = (
        startswith(var.artifact_storage.prefix, "${var.environment}/") &&
        var.artifact_storage.staging.bucket_reference != var.artifact_storage.final.bucket_reference &&
        var.artifact_storage.staging.kms_key_reference != var.artifact_storage.final.kms_key_reference
      )
      error_message = "Artifact final/staging buckets, KMS keys, and object prefix must be environment isolated"
    }

    precondition {
      condition = (
        !local.release_environment ||
        (
          var.artifact_storage.final.versioning_enabled &&
          var.artifact_storage.final.object_lock_enabled &&
          !var.artifact_storage.final.default_retention_enabled &&
          var.artifact_storage.final.per_object_retention_enabled &&
          var.artifact_storage.final.minimum_retention_days >= 90 &&
          var.artifact_storage.final.public_access_blocked &&
          var.artifact_storage.final.tls_only &&
          var.artifact_storage.final.malware_scan_required &&
          var.artifact_storage.final.signed_url_enabled
        )
      )
      error_message = "final Artifact storage must use KMS, versioning, per-object Object Lock, lifecycle retention, blocked public access, TLS, malware scanning, and signed URLs"
    }

    precondition {
      condition = (
        !local.release_environment ||
        (
          var.artifact_storage.staging.versioning_enabled &&
          !var.artifact_storage.staging.object_lock_enabled &&
          var.artifact_storage.staging.abort_incomplete_multipart_days <= 1 &&
          var.artifact_storage.staging.noncurrent_version_expiration_days <= 7 &&
          var.artifact_storage.staging.public_access_blocked &&
          var.artifact_storage.staging.tls_only
        )
      )
      error_message = "multipart staging storage must be KMS/versioned, unlocked, private/TLS-only, and expire incomplete/noncurrent data promptly"
    }

    precondition {
      condition = (
        !local.release_environment ||
        (
          var.temporal.tls_enabled &&
          var.temporal.managed_or_highly_available &&
          var.temporal.namespace_isolated &&
          var.temporal.history_retention_days >= 30 &&
          var.temporal.history_archival_enabled &&
          var.temporal.worker_versioning_enabled &&
          var.temporal.alerting_enabled &&
          strcontains(var.temporal.namespace, var.environment)
        )
      )
      error_message = "staging and prod Temporal must be TLS, managed/HA, environment-isolated, retained/archived, worker-versioned, and alerted"
    }

    precondition {
      condition = (
        !local.release_environment ||
        var.opa_bundle.fail_closed
      )
      error_message = "staging and prod OPA must fail closed with a signed, approved, versioned, rollback-capable bundle"
    }

    precondition {
      condition = (
        var.egress.default_deny &&
        var.egress.metadata_service_denied &&
        var.egress.kubernetes_api_denied &&
        length(setsubtract(local.required_egress_proxies, toset(keys(var.egress.proxy_references)))) == 0 &&
        length(distinct(values(var.egress.proxy_references))) == length(values(var.egress.proxy_references))
      )
      error_message = "egress must default deny metadata/Kubernetes API and supply distinct identity-aware proxy references for every workload boundary"
    }

    precondition {
      condition = (
        var.secret_manager.rotation_enabled &&
        var.secret_manager.access_audit_enabled &&
        var.secret_manager.jit_admin_enabled &&
        length(distinct(values(var.secret_manager.workload_identity_references))) == length(values(var.secret_manager.workload_identity_references)) &&
        length(distinct(values(var.secret_manager.secret_references))) == length(values(var.secret_manager.secret_references)) &&
        length(distinct(values(var.secret_manager.kms_key_references))) == length(values(var.secret_manager.kms_key_references)) &&
        length(setsubtract(
          local.required_workload_identities,
          toset(keys(var.secret_manager.workload_identity_references))
        )) == 0 &&
        length(setsubtract(
          local.required_secret_references,
          toset(keys(var.secret_manager.secret_references))
        )) == 0 &&
        length(setsubtract(
          local.required_kms_key_references,
          toset(keys(var.secret_manager.kms_key_references))
        )) == 0
      )
      error_message = "Secret Manager must use audited rotation/JIT access and provide all workload identity, secret, and independent KMS references"
    }
  }
}
