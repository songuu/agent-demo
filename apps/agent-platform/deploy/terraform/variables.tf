variable "environment" {
  description = "Isolated deployment environment."
  type        = string

  validation {
    condition     = contains(["test", "staging", "prod"], var.environment)
    error_message = "environment must be test, staging, or prod"
  }
}

variable "namespace" {
  description = "Environment-isolated Kubernetes namespace."
  type        = string

  validation {
    condition     = can(regex("^agent-platform-(test|staging|prod)$", var.namespace))
    error_message = "namespace must be agent-platform-test, agent-platform-staging, or agent-platform-prod"
  }
}

variable "image_digest" {
  description = "Promoted immutable application image digest."
  type        = string

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.image_digest))
    error_message = "image_digest must be a sha256 digest"
  }
}

variable "release_id" {
  description = "Immutable release identity bound to the external foundation readback."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", var.release_id))
    error_message = "release_id must be a stable release identifier"
  }
}

variable "git_sha" {
  description = "Exact source commit bound to the external foundation readback."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.git_sha))
    error_message = "git_sha must be a full lowercase Git SHA"
  }
}

variable "foundation_attestation" {
  description = "Signed, content-addressed apply/readback attestation consumed before deployment."
  type = object({
    environment          = string
    release_id           = string
    git_sha              = string
    image_digest         = string
    terraform_version    = string
    source_sha256        = string
    source_uri           = string
    signature_bundle_uri = string
    validation_uri       = string
    signer_identity      = string
    signer_issuer        = string
    validated            = bool
  })

  validation {
    condition = (
      var.foundation_attestation.terraform_version == "1.9.8" &&
      can(regex("^sha256:[0-9a-f]{64}$", var.foundation_attestation.source_sha256)) &&
      can(regex("^https://", var.foundation_attestation.source_uri)) &&
      strcontains(
        var.foundation_attestation.source_uri,
        var.foundation_attestation.source_sha256,
      ) &&
      can(regex("^https://", var.foundation_attestation.signature_bundle_uri)) &&
      can(regex("^https://", var.foundation_attestation.validation_uri)) &&
      length(trimspace(var.foundation_attestation.signer_identity)) >= 3 &&
      can(regex("^https://", var.foundation_attestation.signer_issuer))
    )
    error_message = "foundation_attestation must be signed, content-addressed, Terraform-versioned, and externally validated"
  }
}

variable "foundation_plan" {
  description = "Signed, content-addressed identity of the provider-specific foundation plan."
  type = object({
    environment          = string
    provider             = string
    account_reference    = string
    region               = string
    module_source        = string
    module_version       = string
    plan_id              = string
    plan_sha256          = string
    plan_uri             = string
    signature_bundle_uri = string
    signer_identity      = string
    signer_issuer        = string
  })

  validation {
    condition = (
      can(regex("^[a-z][a-z0-9-]{1,31}$", var.foundation_plan.provider)) &&
      startswith(var.foundation_plan.account_reference, "resource://") &&
      can(regex("^[a-z0-9][a-z0-9-]{1,62}$", var.foundation_plan.region)) &&
      can(regex("^git::https://[^[:space:]]+\\?ref=[^[:space:]]+$", var.foundation_plan.module_source)) &&
      can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.foundation_plan.module_version)) &&
      length(trimspace(var.foundation_plan.plan_id)) >= 8 &&
      can(regex("^sha256:[0-9a-f]{64}$", var.foundation_plan.plan_sha256)) &&
      can(regex("^(https|oci)://", var.foundation_plan.plan_uri)) &&
      strcontains(var.foundation_plan.plan_uri, var.foundation_plan.plan_sha256) &&
      can(regex("^https://", var.foundation_plan.signature_bundle_uri)) &&
      length(trimspace(var.foundation_plan.signer_identity)) >= 3 &&
      can(regex("^https://", var.foundation_plan.signer_issuer))
    )
    error_message = "foundation_plan must identify a signed, content-addressed, versioned external plan using non-secret references"
  }
}

variable "postgres" {
  description = "Provider-neutral contract for the externally managed PostgreSQL foundation."
  type = object({
    environment                = string
    cluster_reference          = string
    role_secret_references     = map(string)
    managed                    = bool
    high_availability          = bool
    multi_zone                 = bool
    pitr_enabled               = bool
    backup_retention_days      = number
    rpo_minutes                = number
    rto_minutes                = number
    tls_required               = bool
    rls_enabled                = bool
    connection_pooling_enabled = bool
    restore_test_evidence_uri  = string
  })

  validation {
    condition = (
      startswith(var.postgres.cluster_reference, "resource://") &&
      alltrue([
        for reference in values(var.postgres.role_secret_references) :
        startswith(reference, "secretref://")
      ]) &&
      var.postgres.backup_retention_days >= 1 &&
      var.postgres.rpo_minutes > 0 &&
      var.postgres.rto_minutes > 0 &&
      can(regex("^https://", var.postgres.restore_test_evidence_uri))
    )
    error_message = "postgres must use typed resource/secret references and positive backup objectives with HTTPS restore evidence"
  }
}

variable "artifact_storage" {
  description = "Governance contract for the final Artifact bucket and isolated multipart staging bucket."
  type = object({
    final = object({
      environment                  = string
      bucket_reference             = string
      kms_key_reference            = string
      versioning_enabled           = bool
      object_lock_enabled          = bool
      object_lock_mode             = string
      default_retention_enabled    = bool
      per_object_retention_enabled = bool
      minimum_retention_days       = number
      lifecycle_policy_reference   = string
      public_access_blocked        = bool
      tls_only                     = bool
      malware_scan_required        = bool
      signed_url_enabled           = bool
    })
    staging = object({
      environment                        = string
      bucket_reference                   = string
      kms_key_reference                  = string
      versioning_enabled                 = bool
      object_lock_enabled                = bool
      lifecycle_policy_reference         = string
      abort_incomplete_multipart_days    = number
      noncurrent_version_expiration_days = number
      public_access_blocked              = bool
      tls_only                           = bool
    })
    prefix = string
  })

  validation {
    condition = (
      startswith(var.artifact_storage.final.bucket_reference, "resource://") &&
      startswith(var.artifact_storage.final.kms_key_reference, "kmsref://") &&
      startswith(var.artifact_storage.final.lifecycle_policy_reference, "resource://") &&
      startswith(var.artifact_storage.staging.bucket_reference, "resource://") &&
      startswith(var.artifact_storage.staging.kms_key_reference, "kmsref://") &&
      startswith(var.artifact_storage.staging.lifecycle_policy_reference, "resource://") &&
      contains(["GOVERNANCE", "COMPLIANCE"], var.artifact_storage.final.object_lock_mode) &&
      var.artifact_storage.final.minimum_retention_days >= 1 &&
      var.artifact_storage.staging.abort_incomplete_multipart_days >= 1 &&
      var.artifact_storage.staging.noncurrent_version_expiration_days >= 1
    )
    error_message = "artifact_storage must use typed bucket/KMS/lifecycle references and valid retention controls"
  }
}

variable "temporal" {
  description = "Provider-neutral contract for externally managed or highly available Temporal."
  type = object({
    environment                 = string
    service_reference           = string
    namespace                   = string
    tls_enabled                 = bool
    managed_or_highly_available = bool
    namespace_isolated          = bool
    history_retention_days      = number
    history_archival_enabled    = bool
    worker_versioning_enabled   = bool
    alerting_enabled            = bool
  })

  validation {
    condition = (
      startswith(var.temporal.service_reference, "resource://") &&
      can(regex("^[a-z0-9][a-z0-9-]{2,62}$", var.temporal.namespace)) &&
      var.temporal.history_retention_days >= 1
    )
    error_message = "temporal must use a typed service reference, valid namespace, and positive history retention"
  }
}

variable "opa_bundle" {
  description = "Signed, versioned, fail-closed OPA bundle identity."
  type = object({
    environment                      = string
    uri                              = string
    digest                           = string
    version                          = string
    signature_bundle_uri             = string
    signer_identity                  = string
    signer_issuer                    = string
    rollback_digest                  = string
    fail_closed                      = bool
    two_person_approval_evidence_uri = string
  })

  validation {
    condition = (
      can(regex("^sha256:[0-9a-f]{64}$", var.opa_bundle.digest)) &&
      can(regex("^sha256:[0-9a-f]{64}$", var.opa_bundle.rollback_digest)) &&
      var.opa_bundle.digest != var.opa_bundle.rollback_digest &&
      can(regex("^(https|oci)://", var.opa_bundle.uri)) &&
      strcontains(var.opa_bundle.uri, var.opa_bundle.digest) &&
      can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.opa_bundle.version)) &&
      can(regex("^https://", var.opa_bundle.signature_bundle_uri)) &&
      length(trimspace(var.opa_bundle.signer_identity)) >= 3 &&
      can(regex("^https://", var.opa_bundle.signer_issuer)) &&
      can(regex("^https://", var.opa_bundle.two_person_approval_evidence_uri))
    )
    error_message = "opa_bundle must be signed, versioned, content-addressed, rollback-capable, and approval-backed"
  }
}

variable "egress" {
  description = "Default-deny egress and identity-aware proxy references supplied by the external foundation."
  type = object({
    environment             = string
    default_deny            = bool
    metadata_service_denied = bool
    kubernetes_api_denied   = bool
    proxy_references        = map(string)
  })

  validation {
    condition = alltrue([
      for reference in values(var.egress.proxy_references) :
      startswith(reference, "resource://")
    ])
    error_message = "all egress proxy entries must be opaque resource:// references, never credentials or endpoints with embedded secrets"
  }
}

variable "secret_manager" {
  description = "Secret Manager, KMS, and Workload Identity references; raw secret values are not accepted."
  type = object({
    environment                  = string
    manager_reference            = string
    workload_identity_references = map(string)
    secret_references            = map(string)
    kms_key_references           = map(string)
    rotation_enabled             = bool
    access_audit_enabled         = bool
    jit_admin_enabled            = bool
  })

  validation {
    condition = (
      startswith(var.secret_manager.manager_reference, "resource://") &&
      alltrue([
        for reference in values(var.secret_manager.workload_identity_references) :
        startswith(reference, "identityref://")
      ]) &&
      alltrue([
        for reference in values(var.secret_manager.secret_references) :
        startswith(reference, "secretref://")
      ]) &&
      alltrue([
        for reference in values(var.secret_manager.kms_key_references) :
        startswith(reference, "kmsref://")
      ])
    )
    error_message = "secret_manager accepts only resource://, identityref://, secretref://, and kmsref:// opaque references"
  }
}

variable "otlp_endpoint" {
  description = "TLS OpenTelemetry collector endpoint."
  type        = string

  validation {
    condition     = can(regex("^(https|grpcs)://", var.otlp_endpoint))
    error_message = "otlp_endpoint must use HTTPS or gRPC over TLS"
  }
}

variable "release_evidence_uri" {
  description = "Immutable external release evidence URI."
  type        = string

  validation {
    condition     = can(regex("^(https|oci)://", var.release_evidence_uri))
    error_message = "release_evidence_uri must use HTTPS or OCI"
  }
}
