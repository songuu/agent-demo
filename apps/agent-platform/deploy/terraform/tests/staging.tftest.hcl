mock_provider "kubernetes" {}

variables {
  environment  = "staging"
  namespace    = "agent-platform-staging"
  image_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  release_id   = "release-staging-20260727"
  git_sha      = "1111111111111111111111111111111111111111"

  foundation_attestation = {
    environment          = "staging"
    release_id           = "release-staging-20260727"
    git_sha              = "1111111111111111111111111111111111111111"
    image_digest         = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    terraform_version    = "1.9.8"
    source_sha256        = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    source_uri           = "https://evidence.example.invalid/foundation/sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    signature_bundle_uri = "https://evidence.example.invalid/foundation/staging.sigstore.json"
    validation_uri       = "https://evidence.example.invalid/foundation-validation/sha256:9999999999999999999999999999999999999999999999999999999999999999"
    signer_identity      = "platform-foundation-staging"
    signer_issuer        = "https://token.actions.githubusercontent.com"
    validated            = true
  }
  foundation_plan = {
    environment          = "staging"
    provider             = "example-cloud"
    account_reference    = "resource://foundation/staging/account"
    region               = "cn-test-1"
    module_source        = "git::https://example.invalid/platform-foundation.git?ref=v1.4.2"
    module_version       = "1.4.2"
    plan_id              = "staging-plan-20260727"
    plan_sha256          = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    plan_uri             = "https://evidence.example.invalid/foundation/sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    signature_bundle_uri = "https://evidence.example.invalid/foundation/staging.sigstore.json"
    signer_identity      = "platform-foundation-staging"
    signer_issuer        = "https://token.actions.githubusercontent.com"
  }

  postgres = {
    environment                = "staging"
    cluster_reference          = "resource://postgres/staging/cluster"
    managed                    = true
    high_availability          = true
    multi_zone                 = true
    pitr_enabled               = true
    backup_retention_days      = 14
    rpo_minutes                = 5
    rto_minutes                = 30
    tls_required               = true
    rls_enabled                = true
    connection_pooling_enabled = true
    restore_test_evidence_uri  = "https://evidence.example.invalid/dr/staging-postgres.json"
    role_secret_references = {
      api        = "secretref://postgres/staging/api"
      commit     = "secretref://postgres/staging/commit"
      management = "secretref://postgres/staging/management"
      migration  = "secretref://postgres/staging/migration"
      outbox     = "secretref://postgres/staging/outbox"
      retention  = "secretref://postgres/staging/retention"
      worker     = "secretref://postgres/staging/worker"
    }
  }

  artifact_storage = {
    prefix = "staging/artifacts/"
    final = {
      environment                  = "staging"
      bucket_reference             = "resource://artifact/staging/final"
      kms_key_reference            = "kmsref://artifact/staging/final"
      versioning_enabled           = true
      object_lock_enabled          = true
      object_lock_mode             = "GOVERNANCE"
      default_retention_enabled    = false
      per_object_retention_enabled = true
      minimum_retention_days       = 90
      lifecycle_policy_reference   = "resource://artifact/staging/final-lifecycle"
      public_access_blocked        = true
      tls_only                     = true
      malware_scan_required        = true
      signed_url_enabled           = true
    }
    staging = {
      environment                        = "staging"
      bucket_reference                   = "resource://artifact/staging/multipart"
      kms_key_reference                  = "kmsref://artifact/staging/multipart"
      versioning_enabled                 = true
      object_lock_enabled                = false
      lifecycle_policy_reference         = "resource://artifact/staging/multipart-lifecycle"
      abort_incomplete_multipart_days    = 1
      noncurrent_version_expiration_days = 7
      public_access_blocked              = true
      tls_only                           = true
    }
  }

  temporal = {
    environment                 = "staging"
    service_reference           = "resource://temporal/staging/service"
    namespace                   = "agent-platform-staging"
    tls_enabled                 = true
    managed_or_highly_available = true
    namespace_isolated          = true
    history_retention_days      = 30
    history_archival_enabled    = true
    worker_versioning_enabled   = true
    alerting_enabled            = true
  }

  opa_bundle = {
    environment                      = "staging"
    uri                              = "oci://registry.example.invalid/opa@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    digest                           = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    version                          = "2.3.1"
    signature_bundle_uri             = "https://evidence.example.invalid/opa/staging.sigstore.json"
    signer_identity                  = "platform-policy-staging"
    signer_issuer                    = "https://token.actions.githubusercontent.com"
    rollback_digest                  = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    fail_closed                      = true
    two_person_approval_evidence_uri = "https://evidence.example.invalid/opa/staging-approval.json"
  }

  egress = {
    environment             = "staging"
    default_deny            = true
    metadata_service_denied = true
    kubernetes_api_denied   = true
    proxy_references = {
      agent         = "resource://egress/staging/agent"
      artifact-scan = "resource://egress/staging/artifact-scan"
      commit        = "resource://egress/staging/commit"
      control       = "resource://egress/staging/control"
      delivery      = "resource://egress/staging/delivery"
      quota-redis   = "resource://egress/staging/quota-redis"
      retention     = "resource://egress/staging/retention"
    }
  }

  secret_manager = {
    environment          = "staging"
    manager_reference    = "resource://secrets/staging/manager"
    rotation_enabled     = true
    access_audit_enabled = true
    jit_admin_enabled    = true
    workload_identity_references = {
      agent-worker  = "identityref://staging/agent-worker"
      api           = "identityref://staging/api"
      commit-worker = "identityref://staging/commit-worker"
      migration     = "identityref://staging/migration"
      outbox        = "identityref://staging/outbox"
      retention     = "identityref://staging/retention"
    }
    secret_references = {
      action-payload-encryption = "secretref://staging/action-payload-encryption"
      agent-broker              = "secretref://staging/agent-broker"
      commit-broker             = "secretref://staging/commit-broker"
      database-api              = "secretref://staging/database-api"
      database-commit           = "secretref://staging/database-commit"
      database-management       = "secretref://staging/database-management"
      database-migration        = "secretref://staging/database-migration"
      database-outbox           = "secretref://staging/database-outbox"
      database-retention        = "secretref://staging/database-retention"
      database-worker           = "secretref://staging/database-worker"
      memory-encryption         = "secretref://staging/memory-encryption"
      openai                    = "secretref://staging/openai"
      quota-redis               = "secretref://staging/quota-redis"
      webhook-signing           = "secretref://staging/webhook-signing"
    }
    kms_key_references = {
      action-payload   = "kmsref://staging/action-payload"
      artifact         = "kmsref://staging/artifact"
      memory           = "kmsref://staging/memory"
      release-evidence = "kmsref://staging/release-evidence"
    }
  }

  otlp_endpoint        = "grpcs://otel.staging.example.invalid:4317"
  release_evidence_uri = "https://evidence.example.invalid/releases/staging/sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
}

run "staging_mock_plan_satisfies_release_contract" {
  command = plan

  assert {
    condition     = output.foundation_plan_identity.plan_sha256 == "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    error_message = "the signed provider foundation plan digest must be preserved"
  }

  assert {
    condition = (
      output.foundation_attestation_identity.release_id == "release-staging-20260727" &&
      output.foundation_attestation_identity.git_sha == "1111111111111111111111111111111111111111" &&
      output.foundation_attestation_identity.image_digest == "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &&
      output.foundation_attestation_identity.validated
    )
    error_message = "the verified foundation attestation must preserve exact release, source, and image identity"
  }
}
