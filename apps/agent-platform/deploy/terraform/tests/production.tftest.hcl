mock_provider "kubernetes" {}

variables {
  environment  = "prod"
  namespace    = "agent-platform-prod"
  image_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  release_id   = "release-prod-20260727"
  git_sha      = "1111111111111111111111111111111111111111"

  foundation_attestation = {
    environment          = "prod"
    release_id           = "release-prod-20260727"
    git_sha              = "1111111111111111111111111111111111111111"
    image_digest         = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    terraform_version    = "1.9.8"
    source_sha256        = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    source_uri           = "https://evidence.example.invalid/foundation/sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    signature_bundle_uri = "https://evidence.example.invalid/foundation/prod.sigstore.json"
    validation_uri       = "https://evidence.example.invalid/foundation-validation/sha256:9999999999999999999999999999999999999999999999999999999999999999"
    signer_identity      = "platform-foundation-prod"
    signer_issuer        = "https://token.actions.githubusercontent.com"
    validated            = true
  }
  foundation_plan = {
    environment          = "prod"
    provider             = "example-cloud"
    account_reference    = "resource://foundation/prod/account"
    region               = "cn-test-1"
    module_source        = "git::https://example.invalid/platform-foundation.git?ref=v1.4.2"
    module_version       = "1.4.2"
    plan_id              = "prod-plan-20260727"
    plan_sha256          = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    plan_uri             = "https://evidence.example.invalid/foundation/sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    signature_bundle_uri = "https://evidence.example.invalid/foundation/prod.sigstore.json"
    signer_identity      = "platform-foundation-prod"
    signer_issuer        = "https://token.actions.githubusercontent.com"
  }

  postgres = {
    environment                = "prod"
    cluster_reference          = "resource://postgres/prod/cluster"
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
    restore_test_evidence_uri  = "https://evidence.example.invalid/dr/prod-postgres.json"
    role_secret_references = {
      api        = "secretref://postgres/prod/api"
      commit     = "secretref://postgres/prod/commit"
      management = "secretref://postgres/prod/management"
      migration  = "secretref://postgres/prod/migration"
      outbox     = "secretref://postgres/prod/outbox"
      retention  = "secretref://postgres/prod/retention"
      worker     = "secretref://postgres/prod/worker"
    }
  }

  artifact_storage = {
    prefix = "prod/artifacts/"
    final = {
      environment                  = "prod"
      bucket_reference             = "resource://artifact/prod/final"
      kms_key_reference            = "kmsref://artifact/prod/final"
      versioning_enabled           = true
      object_lock_enabled          = true
      object_lock_mode             = "GOVERNANCE"
      default_retention_enabled    = false
      per_object_retention_enabled = true
      minimum_retention_days       = 90
      lifecycle_policy_reference   = "resource://artifact/prod/final-lifecycle"
      public_access_blocked        = true
      tls_only                     = true
      malware_scan_required        = true
      signed_url_enabled           = true
    }
    staging = {
      environment                        = "prod"
      bucket_reference                   = "resource://artifact/prod/multipart"
      kms_key_reference                  = "kmsref://artifact/prod/multipart"
      versioning_enabled                 = true
      object_lock_enabled                = false
      lifecycle_policy_reference         = "resource://artifact/prod/multipart-lifecycle"
      abort_incomplete_multipart_days    = 1
      noncurrent_version_expiration_days = 7
      public_access_blocked              = true
      tls_only                           = true
    }
  }

  temporal = {
    environment                 = "prod"
    service_reference           = "resource://temporal/prod/service"
    namespace                   = "agent-platform-prod"
    tls_enabled                 = true
    managed_or_highly_available = true
    namespace_isolated          = true
    history_retention_days      = 30
    history_archival_enabled    = true
    worker_versioning_enabled   = true
    alerting_enabled            = true
  }

  opa_bundle = {
    environment                      = "prod"
    uri                              = "oci://registry.example.invalid/opa@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    digest                           = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    version                          = "2.3.1"
    signature_bundle_uri             = "https://evidence.example.invalid/opa/prod.sigstore.json"
    signer_identity                  = "platform-policy-prod"
    signer_issuer                    = "https://token.actions.githubusercontent.com"
    rollback_digest                  = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    fail_closed                      = true
    two_person_approval_evidence_uri = "https://evidence.example.invalid/opa/prod-approval.json"
  }

  egress = {
    environment             = "prod"
    default_deny            = true
    metadata_service_denied = true
    kubernetes_api_denied   = true
    proxy_references = {
      agent         = "resource://egress/prod/agent"
      artifact-scan = "resource://egress/prod/artifact-scan"
      commit        = "resource://egress/prod/commit"
      control       = "resource://egress/prod/control"
      delivery      = "resource://egress/prod/delivery"
      quota-redis   = "resource://egress/prod/quota-redis"
      retention     = "resource://egress/prod/retention"
    }
  }

  secret_manager = {
    environment          = "prod"
    manager_reference    = "resource://secrets/prod/manager"
    rotation_enabled     = true
    access_audit_enabled = true
    jit_admin_enabled    = true
    workload_identity_references = {
      agent-worker  = "identityref://prod/agent-worker"
      api           = "identityref://prod/api"
      commit-worker = "identityref://prod/commit-worker"
      migration     = "identityref://prod/migration"
      outbox        = "identityref://prod/outbox"
      retention     = "identityref://prod/retention"
    }
    secret_references = {
      action-payload-encryption = "secretref://prod/action-payload-encryption"
      agent-broker              = "secretref://prod/agent-broker"
      commit-broker             = "secretref://prod/commit-broker"
      database-api              = "secretref://prod/database-api"
      database-commit           = "secretref://prod/database-commit"
      database-management       = "secretref://prod/database-management"
      database-migration        = "secretref://prod/database-migration"
      database-outbox           = "secretref://prod/database-outbox"
      database-retention        = "secretref://prod/database-retention"
      database-worker           = "secretref://prod/database-worker"
      memory-encryption         = "secretref://prod/memory-encryption"
      openai                    = "secretref://prod/openai"
      quota-redis               = "secretref://prod/quota-redis"
      webhook-signing           = "secretref://prod/webhook-signing"
    }
    kms_key_references = {
      action-payload   = "kmsref://prod/action-payload"
      artifact         = "kmsref://prod/artifact"
      memory           = "kmsref://prod/memory"
      release-evidence = "kmsref://prod/release-evidence"
    }
  }

  otlp_endpoint        = "grpcs://otel.prod.example.invalid:4317"
  release_evidence_uri = "https://evidence.example.invalid/releases/prod/sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
}

run "production_mock_plan_satisfies_release_contract" {
  command = plan

  assert {
    condition     = output.foundation_plan_identity.plan_sha256 == "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    error_message = "the signed provider foundation plan digest must be preserved"
  }

  assert {
    condition = (
      output.foundation_attestation_identity.release_id == "release-prod-20260727" &&
      output.foundation_attestation_identity.git_sha == "1111111111111111111111111111111111111111" &&
      output.foundation_attestation_identity.image_digest == "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &&
      output.foundation_attestation_identity.validated
    )
    error_message = "the verified foundation attestation must preserve exact release, source, and image identity"
  }
}

run "reject_unsigned_foundation_plan" {
  command = plan

  variables {
    foundation_plan = {
      environment          = "prod"
      provider             = "example-cloud"
      account_reference    = "resource://foundation/prod/account"
      region               = "cn-test-1"
      module_source        = "git::https://example.invalid/platform-foundation.git?ref=v1.4.2"
      module_version       = "1.4.2"
      plan_id              = "prod-plan-20260727"
      plan_sha256          = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      plan_uri             = "https://evidence.example.invalid/foundation/sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      signature_bundle_uri = ""
      signer_identity      = "platform-foundation-prod"
      signer_issuer        = "https://token.actions.githubusercontent.com"
    }
  }

  expect_failures = [var.foundation_plan]
}

run "reject_production_postgres_without_pitr" {
  command = plan

  variables {
    postgres = {
      environment                = "prod"
      cluster_reference          = "resource://postgres/prod/cluster"
      managed                    = true
      high_availability          = true
      multi_zone                 = true
      pitr_enabled               = false
      backup_retention_days      = 14
      rpo_minutes                = 5
      rto_minutes                = 30
      tls_required               = true
      rls_enabled                = true
      connection_pooling_enabled = true
      restore_test_evidence_uri  = "https://evidence.example.invalid/dr/prod-postgres.json"
      role_secret_references = {
        api        = "secretref://postgres/prod/api"
        commit     = "secretref://postgres/prod/commit"
        management = "secretref://postgres/prod/management"
        migration  = "secretref://postgres/prod/migration"
        outbox     = "secretref://postgres/prod/outbox"
        retention  = "secretref://postgres/prod/retention"
        worker     = "secretref://postgres/prod/worker"
      }
    }
  }

  expect_failures = [terraform_data.release_contract]
}

run "reject_production_unlocked_final_artifact_bucket" {
  command = plan

  variables {
    artifact_storage = {
      prefix = "prod/artifacts/"
      final = {
        environment                  = "prod"
        bucket_reference             = "resource://artifact/prod/final"
        kms_key_reference            = "kmsref://artifact/prod/final"
        versioning_enabled           = true
        object_lock_enabled          = false
        object_lock_mode             = "GOVERNANCE"
        default_retention_enabled    = false
        per_object_retention_enabled = true
        minimum_retention_days       = 90
        lifecycle_policy_reference   = "resource://artifact/prod/final-lifecycle"
        public_access_blocked        = true
        tls_only                     = true
        malware_scan_required        = true
        signed_url_enabled           = true
      }
      staging = {
        environment                        = "prod"
        bucket_reference                   = "resource://artifact/prod/multipart"
        kms_key_reference                  = "kmsref://artifact/prod/multipart"
        versioning_enabled                 = true
        object_lock_enabled                = false
        lifecycle_policy_reference         = "resource://artifact/prod/multipart-lifecycle"
        abort_incomplete_multipart_days    = 1
        noncurrent_version_expiration_days = 7
        public_access_blocked              = true
        tls_only                           = true
      }
    }
  }

  expect_failures = [terraform_data.release_contract]
}

run "reject_production_locked_multipart_staging_bucket" {
  command = plan

  variables {
    artifact_storage = {
      prefix = "prod/artifacts/"
      final = {
        environment                  = "prod"
        bucket_reference             = "resource://artifact/prod/final"
        kms_key_reference            = "kmsref://artifact/prod/final"
        versioning_enabled           = true
        object_lock_enabled          = true
        object_lock_mode             = "GOVERNANCE"
        default_retention_enabled    = false
        per_object_retention_enabled = true
        minimum_retention_days       = 90
        lifecycle_policy_reference   = "resource://artifact/prod/final-lifecycle"
        public_access_blocked        = true
        tls_only                     = true
        malware_scan_required        = true
        signed_url_enabled           = true
      }
      staging = {
        environment                        = "prod"
        bucket_reference                   = "resource://artifact/prod/multipart"
        kms_key_reference                  = "kmsref://artifact/prod/multipart"
        versioning_enabled                 = true
        object_lock_enabled                = true
        lifecycle_policy_reference         = "resource://artifact/prod/multipart-lifecycle"
        abort_incomplete_multipart_days    = 1
        noncurrent_version_expiration_days = 7
        public_access_blocked              = true
        tls_only                           = true
      }
    }
  }

  expect_failures = [terraform_data.release_contract]
}

run "reject_production_temporal_without_tls" {
  command = plan

  variables {
    temporal = {
      environment                 = "prod"
      service_reference           = "resource://temporal/prod/service"
      namespace                   = "agent-platform-prod"
      tls_enabled                 = false
      managed_or_highly_available = true
      namespace_isolated          = true
      history_retention_days      = 30
      history_archival_enabled    = true
      worker_versioning_enabled   = true
      alerting_enabled            = true
    }
  }

  expect_failures = [terraform_data.release_contract]
}

run "reject_production_opa_fail_open" {
  command = plan

  variables {
    opa_bundle = {
      environment                      = "prod"
      uri                              = "oci://registry.example.invalid/opa@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
      digest                           = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
      version                          = "2.3.1"
      signature_bundle_uri             = "https://evidence.example.invalid/opa/prod.sigstore.json"
      signer_identity                  = "platform-policy-prod"
      signer_issuer                    = "https://token.actions.githubusercontent.com"
      rollback_digest                  = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
      fail_closed                      = false
      two_person_approval_evidence_uri = "https://evidence.example.invalid/opa/prod-approval.json"
    }
  }

  expect_failures = [terraform_data.release_contract]
}
run "reject_permissive_production_egress" {
  command = plan

  variables {
    egress = {
      environment             = "prod"
      default_deny            = false
      metadata_service_denied = true
      kubernetes_api_denied   = true
      proxy_references = {
        agent         = "resource://egress/prod/agent"
        artifact-scan = "resource://egress/prod/artifact-scan"
        commit        = "resource://egress/prod/commit"
        control       = "resource://egress/prod/control"
        delivery      = "resource://egress/prod/delivery"
        quota-redis   = "resource://egress/prod/quota-redis"
        retention     = "resource://egress/prod/retention"
      }
    }
  }

  expect_failures = [terraform_data.release_contract]
}

run "reject_incomplete_production_secret_references" {
  command = plan

  variables {
    secret_manager = {
      environment          = "prod"
      manager_reference    = "resource://secrets/prod/manager"
      rotation_enabled     = true
      access_audit_enabled = true
      jit_admin_enabled    = true
      workload_identity_references = {
        agent-worker  = "identityref://prod/agent-worker"
        api           = "identityref://prod/api"
        commit-worker = "identityref://prod/commit-worker"
        migration     = "identityref://prod/migration"
        outbox        = "identityref://prod/outbox"
        retention     = "identityref://prod/retention"
      }
      secret_references = {
        action-payload-encryption = "secretref://prod/action-payload-encryption"
        agent-broker              = "secretref://prod/agent-broker"
        commit-broker             = "secretref://prod/commit-broker"
        database-api              = "secretref://prod/database-api"
        database-commit           = "secretref://prod/database-commit"
        database-management       = "secretref://prod/database-management"
        database-migration        = "secretref://prod/database-migration"
        database-outbox           = "secretref://prod/database-outbox"
        database-retention        = "secretref://prod/database-retention"
        database-worker           = "secretref://prod/database-worker"
        memory-encryption         = "secretref://prod/memory-encryption"
        openai                    = "secretref://prod/openai"
        quota-redis               = "secretref://prod/quota-redis"
      }
      kms_key_references = {
        action-payload   = "kmsref://prod/action-payload"
        artifact         = "kmsref://prod/artifact"
        memory           = "kmsref://prod/memory"
        release-evidence = "kmsref://prod/release-evidence"
      }
    }
  }

  expect_failures = [terraform_data.release_contract]
}
run "reject_release_mismatched_foundation_attestation" {
  command = plan

  variables {
    foundation_attestation = {
      environment          = "prod"
      release_id           = "release-prod-20260727"
      git_sha              = "ffffffffffffffffffffffffffffffffffffffff"
      image_digest         = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      terraform_version    = "1.9.8"
      source_sha256        = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      source_uri           = "https://evidence.example.invalid/foundation/sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      signature_bundle_uri = "https://evidence.example.invalid/foundation/prod.sigstore.json"
      validation_uri       = "https://evidence.example.invalid/foundation-validation/sha256:9999999999999999999999999999999999999999999999999999999999999999"
      signer_identity      = "platform-foundation-prod"
      signer_issuer        = "https://token.actions.githubusercontent.com"
      validated            = true
    }
  }

  expect_failures = [terraform_data.release_contract]
}
