output "namespace" {
  value = kubernetes_namespace_v1.agent_platform.metadata[0].name
}

output "release_contract" {
  value = terraform_data.release_contract.output
}

output "foundation_plan_identity" {
  description = "Signed external foundation plan identity bound into the release contract."
  value = {
    plan_id              = var.foundation_plan.plan_id
    plan_sha256          = var.foundation_plan.plan_sha256
    plan_uri             = var.foundation_plan.plan_uri
    signature_bundle_uri = var.foundation_plan.signature_bundle_uri
    signer_identity      = var.foundation_plan.signer_identity
    signer_issuer        = var.foundation_plan.signer_issuer
  }
}
output "foundation_attestation_identity" {
  description = "Verified external foundation attestation bound to this release contract."
  value = {
    release_id           = var.release_id
    git_sha              = var.git_sha
    image_digest         = var.image_digest
    terraform_version    = var.foundation_attestation.terraform_version
    source_sha256        = var.foundation_attestation.source_sha256
    source_uri           = var.foundation_attestation.source_uri
    signature_bundle_uri = var.foundation_attestation.signature_bundle_uri
    validation_uri       = var.foundation_attestation.validation_uri
    signer_identity      = var.foundation_attestation.signer_identity
    signer_issuer        = var.foundation_attestation.signer_issuer
    validated            = var.foundation_attestation.validated
  }
}
