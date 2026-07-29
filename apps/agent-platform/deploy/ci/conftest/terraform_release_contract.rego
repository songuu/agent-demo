package main

import rego.v1

namespace := input.resource.kubernetes_namespace_v1.agent_platform[_]

deny contains message if {
	namespace
	labels := namespace.metadata[_].labels
	labels["pod-security.kubernetes.io/enforce"] != "restricted"
	message := "Terraform namespace must enforce the restricted Pod Security Standard"
}

release_contract := input.resource.terraform_data.release_contract[_].input

deny contains message if {
	release_contract
	required := {
		"artifact_bucket",
		"artifact_prefix",
		"artifact_storage",
		"egress",
		"environment",
		"foundation_attestation",
		"foundation_plan",
		"git_sha",
		"image_digest",
		"release_id",
		"opa_bundle",
		"opa_bundle_uri",
		"postgres",
		"release_evidence_uri",
		"secret_manager",
		"temporal",
		"temporal_namespace",
	}
	missing := required - {key | release_contract[key]}
	count(missing) > 0
	message := sprintf("Terraform release contract is missing fields: %v", [sort(missing)])
}
