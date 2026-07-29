package agent.sandbox

import future.keywords.if
import future.keywords.in

default allow_egress := false

allow_egress if {
	input.task.sandbox_egress == "allowlist"
	input.destination.hostname in input.task.allowed_hosts
	input.destination.port == 443
	input.principal.tenant_id == input.task.tenant_id
	not input.destination.is_private_ip
	not input.destination.is_metadata_service
	not input.destination.is_kubernetes_api
}

reason_codes contains "egress_denied" if {
	not allow_egress
}

result := {
	"allowed": allow_egress,
	"allow_egress": allow_egress,
	"reason_codes": reason_codes,
	"policy_version": data.bundle.version,
}