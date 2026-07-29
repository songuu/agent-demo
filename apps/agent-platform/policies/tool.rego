package agent.tool

import future.keywords.if
import future.keywords.in

default allow := false

deny_reason contains "tenant_mismatch" if {
	input.principal.tenant_id != input.request.data_scope.tenant_id
}

deny_reason contains "tool_disabled" if {
	not input.tool.enabled
}

deny_reason contains "kill_switch" if {
	input.kill_switch.mode == "all"
}

deny_reason contains "kill_switch" if {
	input.kill_switch.mode == "writes"
	input.tool.effect != "read"
}

deny_reason contains "scope_missing" if {
	required := input.tool.required_scopes[_]
	not required in input.principal.scopes
}

deny_reason contains "capability_not_in_contract" if {
	not input.tool.capability_name in input.run.allowed_capabilities
}

deny_reason contains "effect_not_allowed" if {
	input.tool.effect == "commit"
	input.caller == "agent"
}

deny_reason contains "classification_not_allowed" if {
	classification := input.request.classifications[_]
	not classification in input.tool.supported_data_classes
}

allow if {
	count(deny_reason) == 0
	input.tool.effect in {"read", "prepare"}
}

approval_required if {
	allow
	input.tool.effect == "prepare"
	input.tool.risk in {"high", "critical"}
}

default approval_required := false

result := {
	"allowed": allow,
	"reason_codes": deny_reason,
	"approval_required": approval_required,
	"data_scope": input.request.data_scope,
	"policy_version": data.bundle.version,
}
