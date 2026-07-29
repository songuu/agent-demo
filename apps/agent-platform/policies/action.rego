package agent.action

import future.keywords.if
import future.keywords.in

default allow := false

is_commit if {
	input.phase == "commit"
}

is_compensate if {
	input.phase == "compensate"
}

phase_supported if {
	is_commit
}

phase_supported if {
	is_compensate
}

valid_status if {
	is_commit
	input.action.status == "approved"
}

valid_status if {
	is_compensate
	input.action.status in {"committed", "verify_failed"}
}

not_expired if {
	time.now_ns() < time.parse_rfc3339_ns(input.action.expires_at)
}

expiry_ok if {
	is_commit
	not_expired
}

# Compensation is a recovery operation and remains available after the original
# approval expires. A global "all" kill switch can still stop it.
expiry_ok if {
	is_compensate
}

payload_unchanged if {
	input.action.payload_hash == input.approval.payload_hash
}

tenant_matches if {
	input.principal.tenant_id == input.action.tenant_id
}

approval_auth_ok(approval) if {
	input.action.risk in {"low", "medium", "high"}
	approval.auth_strength in {"mfa", "phishing_resistant"}
}

approval_auth_ok(approval) if {
	input.action.risk == "critical"
	approval.auth_strength == "phishing_resistant"
}

approved_actors contains actor_id if {
	approval := input.approvals[_]
	approval.decision == "approved"
	approval.payload_hash == input.action.payload_hash
	approval_auth_ok(approval)
	actor_id := approval.actor_id
}

required_count_ok if {
	count(approved_actors) >= input.action.required_approvals
}

separation_ok if {
	input.action.risk != "critical"
}

separation_ok if {
	input.action.risk == "critical"
	actor_id := approved_actors[_]
	actor_id != input.action.principal_id
}

kill_switch_clear if {
	is_commit
	input.kill_switch.mode == "none"
}

kill_switch_clear if {
	is_compensate
	input.kill_switch.mode in {"none", "writes"}
}

caller_ok if {
	input.tool.effect == "commit"
	input.caller == "commit-worker"
}

allow if {
	phase_supported
	valid_status
	expiry_ok
	payload_unchanged
	tenant_matches
	required_count_ok
	separation_ok
	kill_switch_clear
	caller_ok
}

deny_reason contains "unsupported_phase" if {
	not phase_supported
}

deny_reason contains "invalid_status" if {
	not valid_status
}

deny_reason contains "expired" if {
	not expiry_ok
}

deny_reason contains "stale_action_hash" if {
	not payload_unchanged
}

deny_reason contains "tenant_mismatch" if {
	not tenant_matches
}

deny_reason contains "approval_requirements_not_met" if {
	not required_count_ok
}

deny_reason contains "separation_of_duties" if {
	not separation_ok
}

deny_reason contains "kill_switch" if {
	not kill_switch_clear
}

deny_reason contains "invalid_caller" if {
	not caller_ok
}

result := {
	"allowed": allow,
	"allow_commit": allow,
	"reason_codes": deny_reason,
	"policy_version": data.bundle.version,
}