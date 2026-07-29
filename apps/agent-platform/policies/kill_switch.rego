package agent.kill_switch

import future.keywords.if

default blocked := true

blocked := false if {
	input.mode == "none"
}

blocked := false if {
	input.mode == "writes"
	input.effect == "read"
}

default allowed := false

allowed if {
	not blocked
}

reason_codes contains "kill_switch" if {
	blocked
}

result := {
	"allowed": allowed,
	"reason_codes": reason_codes,
	"policy_version": data.bundle.version,
}