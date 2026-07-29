package agent.tool_test

import data.agent.tool
import future.keywords.if

test_internal_read_is_allowed if {
	tool.result.allowed with input as {
		"principal": {
			"tenant_id": "tenant-a",
			"scopes": ["knowledge:read"],
		},
		"run": {"allowed_capabilities": ["knowledge.search"]},
		"tool": {
			"enabled": true,
			"capability_name": "knowledge.search",
			"effect": "read",
			"risk": "medium",
			"required_scopes": ["knowledge:read"],
			"supported_data_classes": ["public", "internal"],
		},
		"request": {
			"data_scope": {"tenant_id": "tenant-a"},
			"classifications": ["internal"],
		},
		"kill_switch": {"mode": "none"},
		"caller": "agent",
	}
}

test_unsupported_classification_is_denied if {
	not tool.result.allowed with input as {
		"principal": {
			"tenant_id": "tenant-a",
			"scopes": ["knowledge:read"],
		},
		"run": {"allowed_capabilities": ["knowledge.search"]},
		"tool": {
			"enabled": true,
			"capability_name": "knowledge.search",
			"effect": "read",
			"risk": "medium",
			"required_scopes": ["knowledge:read"],
			"supported_data_classes": ["public", "internal"],
		},
		"request": {
			"data_scope": {"tenant_id": "tenant-a"},
			"classifications": ["restricted"],
		},
		"kill_switch": {"mode": "none"},
		"caller": "agent",
	}
}

test_agent_commit_effect_is_denied if {
	not tool.result.allowed with input as {
		"principal": {
			"tenant_id": "tenant-a",
			"scopes": ["email:commit"],
		},
		"run": {"allowed_capabilities": ["email.commit"]},
		"tool": {
			"enabled": true,
			"capability_name": "email.commit",
			"effect": "commit",
			"risk": "critical",
			"required_scopes": ["email:commit"],
			"supported_data_classes": ["internal"],
		},
		"request": {
			"data_scope": {"tenant_id": "tenant-a"},
			"classifications": ["internal"],
		},
		"kill_switch": {"mode": "none"},
		"caller": "agent",
	}
}
