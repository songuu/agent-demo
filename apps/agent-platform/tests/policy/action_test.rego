package agent.action_test

import data.agent.action
import future.keywords.if

test_critical_commit_with_two_phishing_resistant_approvals_is_allowed if {
	action.result.allowed with input as {
		"phase": "commit",
		"principal": {
			"tenant_id": "tenant-a",
			"user_id": "commit-worker",
			"scopes": ["email:commit"],
			"auth_strength": "phishing_resistant",
		},
		"action": {
			"action_id": "action-1",
			"tenant_id": "tenant-a",
			"principal_id": "requester",
			"status": "approved",
			"payload_hash": "hash-1",
			"expires_at": "2099-01-01T00:00:00Z",
			"risk": "critical",
			"required_approvals": 2,
		},
		"approval": {"payload_hash": "hash-1"},
		"approvals": [
			{
				"actor_id": "approver-1",
				"auth_strength": "phishing_resistant",
				"decision": "approved",
				"payload_hash": "hash-1",
			},
			{
				"actor_id": "approver-2",
				"auth_strength": "phishing_resistant",
				"decision": "approved",
				"payload_hash": "hash-1",
			},
		],
		"tool": {"effect": "commit"},
		"caller": "commit-worker",
		"kill_switch": {"mode": "none"},
	}
}

test_critical_commit_with_only_mfa_approvals_is_denied if {
	not action.result.allowed with input as {
		"phase": "commit",
		"principal": {
			"tenant_id": "tenant-a",
			"user_id": "commit-worker",
			"scopes": ["email:commit"],
			"auth_strength": "mfa",
		},
		"action": {
			"action_id": "action-1",
			"tenant_id": "tenant-a",
			"principal_id": "requester",
			"status": "approved",
			"payload_hash": "hash-1",
			"expires_at": "2099-01-01T00:00:00Z",
			"risk": "critical",
			"required_approvals": 2,
		},
		"approval": {"payload_hash": "hash-1"},
		"approvals": [
			{
				"actor_id": "approver-1",
				"auth_strength": "mfa",
				"decision": "approved",
				"payload_hash": "hash-1",
			},
			{
				"actor_id": "approver-2",
				"auth_strength": "mfa",
				"decision": "approved",
				"payload_hash": "hash-1",
			},
		],
		"tool": {"effect": "commit"},
		"caller": "commit-worker",
		"kill_switch": {"mode": "none"},
	}
}

test_compensation_is_allowed_during_writes_only_kill_switch if {
	action.result.allowed with input as {
		"phase": "compensate",
		"principal": {
			"tenant_id": "tenant-a",
			"user_id": "commit-worker",
			"scopes": ["email:commit"],
			"auth_strength": "mfa",
		},
		"action": {
			"action_id": "action-2",
			"tenant_id": "tenant-a",
			"principal_id": "requester",
			"status": "verify_failed",
			"payload_hash": "hash-2",
			"expires_at": "2020-01-01T00:00:00Z",
			"risk": "high",
			"required_approvals": 1,
		},
		"approval": {"payload_hash": "hash-2"},
		"approvals": [
			{
				"actor_id": "approver-1",
				"auth_strength": "mfa",
				"decision": "approved",
				"payload_hash": "hash-2",
			},
		],
		"tool": {"effect": "commit"},
		"caller": "commit-worker",
		"kill_switch": {"mode": "writes"},
	}
}
