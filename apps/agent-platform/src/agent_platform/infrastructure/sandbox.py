"""Hardened Kubernetes Job and default-deny NetworkPolicy generation."""

from __future__ import annotations

from pathlib import PurePath
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agent_platform.domain.hashing import payload_hash

_SHELLS = {
    "bash",
    "cmd",
    "cmd.exe",
    "dash",
    "fish",
    "powershell",
    "pwsh",
    "sh",
    "zsh",
}
_SENSITIVE_ENV_KEYS = {
    "authorization",
    "aws_access_key_id",
    "google_application_credentials",
    "aws_secret_access_key",
    "cookie",
    "database_url",
    "openai_api_key",
    "password",
    "private_key",
    "secret",
    "token",
}


class SandboxLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    cpu_millicores: int = Field(default=500, ge=50, le=4_000)
    memory_mib: int = Field(default=512, ge=64, le=8_192)
    ephemeral_storage_mib: int = Field(default=256, ge=64, le=4_096)
    active_deadline_seconds: int = Field(default=300, ge=1, le=300)
    ttl_seconds_after_finished: int = Field(default=300, ge=30, le=3_600)


class SandboxJobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(min_length=1, max_length=256)
    run_id: str = Field(min_length=1, max_length=256)
    task_id: str = Field(min_length=1, max_length=128)
    namespace: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    image: str = Field(min_length=1, max_length=1_024)
    command: tuple[str, ...] = Field(min_length=1, max_length=32)
    environment: dict[str, str] = Field(default_factory=dict)
    limits: SandboxLimits = Field(default_factory=SandboxLimits)

    @field_validator("image")
    @classmethod
    def require_digest(cls, image: str) -> str:
        marker = "@sha256:"
        if marker not in image:
            raise ValueError("SANDBOX_IMAGE_DIGEST_REQUIRED: image must be pinned by sha256 digest")
        digest = image.rsplit(marker, 1)[1]
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError(
                "SANDBOX_IMAGE_DIGEST_REQUIRED: image digest must be 64 lowercase hex chars"
            )
        return image

    @model_validator(mode="after")
    def enforce_execution_boundary(self) -> Self:
        executable = PurePath(self.command[0]).name.lower()
        if executable in _SHELLS:
            raise ValueError("SANDBOX_SHELL_COMMAND_FORBIDDEN: use a registered runner entrypoint")
        for key in self.environment:
            normalized = key.strip().lower().replace("-", "_")
            if (
                normalized in _SENSITIVE_ENV_KEYS
                or normalized.endswith("_password")
                or normalized.endswith("_secret")
                or normalized.endswith("_token")
                or normalized.endswith("_api_key")
            ):
                raise ValueError(f"SANDBOX_SENSITIVE_ENV_FORBIDDEN: {key!r} cannot enter the Job")
        return self


class SandboxResources(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    job: dict[str, Any]
    network_policy: dict[str, Any]


def build_sandbox_resources(request: SandboxJobRequest) -> SandboxResources:
    identity_hash = payload_hash(
        {
            "tenant_id": request.tenant_id,
            "run_id": request.run_id,
            "task_id": request.task_id,
        }
    )[:16]
    name = f"agent-sandbox-{identity_hash}"
    labels = {
        "app.kubernetes.io/name": "agent-sandbox",
        "agent.openai.com/sandbox-id": identity_hash,
    }
    resource_limits = {
        "cpu": f"{request.limits.cpu_millicores}m",
        "memory": f"{request.limits.memory_mib}Mi",
        "ephemeral-storage": f"{request.limits.ephemeral_storage_mib}Mi",
    }
    job: dict[str, Any] = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": name,
            "namespace": request.namespace,
            "labels": labels,
        },
        "spec": {
            "activeDeadlineSeconds": request.limits.active_deadline_seconds,
            "backoffLimit": 0,
            "ttlSecondsAfterFinished": request.limits.ttl_seconds_after_finished,
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "serviceAccountName": "sandbox",
                    "automountServiceAccountToken": False,
                    "enableServiceLinks": False,
                    "restartPolicy": "Never",
                    "runtimeClassName": "gvisor",
                    "hostNetwork": False,
                    "hostPID": False,
                    "hostIPC": False,
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 65532,
                        "runAsGroup": 65532,
                        "fsGroup": 65532,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [
                        {
                            "name": "runner",
                            "image": request.image,
                            "imagePullPolicy": "IfNotPresent",
                            "command": list(request.command),
                            "env": [
                                {"name": key, "value": value}
                                for key, value in sorted(request.environment.items())
                            ],
                            "resources": {
                                "requests": dict(resource_limits),
                                "limits": dict(resource_limits),
                            },
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "runAsNonRoot": True,
                                "runAsUser": 65532,
                                "privileged": False,
                                "capabilities": {"drop": ["ALL"]},
                                "seccompProfile": {"type": "RuntimeDefault"},
                            },
                            # This is an isolated, size-bounded emptyDir,
                            # not the host temporary directory.
                            "volumeMounts": [
                                {"name": "tmp", "mountPath": "/tmp"}  # noqa: S108  # nosec B108
                            ],
                        }
                    ],
                    "volumes": [
                        {
                            "name": "tmp",
                            "emptyDir": {
                                "medium": "Memory",
                                "sizeLimit": f"{request.limits.ephemeral_storage_mib}Mi",
                            },
                        }
                    ],
                },
            },
        },
    }
    network_policy: dict[str, Any] = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": f"{name}-default-deny",
            "namespace": request.namespace,
            "labels": labels,
        },
        "spec": {
            "podSelector": {"matchLabels": labels},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [],
            "egress": [],
        },
    }
    return SandboxResources(job=job, network_policy=network_policy)
