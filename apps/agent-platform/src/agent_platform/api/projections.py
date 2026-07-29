from __future__ import annotations

from collections.abc import Mapping

from agent_platform.api.schemas import (
    ActionView,
    ArtifactMetadataView,
    CapabilityView,
)
from agent_platform.application.records import (
    ActionRecord,
    ArtifactRecord,
    CapabilityRecord,
)


def _approval_decision(value: object) -> str | None:
    if not isinstance(value, Mapping):
        return None
    decision = value.get("decision")
    return decision if isinstance(decision, str) else None


def action_view(action: ActionRecord) -> ActionView:
    return ActionView(
        action_id=action.action_id,
        run_id=action.run_id,
        action_type=action.action_type,
        preview=action.preview,
        payload_hash=action.payload_hash,
        risk=action.risk.value,
        approval_policy=action.approval_policy,
        required_approvals=action.required_approvals,
        approvals_received=sum(_approval_decision(item) == "approved" for item in action.approvals),
        status=action.status.value,
        expires_at=action.expires_at,
        receipt=action.receipt,
        verification=action.verification,
    )


def artifact_view(artifact: ArtifactRecord) -> ArtifactMetadataView:
    return ArtifactMetadataView(
        artifact_id=artifact.artifact_id,
        run_id=artifact.run_id,
        kind=artifact.kind,
        media_type=artifact.media_type,
        size_bytes=artifact.size_bytes,
        sha256=artifact.sha256,
        classification=artifact.classification.value,
        retention_policy=artifact.retention_policy,
        scan_status=artifact.scan_status,
        scan_provenance=artifact.scan_provenance,
        object_version_id=artifact.object_version_id,
        object_retain_until=artifact.object_retain_until,
        legal_hold_status=artifact.legal_hold_status,
        expires_at=artifact.expires_at,
    )


def capability_view(capability: CapabilityRecord) -> CapabilityView:
    return CapabilityView(
        name=capability.name,
        version=capability.version,
        effect=capability.effect,
        risk=capability.risk,
        enabled=capability.enabled,
        disabled_reason=capability.disabled_reason,
    )
