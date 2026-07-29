"""Role-neutral construction for the Artifact malware scanning boundary."""

from __future__ import annotations

from agent_platform.config import Settings
from agent_platform.infrastructure.artifacts.malware import (
    ExternalMalwareScanner,
    MalwareScanner,
    StructuralOnlyMalwareScanner,
)


def build_malware_scanner(settings: Settings) -> MalwareScanner:
    if settings.artifact_malware_scan_mode == "structural_only":
        if settings.environment not in {"dev", "test"}:
            raise RuntimeError("ARTIFACT_MALWARE_POLICY_FAIL_CLOSED")
        return StructuralOnlyMalwareScanner()
    scan_url = settings.artifact_malware_scan_url
    health_url = settings.artifact_malware_health_url
    proxy_url = settings.artifact_malware_egress_proxy_url
    if not scan_url or not health_url or not proxy_url:
        raise RuntimeError("ARTIFACT_MALWARE_EXTERNAL_SCANNER_REQUIRED")
    return ExternalMalwareScanner(
        scan_url=scan_url,
        health_url=health_url,
        egress_proxy_url=proxy_url,
        timeout_seconds=settings.artifact_malware_scan_timeout_seconds,
        max_result_age_seconds=settings.artifact_malware_max_result_age_seconds,
    )


async def malware_scanner_health(scanner: MalwareScanner) -> str:
    try:
        status = await scanner.healthcheck()
    except Exception as exc:
        code = getattr(exc, "code", type(exc).__name__)
        return f"error:scanner-unavailable:{code}"
    if status != "ok":
        return f"error:policy-fail-closed:{status}"
    return "ok"
