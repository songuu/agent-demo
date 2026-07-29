from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from deploy.ci.validate_external_release_preflight import (
    PreflightInputError,
    PreflightRequirements,
    parse_requirements,
    verify_preflight_report,
)

PLATFORM_ROOT = Path(__file__).resolve().parents[4]
REQUIREMENTS_PATH = PLATFORM_ROOT / "deploy" / "ci" / "external-release-preflight.json"
REPOSITORY = "example/agent-platform"
RELEASE_TAG = "agent-platform-v1.2.3"
GIT_SHA = "a" * 40
RELEASE_ID = "12345-1"
REPORT_FIELDS = {
    "schema_version",
    "passed",
    "operational_failure",
    "repository",
    "default_branch",
    "release_tag",
    "git_sha",
    "release_id",
    "validated_at",
    "main_protection_source",
    "validated_environments",
    "checks",
    "issues",
    "secret_values_accessed",
}


def _requirements() -> tuple[dict[str, Any], PreflightRequirements]:
    raw = json.loads(REQUIREMENTS_PATH.read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    return raw, parse_requirements(raw)


def _valid_report(raw_requirements: dict[str, Any]) -> dict[str, Any]:
    environments = sorted(raw_requirements["environments"])
    return {
        "schema_version": "1.0",
        "passed": True,
        "operational_failure": False,
        "repository": REPOSITORY,
        "default_branch": raw_requirements["default_branch"],
        "release_tag": RELEASE_TAG,
        "git_sha": GIT_SHA,
        "release_id": RELEASE_ID,
        "validated_at": datetime.now(UTC).isoformat(),
        "main_protection_source": "classic",
        "validated_environments": environments,
        "checks": [
            {"id": "repository-and-release-identity", "passed": True},
            {"id": "main-branch-protection", "passed": True, "source": "classic"},
            *[{"id": f"environment:{environment}", "passed": True} for environment in environments],
        ],
        "issues": [],
        "secret_values_accessed": False,
    }


def _verify(report: dict[str, Any]) -> dict[str, Any]:
    _, requirements = _requirements()
    return verify_preflight_report(
        report,
        requirements,
        repository=REPOSITORY,
        release_tag=RELEASE_TAG,
        git_sha=GIT_SHA,
        release_id=RELEASE_ID,
    )


def _issue_codes(report: dict[str, Any]) -> set[str]:
    return {str(issue["code"]) for issue in report["issues"]}


def test_verify_report_accepts_exact_governance_and_emits_only_safe_known_fields() -> None:
    raw_requirements, _ = _requirements()
    report = _valid_report(raw_requirements)
    sentinel = "UNKNOWN-SECRET-MUST-NOT-BE-COPIED"
    report["unknown_payload"] = {"secret": sentinel}
    report["checks"][0]["unknown_payload"] = sentinel

    verified = _verify(report)

    assert verified["passed"] is True
    assert verified["operational_failure"] is False
    assert set(verified) == REPORT_FIELDS
    assert verified["repository"] == REPOSITORY
    assert verified["default_branch"] == "main"
    assert verified["release_tag"] == RELEASE_TAG
    assert verified["git_sha"] == GIT_SHA
    assert verified["release_id"] == RELEASE_ID
    assert verified["main_protection_source"] == "classic"
    assert verified["validated_environments"] == sorted(raw_requirements["environments"])
    assert {check["id"] for check in verified["checks"]} == {
        "repository-and-release-identity",
        "main-branch-protection",
        *{f"environment:{environment}" for environment in raw_requirements["environments"]},
    }
    assert all(check["passed"] is True for check in verified["checks"])
    assert verified["issues"] == []
    assert verified["secret_values_accessed"] is False
    assert sentinel not in json.dumps(verified, sort_keys=True)


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("passed", False, "GITHUB_PREFLIGHT_REPORT_RESULT_MISMATCH"),
        (
            "operational_failure",
            True,
            "GITHUB_PREFLIGHT_REPORT_OPERATIONAL_STATE_MISMATCH",
        ),
        ("repository", "attacker/platform", "GITHUB_PREFLIGHT_REPORT_REPOSITORY_MISMATCH"),
        ("default_branch", "trunk", "GITHUB_PREFLIGHT_REPORT_DEFAULT_BRANCH_MISMATCH"),
        ("release_tag", "agent-platform-v9", "GITHUB_PREFLIGHT_REPORT_RELEASE_TAG_MISMATCH"),
        ("git_sha", "f" * 40, "GITHUB_PREFLIGHT_REPORT_GIT_SHA_MISMATCH"),
        ("release_id", "other-1", "GITHUB_PREFLIGHT_REPORT_RELEASE_ID_MISMATCH"),
        (
            "main_protection_source",
            "unknown",
            "GITHUB_PREFLIGHT_REPORT_MAIN_PROTECTION_SOURCE_MISMATCH",
        ),
        ("issues", [{"secret": "do-not-copy"}], "GITHUB_PREFLIGHT_REPORT_ISSUES_PRESENT"),
        (
            "secret_values_accessed",
            True,
            "GITHUB_PREFLIGHT_REPORT_SECRET_ACCESS_INVALID",
        ),
    ],
)
def test_verify_report_rejects_governance_mismatch_without_copying_values(
    field: str,
    value: object,
    code: str,
) -> None:
    raw_requirements, _ = _requirements()
    report = _valid_report(raw_requirements)
    report[field] = value

    verified = _verify(report)

    assert verified["passed"] is False
    assert verified["operational_failure"] is False
    assert code in _issue_codes(verified)
    assert "do-not-copy" not in json.dumps(verified, sort_keys=True)


@pytest.mark.parametrize(
    "environments", [["agent-platform-staging"], ["agent-platform-staging"] * 3]
)
def test_verify_report_requires_the_exact_unique_environment_set(
    environments: list[str],
) -> None:
    raw_requirements, _ = _requirements()
    report = _valid_report(raw_requirements)
    report["validated_environments"] = environments

    verified = _verify(report)

    assert verified["passed"] is False
    assert "GITHUB_PREFLIGHT_REPORT_ENVIRONMENT_SET_MISMATCH" in _issue_codes(verified)
    assert verified["validated_environments"] == []


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "failed"])
def test_verify_report_requires_the_exact_unique_passing_check_set(mutation: str) -> None:
    raw_requirements, _ = _requirements()
    report = _valid_report(raw_requirements)
    if mutation == "missing":
        report["checks"].pop()
    elif mutation == "duplicate":
        report["checks"].append(dict(report["checks"][0]))
    else:
        report["checks"][0]["passed"] = False

    verified = _verify(report)

    assert verified["passed"] is False
    expected = (
        "GITHUB_PREFLIGHT_REPORT_CHECK_FAILED"
        if mutation == "failed"
        else "GITHUB_PREFLIGHT_REPORT_CHECK_SET_MISMATCH"
    )
    assert expected in _issue_codes(verified)


@pytest.mark.parametrize("validated_at", ["2026-07-28T12:00:00", "not-a-time", 123])
def test_verify_report_rejects_invalid_or_timezone_naive_timestamp(
    validated_at: object,
) -> None:
    raw_requirements, _ = _requirements()
    report = _valid_report(raw_requirements)
    report["validated_at"] = validated_at

    with pytest.raises(PreflightInputError, match="GITHUB_PREFLIGHT_REPORT_INVALID"):
        _verify(report)
