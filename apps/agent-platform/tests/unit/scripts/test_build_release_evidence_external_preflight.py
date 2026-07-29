from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from scripts.build_release_evidence import build_evidence
from tests.unit.scripts.test_build_release_evidence_approvals import (
    RELEASE_ENVIRONMENTS,
    _arguments,
)


def _mutate_preflight(
    path: Path,
    mutation: Callable[[dict[str, Any]], None],
) -> None:
    report = json.loads(path.read_text(encoding="utf-8"))
    mutation(report)
    path.write_text(
        json.dumps(
            report,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )


def test_release_evidence_publishes_validated_external_preflight_uri(
    tmp_path: Path,
) -> None:
    args = _arguments(tmp_path)
    receipt = json.loads(args.published_assets.read_text(encoding="utf-8"))

    evidence = build_evidence(args)

    assert len(evidence["evidence_publication"]["assets"]) == 22
    assert (
        evidence["external_release_preflight_uri"]
        == (receipt["assets"]["external_release_preflight"]["content_uri"])
    )


@pytest.mark.parametrize(
    ("field", "invalid_value", "expected_error"),
    (
        ("passed", False, "GITHUB_PREFLIGHT_REPORT_RESULT_MISMATCH"),
        ("passed", 1, "GITHUB_PREFLIGHT_REPORT_INVALID"),
        (
            "repository",
            "attacker/platform",
            "GITHUB_PREFLIGHT_REPORT_REPOSITORY_MISMATCH",
        ),
        (
            "release_tag",
            "v9.9.9",
            "GITHUB_PREFLIGHT_REPORT_RELEASE_TAG_MISMATCH",
        ),
        (
            "git_sha",
            "f" * 40,
            "GITHUB_PREFLIGHT_REPORT_GIT_SHA_MISMATCH",
        ),
        (
            "release_id",
            "release-attacker",
            "GITHUB_PREFLIGHT_REPORT_RELEASE_ID_MISMATCH",
        ),
        (
            "secret_values_accessed",
            True,
            "GITHUB_PREFLIGHT_REPORT_SECRET_ACCESS_INVALID",
        ),
        (
            "secret_values_accessed",
            0,
            "GITHUB_PREFLIGHT_REPORT_INVALID",
        ),
        ("issues", ["branch protection missing"], "GITHUB_PREFLIGHT_REPORT_ISSUES_PRESENT"),
        ("issues", {}, "GITHUB_PREFLIGHT_REPORT_INVALID"),
    ),
)
def test_release_evidence_rejects_invalid_external_preflight_identity_or_result(
    tmp_path: Path,
    field: str,
    invalid_value: object,
    expected_error: str,
) -> None:
    args = _arguments(tmp_path)
    _mutate_preflight(
        args.external_release_preflight,
        lambda report: report.__setitem__(field, invalid_value),
    )

    with pytest.raises(ValueError, match=expected_error):
        build_evidence(args)


def test_release_evidence_rechecks_release_tag_against_github_pathname_policy(
    tmp_path: Path,
) -> None:
    args = _arguments(tmp_path)
    release_tag = "agent-platform-v/rejected-by-github-glob"
    args.release_tag = release_tag
    _mutate_preflight(
        args.external_release_preflight,
        lambda report: report.__setitem__("release_tag", release_tag),
    )

    with pytest.raises(
        ValueError,
        match="GITHUB_PREFLIGHT_REPORT_RELEASE_TAG_POLICY_MISMATCH",
    ) as exc_info:
        build_evidence(args)
    assert "PUBLICATION_DIGEST_MISMATCH" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    (
        ("schema_version", "2.0"),
        ("default_branch", "develop"),
        ("operational_failure", True),
        ("operational_failure", 0),
        ("main_protection_source", "repository-ruleset"),
        ("main_protection_source", None),
        ("validated_at", "2026-07-28T12:00:00"),
        ("validated_at", "not-a-timestamp"),
    ),
)
def test_release_evidence_rejects_invalid_external_preflight_contract_fields(
    tmp_path: Path,
    field: str,
    invalid_value: object,
) -> None:
    args = _arguments(tmp_path)
    _mutate_preflight(
        args.external_release_preflight,
        lambda report: report.__setitem__(field, invalid_value),
    )

    with pytest.raises(ValueError, match="EXTERNAL_RELEASE_PREFLIGHT") as exc_info:
        build_evidence(args)
    assert "PUBLICATION_DIGEST_MISMATCH" not in str(exc_info.value)


def _valid_checks() -> list[dict[str, object]]:
    return [
        {"id": "repository-and-release-identity", "passed": True},
        {"id": "main-branch-protection", "passed": True, "source": "ruleset"},
        *(
            {"id": f"environment:{environment}", "passed": True}
            for environment in RELEASE_ENVIRONMENTS
        ),
    ]


@pytest.mark.parametrize(
    "checks",
    (
        _valid_checks()[:-1],
        [*_valid_checks(), {"id": "unexpected-check", "passed": True}],
        [*_valid_checks()[:-1], _valid_checks()[0]],
        [
            *(
                {**check, "passed": False}
                if check["id"] == "repository-and-release-identity"
                else check
                for check in _valid_checks()
            )
        ],
        [
            *(
                {**check, "passed": 1} if check["id"] == "main-branch-protection" else check
                for check in _valid_checks()
            )
        ],
        "not-a-check-list",
    ),
)
def test_release_evidence_requires_exact_passing_external_preflight_checks(
    tmp_path: Path,
    checks: object,
) -> None:
    args = _arguments(tmp_path)
    _mutate_preflight(
        args.external_release_preflight,
        lambda report: report.__setitem__("checks", checks),
    )

    with pytest.raises(ValueError, match="EXTERNAL_RELEASE_PREFLIGHT") as exc_info:
        build_evidence(args)
    assert "PUBLICATION_DIGEST_MISMATCH" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("environments", "expected_error"),
    (
        (
            list(RELEASE_ENVIRONMENTS[:-1]),
            "GITHUB_PREFLIGHT_REPORT_ENVIRONMENT_SET_MISMATCH",
        ),
        (
            [*RELEASE_ENVIRONMENTS, "agent-platform-development"],
            "GITHUB_PREFLIGHT_REPORT_ENVIRONMENT_SET_MISMATCH",
        ),
        (
            [
                "agent-platform-staging",
                "agent-platform-production-canary",
                "agent-platform-production-canary",
            ],
            "GITHUB_PREFLIGHT_REPORT_ENVIRONMENT_SET_MISMATCH",
        ),
        ("agent-platform-staging", "GITHUB_PREFLIGHT_REPORT_INVALID"),
    ),
)
def test_release_evidence_requires_exact_external_preflight_environment_set(
    tmp_path: Path,
    environments: object,
    expected_error: str,
) -> None:
    args = _arguments(tmp_path)
    _mutate_preflight(
        args.external_release_preflight,
        lambda report: report.__setitem__("validated_environments", environments),
    )

    with pytest.raises(ValueError, match=expected_error) as exc_info:
        build_evidence(args)
    assert "PUBLICATION_DIGEST_MISMATCH" not in str(exc_info.value)


def test_release_evidence_binds_external_preflight_readback_bytes(
    tmp_path: Path,
) -> None:
    args = _arguments(tmp_path)
    _mutate_preflight(
        args.external_release_preflight,
        lambda report: report.__setitem__("untrusted_extra", "tampered"),
    )

    with pytest.raises(
        ValueError,
        match="EXTERNAL_RELEASE_PREFLIGHT_PUBLICATION_DIGEST_MISMATCH",
    ):
        build_evidence(args)


def test_release_evidence_schema_requires_exactly_22_component_assets(
    tmp_path: Path,
) -> None:
    args = _arguments(tmp_path)
    schema_path = (
        Path(__file__).resolve().parents[3] / "deploy" / "ci" / "release-evidence.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assets_schema = schema["properties"]["evidence_publication"]["properties"]["assets"]

    assert assets_schema["minProperties"] == 22
    assert assets_schema["maxProperties"] == 22
    assert set(assets_schema["required"]) == set(assets_schema["properties"])
    assert "external_release_preflight" in assets_schema["required"]
    assert "external_release_preflight_uri" in schema["required"]

    evidence = build_evidence(args)

    assert (
        schema["properties"]["external_release_preflight_uri"]["pattern"]
        == "^https://.+/v1/artifacts/[0-9a-f-]{36}/content/sha256:[0-9a-f]{64}$"
    )
    assert evidence["external_release_preflight_uri"].startswith("https://")
