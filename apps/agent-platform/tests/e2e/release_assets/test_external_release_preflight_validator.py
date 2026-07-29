from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from urllib.request import Request

import pytest
import yaml
from deploy.ci.validate_external_release_preflight import (
    ApiResponse,
    GitHubApiClient,
    PreflightInputError,
    _RejectRedirects,
    collect_snapshot,
    parse_requirements,
    validate_snapshot,
)

PLATFORM_ROOT = Path(__file__).resolve().parents[3]
REPOSITORY_ROOT = PLATFORM_ROOT.parents[1]
VALIDATOR = PLATFORM_ROOT / "deploy" / "ci" / "validate_external_release_preflight.py"
REQUIREMENTS = PLATFORM_ROOT / "deploy" / "ci" / "external-release-preflight.json"
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "agent-platform-release.yml"
REPOSITORY = "example/agent-platform"
RELEASE_TAG = "agent-platform-v1.2.3"
GIT_SHA = "a" * 40
RELEASE_ID = "12345-1"


def _requirements() -> dict[str, Any]:
    value = json.loads(REQUIREMENTS.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _valid_snapshot(requirements: dict[str, Any]) -> dict[str, Any]:
    environments: dict[str, Any] = {}
    policy = requirements["deployment_policy"]
    for environment_name, requirement in requirements["environments"].items():
        protection_rules: list[dict[str, Any]] = []
        if requirement["minimum_reviewers"]:
            protection_rules.append(
                {
                    "type": "required_reviewers",
                    "prevent_self_review": requirement["prevent_self_review"],
                    "reviewers": [
                        {
                            "type": "Team",
                            "reviewer": {"id": 17, "slug": "release-reviewers"},
                        }
                    ],
                }
            )
        environments[environment_name] = {
            "configuration": {
                "name": environment_name,
                "protection_rules": protection_rules,
                "deployment_branch_policy": {
                    "protected_branches": False,
                    "custom_branch_policies": True,
                },
            },
            "deployment_branch_policies": [{"name": policy["name"], "type": policy["type"]}],
            "variable_names": list(requirement["required_variables"]),
            "secret_names": list(requirement["required_secrets"]),
        }

    return {
        "schema_version": "1.0",
        "repository": {
            "full_name": REPOSITORY,
            "default_branch": requirements["default_branch"],
        },
        "main_branch_protection": {
            "status": 200,
            "body": {
                "enforce_admins": {"enabled": True},
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                    "bypass_pull_request_allowances": {
                        "users": [],
                        "teams": [],
                        "apps": [],
                    },
                },
                "required_status_checks": {
                    "strict": True,
                    "contexts": [
                        requirements["branch_protection"]["required_status_checks"][0]["context"]
                    ],
                    "checks": [
                        {
                            "context": requirements["branch_protection"]["required_status_checks"][
                                0
                            ]["context"],
                            "app_id": requirements["branch_protection"]["required_status_checks"][
                                0
                            ]["integration_id"],
                        }
                    ],
                },
            },
        },
        "rulesets": [],
        "environments": environments,
    }


def _valid_preflight_report() -> dict[str, Any]:
    raw_requirements = _requirements()
    return validate_snapshot(
        _valid_snapshot(raw_requirements),
        parse_requirements(raw_requirements),
        repository=REPOSITORY,
        release_tag=RELEASE_TAG,
        git_sha=GIT_SHA,
        release_id=RELEASE_ID,
    )


def _run(
    tmp_path: Path,
    snapshot: object,
    *,
    requirements: dict[str, Any] | None = None,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    snapshot_path = tmp_path / "github-preflight-snapshot.json"
    requirements_path = tmp_path / "external-release-preflight.json"
    output_path = tmp_path / "external-release-preflight-report.json"
    snapshot_path.write_text(
        json.dumps(snapshot, ensure_ascii=False),
        encoding="utf-8",
    )
    requirements_path.write_text(
        json.dumps(requirements or _requirements(), ensure_ascii=False),
        encoding="utf-8",
    )
    completed = subprocess.run(  # noqa: S603 - repository-owned validator
        [
            sys.executable,
            str(VALIDATOR),
            "--snapshot",
            str(snapshot_path),
            "--requirements",
            str(requirements_path),
            "--repository",
            REPOSITORY,
            "--release-tag",
            RELEASE_TAG,
            "--git-sha",
            GIT_SHA,
            "--release-id",
            RELEASE_ID,
            "--output",
            str(output_path),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    return completed, output_path


def _run_verify_report(
    tmp_path: Path,
    report: object | None,
    *,
    include_snapshot: bool = False,
    release_tag: str = RELEASE_TAG,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    report_path = tmp_path / "downloaded-external-release-preflight.json"
    requirements_path = tmp_path / "external-release-preflight.json"
    output_path = tmp_path / "verified-external-release-preflight.json"
    snapshot_path = tmp_path / "github-preflight-snapshot.json"
    if report is not None:
        report_path.write_text(
            json.dumps(report, ensure_ascii=False),
            encoding="utf-8",
        )
    requirements_path.write_text(
        json.dumps(_requirements(), ensure_ascii=False),
        encoding="utf-8",
    )
    command = [
        sys.executable,
        str(VALIDATOR),
        "--verify-report",
        str(report_path),
        "--requirements",
        str(requirements_path),
        "--repository",
        REPOSITORY,
        "--release-tag",
        release_tag,
        "--git-sha",
        GIT_SHA,
        "--release-id",
        RELEASE_ID,
        "--output",
        str(output_path),
    ]
    if include_snapshot:
        snapshot_path.write_text("{}", encoding="utf-8")
        command.extend(["--snapshot", str(snapshot_path)])
    completed = subprocess.run(  # noqa: S603 - repository-owned validator
        command,
        capture_output=True,
        check=False,
        text=True,
    )
    return completed, output_path


def _issue_codes(report_path: Path) -> set[str]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    return {issue["code"] for issue in report["issues"]}


def _workflow_job_references(job: object, context: str) -> set[str]:
    serialized = json.dumps(job, sort_keys=True)
    return set(re.findall(rf"\$\{{\{{\s*{context}\.([A-Z0-9_]+)\s*\}}\}}", serialized))


class _FakeGitHubClient:
    def __init__(
        self,
        requirements: dict[str, Any],
        *,
        missing_environment: str | None = None,
        ruleset_detail: dict[str, Any] | None = None,
    ) -> None:
        self.requirements = requirements
        self.missing_environment = missing_environment
        self.ruleset_detail = ruleset_detail
        self.sentinel = "LIVE-SECRET-VALUE-MUST-BE-DROPPED"
        self.calls: list[str] = []
        self.environment_payloads = _valid_snapshot(requirements)["environments"]

    def get(self, path: str, *, allow_not_found: bool = False) -> ApiResponse:
        self.calls.append(f"GET {path}")
        repository_path = "/repos/example/agent-platform"
        if path == repository_path:
            return ApiResponse(
                status=200,
                value={"full_name": REPOSITORY, "default_branch": "main"},
            )
        if path == f"{repository_path}/branches/main/protection":
            return ApiResponse(
                status=200,
                value=_valid_snapshot(self.requirements)["main_branch_protection"]["body"],
            )
        if path == f"{repository_path}/rulesets/7?includes_parents=true":
            assert self.ruleset_detail is not None
            return ApiResponse(status=200, value=self.ruleset_detail)
        for environment_name, payload in self.environment_payloads.items():
            environment_path = f"{repository_path}/environments/{environment_name}"
            if path != environment_path:
                continue
            if environment_name == self.missing_environment:
                assert allow_not_found is True
                return ApiResponse(status=404, value=None)
            return ApiResponse(status=200, value=payload["configuration"])
        raise AssertionError(f"unexpected GET {path}")

    def paginated_list(self, path: str, *, per_page: int) -> list[object]:
        self.calls.append(f"GET {path} pages at {per_page}")
        assert path == "/repos/example/agent-platform/rulesets"
        return [] if self.ruleset_detail is None else [{"id": 7}]

    def paginated_object_items(
        self,
        path: str,
        *,
        key: str,
        per_page: int,
    ) -> list[object]:
        self.calls.append(f"GET {path} pages at {per_page}")
        for environment_name, requirement in self.requirements["environments"].items():
            environment_path = f"/repos/example/agent-platform/environments/{environment_name}"
            if not path.startswith(environment_path):
                continue
            assert environment_name != self.missing_environment
            if path.endswith("/deployment-branch-policies"):
                policy = self.requirements["deployment_policy"]
                assert key == "branch_policies"
                return [{"name": policy["name"], "type": policy["type"]}]
            if path.endswith("/variables"):
                assert key == "variables"
                return [{"name": name} for name in requirement["required_variables"]]
            if path.endswith("/secrets"):
                assert key == "secrets"
                return [
                    {"name": name, "value": self.sentinel}
                    for name in requirement["required_secrets"]
                ]
        raise AssertionError(f"unexpected paginated GET {path}")


def _collect_with_fake(
    requirements: dict[str, Any],
    *,
    missing_environment: str | None = None,
    ruleset_detail: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], _FakeGitHubClient]:
    fake = _FakeGitHubClient(
        requirements,
        missing_environment=missing_environment,
        ruleset_detail=ruleset_detail,
    )
    snapshot = collect_snapshot(
        cast(GitHubApiClient, fake),
        repository=REPOSITORY,
        requirements=parse_requirements(requirements),
    )
    return snapshot, fake


def test_redirect_handler_never_forwards_the_app_token() -> None:
    request = Request("https://api.github.com/repos/example/agent-platform")

    redirected = _RejectRedirects().redirect_request(
        request,
        cast(Any, None),
        302,
        "Found",
        cast(Any, {}),
        "https://attacker.invalid/collect",
    )

    assert redirected is None


@pytest.mark.parametrize(
    ("server_url", "api_url"),
    [
        ("https://github.com", "https://api.github.com"),
        ("https://github.example.com", "https://github.example.com/api/v3"),
        ("https://tenant.ghe.com", "https://api.tenant.ghe.com"),
    ],
)
def test_api_client_accepts_only_github_derived_api_origins(
    server_url: str,
    api_url: str,
) -> None:
    GitHubApiClient(
        server_url=server_url,
        api_url=api_url,
        token="test-token",
        timeout_seconds=1,
    )


@pytest.mark.parametrize(
    "api_url",
    [
        "https://attacker.invalid",
        "https://api.github.com.attacker.invalid",
        "https://api-github.com",
    ],
)
def test_api_client_rejects_an_api_origin_not_derived_from_the_server(
    api_url: str,
) -> None:
    with pytest.raises(PreflightInputError, match="GITHUB_PREFLIGHT_API_ORIGIN_UNTRUSTED"):
        GitHubApiClient(
            server_url="https://github.com",
            api_url=api_url,
            token="test-token",
            timeout_seconds=1,
        )


def test_live_collector_reads_only_metadata_and_drops_secret_values() -> None:
    requirements = _requirements()
    parsed_requirements = parse_requirements(requirements)

    snapshot, fake = _collect_with_fake(requirements)
    report = validate_snapshot(
        snapshot,
        parsed_requirements,
        repository=REPOSITORY,
        release_tag=RELEASE_TAG,
        git_sha=GIT_SHA,
        release_id=RELEASE_ID,
    )

    assert report["passed"] is True
    assert fake.sentinel not in json.dumps(snapshot, sort_keys=True)
    assert fake.sentinel not in json.dumps(report, sort_keys=True)
    assert all(call.startswith("GET ") for call in fake.calls)
    for environment_name in requirements["environments"]:
        base = f"/repos/example/agent-platform/environments/{environment_name}"
        assert f"GET {base}" in fake.calls
        assert any(call.startswith(f"GET {base}/variables") for call in fake.calls)
        assert any(call.startswith(f"GET {base}/secrets") for call in fake.calls)
        assert any(call.startswith(f"GET {base}/deployment-branch-policies") for call in fake.calls)


@pytest.mark.parametrize("include_bypass_actors", [True, False])
def test_live_collector_never_invents_missing_ruleset_bypass_evidence(
    include_bypass_actors: bool,
) -> None:
    requirements = _requirements()
    ruleset_detail: dict[str, Any] = {
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "rules": [],
    }
    if include_bypass_actors:
        ruleset_detail["bypass_actors"] = []

    snapshot, _ = _collect_with_fake(
        requirements,
        ruleset_detail=ruleset_detail,
    )

    normalized = snapshot["rulesets"][0]
    assert ("bypass_actors" in normalized) is include_bypass_actors
    if include_bypass_actors:
        assert normalized["bypass_actors"] == []


def test_live_collector_turns_missing_environment_into_a_gate_issue() -> None:
    requirements = _requirements()
    missing_environment = "agent-platform-production"

    snapshot, _ = _collect_with_fake(
        requirements,
        missing_environment=missing_environment,
    )
    report = validate_snapshot(
        snapshot,
        parse_requirements(requirements),
        repository=REPOSITORY,
        release_tag=RELEASE_TAG,
        git_sha=GIT_SHA,
        release_id=RELEASE_ID,
    )

    assert report["passed"] is False
    issue = next(
        issue for issue in report["issues"] if issue["code"] == "GITHUB_ENVIRONMENT_MISSING"
    )
    assert issue["scope"] == missing_environment


def test_external_release_preflight_assets_are_declared() -> None:
    assert VALIDATOR.is_file()
    assert REQUIREMENTS.is_file()

    requirements = _requirements()
    assert requirements["schema_version"] == "1.0"
    assert requirements["default_branch"] == "main"
    assert requirements["branch_protection"] == {
        "minimum_approvals": 1,
        "required_status_checks": [
            {
                "context": "Quality, policy, deployment, and offline eval gates",
                "integration_id": 15368,
            }
        ],
        "require_strict_status_checks": True,
        "require_no_bypass": True,
    }
    assert requirements["deployment_policy"] == {
        "type": "tag",
        "name": "agent-platform-v*",
        "allow_additional": False,
    }
    assert set(requirements["environments"]) == {
        "agent-platform-staging",
        "agent-platform-production-canary",
        "agent-platform-production",
    }


def test_requirements_exactly_match_release_workflow_environment_inputs() -> None:
    requirements = _requirements()
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))

    assert requirements["branch_protection"]["required_status_checks"] == [
        {
            "context": workflow["jobs"]["quality"]["name"],
            "integration_id": 15368,
        }
    ]

    for environment_name, requirement in requirements["environments"].items():
        job = workflow["jobs"][requirement["workflow_job"]]
        assert job["environment"] == environment_name
        assert set(requirement["required_variables"]) == _workflow_job_references(job, "vars")
        assert set(requirement["required_secrets"]) == _workflow_job_references(job, "secrets")


def test_valid_snapshot_passes_without_disclosing_secret_values(tmp_path: Path) -> None:
    requirements = _requirements()
    snapshot = _valid_snapshot(requirements)
    sentinel = "MUST-NOT-APPEAR-IN-REPORT"
    production = snapshot["environments"]["agent-platform-production"]
    production["secret_names"] = [
        {"name": name, "value": sentinel} for name in production["secret_names"]
    ]

    completed, report_path = _run(tmp_path, snapshot, requirements=requirements)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report_text = report_path.read_text(encoding="utf-8")
    report = json.loads(report_text)
    assert report["passed"] is True
    assert report["repository"] == REPOSITORY
    assert report["default_branch"] == "main"
    assert report["release_tag"] == RELEASE_TAG
    assert report["git_sha"] == GIT_SHA
    assert report["release_id"] == RELEASE_ID
    assert report["validated_at"].endswith("+00:00")
    assert report["validated_environments"] == [
        "agent-platform-production",
        "agent-platform-production-canary",
        "agent-platform-staging",
    ]
    assert report["main_protection_source"] == "classic"
    assert sentinel not in report_text
    assert sentinel not in completed.stdout
    assert sentinel not in completed.stderr


def test_release_tag_policy_uses_github_pathname_glob_semantics() -> None:
    requirements = _requirements()
    report = validate_snapshot(
        _valid_snapshot(requirements),
        parse_requirements(requirements),
        repository=REPOSITORY,
        release_tag="agent-platform-v/rejected-by-github-glob",
        git_sha=GIT_SHA,
        release_id=RELEASE_ID,
    )

    assert report["passed"] is False
    assert "GITHUB_RELEASE_TAG_POLICY_MISMATCH" in {issue["code"] for issue in report["issues"]}
    identity_check = next(
        check for check in report["checks"] if check["id"] == "repository-and-release-identity"
    )
    assert identity_check["passed"] is False


@pytest.mark.parametrize(
    ("kind", "code"),
    [
        ("variable_names", "GITHUB_ENVIRONMENT_VARIABLES_MISSING"),
        ("secret_names", "GITHUB_ENVIRONMENT_SECRETS_MISSING"),
    ],
)
def test_missing_environment_metadata_fails_closed(
    tmp_path: Path,
    kind: str,
    code: str,
) -> None:
    requirements = _requirements()
    snapshot = _valid_snapshot(requirements)
    environment_name = "agent-platform-staging"
    missing_name = snapshot["environments"][environment_name][kind].pop()

    completed, report_path = _run(tmp_path, snapshot, requirements=requirements)

    assert completed.returncode == 1
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert code in _issue_codes(report_path)
    matching = next(issue for issue in report["issues"] if issue["code"] == code)
    assert matching["scope"] == environment_name
    assert matching["missing"] == [missing_name]


def test_missing_environment_fails_closed(tmp_path: Path) -> None:
    requirements = _requirements()
    snapshot = _valid_snapshot(requirements)
    snapshot["environments"].pop("agent-platform-production")

    completed, report_path = _run(tmp_path, snapshot, requirements=requirements)

    assert completed.returncode == 1
    assert "GITHUB_ENVIRONMENT_MISSING" in _issue_codes(report_path)


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("reviewers", "GITHUB_ENVIRONMENT_REQUIRED_REVIEWERS_MISSING"),
        ("self_review", "GITHUB_ENVIRONMENT_SELF_REVIEW_ALLOWED"),
    ],
)
def test_production_review_protection_fails_closed(
    tmp_path: Path,
    mutation: str,
    code: str,
) -> None:
    requirements = _requirements()
    snapshot = _valid_snapshot(requirements)
    rules = snapshot["environments"]["agent-platform-production"]["configuration"][
        "protection_rules"
    ]
    if mutation == "reviewers":
        rules.clear()
    else:
        rules[0]["prevent_self_review"] = False

    completed, report_path = _run(tmp_path, snapshot, requirements=requirements)

    assert completed.returncode == 1
    assert code in _issue_codes(report_path)


@pytest.mark.parametrize("mutation", ["missing", "additional", "wrong_mode"])
def test_deployment_tag_policy_must_be_exact(
    tmp_path: Path,
    mutation: str,
) -> None:
    requirements = _requirements()
    snapshot = _valid_snapshot(requirements)
    production = snapshot["environments"]["agent-platform-production"]
    if mutation == "missing":
        production["deployment_branch_policies"] = []
    elif mutation == "additional":
        production["deployment_branch_policies"].append({"name": "*", "type": "tag"})
    else:
        production["configuration"]["deployment_branch_policy"] = {
            "protected_branches": True,
            "custom_branch_policies": False,
        }

    completed, report_path = _run(tmp_path, snapshot, requirements=requirements)

    assert completed.returncode == 1
    assert "GITHUB_ENVIRONMENT_DEPLOYMENT_POLICY_MISMATCH" in _issue_codes(report_path)


def test_active_ruleset_can_supply_main_protection(tmp_path: Path) -> None:
    requirements = _requirements()
    snapshot = _valid_snapshot(requirements)
    snapshot["main_branch_protection"] = {"status": 404, "body": None}
    snapshot["rulesets"] = [
        {
            "id": 7,
            "name": "protected main",
            "bypass_actors": [],
            "target": "branch",
            "enforcement": "active",
            "conditions": {
                "ref_name": {
                    "include": ["~DEFAULT_BRANCH"],
                    "exclude": [],
                }
            },
            "rules": [
                {
                    "type": "pull_request",
                    "parameters": {"required_approving_review_count": 1},
                },
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "strict_required_status_checks_policy": True,
                        "required_status_checks": [
                            {**requirements["branch_protection"]["required_status_checks"][0]}
                        ],
                    },
                },
            ],
        }
    ]

    completed, report_path = _run(tmp_path, snapshot, requirements=requirements)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["main_protection_source"] == "ruleset"


@pytest.mark.parametrize(
    "mutation",
    ["admins", "app_bypass", "wrong_status_context", "wrong_status_app"],
)
def test_classic_main_protection_rejects_bypass_and_unrelated_checks(
    tmp_path: Path,
    mutation: str,
) -> None:
    requirements = _requirements()
    snapshot = _valid_snapshot(requirements)
    protection = snapshot["main_branch_protection"]["body"]
    if mutation == "admins":
        protection["enforce_admins"]["enabled"] = False
    elif mutation == "app_bypass":
        protection["required_pull_request_reviews"]["bypass_pull_request_allowances"]["apps"] = [
            {"slug": "bypass-app"}
        ]
    elif mutation == "wrong_status_context":
        protection["required_status_checks"]["checks"] = [
            {"context": "unrelated-check", "app_id": 15368}
        ]
    else:
        protection["required_status_checks"]["checks"][0]["app_id"] = -1

    completed, report_path = _run(tmp_path, snapshot, requirements=requirements)

    assert completed.returncode == 1
    assert "GITHUB_MAIN_PROTECTION_MISSING" in _issue_codes(report_path)


@pytest.mark.parametrize(
    "mutation",
    ["missing_enforce_admins", "missing_allowances", "missing_actor_list"],
)
def test_classic_main_protection_requires_explicit_no_bypass_evidence(
    tmp_path: Path,
    mutation: str,
) -> None:
    requirements = _requirements()
    snapshot = _valid_snapshot(requirements)
    protection = snapshot["main_branch_protection"]["body"]
    reviews = protection["required_pull_request_reviews"]
    if mutation == "missing_enforce_admins":
        protection.pop("enforce_admins")
    elif mutation == "missing_allowances":
        reviews.pop("bypass_pull_request_allowances")
    else:
        reviews["bypass_pull_request_allowances"].pop("teams")

    completed, report_path = _run(tmp_path, snapshot, requirements=requirements)

    assert completed.returncode == 1
    assert "GITHUB_MAIN_PROTECTION_MISSING" in _issue_codes(report_path)


def test_classic_named_check_can_use_the_checks_api_shape(tmp_path: Path) -> None:
    requirements = _requirements()
    snapshot = _valid_snapshot(requirements)
    checks = snapshot["main_branch_protection"]["body"]["required_status_checks"]
    required_check = requirements["branch_protection"]["required_status_checks"][0]
    checks["contexts"] = []
    checks["checks"] = [
        {
            "context": required_check["context"],
            "app_id": required_check["integration_id"],
        }
    ]

    completed, report_path = _run(tmp_path, snapshot, requirements=requirements)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert _issue_codes(report_path) == set()


def test_ruleset_with_bypass_actor_is_not_accepted(tmp_path: Path) -> None:
    requirements = _requirements()
    snapshot = _valid_snapshot(requirements)
    snapshot["main_branch_protection"] = {"status": 404, "body": None}
    snapshot["rulesets"] = [
        {
            "target": "branch",
            "enforcement": "active",
            "bypass_actors": [{"actor_id": 17, "actor_type": "Team", "bypass_mode": "always"}],
            "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
            "rules": [
                {
                    "type": "pull_request",
                    "parameters": {"required_approving_review_count": 1},
                },
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "strict_required_status_checks_policy": True,
                        "required_status_checks": [
                            {**requirements["branch_protection"]["required_status_checks"][0]}
                        ],
                    },
                },
            ],
        }
    ]

    completed, report_path = _run(tmp_path, snapshot, requirements=requirements)

    assert completed.returncode == 1
    assert "GITHUB_MAIN_PROTECTION_MISSING" in _issue_codes(report_path)


def test_ruleset_without_bypass_actor_visibility_fails_closed(tmp_path: Path) -> None:
    requirements = _requirements()
    snapshot = _valid_snapshot(requirements)
    snapshot["main_branch_protection"] = {"status": 404, "body": None}
    snapshot["rulesets"] = [
        {
            "target": "branch",
            "enforcement": "active",
            "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
            "rules": [
                {
                    "type": "pull_request",
                    "parameters": {"required_approving_review_count": 1},
                },
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "strict_required_status_checks_policy": True,
                        "required_status_checks": [
                            {**requirements["branch_protection"]["required_status_checks"][0]}
                        ],
                    },
                },
            ],
        }
    ]

    completed, report_path = _run(tmp_path, snapshot, requirements=requirements)

    assert completed.returncode == 1
    assert "GITHUB_MAIN_PROTECTION_MISSING" in _issue_codes(report_path)


def test_missing_main_protection_fails_closed(tmp_path: Path) -> None:
    requirements = _requirements()
    snapshot = _valid_snapshot(requirements)
    snapshot["main_branch_protection"] = {"status": 404, "body": None}
    snapshot["rulesets"] = [
        {
            "id": 7,
            "target": "branch",
            "enforcement": "disabled",
            "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
            "rules": [],
        }
    ]

    completed, report_path = _run(tmp_path, snapshot, requirements=requirements)

    assert completed.returncode == 1
    assert "GITHUB_MAIN_PROTECTION_MISSING" in _issue_codes(report_path)


def test_malformed_snapshot_is_an_operational_failure(tmp_path: Path) -> None:
    completed, report_path = _run(
        tmp_path,
        {"schema_version": "1.0", "environments": []},
    )

    assert completed.returncode == 2
    assert "GITHUB_PREFLIGHT_SNAPSHOT_INVALID" in completed.stderr
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["passed"] is False
    assert report["operational_failure"] is True
    assert report["repository"] == REPOSITORY
    assert report["release_tag"] == RELEASE_TAG
    assert report["git_sha"] == GIT_SHA
    assert report["release_id"] == RELEASE_ID
    assert report["issues"] == [{"code": "GITHUB_PREFLIGHT_SNAPSHOT_INVALID", "scope": "preflight"}]
    assert report["secret_values_accessed"] is False


def test_verify_report_cli_accepts_exact_downloaded_report_and_sanitizes_output(
    tmp_path: Path,
) -> None:
    downloaded = _valid_preflight_report()
    sentinel = "DOWNLOADED-UNKNOWN-SECRET-MUST-NOT-BE-COPIED"
    downloaded["unknown_payload"] = {"secret": sentinel}
    downloaded["checks"][0]["unknown_payload"] = sentinel

    completed, output_path = _run_verify_report(tmp_path, downloaded)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    output_text = output_path.read_text(encoding="utf-8")
    verified = json.loads(output_text)
    assert verified["passed"] is True
    assert verified["operational_failure"] is False
    assert verified["repository"] == REPOSITORY
    assert verified["default_branch"] == "main"
    assert verified["release_tag"] == RELEASE_TAG
    assert verified["git_sha"] == GIT_SHA
    assert verified["release_id"] == RELEASE_ID
    assert verified["main_protection_source"] == "classic"
    assert verified["validated_environments"] == sorted(_requirements()["environments"])
    assert all(check["passed"] is True for check in verified["checks"])
    assert verified["issues"] == []
    assert verified["secret_values_accessed"] is False
    assert datetime.fromisoformat(verified["validated_at"]).utcoffset() is not None
    assert sentinel not in output_text
    assert sentinel not in completed.stdout
    assert sentinel not in completed.stderr


def test_verify_report_cli_returns_one_for_governance_mismatch_without_echoing_input(
    tmp_path: Path,
) -> None:
    downloaded = _valid_preflight_report()
    sentinel = "UPSTREAM-ISSUE-SECRET-MUST-NOT-BE-COPIED"
    downloaded["validated_environments"].append(downloaded["validated_environments"][0])
    downloaded["checks"][0]["passed"] = False
    downloaded["issues"] = [{"code": "UPSTREAM_PRIVATE_ISSUE", "detail": sentinel}]
    downloaded["secret_values_accessed"] = True

    completed, output_path = _run_verify_report(tmp_path, downloaded)

    assert completed.returncode == 1
    output_text = output_path.read_text(encoding="utf-8")
    verified = json.loads(output_text)
    assert verified["passed"] is False
    assert verified["operational_failure"] is False
    assert {
        "GITHUB_PREFLIGHT_REPORT_ENVIRONMENT_SET_MISMATCH",
        "GITHUB_PREFLIGHT_REPORT_CHECK_FAILED",
        "GITHUB_PREFLIGHT_REPORT_ISSUES_PRESENT",
        "GITHUB_PREFLIGHT_REPORT_SECRET_ACCESS_INVALID",
    } <= _issue_codes(output_path)
    assert sentinel not in output_text
    assert sentinel not in completed.stdout
    assert sentinel not in completed.stderr


def test_verify_report_rechecks_release_tag_against_github_pathname_policy(
    tmp_path: Path,
) -> None:
    release_tag = "agent-platform-v/rejected-by-github-glob"
    downloaded = _valid_preflight_report()
    downloaded["release_tag"] = release_tag

    completed, output_path = _run_verify_report(
        tmp_path,
        downloaded,
        release_tag=release_tag,
    )

    assert completed.returncode == 1
    verified = json.loads(output_path.read_text(encoding="utf-8"))
    assert verified["passed"] is False
    assert "GITHUB_PREFLIGHT_REPORT_RELEASE_TAG_POLICY_MISMATCH" in _issue_codes(output_path)
    identity_check = next(
        check for check in verified["checks"] if check["id"] == "repository-and-release-identity"
    )
    assert identity_check["passed"] is False


def test_verify_report_cli_returns_operational_report_for_invalid_structure(
    tmp_path: Path,
) -> None:
    downloaded = _valid_preflight_report()
    downloaded["validated_at"] = "2026-07-28T12:00:00"
    downloaded["unknown_secret"] = "STRUCTURAL-SECRET-MUST-NOT-BE-COPIED"

    completed, output_path = _run_verify_report(tmp_path, downloaded)

    assert completed.returncode == 2
    output_text = output_path.read_text(encoding="utf-8")
    operational = json.loads(output_text)
    assert operational["passed"] is False
    assert operational["operational_failure"] is True
    assert operational["issues"] == [
        {"code": "GITHUB_PREFLIGHT_REPORT_INVALID", "scope": "preflight"}
    ]
    assert "STRUCTURAL-SECRET-MUST-NOT-BE-COPIED" not in output_text
    assert "STRUCTURAL-SECRET-MUST-NOT-BE-COPIED" not in completed.stderr


def test_verify_report_cli_returns_operational_report_for_read_failure(
    tmp_path: Path,
) -> None:
    completed, output_path = _run_verify_report(tmp_path, None)

    assert completed.returncode == 2
    operational = json.loads(output_path.read_text(encoding="utf-8"))
    assert operational["passed"] is False
    assert operational["operational_failure"] is True
    assert operational["issues"] == [
        {"code": "GITHUB_PREFLIGHT_REPORT_INVALID", "scope": "preflight"}
    ]


def test_verify_report_and_snapshot_are_mutually_exclusive_with_operational_report(
    tmp_path: Path,
) -> None:
    completed, output_path = _run_verify_report(
        tmp_path,
        _valid_preflight_report(),
        include_snapshot=True,
    )

    assert completed.returncode == 2
    operational = json.loads(output_path.read_text(encoding="utf-8"))
    assert operational["operational_failure"] is True
    assert operational["issues"] == [
        {"code": "GITHUB_PREFLIGHT_SOURCE_CONFLICT", "scope": "preflight"}
    ]


def test_workflow_runs_external_preflight_before_dependency_setup() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["quality"]["steps"]
    names = [step.get("name") for step in steps]

    token = next(step for step in steps if step.get("name") == "Create release preflight token")
    validate = next(
        step for step in steps if step.get("name") == "Validate external release prerequisites"
    )
    upload = next(
        step for step in steps if step.get("name") == "Upload external release preflight report"
    )

    assert names.index("Restrict release source") < names.index("Create release preflight token")
    assert names.index("Create release preflight token") < names.index(
        "Validate external release prerequisites"
    )
    assert names.index("Validate external release prerequisites") < names.index("Enable pnpm")
    assert names.count("Set up Python") == 1
    assert names.index("Set up Python") < names.index("Validate external release prerequisites")
    assert token["if"] == "github.event_name != 'pull_request'"
    assert token["uses"] == (
        "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1"
    )
    assert token["with"] == {
        "client-id": "${{ vars.AGENT_PLATFORM_PREFLIGHT_APP_CLIENT_ID }}",
        "private-key": "${{ secrets.AGENT_PLATFORM_PREFLIGHT_APP_PRIVATE_KEY }}",
        "permission-actions": "read",
        "permission-administration": "read",
        "permission-environments": "read",
    }
    assert validate["if"] == "always() && github.event_name != 'pull_request'"
    assert validate["env"]["AGENT_PLATFORM_PREFLIGHT_GITHUB_TOKEN"] == (
        "${{ steps.release-preflight-token.outputs.token }}"
    )
    assert "validate_external_release_preflight.py" in validate["run"]
    assert "external-release-preflight.json" in validate["run"]
    assert '--release-tag "${GITHUB_REF_NAME}"' in validate["run"]
    assert '--git-sha "${GITHUB_SHA}"' in validate["run"]
    assert '--release-id "${RELEASE_ID}"' in validate["run"]
    assert '--server-url "${GITHUB_SERVER_URL}"' in validate["run"]
    assert '--api-url "${GITHUB_API_URL}"' in validate["run"]
    assert upload["if"] == "always() && github.event_name != 'pull_request'"
    assert upload["with"]["path"] == (
        "apps/agent-platform/.artifacts/external-release-preflight.json"
    )
    assert upload["with"]["retention-days"] == 365


def test_production_revalidates_external_preflight_before_deployment() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["production"]["steps"]
    names = [step.get("name") for step in steps]

    download = next(
        step for step in steps if step.get("name") == "Download external release preflight report"
    )
    verify = next(
        step
        for step in steps
        if step.get("name") == "Verify downloaded external release preflight report"
    )

    assert download["uses"] == (
        "actions/download-artifact@018cc2cf5baa6db3ef3c5f8a56943fffe632ef53"
    )
    assert download["with"] == {
        "name": "external-release-preflight-${{ env.RELEASE_ID }}",
        "path": ".artifacts/external-release-preflight",
    }
    assert names.index("Download external release preflight report") < names.index("Set up Python")
    assert names.index("Set up Python") < names.index(
        "Verify downloaded external release preflight report"
    )
    assert names.index("Verify downloaded external release preflight report") < names.index(
        "Materialize short-lived production inputs"
    )
    assert names.index("Verify downloaded external release preflight report") < names.index(
        "Deploy the same immutable digest to production"
    )
    assert (
        '--verify-report ".artifacts/external-release-preflight/external-release-preflight.json"'
    ) in verify["run"]
    assert '--repository "${GITHUB_REPOSITORY}"' in verify["run"]
    assert '--release-tag "${GITHUB_REF_NAME}"' in verify["run"]
    assert '--git-sha "${GITHUB_SHA}"' in verify["run"]
    assert '--release-id "${RELEASE_ID}"' in verify["run"]
    assert (
        '--output ".artifacts/production/external-release-preflight-validation.json"'
        in verify["run"]
    )
