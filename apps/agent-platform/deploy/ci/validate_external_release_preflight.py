"""Fail closed on missing external GitHub release controls.

The live collector uses read-only GitHub REST calls and keeps only control
metadata. Secret values are neither requested nor written to the report.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

JsonObject = dict[str, Any]
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
RELEASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
ENVIRONMENT_NAME_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]+$")
TOKEN_ENV_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]+$")
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_PAGES = 100


class PreflightInputError(ValueError):
    """Raised when a requirements file or snapshot is structurally invalid."""


class GitHubApiError(RuntimeError):
    """Raised when a read-only GitHub API request cannot be completed."""


@dataclass(frozen=True)
class StatusCheckRequirement:
    context: str
    integration_id: int


@dataclass(frozen=True)
class BranchProtectionRequirement:
    minimum_approvals: int
    required_status_checks: frozenset[StatusCheckRequirement]
    require_strict_status_checks: bool
    require_no_bypass: bool


@dataclass(frozen=True)
class DeploymentPolicyRequirement:
    policy_type: str
    name: str
    allow_additional: bool


@dataclass(frozen=True)
class EnvironmentRequirement:
    workflow_job: str
    minimum_reviewers: int
    prevent_self_review: bool
    required_variables: frozenset[str]
    required_secrets: frozenset[str]


@dataclass(frozen=True)
class PreflightRequirements:
    default_branch: str
    branch_protection: BranchProtectionRequirement
    deployment_policy: DeploymentPolicyRequirement
    environments: dict[str, EnvironmentRequirement]


@dataclass(frozen=True)
class ApiResponse:
    status: int
    value: object | None


class _RejectRedirects(HTTPRedirectHandler):
    """Keep the App bearer token on the validated API origin."""

    def redirect_request(
        self,
        request: Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> Request | None:
        return None


def _mapping(value: object, *, code: str, field: str) -> JsonObject:
    if not isinstance(value, dict):
        raise PreflightInputError(f"{code}: {field} must be an object")
    return cast(JsonObject, value)


def _sequence(value: object, *, code: str, field: str) -> list[object]:
    if not isinstance(value, list):
        raise PreflightInputError(f"{code}: {field} must be an array")
    return cast(list[object], value)


def _required_string(value: object, *, code: str, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise PreflightInputError(f"{code}: {field} must be a non-empty string")
    return value


def _non_negative_int(value: object, *, code: str, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PreflightInputError(f"{code}: {field} must be a non-negative integer")
    return value


def _required_bool(value: object, *, code: str, field: str) -> bool:
    if not isinstance(value, bool):
        raise PreflightInputError(f"{code}: {field} must be a boolean")
    return value


def _name_set(value: object, *, code: str, field: str) -> frozenset[str]:
    names: list[str] = []
    for index, item in enumerate(_sequence(value, code=code, field=field)):
        name = _required_string(item, code=code, field=f"{field}.{index}")
        if ENVIRONMENT_NAME_PATTERN.fullmatch(name) is None:
            raise PreflightInputError(f"{code}: {field}.{index} has an invalid name")
        names.append(name)
    if len(names) != len(set(names)):
        raise PreflightInputError(f"{code}: {field} contains duplicate names")
    return frozenset(names)


def _status_check_requirements(
    value: object,
    *,
    code: str,
    field: str,
) -> frozenset[StatusCheckRequirement]:
    requirements: list[StatusCheckRequirement] = []
    for index, item in enumerate(_sequence(value, code=code, field=field)):
        check = _mapping(item, code=code, field=f"{field}.{index}")
        context = _required_string(
            check.get("context"),
            code=code,
            field=f"{field}.{index}.context",
        )
        integration_id = _non_negative_int(
            check.get("integration_id"),
            code=code,
            field=f"{field}.{index}.integration_id",
        )
        if integration_id == 0:
            raise PreflightInputError(f"{code}: {field}.{index}.integration_id must be positive")
        requirements.append(
            StatusCheckRequirement(
                context=context,
                integration_id=integration_id,
            )
        )
    if not requirements:
        raise PreflightInputError(f"{code}: {field} must not be empty")
    contexts = [requirement.context for requirement in requirements]
    if len(contexts) != len(set(contexts)):
        raise PreflightInputError(f"{code}: {field} contains duplicate contexts")
    return frozenset(requirements)


def _load_object(path: Path, *, code: str) -> JsonObject:
    try:
        value: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PreflightInputError(f"{code}: cannot read valid JSON from {path}") from exc
    return _mapping(value, code=code, field="$")


def parse_requirements(raw: JsonObject) -> PreflightRequirements:
    code = "GITHUB_PREFLIGHT_REQUIREMENTS_INVALID"
    if raw.get("schema_version") != "1.0":
        raise PreflightInputError(f"{code}: schema_version must be 1.0")
    default_branch = _required_string(
        raw.get("default_branch"),
        code=code,
        field="default_branch",
    )

    raw_branch = _mapping(
        raw.get("branch_protection"),
        code=code,
        field="branch_protection",
    )
    branch = BranchProtectionRequirement(
        minimum_approvals=_non_negative_int(
            raw_branch.get("minimum_approvals"),
            code=code,
            field="branch_protection.minimum_approvals",
        ),
        required_status_checks=_status_check_requirements(
            raw_branch.get("required_status_checks"),
            code=code,
            field="branch_protection.required_status_checks",
        ),
        require_strict_status_checks=_required_bool(
            raw_branch.get("require_strict_status_checks"),
            code=code,
            field="branch_protection.require_strict_status_checks",
        ),
        require_no_bypass=_required_bool(
            raw_branch.get("require_no_bypass"),
            code=code,
            field="branch_protection.require_no_bypass",
        ),
    )

    raw_policy = _mapping(
        raw.get("deployment_policy"),
        code=code,
        field="deployment_policy",
    )
    policy_type = _required_string(
        raw_policy.get("type"),
        code=code,
        field="deployment_policy.type",
    )
    if policy_type not in {"branch", "tag"}:
        raise PreflightInputError(f"{code}: deployment_policy.type must be branch or tag")
    policy = DeploymentPolicyRequirement(
        policy_type=policy_type,
        name=_required_string(
            raw_policy.get("name"),
            code=code,
            field="deployment_policy.name",
        ),
        allow_additional=_required_bool(
            raw_policy.get("allow_additional"),
            code=code,
            field="deployment_policy.allow_additional",
        ),
    )

    raw_environments = _mapping(
        raw.get("environments"),
        code=code,
        field="environments",
    )
    if not raw_environments:
        raise PreflightInputError(f"{code}: environments must not be empty")
    environments: dict[str, EnvironmentRequirement] = {}
    for environment_name, value in raw_environments.items():
        requirement = _mapping(
            value,
            code=code,
            field=f"environments.{environment_name}",
        )
        environments[environment_name] = EnvironmentRequirement(
            workflow_job=_required_string(
                requirement.get("workflow_job"),
                code=code,
                field=f"environments.{environment_name}.workflow_job",
            ),
            minimum_reviewers=_non_negative_int(
                requirement.get("minimum_reviewers"),
                code=code,
                field=f"environments.{environment_name}.minimum_reviewers",
            ),
            prevent_self_review=_required_bool(
                requirement.get("prevent_self_review"),
                code=code,
                field=f"environments.{environment_name}.prevent_self_review",
            ),
            required_variables=_name_set(
                requirement.get("required_variables"),
                code=code,
                field=f"environments.{environment_name}.required_variables",
            ),
            required_secrets=_name_set(
                requirement.get("required_secrets"),
                code=code,
                field=f"environments.{environment_name}.required_secrets",
            ),
        )
    return PreflightRequirements(
        default_branch=default_branch,
        branch_protection=branch,
        deployment_policy=policy,
        environments=environments,
    )


def _metadata_names(value: object, *, field: str) -> set[str]:
    code = "GITHUB_PREFLIGHT_SNAPSHOT_INVALID"
    names: set[str] = set()
    for index, item in enumerate(_sequence(value, code=code, field=field)):
        if isinstance(item, str):
            name = item
        elif isinstance(item, dict):
            name = _required_string(
                cast(JsonObject, item).get("name"),
                code=code,
                field=f"{field}.{index}.name",
            )
        else:
            raise PreflightInputError(f"{code}: {field}.{index} has an invalid shape")
        names.add(name)
    return names


def _add_issue(
    issues: list[JsonObject],
    *,
    code: str,
    scope: str,
    missing: list[str] | None = None,
) -> None:
    issue: JsonObject = {"code": code, "scope": scope}
    if missing is not None:
        issue["missing"] = missing
    issues.append(issue)


def _classic_status_checks(
    value: object,
    *,
    field: str,
) -> set[StatusCheckRequirement]:
    code = "GITHUB_PREFLIGHT_SNAPSHOT_INVALID"
    if value is None:
        return set()
    checks = _mapping(value, code=code, field=field)
    status_checks: set[StatusCheckRequirement] = set()
    for index, item in enumerate(
        _sequence(checks.get("checks", []), code=code, field=f"{field}.checks")
    ):
        check = _mapping(item, code=code, field=f"{field}.checks.{index}")
        context = check.get("context")
        app_id = check.get("app_id")
        if (
            isinstance(context, str)
            and context
            and isinstance(app_id, int)
            and not isinstance(app_id, bool)
            and app_id > 0
        ):
            status_checks.add(
                StatusCheckRequirement(
                    context=context,
                    integration_id=app_id,
                )
            )
    return status_checks


def _classic_protection_valid(
    raw: object,
    requirement: BranchProtectionRequirement,
) -> bool:
    code = "GITHUB_PREFLIGHT_SNAPSHOT_INVALID"
    wrapper = _mapping(raw, code=code, field="main_branch_protection")
    status = wrapper.get("status")
    if status == 404:
        return False
    if status != 200:
        raise PreflightInputError(f"{code}: main_branch_protection.status must be 200 or 404")
    body_value = wrapper.get("body")
    if not isinstance(body_value, dict):
        return False
    body = cast(JsonObject, body_value)
    reviews_value = body.get("required_pull_request_reviews")
    checks_value = body.get("required_status_checks")
    if not isinstance(reviews_value, dict) or not isinstance(checks_value, dict):
        return False
    reviews = cast(JsonObject, reviews_value)
    checks = cast(JsonObject, checks_value)
    approvals = reviews.get("required_approving_review_count")
    if isinstance(approvals, bool) or not isinstance(approvals, int):
        return False
    if approvals < requirement.minimum_approvals:
        return False
    if requirement.require_strict_status_checks and checks.get("strict") is not True:
        return False
    if requirement.require_no_bypass:
        enforce_admins = body.get("enforce_admins")
        if not isinstance(enforce_admins, dict) or enforce_admins.get("enabled") is not True:
            return False
        allowances = reviews.get("bypass_pull_request_allowances")
        if not isinstance(allowances, dict):
            return False
        for actor_type in ("users", "teams", "apps"):
            actors = allowances.get(actor_type)
            if not isinstance(actors, list) or actors:
                return False
    actual_status_checks = _classic_status_checks(
        checks,
        field="main_branch_protection.body.required_status_checks",
    )
    return requirement.required_status_checks.issubset(actual_status_checks)


def _ref_matches(pattern: str, *, branch: str, full_ref: str) -> bool:
    if pattern == "~ALL":
        return True
    if pattern == "~DEFAULT_BRANCH":
        return True
    return fnmatch.fnmatchcase(full_ref, pattern) or fnmatch.fnmatchcase(branch, pattern)


def _github_pathname_glob_matches(value: str, pattern: str) -> bool:
    """Match GitHub environment patterns without letting `*` cross `/`."""

    value_parts = value.split("/")
    positions = {0}
    for pattern_part in pattern.split("/"):
        if pattern_part == "**":
            positions = {
                candidate
                for position in positions
                for candidate in range(position, len(value_parts) + 1)
            }
            continue
        positions = {
            position + 1
            for position in positions
            if position < len(value_parts)
            and fnmatch.fnmatchcase(value_parts[position], pattern_part)
        }
    return len(value_parts) in positions


def _ruleset_applies_to_branch(ruleset: JsonObject, *, branch: str) -> bool:
    if ruleset.get("target") != "branch" or ruleset.get("enforcement") != "active":
        return False
    code = "GITHUB_PREFLIGHT_SNAPSHOT_INVALID"
    conditions = _mapping(
        ruleset.get("conditions"),
        code=code,
        field="rulesets.conditions",
    )
    ref_name = _mapping(
        conditions.get("ref_name"),
        code=code,
        field="rulesets.conditions.ref_name",
    )
    include = [
        _required_string(
            value,
            code=code,
            field="rulesets.conditions.ref_name.include",
        )
        for value in _sequence(
            ref_name.get("include", []),
            code=code,
            field="rulesets.conditions.ref_name.include",
        )
    ]
    exclude = [
        _required_string(
            value,
            code=code,
            field="rulesets.conditions.ref_name.exclude",
        )
        for value in _sequence(
            ref_name.get("exclude", []),
            code=code,
            field="rulesets.conditions.ref_name.exclude",
        )
    ]
    full_ref = f"refs/heads/{branch}"
    return any(
        _ref_matches(pattern, branch=branch, full_ref=full_ref) for pattern in include
    ) and not any(_ref_matches(pattern, branch=branch, full_ref=full_ref) for pattern in exclude)


def _ruleset_protection_valid(
    raw: object,
    *,
    branch: str,
    requirement: BranchProtectionRequirement,
) -> bool:
    code = "GITHUB_PREFLIGHT_SNAPSHOT_INVALID"
    maximum_approvals = 0
    status_checks: set[StatusCheckRequirement] = set()
    strict_status_checks = False
    applicable_ruleset_found = False
    for ruleset_index, value in enumerate(_sequence(raw, code=code, field="rulesets")):
        ruleset = _mapping(
            value,
            code=code,
            field=f"rulesets.{ruleset_index}",
        )
        if not _ruleset_applies_to_branch(ruleset, branch=branch):
            continue
        applicable_ruleset_found = True
        if requirement.require_no_bypass:
            bypass_actors = ruleset.get("bypass_actors")
            if not isinstance(bypass_actors, list) or bypass_actors:
                return False
        for rule_index, raw_rule in enumerate(
            _sequence(
                ruleset.get("rules"),
                code=code,
                field=f"rulesets.{ruleset_index}.rules",
            )
        ):
            rule = _mapping(
                raw_rule,
                code=code,
                field=f"rulesets.{ruleset_index}.rules.{rule_index}",
            )
            rule_type = rule.get("type")
            parameters_value = rule.get("parameters", {})
            parameters = _mapping(
                parameters_value,
                code=code,
                field=f"rulesets.{ruleset_index}.rules.{rule_index}.parameters",
            )
            if rule_type == "pull_request":
                count = parameters.get("required_approving_review_count", 0)
                if isinstance(count, int) and not isinstance(count, bool):
                    maximum_approvals = max(maximum_approvals, count)
            elif rule_type == "required_status_checks":
                strict_status_checks = strict_status_checks or (
                    parameters.get("strict_required_status_checks_policy") is True
                )
                for check_index, raw_check in enumerate(
                    _sequence(
                        parameters.get("required_status_checks", []),
                        code=code,
                        field=(
                            f"rulesets.{ruleset_index}.rules.{rule_index}."
                            "parameters.required_status_checks"
                        ),
                    )
                ):
                    check = _mapping(
                        raw_check,
                        code=code,
                        field=(
                            f"rulesets.{ruleset_index}.rules.{rule_index}."
                            f"parameters.required_status_checks.{check_index}"
                        ),
                    )
                    context = check.get("context")
                    integration_id = check.get("integration_id")
                    if (
                        isinstance(context, str)
                        and context
                        and isinstance(integration_id, int)
                        and not isinstance(integration_id, bool)
                        and integration_id > 0
                    ):
                        status_checks.add(
                            StatusCheckRequirement(
                                context=context,
                                integration_id=integration_id,
                            )
                        )
    return (
        applicable_ruleset_found
        and maximum_approvals >= requirement.minimum_approvals
        and requirement.required_status_checks.issubset(status_checks)
        and (not requirement.require_strict_status_checks or strict_status_checks)
    )


def _reviewer_count_and_self_review(configuration: JsonObject) -> tuple[int, bool]:
    code = "GITHUB_PREFLIGHT_SNAPSHOT_INVALID"
    reviewer_count = 0
    prevent_self_review = False
    for index, raw_rule in enumerate(
        _sequence(
            configuration.get("protection_rules"),
            code=code,
            field="environment.configuration.protection_rules",
        )
    ):
        rule = _mapping(
            raw_rule,
            code=code,
            field=f"environment.configuration.protection_rules.{index}",
        )
        if rule.get("type") != "required_reviewers":
            continue
        prevent_self_review = prevent_self_review or (rule.get("prevent_self_review") is True)
        for reviewer_index, raw_reviewer in enumerate(
            _sequence(
                rule.get("reviewers"),
                code=code,
                field=(f"environment.configuration.protection_rules.{index}.reviewers"),
            )
        ):
            reviewer = _mapping(
                raw_reviewer,
                code=code,
                field=(
                    f"environment.configuration.protection_rules.{index}.reviewers.{reviewer_index}"
                ),
            )
            if reviewer.get("type") not in {"User", "Team"}:
                continue
            identity = reviewer.get("reviewer")
            if isinstance(identity, dict) and identity:
                reviewer_count += 1
    return reviewer_count, prevent_self_review


def _policy_pairs(value: object, *, field: str) -> set[tuple[str, str]]:
    code = "GITHUB_PREFLIGHT_SNAPSHOT_INVALID"
    policies: set[tuple[str, str]] = set()
    for index, raw_policy in enumerate(_sequence(value, code=code, field=field)):
        policy = _mapping(
            raw_policy,
            code=code,
            field=f"{field}.{index}",
        )
        policies.add(
            (
                _required_string(
                    policy.get("type"),
                    code=code,
                    field=f"{field}.{index}.type",
                ),
                _required_string(
                    policy.get("name"),
                    code=code,
                    field=f"{field}.{index}.name",
                ),
            )
        )
    return policies


def validate_snapshot(
    snapshot: JsonObject,
    requirements: PreflightRequirements,
    *,
    repository: str,
    release_tag: str,
    git_sha: str,
    release_id: str,
) -> JsonObject:
    code = "GITHUB_PREFLIGHT_SNAPSHOT_INVALID"
    if snapshot.get("schema_version") != "1.0":
        raise PreflightInputError(f"{code}: schema_version must be 1.0")
    raw_repository = _mapping(
        snapshot.get("repository"),
        code=code,
        field="repository",
    )
    actual_repository = _required_string(
        raw_repository.get("full_name"),
        code=code,
        field="repository.full_name",
    )
    actual_default_branch = _required_string(
        raw_repository.get("default_branch"),
        code=code,
        field="repository.default_branch",
    )
    raw_environments = _mapping(
        snapshot.get("environments"),
        code=code,
        field="environments",
    )

    issues: list[JsonObject] = []
    checks: list[JsonObject] = []
    repository_ok = actual_repository.casefold() == repository.casefold()
    if not repository_ok:
        _add_issue(
            issues,
            code="GITHUB_REPOSITORY_IDENTITY_MISMATCH",
            scope="repository",
        )
    default_branch_ok = actual_default_branch == requirements.default_branch
    if not default_branch_ok:
        _add_issue(
            issues,
            code="GITHUB_DEFAULT_BRANCH_MISMATCH",
            scope="repository",
        )
    release_tag_ok = _github_pathname_glob_matches(
        release_tag,
        requirements.deployment_policy.name,
    )
    if not release_tag_ok:
        _add_issue(
            issues,
            code="GITHUB_RELEASE_TAG_POLICY_MISMATCH",
            scope="release",
        )
    checks.append(
        {
            "id": "repository-and-release-identity",
            "passed": repository_ok and default_branch_ok and release_tag_ok,
        }
    )

    classic_valid = _classic_protection_valid(
        snapshot.get("main_branch_protection"),
        requirements.branch_protection,
    )
    ruleset_valid = _ruleset_protection_valid(
        snapshot.get("rulesets"),
        branch=requirements.default_branch,
        requirement=requirements.branch_protection,
    )
    main_protection_source: str | None
    if classic_valid:
        main_protection_source = "classic"
    elif ruleset_valid:
        main_protection_source = "ruleset"
    else:
        main_protection_source = None
        _add_issue(
            issues,
            code="GITHUB_MAIN_PROTECTION_MISSING",
            scope=requirements.default_branch,
        )
    checks.append(
        {
            "id": "main-branch-protection",
            "passed": main_protection_source is not None,
            "source": main_protection_source,
        }
    )

    validated_environments: list[str] = []
    for environment_name in sorted(requirements.environments):
        requirement = requirements.environments[environment_name]
        issue_count = len(issues)
        raw_environment = raw_environments.get(environment_name)
        if raw_environment is None:
            _add_issue(
                issues,
                code="GITHUB_ENVIRONMENT_MISSING",
                scope=environment_name,
            )
            checks.append({"id": f"environment:{environment_name}", "passed": False})
            continue
        environment = _mapping(
            raw_environment,
            code=code,
            field=f"environments.{environment_name}",
        )
        configuration = _mapping(
            environment.get("configuration"),
            code=code,
            field=f"environments.{environment_name}.configuration",
        )
        if configuration.get("name") != environment_name:
            _add_issue(
                issues,
                code="GITHUB_ENVIRONMENT_IDENTITY_MISMATCH",
                scope=environment_name,
            )

        missing_variables = sorted(
            requirement.required_variables
            - _metadata_names(
                environment.get("variable_names"),
                field=f"environments.{environment_name}.variable_names",
            )
        )
        if missing_variables:
            _add_issue(
                issues,
                code="GITHUB_ENVIRONMENT_VARIABLES_MISSING",
                scope=environment_name,
                missing=missing_variables,
            )
        missing_secrets = sorted(
            requirement.required_secrets
            - _metadata_names(
                environment.get("secret_names"),
                field=f"environments.{environment_name}.secret_names",
            )
        )
        if missing_secrets:
            _add_issue(
                issues,
                code="GITHUB_ENVIRONMENT_SECRETS_MISSING",
                scope=environment_name,
                missing=missing_secrets,
            )

        branch_policy_value = configuration.get("deployment_branch_policy")
        branch_policy_ok = False
        if isinstance(branch_policy_value, dict):
            branch_policy = cast(JsonObject, branch_policy_value)
            branch_policy_ok = (
                branch_policy.get("protected_branches") is False
                and branch_policy.get("custom_branch_policies") is True
            )
        expected_policy = {
            (
                requirements.deployment_policy.policy_type,
                requirements.deployment_policy.name,
            )
        }
        actual_policies = _policy_pairs(
            environment.get("deployment_branch_policies"),
            field=f"environments.{environment_name}.deployment_branch_policies",
        )
        policy_set_ok = (
            expected_policy.issubset(actual_policies)
            if requirements.deployment_policy.allow_additional
            else actual_policies == expected_policy
        )
        if not branch_policy_ok or not policy_set_ok:
            _add_issue(
                issues,
                code="GITHUB_ENVIRONMENT_DEPLOYMENT_POLICY_MISMATCH",
                scope=environment_name,
            )

        reviewer_count, prevent_self_review = _reviewer_count_and_self_review(configuration)
        if reviewer_count < requirement.minimum_reviewers:
            _add_issue(
                issues,
                code="GITHUB_ENVIRONMENT_REQUIRED_REVIEWERS_MISSING",
                scope=environment_name,
            )
        if requirement.prevent_self_review and not prevent_self_review:
            _add_issue(
                issues,
                code="GITHUB_ENVIRONMENT_SELF_REVIEW_ALLOWED",
                scope=environment_name,
            )

        environment_passed = issue_count == len(issues)
        if environment_passed:
            validated_environments.append(environment_name)
        checks.append(
            {
                "id": f"environment:{environment_name}",
                "passed": environment_passed,
            }
        )

    return {
        "schema_version": "1.0",
        "passed": not issues,
        "repository": repository,
        "default_branch": requirements.default_branch,
        "release_tag": release_tag,
        "git_sha": git_sha,
        "release_id": release_id,
        "validated_at": datetime.now(UTC).isoformat(),
        "operational_failure": False,
        "main_protection_source": main_protection_source,
        "validated_environments": validated_environments,
        "checks": checks,
        "issues": issues,
        "secret_values_accessed": False,
    }


def _require_timezone_aware_iso_datetime(value: object, *, field: str) -> None:
    code = "GITHUB_PREFLIGHT_REPORT_INVALID"
    timestamp = _required_string(value, code=code, field=field)
    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError as exc:
        raise PreflightInputError(f"{code}: {field} must be an ISO datetime") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PreflightInputError(f"{code}: {field} must include a timezone")


def verify_preflight_report(
    report: JsonObject,
    requirements: PreflightRequirements,
    *,
    repository: str,
    release_tag: str,
    git_sha: str,
    release_id: str,
) -> JsonObject:
    """Verify and sanitize a downloaded external preflight report."""

    code = "GITHUB_PREFLIGHT_REPORT_INVALID"
    if report.get("schema_version") != "1.0":
        raise PreflightInputError(f"{code}: schema_version must be 1.0")
    reported_passed = _required_bool(report.get("passed"), code=code, field="passed")
    reported_operational_failure = _required_bool(
        report.get("operational_failure"),
        code=code,
        field="operational_failure",
    )
    actual_repository = _required_string(report.get("repository"), code=code, field="repository")
    actual_default_branch = _required_string(
        report.get("default_branch"), code=code, field="default_branch"
    )
    actual_release_tag = _required_string(report.get("release_tag"), code=code, field="release_tag")
    actual_git_sha = _required_string(report.get("git_sha"), code=code, field="git_sha")
    actual_release_id = _required_string(report.get("release_id"), code=code, field="release_id")
    _require_timezone_aware_iso_datetime(report.get("validated_at"), field="validated_at")
    release_tag_policy_ok = all(
        _github_pathname_glob_matches(tag, requirements.deployment_policy.name)
        for tag in (actual_release_tag, release_tag)
    )

    protection_source_value = report.get("main_protection_source")
    if protection_source_value is not None and not isinstance(protection_source_value, str):
        raise PreflightInputError(f"{code}: main_protection_source must be a string or null")
    protection_source = protection_source_value

    actual_environments = [
        _required_string(value, code=code, field=f"validated_environments.{index}")
        for index, value in enumerate(
            _sequence(
                report.get("validated_environments"),
                code=code,
                field="validated_environments",
            )
        )
    ]

    check_states: dict[str, list[bool]] = {}
    for index, value in enumerate(_sequence(report.get("checks"), code=code, field="checks")):
        check = _mapping(value, code=code, field=f"checks.{index}")
        check_id = _required_string(check.get("id"), code=code, field=f"checks.{index}.id")
        check_passed = _required_bool(
            check.get("passed"), code=code, field=f"checks.{index}.passed"
        )
        check_states.setdefault(check_id, []).append(check_passed)

    upstream_issues = _sequence(report.get("issues"), code=code, field="issues")
    secret_values_accessed = _required_bool(
        report.get("secret_values_accessed"),
        code=code,
        field="secret_values_accessed",
    )

    expected_environments = set(requirements.environments)
    expected_check_order = [
        "repository-and-release-identity",
        "main-branch-protection",
        *(f"environment:{name}" for name in sorted(expected_environments)),
    ]
    expected_check_ids = set(expected_check_order)
    actual_check_ids = [check_id for check_id, states in check_states.items() for _ in states]
    environments_ok = (
        len(actual_environments) == len(set(actual_environments))
        and set(actual_environments) == expected_environments
    )
    checks_ok = (
        len(actual_check_ids) == len(set(actual_check_ids))
        and set(actual_check_ids) == expected_check_ids
    )

    issues: list[JsonObject] = []
    comparisons = (
        (reported_passed is True, "GITHUB_PREFLIGHT_REPORT_RESULT_MISMATCH", "passed"),
        (
            reported_operational_failure is False,
            "GITHUB_PREFLIGHT_REPORT_OPERATIONAL_STATE_MISMATCH",
            "operational_failure",
        ),
        (
            actual_repository == repository,
            "GITHUB_PREFLIGHT_REPORT_REPOSITORY_MISMATCH",
            "repository",
        ),
        (
            actual_default_branch == requirements.default_branch,
            "GITHUB_PREFLIGHT_REPORT_DEFAULT_BRANCH_MISMATCH",
            "default_branch",
        ),
        (
            actual_release_tag == release_tag,
            "GITHUB_PREFLIGHT_REPORT_RELEASE_TAG_MISMATCH",
            "release_tag",
        ),
        (
            release_tag_policy_ok,
            "GITHUB_PREFLIGHT_REPORT_RELEASE_TAG_POLICY_MISMATCH",
            "release_tag",
        ),
        (
            actual_git_sha == git_sha,
            "GITHUB_PREFLIGHT_REPORT_GIT_SHA_MISMATCH",
            "git_sha",
        ),
        (
            actual_release_id == release_id,
            "GITHUB_PREFLIGHT_REPORT_RELEASE_ID_MISMATCH",
            "release_id",
        ),
        (
            protection_source in {"classic", "ruleset"},
            "GITHUB_PREFLIGHT_REPORT_MAIN_PROTECTION_SOURCE_MISMATCH",
            "main_protection_source",
        ),
        (
            environments_ok,
            "GITHUB_PREFLIGHT_REPORT_ENVIRONMENT_SET_MISMATCH",
            "validated_environments",
        ),
        (checks_ok, "GITHUB_PREFLIGHT_REPORT_CHECK_SET_MISMATCH", "checks"),
        (not upstream_issues, "GITHUB_PREFLIGHT_REPORT_ISSUES_PRESENT", "issues"),
        (
            secret_values_accessed is False,
            "GITHUB_PREFLIGHT_REPORT_SECRET_ACCESS_INVALID",
            "secret_values_accessed",
        ),
    )
    for passed, issue_code, scope in comparisons:
        if not passed:
            _add_issue(issues, code=issue_code, scope=scope)

    def exact_check_passed(check_id: str) -> bool:
        return check_states.get(check_id) == [True]

    if any(
        not exact_check_passed(check_id)
        for check_id in expected_check_ids
        if check_id in check_states
    ):
        _add_issue(issues, code="GITHUB_PREFLIGHT_REPORT_CHECK_FAILED", scope="checks")

    identity_ok = all(
        (
            actual_repository == repository,
            actual_default_branch == requirements.default_branch,
            actual_release_tag == release_tag,
            release_tag_policy_ok,
            actual_git_sha == git_sha,
            actual_release_id == release_id,
        )
    )
    source_ok = protection_source in {"classic", "ruleset"}
    normalized_checks: list[JsonObject] = []
    for check_id in expected_check_order:
        check_passed = exact_check_passed(check_id)
        if check_id == "repository-and-release-identity":
            check_passed = check_passed and identity_ok
        elif check_id == "main-branch-protection":
            check_passed = check_passed and source_ok
        elif check_id.startswith("environment:"):
            check_passed = check_passed and environments_ok
        normalized: JsonObject = {"id": check_id, "passed": check_passed}
        if check_id == "main-branch-protection":
            normalized["source"] = protection_source if check_passed else None
        normalized_checks.append(normalized)

    return {
        "schema_version": "1.0",
        "passed": not issues,
        "operational_failure": False,
        "repository": repository,
        "default_branch": requirements.default_branch,
        "release_tag": release_tag,
        "git_sha": git_sha,
        "release_id": release_id,
        "validated_at": datetime.now(UTC).isoformat(),
        "main_protection_source": (
            protection_source
            if source_ok and exact_check_passed("main-branch-protection")
            else None
        ),
        "validated_environments": (
            sorted(expected_environments)
            if environments_ok
            and all(exact_check_passed(f"environment:{name}") for name in expected_environments)
            else []
        ),
        "checks": normalized_checks,
        "issues": issues,
        "secret_values_accessed": False,
    }


class GitHubApiClient:
    """Small read-only GitHub REST client with bounded responses and pagination."""

    def __init__(
        self,
        *,
        server_url: str,
        api_url: str,
        token: str,
        timeout_seconds: float,
    ) -> None:
        server = urlparse(server_url)
        parsed = urlparse(api_url)
        server_hostname = server.hostname
        api_hostname = parsed.hostname
        if (
            parsed.scheme != "https"
            or not api_hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise PreflightInputError(
                "GITHUB_PREFLIGHT_API_URL_INVALID: api URL must be a credential-free HTTPS URL"
            )
        if (
            server.scheme != "https"
            or not server_hostname
            or server.username is not None
            or server.password is not None
            or server.path not in {"", "/"}
            or server.query
            or server.fragment
        ):
            raise PreflightInputError(
                "GITHUB_PREFLIGHT_SERVER_URL_INVALID: "
                "server URL must be a credential-free HTTPS origin"
            )
        try:
            server_port = server.port or 443
            api_port = parsed.port or 443
        except ValueError as exc:
            raise PreflightInputError("GITHUB_PREFLIGHT_API_URL_INVALID") from exc
        server_host = server_hostname.lower().rstrip(".")
        api_host = api_hostname.lower().rstrip(".")
        trusted_api_hosts = (
            {"api.github.com"}
            if server_host == "github.com"
            else {server_host, f"api.{server_host}"}
        )
        if api_host not in trusted_api_hosts or api_port != server_port:
            raise PreflightInputError("GITHUB_PREFLIGHT_API_ORIGIN_UNTRUSTED")
        if not token:
            raise PreflightInputError("GITHUB_PREFLIGHT_TOKEN_MISSING")
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise PreflightInputError(
                "GITHUB_PREFLIGHT_TIMEOUT_INVALID: timeout must be in (0, 60]"
            )
        self._api_url = api_url.rstrip("/")
        self._token = token
        self._timeout_seconds = timeout_seconds
        self._opener = build_opener(_RejectRedirects())

    def get(self, path: str, *, allow_not_found: bool = False) -> ApiResponse:
        if not path.startswith("/") or "\r" in path or "\n" in path:
            raise GitHubApiError("GITHUB_PREFLIGHT_API_PATH_INVALID")
        request = Request(  # noqa: S310 - constructor receives a validated HTTPS URL
            f"{self._api_url}{path}",
            method="GET",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "X-GitHub-Api-Version": "2026-03-10",
                "User-Agent": "agent-platform-release-preflight/1.0",
            },
        )
        try:
            # The base URL is validated as HTTPS and every path is repository-owned.
            with self._opener.open(
                request,
                timeout=self._timeout_seconds,
            ) as response:
                status = response.status
                body = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            if exc.code == 404 and allow_not_found:
                return ApiResponse(status=404, value=None)
            raise GitHubApiError(
                f"GITHUB_PREFLIGHT_API_ERROR: GET {path} returned HTTP {exc.code}"
            ) from exc
        except (TimeoutError, URLError) as exc:
            raise GitHubApiError(
                f"GITHUB_PREFLIGHT_API_ERROR: transport failure for GET {path}"
            ) from exc
        if status != 200:
            raise GitHubApiError(f"GITHUB_PREFLIGHT_API_ERROR: GET {path} returned HTTP {status}")
        if len(body) > MAX_RESPONSE_BYTES:
            raise GitHubApiError(f"GITHUB_PREFLIGHT_API_RESPONSE_TOO_LARGE: GET {path}")
        try:
            value: object = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GitHubApiError(f"GITHUB_PREFLIGHT_API_RESPONSE_INVALID: GET {path}") from exc
        return ApiResponse(status=200, value=value)

    def paginated_object_items(
        self,
        path: str,
        *,
        key: str,
        per_page: int,
    ) -> list[object]:
        items: list[object] = []
        for page in range(1, MAX_PAGES + 1):
            query = urlencode({"per_page": per_page, "page": page})
            response = self.get(f"{path}?{query}")
            payload = _mapping(
                response.value,
                code="GITHUB_PREFLIGHT_API_RESPONSE_INVALID",
                field=path,
            )
            page_items = _sequence(
                payload.get(key),
                code="GITHUB_PREFLIGHT_API_RESPONSE_INVALID",
                field=f"{path}.{key}",
            )
            items.extend(page_items)
            if len(page_items) < per_page:
                return items
        raise GitHubApiError(f"GITHUB_PREFLIGHT_API_PAGINATION_LIMIT: GET {path}")

    def paginated_list(self, path: str, *, per_page: int) -> list[object]:
        items: list[object] = []
        for page in range(1, MAX_PAGES + 1):
            query = urlencode({"per_page": per_page, "page": page})
            response = self.get(f"{path}?{query}")
            page_items = _sequence(
                response.value,
                code="GITHUB_PREFLIGHT_API_RESPONSE_INVALID",
                field=path,
            )
            items.extend(page_items)
            if len(page_items) < per_page:
                return items
        raise GitHubApiError(f"GITHUB_PREFLIGHT_API_PAGINATION_LIMIT: GET {path}")


def _metadata_name_list(items: list[object], *, field: str) -> list[str]:
    names: list[str] = []
    for index, item in enumerate(items):
        metadata = _mapping(
            item,
            code="GITHUB_PREFLIGHT_API_RESPONSE_INVALID",
            field=f"{field}.{index}",
        )
        names.append(
            _required_string(
                metadata.get("name"),
                code="GITHUB_PREFLIGHT_API_RESPONSE_INVALID",
                field=f"{field}.{index}.name",
            )
        )
    return sorted(set(names))


def _normalize_environment(value: object, *, name: str) -> JsonObject:
    environment = _mapping(
        value,
        code="GITHUB_PREFLIGHT_API_RESPONSE_INVALID",
        field=f"environments.{name}",
    )
    protection_rules: list[JsonObject] = []
    for index, raw_rule in enumerate(
        _sequence(
            environment.get("protection_rules", []),
            code="GITHUB_PREFLIGHT_API_RESPONSE_INVALID",
            field=f"environments.{name}.protection_rules",
        )
    ):
        rule = _mapping(
            raw_rule,
            code="GITHUB_PREFLIGHT_API_RESPONSE_INVALID",
            field=f"environments.{name}.protection_rules.{index}",
        )
        normalized_rule: JsonObject = {"type": rule.get("type")}
        if rule.get("type") == "required_reviewers":
            normalized_rule["prevent_self_review"] = rule.get("prevent_self_review")
            reviewers: list[JsonObject] = []
            for raw_reviewer in _sequence(
                rule.get("reviewers", []),
                code="GITHUB_PREFLIGHT_API_RESPONSE_INVALID",
                field=f"environments.{name}.protection_rules.{index}.reviewers",
            ):
                reviewer = _mapping(
                    raw_reviewer,
                    code="GITHUB_PREFLIGHT_API_RESPONSE_INVALID",
                    field=f"environments.{name}.reviewers",
                )
                identity_value = reviewer.get("reviewer")
                identity = (
                    cast(JsonObject, identity_value) if isinstance(identity_value, dict) else {}
                )
                reviewers.append(
                    {
                        "type": reviewer.get("type"),
                        "reviewer": {"id": identity.get("id")},
                    }
                )
            normalized_rule["reviewers"] = reviewers
        protection_rules.append(normalized_rule)
    branch_policy_value = environment.get("deployment_branch_policy")
    branch_policy: object
    if isinstance(branch_policy_value, dict):
        raw_branch_policy = cast(JsonObject, branch_policy_value)
        branch_policy = {
            "protected_branches": raw_branch_policy.get("protected_branches"),
            "custom_branch_policies": raw_branch_policy.get("custom_branch_policies"),
        }
    else:
        branch_policy = None
    return {
        "name": environment.get("name"),
        "protection_rules": protection_rules,
        "deployment_branch_policy": branch_policy,
    }


def _normalize_branch_protection(value: object) -> JsonObject:
    body = _mapping(
        value,
        code="GITHUB_PREFLIGHT_API_RESPONSE_INVALID",
        field="main_branch_protection",
    )
    reviews_value = body.get("required_pull_request_reviews")
    checks_value = body.get("required_status_checks")
    enforce_admins_value = body.get("enforce_admins")
    reviews: object = None
    checks: object = None
    enforce_admins: object = None
    if isinstance(enforce_admins_value, dict):
        raw_enforce_admins = cast(JsonObject, enforce_admins_value)
        enforce_admins = {"enabled": raw_enforce_admins.get("enabled")}
    if isinstance(reviews_value, dict):
        raw_reviews = cast(JsonObject, reviews_value)
        reviews = {
            "required_approving_review_count": raw_reviews.get("required_approving_review_count"),
            "bypass_pull_request_allowances": raw_reviews.get("bypass_pull_request_allowances"),
        }
    if isinstance(checks_value, dict):
        raw_checks = cast(JsonObject, checks_value)
        checks = {
            "strict": raw_checks.get("strict"),
            "contexts": raw_checks.get("contexts", []),
            "checks": raw_checks.get("checks", []),
        }
    return {
        "enforce_admins": enforce_admins,
        "required_pull_request_reviews": reviews,
        "required_status_checks": checks,
    }


def _normalize_ruleset(value: object) -> JsonObject:
    ruleset = _mapping(
        value,
        code="GITHUB_PREFLIGHT_API_RESPONSE_INVALID",
        field="ruleset",
    )
    conditions_value = ruleset.get("conditions")
    conditions = cast(JsonObject, conditions_value) if isinstance(conditions_value, dict) else {}
    ref_name_value = conditions.get("ref_name")
    ref_name = cast(JsonObject, ref_name_value) if isinstance(ref_name_value, dict) else {}
    normalized_rules: list[JsonObject] = []
    for raw_rule in (
        cast(list[object], ruleset.get("rules")) if isinstance(ruleset.get("rules"), list) else []
    ):
        if not isinstance(raw_rule, dict):
            continue
        rule = cast(JsonObject, raw_rule)
        if rule.get("type") not in {"pull_request", "required_status_checks"}:
            continue
        normalized_rules.append(
            {
                "type": rule.get("type"),
                "parameters": rule.get("parameters", {}),
            }
        )
    normalized: JsonObject = {
        "target": ruleset.get("target"),
        "enforcement": ruleset.get("enforcement"),
        "conditions": {
            "ref_name": {
                "include": ref_name.get("include", []),
                "exclude": ref_name.get("exclude", []),
            }
        },
        "rules": normalized_rules,
    }
    if "bypass_actors" in ruleset:
        normalized["bypass_actors"] = ruleset["bypass_actors"]
    return normalized


def collect_snapshot(
    client: GitHubApiClient,
    *,
    repository: str,
    requirements: PreflightRequirements,
) -> JsonObject:
    encoded_repository = "/".join(quote(part, safe="") for part in repository.split("/"))
    repository_response = client.get(f"/repos/{encoded_repository}")
    repository_payload = _mapping(
        repository_response.value,
        code="GITHUB_PREFLIGHT_API_RESPONSE_INVALID",
        field="repository",
    )
    protection_response = client.get(
        (
            f"/repos/{encoded_repository}/branches/"
            f"{quote(requirements.default_branch, safe='')}/protection"
        ),
        allow_not_found=True,
    )
    if protection_response.status == 200:
        protection_body: object = _normalize_branch_protection(protection_response.value)
    else:
        protection_body = None

    rulesets: list[JsonObject] = []
    for index, raw_summary in enumerate(
        client.paginated_list(
            f"/repos/{encoded_repository}/rulesets",
            per_page=100,
        )
    ):
        summary = _mapping(
            raw_summary,
            code="GITHUB_PREFLIGHT_API_RESPONSE_INVALID",
            field=f"rulesets.{index}",
        )
        ruleset_id = summary.get("id")
        if isinstance(ruleset_id, bool) or not isinstance(ruleset_id, int):
            raise GitHubApiError("GITHUB_PREFLIGHT_API_RESPONSE_INVALID: ruleset id is missing")
        detail = client.get(
            f"/repos/{encoded_repository}/rulesets/{ruleset_id}?includes_parents=true"
        )
        rulesets.append(_normalize_ruleset(detail.value))

    environments: dict[str, JsonObject] = {}
    for environment_name in sorted(requirements.environments):
        encoded_environment = quote(environment_name, safe="")
        base_path = f"/repos/{encoded_repository}/environments/{encoded_environment}"
        configuration = client.get(base_path, allow_not_found=True)
        if configuration.status == 404:
            continue
        normalized_configuration = _normalize_environment(
            configuration.value,
            name=environment_name,
        )
        branch_policy = normalized_configuration.get("deployment_branch_policy")
        custom_branch_policies = (
            isinstance(branch_policy, dict) and branch_policy.get("custom_branch_policies") is True
        )
        policies = (
            client.paginated_object_items(
                f"{base_path}/deployment-branch-policies",
                key="branch_policies",
                per_page=100,
            )
            if custom_branch_policies
            else []
        )
        variables = client.paginated_object_items(
            f"{base_path}/variables",
            key="variables",
            per_page=30,
        )
        secrets = client.paginated_object_items(
            f"{base_path}/secrets",
            key="secrets",
            per_page=100,
        )
        environments[environment_name] = {
            "configuration": normalized_configuration,
            "deployment_branch_policies": [
                {
                    "name": _mapping(
                        policy,
                        code="GITHUB_PREFLIGHT_API_RESPONSE_INVALID",
                        field=f"{environment_name}.deployment_branch_policies",
                    ).get("name"),
                    "type": _mapping(
                        policy,
                        code="GITHUB_PREFLIGHT_API_RESPONSE_INVALID",
                        field=f"{environment_name}.deployment_branch_policies",
                    ).get("type"),
                }
                for policy in policies
            ],
            "variable_names": _metadata_name_list(
                variables,
                field=f"{environment_name}.variables",
            ),
            "secret_names": _metadata_name_list(
                secrets,
                field=f"{environment_name}.secrets",
            ),
        }

    return {
        "schema_version": "1.0",
        "repository": {
            "full_name": repository_payload.get("full_name"),
            "default_branch": repository_payload.get("default_branch"),
        },
        "main_branch_protection": {
            "status": protection_response.status,
            "body": protection_body,
        },
        "rulesets": rulesets,
        "environments": environments,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate read-only GitHub control metadata before a release"
    )
    parser.add_argument("--requirements", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--git-sha", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--snapshot",
        type=Path,
        help="Validate a previously captured metadata-only snapshot instead of GitHub",
    )
    parser.add_argument(
        "--verify-report",
        type=Path,
        help="Verify and sanitize a downloaded external preflight report",
    )
    parser.add_argument(
        "--server-url",
        default=os.environ.get("GITHUB_SERVER_URL", "https://github.com"),
    )
    parser.add_argument(
        "--api-url",
        default=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
    )
    parser.add_argument(
        "--token-env",
        default="AGENT_PLATFORM_PREFLIGHT_GITHUB_TOKEN",
    )
    parser.add_argument("--timeout-seconds", type=float, default=15.0)
    return parser


def _write_report(path: Path, report: JsonObject) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    args = _parser().parse_args()
    repository = str(args.repository)
    release_tag = str(args.release_tag)
    git_sha = str(args.git_sha)
    release_id = str(args.release_id)
    token_env = str(args.token_env)
    output = cast(Path, args.output)
    try:
        if REPOSITORY_PATTERN.fullmatch(repository) is None:
            raise PreflightInputError("GITHUB_PREFLIGHT_REPOSITORY_INVALID")
        if (
            not release_tag
            or release_tag.startswith("refs/")
            or any(character in release_tag for character in "\r\n")
        ):
            raise PreflightInputError("GITHUB_PREFLIGHT_RELEASE_TAG_INVALID")
        if GIT_SHA_PATTERN.fullmatch(git_sha) is None:
            raise PreflightInputError("GITHUB_PREFLIGHT_GIT_SHA_INVALID")
        if RELEASE_ID_PATTERN.fullmatch(release_id) is None:
            raise PreflightInputError("GITHUB_PREFLIGHT_RELEASE_ID_INVALID")
        requirements = parse_requirements(
            _load_object(
                cast(Path, args.requirements),
                code="GITHUB_PREFLIGHT_REQUIREMENTS_INVALID",
            )
        )
        snapshot_path = cast(Path | None, args.snapshot)
        downloaded_report_path = cast(Path | None, args.verify_report)
        if snapshot_path is not None and downloaded_report_path is not None:
            raise PreflightInputError("GITHUB_PREFLIGHT_SOURCE_CONFLICT")
        if downloaded_report_path is not None:
            report = verify_preflight_report(
                _load_object(
                    downloaded_report_path,
                    code="GITHUB_PREFLIGHT_REPORT_INVALID",
                ),
                requirements,
                repository=repository,
                release_tag=release_tag,
                git_sha=git_sha,
                release_id=release_id,
            )
        else:
            if snapshot_path is None:
                if TOKEN_ENV_PATTERN.fullmatch(token_env) is None:
                    raise PreflightInputError("GITHUB_PREFLIGHT_TOKEN_ENV_INVALID")
                token = os.environ.get(token_env, "")
                client = GitHubApiClient(
                    server_url=str(args.server_url),
                    api_url=str(args.api_url),
                    token=token,
                    timeout_seconds=float(args.timeout_seconds),
                )
                snapshot = collect_snapshot(
                    client,
                    repository=repository,
                    requirements=requirements,
                )
            else:
                snapshot = _load_object(
                    snapshot_path,
                    code="GITHUB_PREFLIGHT_SNAPSHOT_INVALID",
                )
            report = validate_snapshot(
                snapshot,
                requirements,
                repository=repository,
                release_tag=release_tag,
                git_sha=git_sha,
                release_id=release_id,
            )
    except (PreflightInputError, GitHubApiError) as exc:
        error_code = str(exc).partition(":")[0]
        if TOKEN_ENV_PATTERN.fullmatch(error_code) is None:
            error_code = "GITHUB_PREFLIGHT_OPERATIONAL_FAILURE"
        report = {
            "schema_version": "1.0",
            "passed": False,
            "operational_failure": True,
            "repository": repository[:256],
            "release_tag": release_tag[:256],
            "git_sha": git_sha[:64],
            "release_id": release_id[:128],
            "validated_at": datetime.now(UTC).isoformat(),
            "main_protection_source": None,
            "validated_environments": [],
            "checks": [],
            "issues": [{"code": error_code, "scope": "preflight"}],
            "secret_values_accessed": False,
        }
        _write_report(output, report)
        print(f"external release preflight failed: {exc}", file=sys.stderr)
        return 2

    _write_report(output, report)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    if report["passed"] is not True:
        codes = ", ".join(str(issue["code"]) for issue in report["issues"])
        print(f"external release preflight blocked: {codes}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
