from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any

import yaml

PLATFORM_ROOT = Path(__file__).resolve().parents[3]
REPOSITORY_ROOT = PLATFORM_ROOT.parents[1]
WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "agent-platform-release.yml"
ROOT_WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "agent-demo-deploy.yml"
PR_PIPELINE_PATH = PLATFORM_ROOT / "deploy" / "ci" / "pr-pipeline.yaml"
PYPROJECT_PATH = PLATFORM_ROOT / "pyproject.toml"
UV_LOCK_PATH = PLATFORM_ROOT / "uv.lock"
DOCKERFILE_PATH = PLATFORM_ROOT / "deploy" / "docker" / "Dockerfile"
DOCKERIGNORE_PATH = PLATFORM_ROOT / ".dockerignore"
COMPOSE_PATH = PLATFORM_ROOT / "deploy" / "docker" / "docker-compose.yml"
PACKAGE_PATH = PLATFORM_ROOT / "package.json"
EXPECTED_CONTAINER_IMAGES = {
    "ghcr.io/gitleaks/gitleaks:v8.28.0": (
        "sha256:cdbb7c955abce02001a9f6c9f602fb195b7fadc1e812065883f695d1eeaba854"
    ),
    "openpolicyagent/opa:1.5.1-static": (
        "sha256:72c5186ef74bc7a88faf88204109476be41cdc392ff1de722f7d8ecb08f18c4d"
    ),
    "openpolicyagent/conftest:v0.62.0": (
        "sha256:6182c0c61e83ae6522ed29e5084ac5cce4c88cd0aa26ffb1c6fc57bb34e9daa9"
    ),
    "postgres:16.9-alpine": (
        "sha256:7c688148e5e156d0e86df7ba8ae5a05a2386aaec1e2ad8e6d11bdf10504b1fb7"
    ),
    "temporalio/auto-setup:1.27.2": (
        "sha256:b44cbfeb43dbeae42db113b44fb8414c3452f05643b3d6b1592f955277d73526"
    ),
    "minio/minio:RELEASE.2025-04-22T22-12-26Z": (
        "sha256:a1ea29fa28355559ef137d71fc570e508a214ec84ff8083e39bc5428980b015e"
    ),
    "minio/mc:RELEASE.2025-04-16T18-13-26Z": (
        "sha256:aead63c77f9db9107f1696fb08ecb0faeda23729cde94b0f663edf4fe09728e3"
    ),
    "redis:7.4.9": ("sha256:33d7c9a245edd95e6703a0addbeaa48fe40c3b3b4783627a72085155462ebfdb"),
}
EXPECTED_ACTION_TAGS = {
    "actions/attest": "v4",
    "actions/checkout": "v6",
    "actions/create-github-app-token": "v3",
    "actions/download-artifact": "v6",
    "actions/setup-node": "v6",
    "actions/setup-python": "v6",
    "actions/upload-artifact": "v6",
    "anchore/sbom-action": "v0",
    "anchore/sbom-action/download-syft": "v0",
    "aquasecurity/trivy-action": "v0.36.0",
    "astral-sh/setup-uv": "v7",
    "Azure/setup-helm": "v5",
    "Azure/setup-kubectl": "v5",
    "docker/build-push-action": "v7",
    "docker/login-action": "v4",
    "docker/setup-buildx-action": "v3",
    "hashicorp/setup-terraform": "v3",
    "pnpm/action-setup": "v4",
    "sigstore/cosign-installer": "v4.1.2",
}
EXPECTED_ACTION_COMMITS = {
    "actions/attest": "f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6",
    "actions/checkout": "d23441a48e516b6c34aea4fa41551a30e30af803",
    "actions/create-github-app-token": "bcd2ba49218906704ab6c1aa796996da409d3eb1",
    "actions/download-artifact": "018cc2cf5baa6db3ef3c5f8a56943fffe632ef53",
    "actions/setup-node": "249970729cb0ef3589644e2896645e5dc5ba9c38",
    "actions/setup-python": "ece7cb06caefa5fff74198d8649806c4678c61a1",
    "actions/upload-artifact": "b7c566a772e6b6bfb58ed0dc250532a479d7789f",
    "anchore/sbom-action": "e22c389904149dbc22b58101806040fa8d37a610",
    "anchore/sbom-action/download-syft": "e22c389904149dbc22b58101806040fa8d37a610",
    "aquasecurity/trivy-action": "ed142fd0673e97e23eac54620cfb913e5ce36c25",
    "astral-sh/setup-uv": "37802adc94f370d6bfd71619e3f0bf239e1f3b78",
    "Azure/setup-helm": "9bc31f4ebc9c6b171d7bfbaa5d006ae7abdb4310",
    "Azure/setup-kubectl": "829323503d1be3d00ca8346e5391ca0b07a9ab0d",
    "docker/build-push-action": "53b7df96c91f9c12dcc8a07bcb9ccacbed38856a",
    "docker/login-action": "abd2ef45e78c5afb21d64d4ca52ee8550d9572c7",
    "docker/setup-buildx-action": "8d2750c68a42422c14e847fe6c8ac0403b4cbd6f",
    "hashicorp/setup-terraform": "b9cd54a3c349d3f38e8881555d616ced269862dd",
    "pnpm/action-setup": "b906affcce14559ad1aafd4ab0e942779e9f58b1",
    "sigstore/cosign-installer": "6f9f17788090df1f26f669e9d70d6ae9567deba6",
}
ACTION_USE_LINE = re.compile(
    r"^\s*(?:-\s+)?uses:\s+"
    r"(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?)"
    r"@(?P<ref>[a-f0-9]{40})\s+#\s+(?P<tag>\S+)\s*$"
)
CONTAINER_REFERENCE = re.compile(
    r"(?P<reference>(?:ghcr\.io/gitleaks/gitleaks|"
    r"openpolicyagent/(?:opa|conftest)|postgres|temporalio/auto-setup|"
    r"minio/(?:minio|mc)|redis):[A-Za-z0-9._-]+"
    r"(?:@sha256:[a-f0-9]{64})?)"
)


def _workflow() -> dict[str, Any]:
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    return workflow


def _job_text(job: dict[str, Any]) -> str:
    values: list[str] = []

    def collect(value: object) -> None:
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, dict):
            for nested in value.values():
                collect(nested)
        elif isinstance(value, list):
            for nested in value:
                collect(nested)

    collect(job)
    return "\n".join(values)


def test_platform_quality_workflows_pin_every_action_to_a_reviewed_commit() -> None:
    seen: set[str] = set()
    for workflow_path in (WORKFLOW_PATH, ROOT_WORKFLOW_PATH):
        for line_number, line in enumerate(
            workflow_path.read_text(encoding="utf-8").splitlines(),
            start=1,
        ):
            if "uses:" not in line:
                continue
            matched = ACTION_USE_LINE.fullmatch(line)
            assert matched is not None, f"{workflow_path}:{line_number}: mutable action ref: {line}"
            action = matched.group("action")
            assert action in EXPECTED_ACTION_TAGS, (
                f"{workflow_path}:{line_number}: unreviewed action: {action}"
            )
            assert matched.group("tag") == EXPECTED_ACTION_TAGS[action]
            assert matched.group("ref") == EXPECTED_ACTION_COMMITS[action]
            seen.add(action)

    assert seen == set(EXPECTED_ACTION_TAGS)


def test_all_ci_helpers_and_required_services_are_pinned_to_reviewed_digests() -> None:
    paths = (WORKFLOW_PATH, ROOT_WORKFLOW_PATH, COMPOSE_PATH, PR_PIPELINE_PATH)
    seen: set[str] = set()

    for path in paths:
        candidate_lines = (
            line
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip().startswith(("image: ", "- ")) or line.rstrip().endswith("\\")
        )
        for line in candidate_lines:
            matched = CONTAINER_REFERENCE.search(line)
            if matched is None:
                continue
            reference = matched.group("reference")
            assert "@sha256:" in reference, f"{path}: mutable container image: {reference}"
            tag, digest = reference.split("@", maxsplit=1)
            assert tag in EXPECTED_CONTAINER_IMAGES, f"{path}: unreviewed container image: {tag}"
            assert digest == EXPECTED_CONTAINER_IMAGES[tag]
            seen.add(tag)

    assert seen == set(EXPECTED_CONTAINER_IMAGES)


def test_quality_job_enforces_static_unit_and_source_supply_chain_gates() -> None:
    quality = _workflow()["jobs"]["quality"]
    quality_text = _job_text(quality)

    for command in (
        "ruff check src tests",
        "ruff format --check src tests",
        "mypy src",
        "bandit -c pyproject.toml -r src",
        "pytest tests/unit",
        "--cov=agent_platform",
        "--cov-branch",
        "--cov-fail-under=85",
        "gitleaks",
        "pip-audit",
        "anchore/sbom-action@",
        "aquasecurity/trivy-action@",
    ):
        assert command in quality_text

    workflow_source = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "fetch-depth: 0" in workflow_source
    for configuration in (
        "scan-type: fs",
        "severity: HIGH,CRITICAL",
        "exit-code: 1",
    ):
        assert configuration in workflow_source

    source_scan = next(
        step
        for step in quality["steps"]
        if step.get("name") == "Scan source dependencies, secrets, and configuration"
    )
    assert source_scan["with"]["skip-dirs"] == (
        "apps/agent-platform/.venv,apps/agent-platform/.artifacts"
    )
    assert source_scan["with"]["timeout"] == "15m"


def test_repository_default_coverage_gate_matches_required_eighty_five_percent() -> None:
    configuration = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))

    assert configuration["tool"]["coverage"]["report"]["fail_under"] == 85


def test_runtime_base_and_jwt_stack_are_pinned_to_scanned_versions() -> None:
    configuration = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))
    dependencies = set(configuration["project"]["dependencies"])
    dev_dependencies = set(configuration["dependency-groups"]["dev"])
    lock_packages = tomllib.loads(UV_LOCK_PATH.read_text(encoding="utf-8"))["package"]
    locked = {package["name"]: package["version"] for package in lock_packages}
    project_lock = next(package for package in lock_packages if package["name"] == "agent-platform")
    project_lock_dependencies = {dependency["name"] for dependency in project_lock["dependencies"]}
    dockerfile = DOCKERFILE_PATH.read_text(encoding="utf-8")

    assert "cryptography>=48,<49" in dependencies
    assert "defusedxml>=0.7,<1" in dependencies
    assert "PyJWT[crypto]>=2.13,<3" in dependencies
    assert all(not dependency.lower().startswith("python-jose") for dependency in dependencies)
    assert all(not dependency.lower().startswith("defusedxml") for dependency in dev_dependencies)
    assert locked["cryptography"] == "48.0.1"
    assert locked["defusedxml"] == "0.7.1"
    assert locked["pyjwt"] == "2.13.0"
    assert "defusedxml" in project_lock_dependencies
    assert "ecdsa" not in locked
    assert (
        "ARG PYTHON_BUILDER_IMAGE=python:3.12.13-slim-trixie@"
        "sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de"
    ) in dockerfile
    assert (
        "ARG PYTHON_RUNTIME_IMAGE=ubuntu:24.04@"
        "sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90"
    ) in dockerfile
    assert "FROM ${PYTHON_BUILDER_IMAGE} AS builder" in dockerfile
    assert "FROM ${PYTHON_RUNTIME_IMAGE} AS runtime" in dockerfile
    assert "apt-get install -y --no-install-recommends python3.12 ca-certificates" in dockerfile
    assert '.venv/bin/python -c "import defusedxml.ElementTree"' in dockerfile


def test_docker_build_context_is_an_explicit_source_allowlist() -> None:
    entries = {
        line.strip()
        for line in DOCKERIGNORE_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    assert "**" in entries
    for required in (
        "!pyproject.toml",
        "!uv.lock",
        "!README.md",
        "!src",
        "!src/**",
        "!prompts",
        "!prompts/**",
        "!evals",
        "!evals/**",
        "!migrations",
        "!migrations/**",
        "!alembic.ini",
    ):
        assert required in entries
    assert not any(entry.startswith("!.env") for entry in entries)


def test_quality_job_runs_required_services_integration_replay_and_smoke_eval() -> None:
    quality_text = _job_text(_workflow()["jobs"]["quality"])

    for service in ("postgres", "temporal", "minio", "opa"):
        assert service in quality_text
    for command in (
        "alembic upgrade head",
        "pytest tests/integration tests/contract",
        "--junitxml=",
        "validate_junit_no_skips.py",
        "--minimum-tests",
        "replay_workflow_histories.py",
        "--minimum-histories",
        "run_release_evals.py",
        "agent-eval-smoke-manifest.json",
    ):
        assert command in quality_text


def test_pytest_entrypoints_preserve_the_application_root_import_path() -> None:
    package = json.loads(PACKAGE_PATH.read_text(encoding="utf-8"))
    quality_text = _job_text(_workflow()["jobs"]["quality"])

    assert package["scripts"]["test"] == "uv run --frozen python -m pytest"
    assert "python -m pytest tests/unit" in quality_text
    assert "python -m pytest tests/integration tests/contract" in quality_text
    assert "uv run --frozen pytest" not in quality_text


def test_policy_preview_runs_opa_and_conftest_against_rendered_iac() -> None:
    workflow = _workflow()
    quality_text = _job_text(workflow["jobs"]["quality"])

    assert workflow["env"]["TERRAFORM_VERSION"] == "1.9.8"
    assert "opa:1.5.1-static" in quality_text
    assert "test policies tests/policy" in quality_text
    assert "openpolicyagent/conftest:" in quality_text
    assert "conftest" in quality_text
    assert "deploy/ci/conftest" in quality_text
    assert "deploy/terraform" in quality_text
    assert "agent-platform-staging.yaml" in quality_text
    assert "kustomize-production.yaml" in quality_text
    for command in (
        "hashicorp/setup-terraform@",
        "terraform fmt -check -recursive",
        "init -backend=false -input=false -lockfile=readonly",
        "validate -no-color",
        "test -no-color",
        ".artifacts/quality/terraform-test.txt",
    ):
        assert command in quality_text


def test_exact_image_is_scanned_before_it_is_signed_and_attested() -> None:
    build = _workflow()["jobs"]["build_image"]
    build_text = yaml.safe_dump(build, sort_keys=False)

    scan_index = build_text.index("aquasecurity/trivy-action@")
    sign_index = build_text.index("cosign sign --yes")
    assert scan_index < sign_index
    assert "scan-type: image" in build_text
    assert "${{ steps.image.outputs.repository }}@${{ steps.build.outputs.digest }}" in build_text
    assert "severity: HIGH,CRITICAL" in build_text
    assert "exit-code: 1" in build_text
    assert "anchore/sbom-action@" in build_text
    assert build_text.count("actions/attest@") == 2


def test_documented_pr_pipeline_uses_only_real_executable_gates() -> None:
    pipeline = PR_PIPELINE_PATH.read_text(encoding="utf-8")

    assert "secret-scan" not in pipeline
    assert "dependency-scan" not in pipeline
    assert "evals/graders/run_suite.py" not in pipeline
    for command in (
        "gitleaks",
        "pip-audit",
        "trivy fs",
        "validate_junit_no_skips.py",
        "replay_workflow_histories.py",
        "run_release_evals.py",
        "terraform -chdir=deploy/terraform fmt -check -recursive",
        "terraform -chdir=deploy/terraform init -backend=false -input=false -lockfile=readonly",
        "terraform -chdir=deploy/terraform validate -no-color",
        "terraform -chdir=deploy/terraform test -no-color",
        "conftest test",
    ):
        assert command in pipeline


def test_release_workflow_pins_the_verified_helm_toolchain() -> None:
    workflow = _workflow()
    source = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert workflow["env"]["HELM_VERSION"] == "v4.2.3"
    assert source.count("version: ${{ env.HELM_VERSION }}") == 3


def test_release_workflow_pins_the_verified_kubectl_toolchain() -> None:
    workflow = _workflow()
    source = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert workflow["env"]["KUBECTL_VERSION"] == "v1.36.2"
    assert source.count("version: ${{ env.KUBECTL_VERSION }}") == 3
