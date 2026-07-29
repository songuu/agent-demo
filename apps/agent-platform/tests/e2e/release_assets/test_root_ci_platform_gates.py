from __future__ import annotations

from pathlib import Path

PLATFORM_ROOT = Path(__file__).parents[3]
REPOSITORY_ROOT = PLATFORM_ROOT.parents[1]
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "agent-demo-deploy.yml"


def test_root_ci_bootstraps_python_uv_and_runs_all_platform_gates() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "actions/setup-python@" in workflow
    assert 'python-version: "3.12"' in workflow
    assert "astral-sh/setup-uv@" in workflow
    assert "cache-dependency-glob: apps/agent-platform/uv.lock" in workflow
    assert "uv sync --frozen --extra dev" in workflow

    assert "pnpm --filter @agent-demo/agent-platform lint" in workflow
    assert "pnpm --filter @agent-demo/agent-platform format:check" in workflow
    for recursive_gate in ("pnpm typecheck", "pnpm test", "pnpm build"):
        assert recursive_gate in workflow

    assert "evals/run_release_evals.py" in workflow
    assert "--mode offline" in workflow
    assert "offline-release-evals.json" in workflow


def test_root_ci_preserves_spiffe_build_and_production_verification() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert 'require("./apps/spiffe-mtls-agent/dist/src/web/demo-model.js")' in workflow
    assert "expected 8 demo steps" in workflow
    assert "pnpm deploy:prod" in workflow
    assert "Verify production" in workflow
    assert "/assets/spiffe-agent-mtls-complete-architecture.svg" in workflow


def test_root_ci_validates_opa_policies_with_a_pinned_image() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "openpolicyagent/opa:1.5.1-static" in workflow
    assert "check --strict policies" in workflow
    assert "test policies tests/policy" in workflow
    assert "Build self-check" in workflow
