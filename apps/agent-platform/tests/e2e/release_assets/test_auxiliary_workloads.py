from __future__ import annotations

from pathlib import Path

PLATFORM_ROOT = Path(__file__).parents[3]
TEMPLATE_ROOT = PLATFORM_ROOT / "deploy" / "helm" / "agent-platform" / "templates"


def test_runtime_image_contains_versioned_prompts_and_eval_assets() -> None:
    dockerfile = (PLATFORM_ROOT / "deploy" / "docker" / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY prompts ./prompts" in dockerfile
    assert "COPY evals ./evals" in dockerfile
    assert "/app/prompts" in dockerfile
    assert "/app/evals" in dockerfile


def test_migration_and_eval_workloads_have_separate_restricted_identities() -> None:
    migration = (TEMPLATE_ROOT / "migration-job.yaml").read_text(encoding="utf-8")
    eval_worker = (TEMPLATE_ROOT / "eval-worker-deployment.yaml").read_text(encoding="utf-8")

    assert "serviceAccountName: db-migrator" in migration
    assert 'command: ["alembic", "upgrade", "head"]' in migration
    assert "migration-dsn" in migration
    assert "AGENT_OPENAI_API_KEY" not in migration
    assert "runAsNonRoot: true" in migration
    assert "readOnlyRootFilesystem: true" in migration

    assert "serviceAccountName: eval-worker" in eval_worker
    assert "kind: Job" in eval_worker
    assert "evals/run_release_evals.py" in eval_worker
    assert '"--mode", "offline"' in eval_worker
    assert 'args: ["--help"]' not in eval_worker
    assert "AGENT_OPENAI_API_KEY" not in eval_worker
    assert "test-openai-project" not in eval_worker
    assert "business-system-credentials" not in eval_worker
    assert "runAsNonRoot: true" in eval_worker
    assert "readOnlyRootFilesystem: true" in eval_worker
