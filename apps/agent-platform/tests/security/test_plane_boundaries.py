from __future__ import annotations

import ast
from pathlib import Path

from agent_platform.tools.function_tools import AGENT_FUNCTION_TOOLS

SOURCE_ROOT = Path(__file__).parents[2] / "src" / "agent_platform"


def test_agent_runtime_has_no_commit_service_dependency() -> None:
    forbidden = {
        "agent_platform.application.commit_service",
        "agent_platform.workflows.activities",
    }
    violations: list[str] = []
    for path in (SOURCE_ROOT / "agents").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = {alias.name for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                modules = {node.module or ""}
            else:
                continue
            blocked = modules & forbidden
            if blocked:
                violations.append(f"{path.relative_to(SOURCE_ROOT)} imports {sorted(blocked)}")
    assert violations == []


def test_agent_visible_tools_expose_read_and_prepare_but_never_commit() -> None:
    names = frozenset(AGENT_FUNCTION_TOOLS)
    assert "knowledge.search" in names
    assert "email.prepare" in names
    assert all("commit" not in name.casefold() for name in names)


def test_commit_worker_is_a_separate_deployment_and_service_account() -> None:
    chart = Path(__file__).parents[2] / "deploy" / "helm" / "agent-platform"
    commit = (chart / "templates" / "commit-worker-deployment.yaml").read_text(encoding="utf-8")
    worker = (chart / "templates" / "agent-worker-deployment.yaml").read_text(encoding="utf-8")

    assert "serviceAccountName: commit-worker" in commit
    assert "serviceAccountName: agent-worker" in worker
    assert "commit-worker" not in worker
