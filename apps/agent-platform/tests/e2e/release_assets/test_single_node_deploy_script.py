from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[5]
SCRIPT = REPO_ROOT / "scripts" / "deploy-agent-platform-single-node.mjs"
SMOKE_SCRIPT = REPO_ROOT / "apps" / "agent-platform" / "scripts" / "smoke_single_node_deployment.py"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "agent-demo-deploy.yml"
NODE = shutil.which("node")
if NODE is None:
    raise RuntimeError("node is required for deployment asset tests")
GIT = shutil.which("git")
if GIT is None:
    raise RuntimeError("git is required for deployment asset tests")


def test_single_node_deploy_script_is_dry_run_by_default() -> None:
    result = subprocess.run(  # noqa: S603 - fixed local Node executable and script
        [
            NODE,
            str(SCRIPT),
            "--release-id",
            "20260729-test",
            "--git-sha",
            "0123456789abcdef0123456789abcdef01234567",
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "DRY RUN: no local or server mutation" in result.stdout
    assert "root@47.253.230.197" in result.stdout
    assert "https://songuu.top/agent-demo/agent-platform/" in result.stdout
    assert "127.0.0.1:5181" in result.stdout


def test_default_release_id_is_git_bound_and_upgrade_guard_runs_before_clone() -> None:
    git_sha = subprocess.run(  # noqa: S603 - fixed local Git executable and arguments
        [GIT, "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    result = subprocess.run(  # noqa: S603 - fixed local Node executable and script
        [NODE, str(SCRIPT)],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert f"/releases/git-{git_sha}" in result.stdout
    source = SCRIPT.read_text(encoding="utf-8")
    assert source.index("single-node upgrades are refused") < source.index("git clone --depth 1")
    assert source.index("git ls-remote") < source.index("mktemp -d")
    assert source.index("mktemp -d") < source.index("git clone --depth 1")


def test_single_node_deploy_script_keeps_security_and_capacity_gates() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert "docker" in source
    assert "compose" in source
    assert "--no-build" in source
    assert "docker load" in source
    assert "minimumFreeDiskBytes" in source
    assert "minimumAvailableRuntimeBytes" in source
    assert "AGENT_PLATFORM_SINGLE_NODE_POSTGRES_PASSWORD" in source
    assert "AGENT_PLATFORM_SINGLE_NODE_MINIO_ROOT_PASSWORD" in source
    assert 'location ^~ " base_path "/ {' in source
    assert 'print "        return 404;"' in source
    assert "BEGIN managed Agent Platform single-node" in source
    assert "cmp -s" in source
    assert "candidate == domain" in source
    assert "matched_servers" in source
    assert source.count("current path exists but is not a symlink") == 2
    assert 'mv -T --no-clobber "$clone_dir" "$release"' in source
    assert "service_is_healthy" in source
    assert "job_completed_successfully" in source
    assert 'compose ps --all -q "$service"' in source
    assert source.index(
        'python3 "$release/apps/agent-platform/scripts/smoke_single_node_deployment.py"'
    ) < source.index('nginx_begin_marker="# BEGIN managed Agent Platform single-node')
    assert source.index('public_denied_code="$(curl') < source.index(
        'ln -sfn "$release" "$current"'
    )
    assert "if ($dm_authed" not in source
    assert "nginx -t" in source
    assert "AGENT_PLATFORM_RELEASE_GIT_SHA" in source
    assert "AGENT_PLATFORM_RELEASE_IMAGE_DIGEST" in source
    assert "actual_image_digest" in source
    assert "--expected-git-sha" in source
    assert "--expected-image-digest" in source
    assert "--expect-structural-only-readiness-block" in source
    assert "single-node-deployed-with-known-readiness-block" in source
    assert "pm2" not in source.lower()


def test_agent_platform_is_registered_at_the_deployed_base_path() -> None:
    registry = json.loads((REPO_ROOT / "app-registry.json").read_text(encoding="utf-8"))
    app = next(item for item in registry["apps"] if item["id"] == "agent-platform")

    assert app["workspace"] == "apps/agent-platform"
    assert app["local"]["url"] == "http://127.0.0.1:8080"
    assert app["deploy"] == {
        "basePath": "/agent-demo/agent-platform/",
        "port": 5181,
        "healthPath": "/health",
        "startCommand": "pnpm deploy:agent-platform:single-node",
    }


def test_spiffe_workflow_can_explicitly_deploy_the_single_node_platform() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")

    assert "deploy_agent_platform_single_node:" in source
    assert "if: inputs.deploy_agent_platform_single_node" in source
    assert (
        "github.event_name != 'workflow_dispatch' || !inputs.deploy_agent_platform_single_node"
        in source
    )
    assert "pnpm deploy:agent-platform:single-node --" in source
    assert '--git-sha "${GITHUB_SHA}"' in source
    assert '"${local_ready_code}" = "503"' in source
    assert "error:policy-fail-closed:structural-only" in source
    assert "spiffe_before_code" in source
    assert "spiffe_after_code" in source
    assert source.count("/assets/spiffe-agent-mtls-complete-architecture.svg") >= 3
    assert 'test "${spiffe_before_code}" = "200"' in source
    assert 'test "${spiffe_before_architecture_code}" = "200"' in source
    assert 'test "${spiffe_after_code}" = "200"' in source
    assert 'test "${spiffe_after_architecture_code}" = "200"' in source


def test_single_node_smoke_fails_fast_when_run_requires_manual_resume(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = importlib.util.spec_from_file_location("single_node_smoke", SMOKE_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    expected_sha = "0" * 40
    expected_digest = "sha256:" + "1" * 64

    def request_json(method: str, url: str, **_kwargs: Any) -> dict[str, Any]:
        if url.endswith("/health"):
            return {
                "ok": True,
                "release_git_sha": expected_sha,
                "release_image_digest": expected_digest,
            }
        if url.endswith("/ready"):
            return {
                "ready": False,
                "dependencies": {
                    "artifact_malware_scanner": ("error:policy-fail-closed:structural-only")
                },
            }
        if method == "POST" and url.endswith("/v1/runs"):
            return {"run_id": "run-paused"}
        if method == "GET" and url.endswith("/v1/runs/run-paused"):
            return {"status": "paused"}
        raise AssertionError((method, url))

    monkeypatch.setattr(module, "_request_json", request_json)
    monkeypatch.setattr(
        module.time,
        "sleep",
        lambda _seconds: pytest.fail("paused smoke must not sleep"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SMOKE_SCRIPT),
            "--expected-git-sha",
            expected_sha,
            "--expected-image-digest",
            expected_digest,
            "--expect-structural-only-readiness-block",
        ],
    )

    with pytest.raises(RuntimeError, match="terminal failure paused"):
        module.main()


def test_single_node_smoke_reads_artifact_metadata_and_content(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    spec = importlib.util.spec_from_file_location("single_node_smoke", SMOKE_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    expected_sha = "0" * 40
    expected_digest = "sha256:" + "1" * 64
    artifact_content = b'{"report":"verified"}'
    artifact_sha256 = hashlib.sha256(artifact_content).hexdigest()

    def request_json(method: str, url: str, **_kwargs: Any) -> dict[str, Any]:
        if url.endswith("/health"):
            return {
                "ok": True,
                "release_git_sha": expected_sha,
                "release_image_digest": expected_digest,
            }
        if url.endswith("/ready"):
            return {
                "ready": False,
                "dependencies": {
                    "artifact_malware_scanner": ("error:policy-fail-closed:structural-only")
                },
            }
        if method == "POST" and url.endswith("/v1/runs"):
            return {"run_id": "run-completed"}
        if method == "GET" and url.endswith("/v1/runs/run-completed"):
            return {
                "status": "completed",
                "result": {
                    "artifacts": [
                        {
                            "artifact_id": "00000000-0000-4000-8000-000000000001",
                            "sha256": artifact_sha256,
                            "size_bytes": len(artifact_content),
                        }
                    ]
                },
            }
        if method == "GET" and url.endswith("/v1/artifacts/00000000-0000-4000-8000-000000000001"):
            return {
                "artifact_id": "00000000-0000-4000-8000-000000000001",
                "run_id": "run-completed",
                "sha256": artifact_sha256,
                "size_bytes": len(artifact_content),
            }
        raise AssertionError((method, url))

    def request_bytes(method: str, url: str) -> bytes:
        assert method == "GET"
        assert url.endswith(
            "/v1/artifacts/00000000-0000-4000-8000-000000000001?download=true&purpose=single-node-release-smoke"
        )
        return artifact_content

    monkeypatch.setattr(module, "_request_json", request_json)
    monkeypatch.setattr(module, "_request_bytes", request_bytes)
    monkeypatch.setattr(module, "_request_text", lambda _method, _url: "run.completed")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SMOKE_SCRIPT),
            "--expected-git-sha",
            expected_sha,
            "--expected-image-digest",
            expected_digest,
            "--expect-structural-only-readiness-block",
        ],
    )

    assert module.main() == 0
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["artifact_readback"] is True
    assert receipt["artifact_id"] == "00000000-0000-4000-8000-000000000001"
    assert receipt["artifact_sha256"] == artifact_sha256
    assert receipt["artifact_size_bytes"] == len(artifact_content)


@pytest.mark.parametrize(
    ("metadata_sha256", "downloaded_content", "expected_error"),
    [
        ("0" * 64, b'{"report":"verified"}', "metadata readback mismatch"),
        (None, b'{"report":"tampered"}', "content readback mismatch"),
    ],
)
def test_single_node_smoke_artifact_readback_fails_closed_on_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    metadata_sha256: str | None,
    downloaded_content: bytes,
    expected_error: str,
) -> None:
    spec = importlib.util.spec_from_file_location("single_node_smoke", SMOKE_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    artifact_content = b'{"report":"verified"}'
    artifact_sha256 = hashlib.sha256(artifact_content).hexdigest()
    snapshot = {
        "status": "completed",
        "result": {
            "artifacts": [
                {
                    "artifact_id": "00000000-0000-4000-8000-000000000001",
                    "sha256": artifact_sha256,
                    "size_bytes": len(artifact_content),
                }
            ]
        },
    }
    metadata = {
        "artifact_id": "00000000-0000-4000-8000-000000000001",
        "run_id": "run-completed",
        "sha256": metadata_sha256 or artifact_sha256,
        "size_bytes": len(artifact_content),
    }
    monkeypatch.setattr(module, "_request_json", lambda *_args, **_kwargs: metadata)
    monkeypatch.setattr(
        module,
        "_request_bytes",
        lambda *_args, **_kwargs: downloaded_content,
    )

    with pytest.raises(RuntimeError, match=expected_error):
        module._read_back_artifact(
            "http://127.0.0.1:5181",
            "run-completed",
            snapshot,
        )


def test_single_node_smoke_script_covers_health_run_and_event_readback() -> None:
    help_result = subprocess.run(  # noqa: S603 - fixed local Python executable and script
        [sys.executable, str(SMOKE_SCRIPT), "--help"],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert help_result.returncode == 0, help_result.stderr
    source = SMOKE_SCRIPT.read_text(encoding="utf-8")
    assert 'f"{base_url}/health"' in source
    assert 'f"{base_url}/ready"' in source
    assert '"--expected-git-sha"' in source
    assert '"--expected-image-digest"' in source
    assert '"--expect-structural-only-readiness-block"' in source
    assert '"known_constrained_readiness_block"' in source
    assert '"paused",' in source
    assert '"waiting_approval",' in source
    assert 'f"{base_url}/v1/runs"' in source
    assert '"Idempotency-Key"' in source
    assert '"completed"' in source
    assert 'f"{base_url}/v1/runs/{run_id}/events"' in source
    assert '"artifact_readback": True' in source
