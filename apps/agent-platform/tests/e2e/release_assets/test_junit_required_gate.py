from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from deploy.ci.validate_junit_no_skips import validate_junit

PLATFORM_ROOT = Path(__file__).resolve().parents[3]
VALIDATOR = PLATFORM_ROOT / "deploy" / "ci" / "validate_junit_no_skips.py"


def _write_junit(path: Path, cases: str) -> None:
    path.write_text(
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<testsuites><testsuite name="required">{cases}</testsuite></testsuites>',
        encoding="utf-8",
    )


def test_required_junit_gate_accepts_only_nonempty_skip_free_suite(tmp_path: Path) -> None:
    passing = tmp_path / "passing.xml"
    _write_junit(
        passing,
        '<testcase classname="integration.db" name="test_rls"/>'
        '<testcase classname="integration.temporal" name="test_replay"/>',
    )

    report = validate_junit(passing, suite_name="integration", minimum_tests=2)

    assert report["passed"] is True
    assert report["tests"] == 2


def test_required_junit_gate_rejects_skips_and_missing_tests(tmp_path: Path) -> None:
    skipped = tmp_path / "skipped.xml"
    _write_junit(
        skipped,
        '<testcase classname="integration.temporal" name="test_replay">'
        '<skipped message="server unavailable"/>'
        "</testcase>",
    )
    with pytest.raises(ValueError, match="REQUIRED_TESTS_SKIPPED"):
        validate_junit(skipped, suite_name="temporal", minimum_tests=1)

    empty = tmp_path / "empty.xml"
    _write_junit(empty, "")
    with pytest.raises(ValueError, match="REQUIRED_TEST_COUNT_NOT_MET"):
        validate_junit(empty, suite_name="postgres", minimum_tests=1)


def test_required_junit_gate_rejects_a_missing_document_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RootlessTree:
        @staticmethod
        def getroot() -> None:
            return None

    monkeypatch.setattr(
        "deploy.ci.validate_junit_no_skips.ET.parse",
        lambda _path: RootlessTree(),
    )

    with pytest.raises(ValueError, match="JUNIT_ROOT_MISSING: integration"):
        validate_junit(
            tmp_path / "rootless.xml",
            suite_name="integration",
            minimum_tests=1,
        )


def test_required_junit_cli_fails_closed_and_writes_passing_evidence(tmp_path: Path) -> None:
    passing = tmp_path / "passing.xml"
    output = tmp_path / "evidence.json"
    _write_junit(passing, '<testcase classname="integration.db" name="test_migrations"/>')

    # The executable and script path are repository-controlled constants.
    completed = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(VALIDATOR),
            "--junit",
            str(passing),
            "--suite-name",
            "postgres",
            "--minimum-tests",
            "1",
            "--output",
            str(output),
        ],
        capture_output=True,
        check=False,
        text=True,
    )

    assert completed.returncode == 0
    assert '"passed": true' in output.read_text(encoding="utf-8")
