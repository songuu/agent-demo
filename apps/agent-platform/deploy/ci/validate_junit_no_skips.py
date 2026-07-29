"""Fail a release gate when a required integration suite silently skipped tests."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import defusedxml.ElementTree as ET


def validate_junit(path: Path, *, suite_name: str, minimum_tests: int) -> dict[str, object]:
    root = ET.parse(path).getroot()
    if root is None:
        raise ValueError(f"JUNIT_ROOT_MISSING: {suite_name}")
    cases = list(root.iter("testcase"))
    skipped = [
        f"{case.get('classname', '')}::{case.get('name', '')}"
        for case in cases
        if case.find("skipped") is not None
    ]
    failures = [
        f"{case.get('classname', '')}::{case.get('name', '')}"
        for case in cases
        if case.find("failure") is not None or case.find("error") is not None
    ]
    if len(cases) < minimum_tests:
        raise ValueError(
            f"REQUIRED_TEST_COUNT_NOT_MET: {suite_name} ran {len(cases)}, "
            f"expected at least {minimum_tests}"
        )
    if skipped:
        raise ValueError(f"REQUIRED_TESTS_SKIPPED: {suite_name}: {sorted(skipped)}")
    if failures:
        raise ValueError(f"REQUIRED_TESTS_FAILED: {suite_name}: {sorted(failures)}")
    return {
        "schema_version": "1.0",
        "suite": suite_name,
        "tests": len(cases),
        "skipped": 0,
        "failed": 0,
        "passed": True,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Require a non-empty pytest JUnit suite with zero skipped tests"
    )
    parser.add_argument("--junit", type=Path, required=True)
    parser.add_argument("--suite-name", required=True)
    parser.add_argument("--minimum-tests", type=int, default=1)
    parser.add_argument("--output", type=Path)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        report = validate_junit(
            args.junit,
            suite_name=args.suite_name,
            minimum_tests=args.minimum_tests,
        )
    except (OSError, ET.ParseError, ValueError) as exc:
        print(f"required test validation failed: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(report, sort_keys=True)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
