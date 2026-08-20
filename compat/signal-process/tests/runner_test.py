#!/usr/bin/env python3
"""Portable unit checks for the signal/process runner helpers."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("signal_process_runner", ROOT / "run.py")
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def test_help() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "run.py"), "--help"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert result.returncode == 0
    assert b"fork-worker-exec" in result.stdout
    assert b"mask-pending" in result.stdout
    assert b"thread-mask" in result.stdout
    assert b"sigwait" in result.stdout
    assert b"timer" in result.stdout


def test_raw_comparison_and_snapshot() -> None:
    reference = (0, b"stable\x00bytes", b"")
    candidate = (0, b"stable\x00bytes", b"")
    with contextlib.redirect_stdout(io.StringIO()):
        passed, report = RUNNER.compare_subcase("raw", reference, candidate)
    assert passed
    assert report["comparisons"] == {
        "exit_status_match": True,
        "stdout_match": True,
        "stderr_match": True,
        "normalization": "none",
    }
    assert report["reference"]["stdout"]["hex"] == "737461626c65006279746573"

    changed = (0, b"stable\x00bytes", b"loader diagnostic\n")
    with contextlib.redirect_stderr(io.StringIO()):
        passed, changed_report = RUNNER.compare_subcase("raw", reference, changed)
    assert not passed
    assert not changed_report["comparisons"]["stderr_match"]


def test_atomic_report() -> None:
    with tempfile.TemporaryDirectory(prefix="signal-process-runner-test-") as directory:
        destination = Path(directory) / "nested" / "report.json"
        RUNNER.atomic_write_json(destination, {"schema_version": 1, "raw": "ok"})
        assert json.loads(destination.read_text(encoding="utf-8")) == {
            "schema_version": 1,
            "raw": "ok",
        }
        assert not list(destination.parent.glob(".*.tmp"))


if __name__ == "__main__":
    test_help()
    test_raw_comparison_and_snapshot()
    test_atomic_report()
    print("signal-process runner tests: PASS")
