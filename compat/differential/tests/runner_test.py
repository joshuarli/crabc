#!/usr/bin/env python3
"""Smoke-test the runner entry point and execute its foundational case."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    subprocess.run([sys.executable, str(ROOT / "run.py"), "--help"], check=True)
    with tempfile.TemporaryDirectory(prefix="crabc-differential-test-") as directory:
        report = Path(directory) / "foundational.json"
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "run.py"),
                "foundational",
                "--report",
                str(report),
            ],
            check=True,
        )
        result = json.loads(report.read_text(encoding="utf-8"))
        assert result["case"] == "foundational"
        assert result["passed"] is True
        assert result["reference"]["exit_status"] == 0
        assert result["candidate"]["exit_status"] == 0
        assert result["comparisons"] == {
            "errno_match": True,
            "exit_status_match": True,
            "stderr_match": True,
            "stdout_match": True,
        }
        assert result["normalized_lines"] == []
        assert result["normalized_line_count"] == 0
        assert result["candidate"]["stderr_normalized"] == result["candidate"]["stderr"]
        assert result["errno"] == {"candidate": 34, "match": True, "reference": 34}
        assert not list(Path(directory).glob(".*.tmp"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
