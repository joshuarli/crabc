#!/usr/bin/env python3
"""Contract tests for the test-only host-tool TLS-model wrapper."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "scripts" / "rustc_test_host_tool_wrapper.sh"


class RustcTestHostToolWrapperTests(unittest.TestCase):
    def run_wrapper(self, *arguments: str) -> list[str]:
        completed = subprocess.run(
            ["bash", str(WRAPPER), "/bin/echo", *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return completed.stdout.split()

    def test_runtime_crate_keeps_initial_exec(self) -> None:
        self.assertEqual(
            self.run_wrapper(
                "--crate-name",
                "crabc_mimalloc",
                "-Ztls-model=initial-exec",
                "--crate-type=lib",
            ),
            [
                "--crate-name",
                "crabc_mimalloc",
                "-Ztls-model=initial-exec",
                "--crate-type=lib",
            ],
        )

    def test_build_script_removes_initial_exec(self) -> None:
        self.assertEqual(
            self.run_wrapper(
                "--crate-name",
                "build_script_build",
                "-Ztls-model=initial-exec",
            ),
            ["--crate-name", "build_script_build"],
        )

    def test_proc_macro_removes_initial_exec(self) -> None:
        self.assertEqual(
            self.run_wrapper(
                "--crate-type=proc-macro",
                "-Ztls-model=initial-exec",
            ),
            ["--crate-type=proc-macro"],
        )


if __name__ == "__main__":
    unittest.main()
