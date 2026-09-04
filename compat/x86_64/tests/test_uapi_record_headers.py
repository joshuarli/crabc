#!/usr/bin/env python3
"""Focused x86 regression for the pinned Linux UAPI record boundary."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat" / "x86_64" / "run_uapi_wrapper_matrix.sh"
INVENTORY = ROOT / "compat" / "x86_64" / "public_headers.txt"
WRAPPERS = {
    "sys/kd.h": "linux/kd.h",
    "sys/soundcard.h": "linux/soundcard.h",
    "sys/vt.h": "linux/vt.h",
}


class UapiRecordHeaderTests(unittest.TestCase):
    def test_wrappers_forward_records_to_the_pinned_uapi_input(self) -> None:
        for wrapper, dependency in WRAPPERS.items():
            source = (ROOT / "include" / wrapper).read_text(encoding="utf-8")
            self.assertIn(f"#include <{dependency}>", source)
            self.assertFalse((ROOT / "include" / dependency).exists())

        public_headers = INVENTORY.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(public_headers), 183)
        self.assertEqual(
            [header for header in public_headers if header in WRAPPERS],
            list(WRAPPERS),
        )

    def test_matrix_keeps_project_first_and_external_uapi_roots(self) -> None:
        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        runner = RUNNER.read_text(encoding="utf-8")

        for phrase in (
            "readonly PROJECT_INCLUDE=\"$ROOT_DIR/include\"",
            "readonly LINUX_UAPI_INCLUDE=\"$LINUX_UAPI_ROOT/include\"",
            "-nostdinc",
            "-nostdinc++",
            '"$PROJECT_INCLUDE"/*|"$candidate_compiler_builtin_include"/*|"$LINUX_UAPI_INCLUDE"/*',
            "candidate trace escaped project/builtin/Linux-5.10 roots",
            "reference trace escaped musl/builtin/Linux-5.10 roots",
            "EXPECTED_ROW_COUNT=21",
        ):
            self.assertIn(phrase, runner)

        self.assertNotIn("-I /usr/include", runner)
        self.assertNotIn("include/linux/kd.h", runner)
        self.assertNotIn("include/linux/soundcard.h", runner)
        self.assertNotIn("include/linux/vt.h", runner)


if __name__ == "__main__":
    unittest.main()
