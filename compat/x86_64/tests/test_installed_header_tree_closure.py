#!/usr/bin/env python3
"""Structural contract for the private x86 installed-header-tree closure gate."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat" / "x86_64" / "run_installed_header_tree_closure.sh"


class InstalledHeaderTreeClosureTests(unittest.TestCase):
    def test_runner_is_executable_and_shell_valid(self) -> None:
        result = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode), 0o755)

    def test_runner_materializes_and_closes_only_the_installed_tree(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")

        for phrase in (
            "readonly CANDIDATE_CLOSURE_RUNNER=",
            "readonly EXPECTED_PINNED_PUBLIC_HEADER_COUNT=183",
            "readonly EXPECTED_CANDIDATE_PUBLIC_HEADER_COUNT=191",
            "readonly EXPECTED_PROFILE_COUNT=7",
            "readonly EXPECTED_RECORD_COUNT=1337",
            "readonly -a ORACLE_NOT_APPLICABLE_ROWS=(aio.h:c11-strict aio.h:cxx17-strict)",
            "materialize_header_tree",
            'installed_include="$materialized_project/usr/include"',
            "validate_regular_header_tree",
            "source header tree contains a symlink",
            "source header tree contains a non-regular path",
            "write_manifest",
            "sha256sum",
            "installed header manifest differs from source tree",
            "run_candidate_header_closure.sh",
            'readonly PROJECT_INCLUDE="$ROOT_DIR/usr/include"',
            '"# pinned_public_header_count=$EXPECTED_PINNED_PUBLIC_HEADER_COUNT"',
            '"# candidate_public_header_count=$EXPECTED_CANDIDATE_PUBLIC_HEADER_COUNT"',
            "# profiles=c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict",
            "# record_count=$EXPECTED_RECORD_COUNT",
            "# status.reference-not-applicable=2",
            "exactly two aio strict oracle-N/A rows",
            "candidate include trace reached source include tree",
            "candidate include trace reached pinned musl despite -nostdinc",
            "candidate include trace escaped installed-tree/builtin/Linux-5.10 roots",
            "-nostdinc",
            "-nostdinc++",
            "# `-H` trace accepts that tree",
            "# schema=crabc.x86_64-installed-header-tree-closure/v1",
            "# scope=header-tree closure only; not ABI/layout/linkage/sysroot/promotion/public-support parity",
            "x86 installed header-tree closure: PASS",
        ):
            self.assertIn(phrase, runner)

        self.assertNotIn("--report-only", runner)
        self.assertNotIn("installed-header completion", runner)


if __name__ == "__main__":
    unittest.main()
