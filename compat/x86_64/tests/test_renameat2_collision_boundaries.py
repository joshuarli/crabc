#!/usr/bin/env python3
"""Keep independently selected ``renameat2`` out of unrelated static fixtures."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
PATHNAME_LIFECYCLE = ROOT / "compat" / "x86_64" / "run_libc_pathname_lifecycle.sh"
UNRELATED_LEAF_RUNNERS = (
    ROOT / "compat" / "x86_64" / "run_libc_readlinkat.sh",
    ROOT / "compat" / "x86_64" / "run_libc_linkat.sh",
    ROOT / "compat" / "x86_64" / "run_libc_lchown.sh",
    ROOT / "compat" / "x86_64" / "run_libc_chown.sh",
    ROOT / "compat" / "x86_64" / "run_libc_unlinkat.sh",
)


class Renameat2CollisionBoundaryTests(unittest.TestCase):
    def test_pathname_lifecycle_accepts_archive_selection_but_rejects_candidate_leakage(
        self,
    ) -> None:
        runner = PATHNAME_LIFECYCLE.read_text(encoding="utf-8")
        archive_guard = runner.split("for unselected in", 1)[1].split(
            "readelf --relocs", 1
        )[0]

        self.assertNotIn("renameat2", archive_guard)
        self.assertIn("-Wl,--gc-sections", runner)
        self.assertIn(
            'if grep -Eq "[[:space:]]renameat2$" "$candidate_symbols"; then',
            runner,
        )
        self.assertIn(
            'fail "candidate unexpectedly pulls independently selected renameat2"',
            runner,
        )

    def test_unrelated_leaf_candidates_collect_sections_and_keep_both_guards(
        self,
    ) -> None:
        for runner_path in UNRELATED_LEAF_RUNNERS:
            with self.subTest(runner=runner_path.name):
                runner = runner_path.read_text(encoding="utf-8")
                self.assertIn("-Wl,--gc-sections", runner)
                self.assertIn("renameat2", runner)
                self.assertIn("candidate unexpectedly pulls independently selected", runner)
                self.assertIn("delegates to an unrelated C entry", runner)
                self.assertNotIn("candidate exports an unselected", runner)
                self.assertNotIn("delegates to an unselected", runner)


if __name__ == "__main__":
    unittest.main()
