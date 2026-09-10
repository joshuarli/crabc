#!/usr/bin/env python3
"""The installed locale component keeps one narrow source and product boundary."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_locale.sh"


class OwnedLocaleTests(unittest.TestCase):
    def assert_usage(self, *arguments: str) -> None:
        result = subprocess.run(
            ["bash", str(RUNNER), *arguments], cwd=ROOT, capture_output=True,
            text=True, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            result.stderr,
            f"usage: {RUNNER} [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n",
        )

    def test_replay_parser_rejects_missing_and_ambiguous_products(self) -> None:
        for arguments in (
            ("--static-sysroot",), ("--static-sysroot", ""),
            ("--static-sysroot", "-x"), ("",), ("-x",),
            ("--static-sysroot", "/one", "--static-sysroot", "/two"),
            ("/one", "/two"),
        ):
            with self.subTest(arguments=arguments):
                self.assert_usage(*arguments)

    def test_paths_reject_symlink_and_parent_components_before_evidence_creation(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="owned-locale-path.", dir=scratch) as temporary:
            base = Path(temporary)
            product = base / "product"
            product.mkdir()
            alias = base / "product-alias"
            alias.symlink_to(product, target_is_directory=True)
            parent = base / "parent"
            parent.mkdir()
            raw_parent = parent / ".." / "product"
            for argument in (alias, raw_parent, ROOT):
                with self.subTest(argument=argument):
                    result = subprocess.run(
                        ["bash", str(RUNNER), str(argument)], cwd=ROOT,
                        env={**os.environ, "TMPDIR": str(base)}, capture_output=True,
                        text=True, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("owned locale products dynamic product", result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(set(base.iterdir()), {product, alias, parent})

    def test_runner_remains_shell_syntax_valid(self) -> None:
        result = subprocess.run(["bash", "-n", str(RUNNER)], cwd=ROOT,
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
