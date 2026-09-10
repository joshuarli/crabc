#!/usr/bin/env python3
"""Reject ambiguous utmpx replay arguments before tool or evidence creation."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_utmpx.sh"


class OwnedUtmpxTests(unittest.TestCase):
    def invoke(self, arguments: tuple[str, ...], temporary: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(RUNNER), *arguments], cwd=ROOT,
            env={**os.environ, "TMPDIR": temporary},
            capture_output=True, text=True, check=False,
        )

    def test_multiple_products_are_usage_errors(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="utmpx-parser.", dir=scratch) as temporary:
            result = self.invoke(("/one", "/two"), temporary)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertEqual(
                result.stderr,
                f"usage: {RUNNER} [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n",
            )

    def test_product_outside_checkout_work_is_rejected_before_evidence_creation(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="utmpx-containment.", dir=scratch) as temporary:
            result = self.invoke((str(ROOT),), temporary)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "owned-utmpx dynamic product must be a checkout .work directory",
                result.stderr,
            )
            self.assertEqual(result.stdout, "")
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_temporary_evidence_boundary_rejects_a_symlink(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="utmpx-tmp.", dir=scratch) as temporary:
            real = Path(temporary) / "real"
            real.mkdir()
            alias = Path(temporary) / "alias"
            alias.symlink_to(real, target_is_directory=True)
            result = self.invoke((), str(alias))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "owned-utmpx TMPDIR must be a physical checkout .work directory",
                result.stderr,
            )
            self.assertEqual(result.stdout, "")
            self.assertEqual(list(real.iterdir()), [])

    def test_same_static_and_dynamic_product_is_ambiguous_before_evidence_creation(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="utmpx-same-product.", dir=scratch) as product:
            product_path = Path(product)
            with tempfile.TemporaryDirectory(prefix="utmpx-parser.", dir=scratch) as temporary:
                result = self.invoke(
                    ("--static-sysroot", str(product_path), str(product_path)), temporary
                )
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertEqual(
                    result.stderr,
                    f"usage: {RUNNER} [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n",
                )
                self.assertEqual(list(Path(temporary).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
