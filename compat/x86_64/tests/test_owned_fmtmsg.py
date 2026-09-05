#!/usr/bin/env python3
"""Reject ambiguous fmtmsg product replay before tools or evidence creation."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_fmtmsg.sh"


class OwnedFmtmsgTests(unittest.TestCase):
    def invoke(self, arguments: tuple[str, ...], temporary: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(RUNNER), *arguments], cwd=ROOT,
            env={**os.environ, "TMPDIR": temporary},
            capture_output=True, text=True, check=False,
        )

    def test_ambiguous_product_arguments_are_usage_errors(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="fmtmsg-parser.", dir=scratch) as temporary:
            product = Path(temporary) / "product"
            product.mkdir()
            alias = Path(temporary) / "alias"
            alias.symlink_to(product, target_is_directory=True)
            for arguments in (
                ("--static-sysroot",), ("--static-sysroot", ""), ("",),
                ("--static-sysroot", "--not-a-product"), ("-x",),
                ("--static-sysroot", "/one", "--static-sysroot", "/two"),
                ("/one", "/two"),
                ("--static-sysroot", str(product), str(alias)),
            ):
                with self.subTest(arguments=arguments):
                    result = self.invoke(arguments, temporary)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(
                        result.stderr,
                        f"usage: {RUNNER} [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n",
                    )

    def test_products_outside_checkout_work_are_rejected_before_evidence_creation(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="fmtmsg-containment.", dir=scratch) as temporary:
            for arguments, family in (
                ((str(ROOT),), "dynamic"),
                (("--static-sysroot", str(ROOT)), "static"),
            ):
                with self.subTest(arguments=arguments):
                    result = self.invoke(arguments, temporary)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(f"fmtmsg {family} product must be a checkout .work directory", result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_temporary_evidence_boundary_rejects_a_symlink(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="fmtmsg-tmp.", dir=scratch) as temporary:
            real = Path(temporary) / "real"
            real.mkdir()
            alias = Path(temporary) / "alias"
            alias.symlink_to(real, target_is_directory=True)
            result = self.invoke((), str(alias))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("fmtmsg TMPDIR must be a physical checkout .work directory", result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(list(real.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
