#!/usr/bin/env python3
"""Reject ambiguous utmpx replay arguments before tool or evidence creation."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
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

    def test_symlink_product_is_rejected_before_normalization_or_payload_access(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="utmpx-product-target.", dir=scratch) as target:
            link = scratch / "utmpx-product-link"
            link.symlink_to(target, target_is_directory=True)
            try:
                with tempfile.TemporaryDirectory(prefix="utmpx-parser.", dir=scratch) as temporary:
                    result = self.invoke((str(link),), temporary)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(
                        "owned-utmpx dynamic product must be a checkout .work directory",
                        result.stderr,
                    )
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(list(Path(temporary).iterdir()), [])
            finally:
                link.unlink(missing_ok=True)

    def test_invalid_receipt_retention_switch_is_rejected_before_evidence_creation(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="utmpx-retention.", dir=scratch) as temporary:
            result = subprocess.run(
                ["bash", str(RUNNER)], cwd=ROOT,
                env={**os.environ, "TMPDIR": temporary, "CRABC_X86_64_RETAIN_UTMPX_COMMANDS": "yes"},
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertIn("CRABC_X86_64_RETAIN_UTMPX_COMMANDS must be unset or 1", result.stderr)
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_dynamic_consumers_do_not_claim_to_define_libc_providers(self) -> None:
        """Keep the established static-provider and dynamic-import boundaries."""
        source = RUNNER.read_text(encoding="utf-8")
        matrix = source.index("# A supplied static product")
        static = source[source.index('if [ -n "$static_product" ]', matrix):source.index("assert_shared_symbols", matrix)]
        dynamic_start = source.index("for mode in pie non-pie; do", matrix)
        dynamic = source[dynamic_start:source.index("if [ -n \"$static_product\" ]", dynamic_start)]
        self.assertIn('assert_executable_symbols "static-$mode"', static)
        self.assertNotIn("assert_executable_symbols", dynamic)

    def test_archive_symbol_judge_rejects_duplicate_wrong_binding(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        function_start = source.index("assert_archive_symbols()")
        script_start = source.index("<<'PY'\n", function_start) + len("<<'PY'\n")
        script_end = source.index("\nPY\n}", script_start)
        descriptor, symbol_path = tempfile.mkstemp(
            prefix="utmpx-symbols.", dir=ROOT / ".work/x86_64/tmp"
        )
        os.close(descriptor)
        symbols = Path(symbol_path)
        try:
            strong = (
                "endutxent", "setutxent", "getutxent", "getutxid",
                "getutxline", "pututxline", "updwtmpx",
            )
            weak = (
                "endutent", "setutent", "getutent", "getutid", "getutline",
                "pututline", "updwtmp", "utmpname", "utmpxname",
            )
            symbols.write_text(
                "".join(f"00000000 T {name}\n" for name in strong)
                + "".join(f"00000000 W {name}\n" for name in weak)
                + "00000000 W endutxent\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, "-", str(symbols)],
                input=source[script_start:script_end],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
        finally:
            symbols.unlink(missing_ok=True)

    def test_shared_symbol_judge_rejects_duplicate_wrong_binding(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        function_start = source.index("assert_shared_symbols()")
        script_start = source.index("<<'PY'\n", function_start) + len("<<'PY'\n")
        script_end = source.index("\nPY\n}", script_start)
        descriptor, symbol_path = tempfile.mkstemp(
            prefix="utmpx-dyn-symbols.", dir=ROOT / ".work/x86_64/tmp"
        )
        os.close(descriptor)
        symbols = Path(symbol_path)
        try:
            strong = (
                "endutxent", "setutxent", "getutxent", "getutxid",
                "getutxline", "pututxline", "updwtmpx",
            )
            weak = (
                "endutent", "setutent", "getutent", "getutid", "getutline",
                "pututline", "updwtmp", "utmpname", "utmpxname",
            )
            symbols.write_text(
                "".join(f"  1: 00000000 0 FUNC GLOBAL DEFAULT 1 {name}\n" for name in strong)
                + "".join(f"  1: 00000000 0 FUNC WEAK DEFAULT 1 {name}\n" for name in weak)
                + "  1: 00000000 0 FUNC WEAK DEFAULT 1 endutxent\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, "-", str(symbols)],
                input=source[script_start:script_end],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
        finally:
            symbols.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
