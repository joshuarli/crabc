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
SOURCE = ROOT / "compat/x86_64/owned_locale_probe.c"
DOCUMENT = ROOT / "compat/x86_64/owned-locale.md"


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

    def test_one_object_keeps_the_selected_locale_and_utf_boundaries(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")
        document = DOCUMENT.read_text(encoding="utf-8")

        self.assertIn("struct thread_case", source)
        self.assertIn("pthread_create(&utf8_thread", source)
        self.assertIn("pthread_create(&c_thread", source)
        self.assertIn("uselocale(test->locale)", source)
        self.assertIn("errno != ERANGE", source)
        self.assertIn("mbrtowc(&wide, euro, 2, &state)", source)
        self.assertIn("mbrtowc(&wide, truncated, sizeof(truncated), &state)", source)
        self.assertIn('iconv_open("UTF-16LE", "UTF-8")', source)
        self.assertIn('iconv_open("UTF-8", "UTF-32BE")', source)
        for error in ("EILSEQ", "EINVAL", "E2BIG"):
            self.assertIn(error, source)

        self.assertIn('readonly PROBE="$ROOT/compat/x86_64/owned_locale_probe.c"', runner)
        self.assertIn('readonly RUNNER="$ROOT/compat/x86_64/run_owned_locale.sh"', runner)
        self.assertIn("-nostdinc -isystem \"$DYNAMIC_PRODUCT/usr/include\"", runner)
        self.assertIn('sha256sum "$PROBE" "$RUNNER" "$WORK/workload.o"', runner)
        compile_start = runner.index('capture compile ')
        compile_end = runner.index('\nsha256sum ', compile_start)
        self.assertNotIn('-pthread', runner[compile_start:compile_end])
        oracle_start = runner.index('capture oracle-link ')
        oracle_end = runner.index('\ncapture oracle-run ', oracle_start)
        self.assertNotIn('-static', runner[oracle_start:oracle_end])
        self.assertIn("for mode in static static-pie; do", runner)
        self.assertIn("for mode in pie non-pie; do", runner)
        self.assertIn("validate_link", runner)
        self.assertIn('capture "$stem-validate" python3 -B -', runner)
        self.assertIn("record \\\n        --product \"$DYNAMIC_PRODUCT\" --execution-root \"$root\"", runner)
        self.assertIn("audit \\\n        --product \"$DYNAMIC_PRODUCT\" --execution-root \"$root\"", runner)
        self.assertIn("family_completion': False", runner)
        self.assertIn("locale.core", document)
        self.assertIn("legacy encodings", document)
        self.assertIn("does not close", document)

    def test_runner_remains_shell_syntax_valid(self) -> None:
        result = subprocess.run(["bash", "-n", str(RUNNER)], cwd=ROOT,
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
