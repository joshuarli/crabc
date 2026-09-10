#!/usr/bin/env python3
"""The installed stdio component keeps one finite object and receipt boundary."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_stdio.sh"
SOURCE = ROOT / "compat/x86_64/owned_stdio_probe.c"
DOCUMENT = ROOT / "compat/x86_64/owned-stdio.md"


class OwnedStdioTests(unittest.TestCase):
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
        with tempfile.TemporaryDirectory(prefix="owned-stdio-path.", dir=scratch) as temporary:
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
                    self.assertIn("owned stdio products dynamic product", result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(set(base.iterdir()), {product, alias, parent})

    def test_one_object_keeps_byte_wide_and_descriptor_boundaries_separate(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")
        document = DOCUMENT.read_text(encoding="utf-8")

        self.assertIn("static int byte_stream", source)
        self.assertIn("static int wide_stream", source)
        self.assertIn("fgetpos(stream, &saved)", source)
        self.assertIn("fsetpos(stream, &saved)", source)
        self.assertIn('freopen(second, "w+", stream) != stream', source)
        self.assertIn("errno = EAGAIN", source)
        self.assertIn("fputc('x', read_only) != EOF || !ferror(read_only) || errno != EAGAIN", source)
        self.assertIn("clearerr(read_only)", source)
        self.assertIn("adopted = fdopen(adopted_descriptor, \"r\")", source)
        self.assertIn("surviving_descriptor = dup(adopted_descriptor)", source)
        self.assertIn("fcntl(adopted_descriptor, F_GETFD) != -1 || errno != EBADF", source)
        self.assertIn("fwide(stream, 1) <= 0", source)
        self.assertIn("fputwc(0x20ac, stream)", source)
        self.assertIn('fputws(L"\\U0001f642\\n", stream)', source)
        self.assertIn("ungetwc(0x20ac, stream)", source)
        self.assertIn("fgetws(line, 3, stream)", source)

        self.assertIn('readonly PROBE="$ROOT/compat/x86_64/owned_stdio_probe.c"', runner)
        self.assertIn('readonly RUNNER="$ROOT/compat/x86_64/run_owned_stdio.sh"', runner)
        self.assertIn("-nostdinc -isystem \"$DYNAMIC_PRODUCT/usr/include\"", runner)
        self.assertIn('sha256sum "$PROBE" "$RUNNER" "$WORK/workload.o"', runner)
        self.assertIn('capture oracle-link "$ORACLE_CC" -std=c11 -static -fno-pie -no-pie', runner)
        self.assertIn("for mode in static static-pie; do", runner)
        self.assertIn("for mode in pie non-pie; do", runner)
        self.assertIn('mkdir "$root/scratch"', runner)
        self.assertIn('rmdir "$root/scratch"', runner)
        self.assertIn("/scratch/first /scratch/second /scratch/wide", runner)
        self.assertIn("validate_link", runner)
        self.assertIn('capture "$stem-validate" python3 -B -', runner)
        self.assertIn("record \\\n        --product \"$DYNAMIC_PRODUCT\" --execution-root \"$root\"", runner)
        self.assertIn("audit \\\n        --product \"$DYNAMIC_PRODUCT\" --execution-root \"$root\"", runner)
        self.assertIn("'family_completion': False", runner)
        for scope in ("stdio.path-stream", "stdio.stream-io", "stdio.position-buffering", "stdio.format-scan"):
            self.assertIn(scope, document)
        self.assertIn("close the stdio family", document)

    def test_runner_remains_shell_syntax_valid(self) -> None:
        result = subprocess.run(["bash", "-n", str(RUNNER)], cwd=ROOT,
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
