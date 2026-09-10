#!/usr/bin/env python3
"""Account-file runner rejects ambiguous replay paths and provider evidence."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_account_files.sh"
DOCUMENT = ROOT / "compat/x86_64/owned-account-files.md"
HEADER_C = ROOT / "compat/x86_64/owned_account_files_header_abi_probe.c"
HEADER_CXX = ROOT / "compat/x86_64/owned_account_files_header_abi_probe.cpp"
SYMBOLS = (
    "cuserid", "getusershell", "setusershell", "endusershell", "endspent",
    "setspent", "getspent", "fgetspent", "getspnam", "getspnam_r",
    "putspent", "lckpwdf", "ulckpwdf",
)


class OwnedAccountFilesTests(unittest.TestCase):
    def invoke(self, arguments: tuple[str, ...], temporary: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(RUNNER), *arguments],
            cwd=ROOT,
            env={**os.environ, "TMPDIR": temporary},
            capture_output=True,
            text=True,
            check=False,
        )

    def test_raw_symlink_and_parent_components_are_rejected_before_normalization(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="account-path-target.", dir=scratch) as target:
            link = scratch / "account-files-product-link"
            link.symlink_to(target, target_is_directory=True)
            detour = scratch / "account-files-parent-component"
            detour.mkdir()
            try:
                raw_parent = f"{detour}/../{Path(target).name}"
                for label, argument in (("symlink", str(link)), ("parent", raw_parent)):
                    with self.subTest(label=label), tempfile.TemporaryDirectory(
                        prefix="account-parser.", dir=scratch
                    ) as temporary:
                        result = self.invoke((argument,), temporary)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(
                            "owned account files dynamic product must be a checkout .work directory",
                            result.stderr,
                        )
                        self.assertEqual(result.stdout, "")
                        self.assertEqual(list(Path(temporary).iterdir()), [])
            finally:
                link.unlink(missing_ok=True)
                detour.rmdir()

    def test_archive_symbol_judge_rejects_duplicate_wrong_binding(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        function_start = source.index("assert_symbols()")
        script_start = source.index("<<'PY'\n", function_start) + len("<<'PY'\n")
        script_end = source.index("\nPY\n}", script_start)
        descriptor, symbol_path = tempfile.mkstemp(
            prefix="account-files-symbols.", dir=ROOT / ".work/x86_64/tmp"
        )
        os.close(descriptor)
        symbols = Path(symbol_path)
        try:
            symbols.write_text(
                "".join(f"00000000 T {name}\n" for name in SYMBOLS)
                + "00000000 W cuserid\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, "-", str(symbols), "nm", *SYMBOLS],
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
        function_start = source.index("assert_symbols()")
        script_start = source.index("<<'PY'\n", function_start) + len("<<'PY'\n")
        script_end = source.index("\nPY\n}", script_start)
        descriptor, symbol_path = tempfile.mkstemp(
            prefix="account-files-dyn-symbols.", dir=ROOT / ".work/x86_64/tmp"
        )
        os.close(descriptor)
        symbols = Path(symbol_path)
        try:
            symbols.write_text(
                "".join(
                    f"  1: 00000000 0 FUNC GLOBAL DEFAULT 1 {name}\n" for name in SYMBOLS
                )
                + "  1: 00000000 0 FUNC WEAK DEFAULT 1 cuserid\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, "-", str(symbols), "readelf", *SYMBOLS],
                input=source[script_start:script_end],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
        finally:
            symbols.unlink(missing_ok=True)

    def test_source_and_installed_header_witnesses_keep_workload_receipt_distinct(self) -> None:
        document = DOCUMENT.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("source-and-installed-header witness objects", document)
        self.assertIn("installed-header dependency receipt", document)
        self.assertIn('compile_header_witnesses source "$ROOT/include"', runner)
        self.assertIn('compile_header_witnesses installed "$installed/usr/include"', runner)
        self.assertIn("Source-and-installed-header C ABI witness", HEADER_C.read_text(encoding="utf-8"))
        self.assertIn("Source-and-installed-header C++17 ABI witness", HEADER_CXX.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
