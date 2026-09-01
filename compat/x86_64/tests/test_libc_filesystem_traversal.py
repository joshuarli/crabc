#!/usr/bin/env python3
"""Contracts for the opt-in native x86 ftw/nftw traversal package."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class X86LibcFilesystemTraversalTests(unittest.TestCase):
    def test_feature_keeps_ftw_and_nftw_out_of_default_static_exports(self) -> None:
        manifest = (ROOT / "libc" / "Cargo.toml").read_text(encoding="utf-8")
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "filesystem_traversal.rs"
        ).read_text(encoding="utf-8")

        self.assertIn('x86-filesystem-traversal = []', manifest)
        self.assertIn('#[cfg(feature = "x86-filesystem-traversal")]', static_root)
        self.assertIn('mod filesystem_traversal;', static_root)
        self.assertNotIn("\nftw\n", static_exports)
        self.assertNotIn("\nnftw\n", static_exports)
        for required in (
            "src/legacy/ftw.c",
            "src/misc/nftw.c",
            "FTW_CHDIR",
            "C++ exceptions and C `longjmp`",
            "cancellation",
            "A preceding non-directory callback may have changed CWD.",
            "pub unsafe extern \"C\" fn ftw(",
            "pub unsafe extern \"C\" fn nftw(",
        ):
            self.assertIn(required, implementation)
        self.assertNotIn("scandir(", implementation)
        self.assertNotIn("cabi_scandir", implementation)
        self.assertNotIn("cabi_malloc", implementation)

    def test_runner_and_fixture_keep_the_oracle_split_and_exact_opt_in_closure(self) -> None:
        probe = (
            ROOT / "compat" / "x86_64" / "libc_filesystem_traversal_probe.c"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" / "run_libc_filesystem_traversal.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_ftw_header_abi.sh"
        ).read_text(encoding="utf-8")
        dispatcher = (ROOT / "scripts" / "dev-x86_64.sh").read_text(
            encoding="utf-8"
        )

        for required in (
            "FTW_PHYS",
            "FTW_DEPTH",
            "FTW_MOUNT",
            "FTW_CHDIR",
            "CRABC_TRAVERSAL_CANDIDATE",
            "ftw(",
            "nftw(",
            "callback_abort",
            "walk-tree/alpha",
            "type == FTW_F",
        ):
            self.assertIn(required, probe)
        for required in (
            "x86-filesystem-traversal",
            "run_ftw_header_abi.sh",
            "pinned-musl ordinary traversal reference",
            "frozen FTW_CHDIR profile",
            "selected archive member set drifted during extraction",
            "ftw.lo",
            "nftw.lo",
            "scandir.lo",
            "malloc",
            "-nostdlib -static",
        ):
            self.assertIn(required, runner)
        self.assertIn("ftw.h", header_runner)
        self.assertIn("libc-filesystem-traversal)", dispatcher)
        self.assertIn("run_libc_filesystem_traversal()", dispatcher)
        self.assertIn("ftw-header-abi)", dispatcher)


if __name__ == "__main__":
    unittest.main()
