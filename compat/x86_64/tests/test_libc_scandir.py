#!/usr/bin/env python3
"""Contracts for the opt-in native x86 scandir allocation client."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class X86LibcScandirTests(unittest.TestCase):
    def test_feature_keeps_scandir_out_of_default_static_exports(self) -> None:
        manifest = (ROOT / "libc" / "Cargo.toml").read_text(encoding="utf-8")
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "directory_streams.rs"
        ).read_text(encoding="utf-8")

        self.assertIn("default = []", manifest)
        self.assertIn('x86-scandir = ["x86-allocator-runtime"]', manifest)
        self.assertNotIn("x86-scandir", static_root)
        self.assertNotIn("\nscandir\n", static_exports)
        self.assertNotIn("\n__crabc_x86_scandir_v1\n", static_exports)
        self.assertIn('#[cfg(feature = "x86-scandir")]', implementation)
        self.assertIn('pub unsafe extern "C" fn scandir(', implementation)
        self.assertIn("src/dirent/scandir.c", implementation)
        self.assertIn("C++ exceptions and C `longjmp`", implementation)
        self.assertIn("same C `free` ABI", implementation)
        self.assertIn("jmp malloc", implementation)
        self.assertIn("jmp realloc", implementation)
        self.assertIn("jmp free", implementation)
        self.assertNotIn("scandirat", implementation)
        self.assertNotIn("libmimalloc_sys", implementation)

    def test_native_probe_and_runner_prove_the_mixed_boundary_and_rollback(self) -> None:
        probe = (
            ROOT / "compat" / "x86_64" / "libc_scandir_probe.c"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" / "run_libc_scandir.sh"
        ).read_text(encoding="utf-8")
        dispatcher = (ROOT / "scripts" / "dev-x86_64.sh").read_text(
            encoding="utf-8"
        )

        for required in (
            "__wrap_malloc",
            "__wrap_realloc",
            "__wrap_free",
            "CRABC_FAIL_VECTOR_REALLOC",
            "CRABC_FAIL_COPIED_ENTRY_MALLOC",
            "check_allocation_failure_case",
            "check_allocation_failure_rollback",
            "tracked_release_calls",
            "1 -> 3 -> 7 vector growth",
            "__real_malloc",
            "__real_realloc",
            "__real_free",
            "scandir-directory",
            "scandir-allocation-failure",
            "entries != &sentinel_entry",
        ):
            self.assertIn(required, probe)
        self.assertNotIn("scandirat(", probe)

        for required in (
            "mixed-runtime differential",
            "--features x86-scandir",
            "CRABC_SCANDIR_ALLOCATION_WRAP",
            "-Wl,--wrap=malloc",
            "-Wl,--wrap=realloc",
            "-Wl,--wrap=free",
            "selected archive member set drifted during extraction",
            "candidate selected pinned-musl fallback object",
            "hidden C ABI thunk",
            "candidate scandir bypassed C ABI thunk",
            "candidate C ABI thunk did not reach wrapped",
            "allocator backend internals directly",
            "scandir.lo",
            "strverscmp.lo",
            "donate.lo",
            "__crabc_x86_scandir_v1",
            "run_dirent_header_abi.sh",
            "-static -fno-pie -no-pie",
            "env -i LC_ALL=C TZ=UTC",
            "TLSGD|TLSLD|TLSDESC",
            "glibc|ld-linux|libc\\.so\\.6",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)
        for required in (
            "libc-scandir)",
            "run_libc_scandir()",
            "/workspace/compat/x86_64/run_libc_scandir.sh",
        ):
            self.assertIn(required, dispatcher)


if __name__ == "__main__":
    unittest.main()
