#!/usr/bin/env python3
"""Contracts for the complete private x86 allocator-observability slice."""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class X86LibcAllocatorObservabilityTests(unittest.TestCase):
    def test_surface_is_exactly_the_aarch64_one_symbol_capability(self) -> None:
        coverage = tomllib.loads(
            (ROOT / "compat" / "crabc-rs" / "coverage.toml").read_text(
                encoding="utf-8"
            )
        )
        capability = next(
            entry
            for entry in coverage["capability"]
            if entry["id"] == "memory.allocator-observability"
        )
        self.assertEqual(capability["symbols"], ["malloc_usable_size"])

        header = (ROOT / "include" / "malloc.h").read_text(encoding="utf-8")
        self.assertEqual(header.count("malloc_usable_size"), 1)
        for absent in ("mallinfo", "mallinfo2", "malloc_info", "malloc_stats", "mallopt"):
            self.assertNotIn(absent, header)

        manifest = (ROOT / "libc" / "Cargo.toml").read_text(encoding="utf-8")
        target = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        shared = (
            ROOT / "libc" / "src" / "allocator_observability_mimalloc.rs"
        ).read_text(encoding="utf-8")
        aarch64 = (ROOT / "libc" / "src" / "c_abi.rs").read_text(encoding="utf-8")
        self.assertIn(
            'x86-allocator-observability = ["x86-allocator-runtime"]', manifest
        )
        self.assertIn('#[cfg(feature = "x86-allocator-observability")]', target)
        self.assertIn(
            'include!("../../allocator_observability_mimalloc.rs");', target
        )
        self.assertIn('include!("allocator_observability_mimalloc.rs");', aarch64)
        self.assertIn("pub unsafe extern \"C\" fn malloc_usable_size", shared)
        self.assertIn("libmimalloc_sys::mi_usable_size(ptr)", shared)
        self.assertNotIn("#[linkage = \"weak\"]", shared)

    def test_runner_closes_runtime_ownership_and_residual_musl_boundary(self) -> None:
        runner = (
            ROOT / "compat" / "x86_64" / "run_libc_allocator_observability.sh"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "tests" / "fixtures" / "allocator_observability_test.c"
        ).read_text(encoding="utf-8")

        for required in (
            "x86-allocator-observability",
            "crt/src/x86_64_${object}.rs",
            "__crabc_x86_static_tls_bootstrap",
            "__libc_start_main",
            "pthread_create",
            "pthread_key_create",
            "malloc_usable_size",
            "mi_usable_size",
            "strong global function",
            "exact eleven-object",
            "assert_crabc_backend_support_owner",
            "(.text.fputs)",
            "(.text.sleep)",
            "__stack_chk_fail",
            "objcopy --weaken-symbol=__progname --weaken-symbol=__progname_full",
            "candidate-local copy weakens only musl's duplicate `__progname` globals",
            "candidate does not retain crabc's strong ${symbol} owner",
            "env -i",
        ):
            self.assertIn(required, runner)
        for member in (
            "__lock.lo",
            "abort.lo",
            "abort_lock.lo",
            "block.lo",
            "libc.lo",
            "prctl.lo",
            "realpath.lo",
            "strchrnul.lo",
            "strdup.lo",
            "syscall.lo",
            "syscall_ret.lo",
        ):
            self.assertIn(member, runner)
        for required in (
            "malloc_usable_size(NULL)",
            "pthread_create",
            "pthread_join",
            "observability_fork",
            '"a"(57L)',
            "malloc_usable_size(workers[index].pointer)",
            "malloc_usable_size(pointer) != usable",
            "errno != ENOTTY",
        ):
            self.assertIn(required, probe)


if __name__ == "__main__":
    unittest.main()
