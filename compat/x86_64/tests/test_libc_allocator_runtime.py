#!/usr/bin/env python3
"""Contracts for the opt-in native x86 crabc-libc allocator wrapper."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class X86LibcAllocatorRuntimeTests(unittest.TestCase):
    def test_feature_is_opt_in_and_reuses_the_aarch64_wrapper(self) -> None:
        manifest = (ROOT / "libc" / "Cargo.toml").read_text(encoding="utf-8")
        crate_root = (ROOT / "libc" / "src" / "lib.rs").read_text(
            encoding="utf-8"
        )
        target_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        wrapper = (ROOT / "libc" / "src" / "allocator_mimalloc.rs").read_text(
            encoding="utf-8"
        )
        string_exports = (ROOT / "libc" / "src" / "string_exports.rs").read_text(
            encoding="utf-8"
        )
        program_utils = (
            ROOT / "libc" / "src" / "program_utils_exports.rs"
        ).read_text(encoding="utf-8")

        self.assertIn("default = []", manifest)
        self.assertIn(
            'x86-allocator-runtime = ["dep:libmimalloc-sys"]', manifest
        )
        self.assertIn('optional = true', manifest)
        self.assertIn('target_arch = "x86_64"', crate_root)
        self.assertIn('mod x86_64_static_c_abi;', crate_root)
        self.assertNotIn('feature = "x86-allocator-runtime"', crate_root)
        self.assertIn('#[cfg(feature = "x86-allocator-runtime")]', target_root)
        self.assertIn('include!("../../allocator_mimalloc.rs");', target_root)
        self.assertIn("__crabc_x86_allocator_runtime_v1", target_root)
        self.assertIn("cabi_set_allocator_errno(EINVAL);", wrapper)
        self.assertIn("pub unsafe extern \"C\" fn reallocarray", wrapper)
        self.assertIn("pub unsafe extern \"C\" fn memalign", wrapper)
        self.assertIn("pub unsafe extern \"C\" fn valloc", wrapper)
        self.assertNotIn("pub unsafe extern \"C\" fn reallocarray", string_exports)
        self.assertNotIn("pub unsafe extern \"C\" fn memalign", program_utils)
        self.assertNotIn("pub unsafe extern \"C\" fn valloc", program_utils)
        self.assertNotIn("ERRNO = ENOMEM", wrapper)

    def test_probe_and_runner_keep_the_mixed_boundary_closed(self) -> None:
        probe = (
            ROOT / "compat" / "x86_64" / "libc_allocator_runtime_probe.c"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" / "run_libc_allocator_runtime.sh"
        ).read_text(encoding="utf-8")

        for required in (
            "malloc(0)",
            "calloc((size_t)-1, 2)",
            "realloc(block, (size_t)-1)",
            "realloc(block, 0)",
            "reallocarray(NULL, 4, sizeof(*block))",
            "reallocarray(resized, (size_t)-1, 2)",
            "aligned_alloc(64, 65)",
            "aligned_alloc(3, 64)",
            "posix_memalign(&aligned, 24, 64)",
            "posix_memalign(&aligned, 64, 1)",
            "memalign(64, 19)",
            "memalign(0, 7)",
            "valloc(7)",
            "errno != EINVAL",
            "errno != EDOM",
        ):
            self.assertIn(required, probe)

        for required in (
            "mixed-runtime differential",
            "--features x86-allocator-runtime",
            "archive_member_for_symbol",
            "__crabc_x86_allocator_runtime_v1",
            "mi_malloc_aligned",
            "mi_zalloc",
            "mi_realloc",
            "mi_free",
            "libc\\.a\\((aligned_alloc|calloc|free|malloc|memalign|posix_memalign|realloc|reallocarray|valloc)\\.lo\\)",
            "TLSGD|TLSLD|TLSDESC",
            "glibc|ld-linux|libc\\.so\\.6",
            "env -i LC_ALL=C TZ=UTC",
        ):
            self.assertIn(required, runner)


if __name__ == "__main__":
    unittest.main()
