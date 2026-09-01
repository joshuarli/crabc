#!/usr/bin/env python3
"""Structure checks for the private x86 allocator-basic real-runtime proof."""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class X86LibcAllocatorBasicRuntimeV1Tests(unittest.TestCase):
    def test_fixture_and_runner_cover_the_complete_basic_boundary(self) -> None:
        coverage = tomllib.loads(
            (ROOT / "compat" / "crabc-rs" / "coverage.toml").read_text(
                encoding="utf-8"
            )
        )
        capability = next(
            entry
            for entry in coverage["capability"]
            if entry["id"] == "memory.allocator-basic"
        )
        self.assertEqual(
            capability["symbols"],
            [
                "aligned_alloc",
                "calloc",
                "free",
                "malloc",
                "memalign",
                "posix_memalign",
                "realloc",
                "reallocarray",
                "valloc",
            ],
        )

        fixture = (
            ROOT / "compat" / "x86_64" / "libc_allocator_basic_runtime_v1_probe.c"
        ).read_text(encoding="utf-8")
        wrapper = (ROOT / "libc" / "src" / "allocator_mimalloc.rs").read_text(
            encoding="utf-8"
        )
        runner = (
            ROOT / "compat" / "x86_64" / "run_libc_allocator_basic_runtime_v1.sh"
        ).read_text(encoding="utf-8")

        self.assertIn("if total == 0 {\n        return malloc(0);\n    }", wrapper)

        for required in (
            "CRABC_ALLOCATOR_BASIC_RUNTIME_V1_CANDIDATE",
            "malloc(0)",
            "free(NULL)",
            "calloc(0, 17)",
            "calloc(17, 0)",
            "realloc(NULL, 0)",
            "reallocarray(NULL, 0, 17)",
            "posix_memalign(&aligned, 64, 0)",
            "valloc(0)",
            "calloc((size_t)-1, 2)",
            "realloc(block, (size_t)-1)",
            "realloc(NULL, 17)",
            "realloc(block, 0)",
            "reallocarray(resized, (size_t)-1, 2)",
            "aligned_alloc(64, (size_t)-64)",
            "aligned_alloc(musl_mallocng_max_alignment, 1)",
            "posix_memalign(&aligned, 24, 64)",
            "posix_memalign(&aligned, musl_mallocng_max_alignment, 1)",
            "memalign(0, 7)",
            "valloc(7)",
            "malloc_usable_size(NULL)",
            "pthread_create",
            "pthread_join",
            "pthread_atfork",
            "fork()",
            "joined-worker-only",
            "atexit(allocator_exit_probe)",
            "ALLOCATOR_BASIC_RUNTIME_V1_ATEXIT",
        ):
            self.assertIn(required, fixture)

        for required in (
            "x86-allocator-observability",
            "crt/src/x86_64_${object}.rs",
            "__crabc_x86_allocator_observability_v1",
            "__crabc_x86_allocator_runtime_v1",
            "malloc_usable_size",
            "expected_wrapper_symbols",
            "pthread_atfork",
            "__funcs_on_exit",
            "exact eleven-object",
            "__lock.lo",
            "syscall_ret.lo",
            "objcopy --weaken-symbol=__progname --weaken-symbol=__progname_full",
            "candidate selected a pinned-musl allocator implementation",
            "candidate selected a pinned-musl observer implementation",
            "candidate selected a pinned-musl runtime implementation",
            "TLSGD|TLSLD|TLSDESC",
            "glibc|ld-linux|libc\\.so\\.6",
            "ALLOCATOR_BASIC_RUNTIME_V1_ATEXIT",
            "deterministic backend allocation failure remains intentionally unproved",
        ):
            self.assertIn(required, runner)


if __name__ == "__main__":
    unittest.main()
