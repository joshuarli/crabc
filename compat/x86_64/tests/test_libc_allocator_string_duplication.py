#!/usr/bin/env python3
"""Contracts for the opt-in native x86 strdup/strndup allocation client."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class X86LibcAllocatorStringDuplicationTests(unittest.TestCase):
    def test_feature_is_separate_from_the_completed_allocator_wrapper(self) -> None:
        manifest = (ROOT / "libc" / "Cargo.toml").read_text(encoding="utf-8")
        target = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT
            / "libc"
            / "src"
            / "c_abi"
            / "x86_64"
            / "allocator_string_duplication.rs"
        ).read_text(encoding="utf-8")

        self.assertIn("default = []", manifest)
        self.assertIn(
            'x86-allocator-string-duplication = ["x86-allocator-runtime"]',
            manifest,
        )
        self.assertIn(
            '#[cfg(feature = "x86-allocator-string-duplication")]', target
        )
        self.assertIn('#[path = "allocator_string_duplication.rs"]', target)
        for required in (
            "src/string/strdup.c",
            "src/string/strndup.c",
            "fn strdup(",
            "fn strndup(",
            "cabi_allocator_malloc",
            "duplicate_prefix",
            "errno::set_errno(ENOMEM)",
            "__crabc_x86_allocator_string_duplication_v1",
        ):
            self.assertIn(required, implementation)
        for forbidden in (
            "libmimalloc_sys",
            "fn malloc(",
            "fn free(",
            "pthread_",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, implementation)

    def test_differential_and_header_gates_close_the_client_boundary(self) -> None:
        probe = (
            ROOT / "compat" / "x86_64" / "libc_allocator_string_duplication_probe.c"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" / "run_libc_allocator_string_duplication.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_string_duplication_header_abi.sh"
        ).read_text(encoding="utf-8")

        for required in (
            "strdup(source)",
            'strndup("abcdef", 3)',
            'strndup("ignored", 0)',
            "check_page_edges",
            "raw_mprotect",
            "__crabc_x86_allocator_string_duplication_v1",
            "errno != E2BIG",
            "errno != ENOTTY",
        ):
            self.assertIn(required, probe)
        for required in (
            "mixed-runtime differential",
            "x86-allocator-string-duplication",
            "__crabc_x86_allocator_string_duplication_v1",
            "strdup_members",
            "strndup_members",
            "string-duplication export surface drifted",
            "pinned-musl duplication or allocator implementation",
            "TLSGD|TLSLD|TLSDESC",
            "glibc|ld-linux|libc\\.so\\.6",
            "env -i LC_ALL=C TZ=UTC",
        ):
            self.assertIn(required, runner)
        for required in (
            "CRABC_EXPECT_STRING_DUPLICATION",
            "CRABC_REQUIRE_STRING_DUPLICATION_HIDDEN",
            "_POSIX_C_SOURCE=200809L",
            "-std=c++17",
            "project <string.h>",
        ):
            self.assertIn(required, header_runner)


if __name__ == "__main__":
    unittest.main()
