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
        self.assertIn('#[cfg(all(\n    crabc_x86_allocator_observability,\n    not(feature = "native-mimalloc-shadow"),\n))]', target)
        self.assertIn(
            'include!("../../allocator_observability_mimalloc.rs");', target
        )
        self.assertIn('include!("allocator_observability_mimalloc.rs");', aarch64)
        self.assertIn("pub unsafe extern \"C\" fn malloc_usable_size", shared)
        self.assertIn("libmimalloc_sys::mi_usable_size(ptr)", shared)
        self.assertNotIn("#[linkage = \"weak\"]", shared)

if __name__ == "__main__":
    unittest.main()
