#!/usr/bin/env python3
"""Contracts for the private x86 static <alloca.h> compiler-builtin leaf."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class X86LibcAllocaTests(unittest.TestCase):
    def test_header_matches_the_pinned_musl_builtin_shape(self) -> None:
        header = (ROOT / "include" / "alloca.h").read_text(encoding="utf-8")

        self.assertIn("#ifndef\t_ALLOCA_H", header)
        self.assertIn("#define\t__NEED_size_t", header)
        self.assertIn("#include <bits/alltypes.h>", header)
        self.assertIn("void *alloca(size_t);", header)
        self.assertIn("#define alloca __builtin_alloca", header)
        self.assertNotIn("#include <stddef.h>", header)

    def test_probe_and_runner_keep_alloca_bounded_to_the_builtin(self) -> None:
        c_probe = (
            ROOT / "compat" / "x86_64" / "alloca_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_probe = (
            ROOT / "compat" / "x86_64" / "alloca_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        runtime_probe = (
            ROOT / "compat" / "x86_64" / "libc_alloca_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_alloca_start.S"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" / "run_libc_alloca.sh"
        ).read_text(encoding="utf-8")

        for probe in (c_probe, cxx_probe):
            self.assertIn("#include <alloca.h>", probe)
            self.assertIn("#ifndef alloca", probe)
            self.assertIn("alloca", probe)
        for required in (
            "crabc_x86_64_alloca_case",
            "crabc_x86_64_alloca_nested_case",
            "(size_t)1024",
            "alloca((size_t)257)",
            "does not define alloca(0)",
            "CRABC_ALLOCA_FREESTANDING",
        ):
            self.assertIn(required, runtime_probe)
        for required in (
            "crabc_x86_64_alloca_probe",
            "mov $60, %eax",
            "syscall",
        ):
            self.assertIn(required, start)
        for required in (
            "MUSL_ALLOCA_HEADER",
            "AARCH64_ALLOCA_HEADER_ROW",
            "8768404d7cf4af5fb135b1a2ca91765bd2be311ac072e0ec8b68f5cb3e6e0f3e",
            "cmp -s",
            "#define alloca __builtin_alloca",
            "-std=c++17",
            "-nostdlib -static",
            "-ffreestanding",
            "-Wl,-e,_start",
            "callable alloca symbol",
            "dynamic stack allocation",
            "malloc malloc_usable_size",
            "TLSGD|TLSLD|TLSDESC",
            "env -i",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("cargo", runner)
        self.assertNotIn("libc.a", runner)


if __name__ == "__main__":
    unittest.main()
