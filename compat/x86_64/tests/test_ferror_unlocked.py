#!/usr/bin/env python3
"""Focused contract for the selected x86 ``ferror_unlocked`` C ABI alias."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
IMPLEMENTATION = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "stdio_standard.rs"
STDIO_HEADER = ROOT / "include" / "stdio.h"
STATIC_EXPORTS = ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"


class FerrorUnlockedTests(unittest.TestCase):
    def test_selected_alias_has_one_weak_same_address_implementation_boundary(self) -> None:
        """Musl's ferror alias stays a weak ELF alias, never a forwarding wrapper."""
        implementation = IMPLEMENTATION.read_text(encoding="utf-8")
        header = STDIO_HEADER.read_text(encoding="utf-8")
        exports = {
            line
            for line in STATIC_EXPORTS.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }

        for required in (
            "src/stdio/ferror.c",
            "weak_alias(ferror, ferror_unlocked)",
            'pub unsafe extern "C" fn ferror',
            ".weak ferror_unlocked",
            ".set ferror_unlocked, ferror",
            "F_ERR",
        ):
            self.assertIn(required, implementation)
        self.assertIn("int ferror_unlocked(FILE *);", header)
        self.assertIn("ferror", exports)
        self.assertIn("ferror_unlocked", exports)
        self.assertNotIn("_IO_ferror_unlocked", exports)


if __name__ == "__main__":
    unittest.main()
