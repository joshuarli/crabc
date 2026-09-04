#!/usr/bin/env python3
"""Regression for the pinned musl malloc.h declaration/source form."""

from __future__ import annotations

import hashlib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HEADER = ROOT / "include" / "malloc.h"
MUSL_MALLOC_HEADER_SHA256 = (
    "8aba27d6cf64d9a93cf3fbd534f5c81b00e6e8419a2f3ec075ee012e834b2c02"
)


class MallocHeaderFormsTests(unittest.TestCase):
    def test_malloc_header_matches_pinned_musl_source_form(self) -> None:
        """Keep the allocator observability boundary on musl's exact source form."""
        self.assertEqual(
            hashlib.sha256(HEADER.read_bytes()).hexdigest(),
            MUSL_MALLOC_HEADER_SHA256,
        )

    def test_malloc_header_excludes_unselected_control_surfaces(self) -> None:
        source = HEADER.read_text(encoding="utf-8")
        for absent in ("mallinfo", "mallinfo2", "malloc_info", "malloc_stats", "mallopt"):
            self.assertNotIn(absent, source)


if __name__ == "__main__":
    unittest.main()
