#!/usr/bin/env python3
"""Regression for the pinned musl x86 <regex.h> declaration/source forms."""

from __future__ import annotations

import hashlib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HEADER = ROOT / "include" / "regex.h"
MUSL_REGEX_HEADER_SHA256 = (
    "4acf94cf0e0f14b2eb50accac93fee886fcc4f821a9b7bb5347a5d035a027ad3"
)


class RegexHeaderFormsTests(unittest.TestCase):
    def test_regex_header_matches_pinned_musl_source_form(self) -> None:
        """Keep all seven declaration/macro profiles on musl's source boundary."""
        self.assertEqual(
            hashlib.sha256(HEADER.read_bytes()).hexdigest(),
            MUSL_REGEX_HEADER_SHA256,
        )


if __name__ == "__main__":
    unittest.main()
