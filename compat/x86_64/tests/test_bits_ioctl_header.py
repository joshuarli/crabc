#!/usr/bin/env python3
"""Regression for pinned musl's generic x86 ``bits/ioctl.h`` form."""

from __future__ import annotations

import hashlib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
BITS = ROOT / "include/bits"
MUSL_GENERIC_IOCTL_SHA256 = "a1ef9fa70d6d1f14e1a370b21c428b27c5f89e88ebe7500174d60683b096219e"


class BitsIoctlHeaderTests(unittest.TestCase):
    def test_x86_generic_header_matches_pinned_musl_source_form(self) -> None:
        self.assertEqual(
            hashlib.sha256((BITS / "ioctl.h").read_bytes()).hexdigest(),
            MUSL_GENERIC_IOCTL_SHA256,
        )

    def test_x86_generic_fix_header_is_the_empty_pinned_musl_sidecar(self) -> None:
        self.assertEqual((BITS / "ioctl_fix.h").read_bytes(), b"")


if __name__ == "__main__":
    unittest.main()
