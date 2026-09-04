#!/usr/bin/env python3
"""Regression for pinned musl's generic x86 ``bits/ioctl.h`` form."""

from __future__ import annotations

import hashlib
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
BITS = ROOT / "include/bits"
MUSL_GENERIC_IOCTL_SHA256 = "a1ef9fa70d6d1f14e1a370b21c428b27c5f89e88ebe7500174d60683b096219e"
LEGACY_IOCTL_SHA256 = "4fb45a8cd9b16fa189d6e3874d1c49669f67b9ea7a996c254fd63428af53eddd"

OPEN = re.compile(r"^\s*#\s*(?:if|ifdef|ifndef)\b")
CLOSE = re.compile(r"^\s*#\s*endif\b")
ELSE = re.compile(r"^\s*#\s*(?:else|elif)\b")


def split_x86_branch(path: Path) -> tuple[bytes, bytes]:
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    if not lines or lines[0] != "#if defined(__x86_64__)\n":
        raise AssertionError(f"{path} must begin with its x86 source-form branch")

    depth = 1
    x86: list[str] = []
    legacy: list[str] = []
    in_legacy = False
    for line in lines[1:]:
        if not in_legacy and ELSE.match(line) and depth == 1:
            in_legacy = True
            continue
        if in_legacy and CLOSE.match(line) and depth == 1:
            break
        if in_legacy:
            legacy.append(line)
        else:
            x86.append(line)
        if OPEN.match(line):
            depth += 1
        elif CLOSE.match(line):
            depth -= 1
    else:
        raise AssertionError(f"{path} is missing its closing x86 source-form branch")

    return "".join(x86).encode(), "".join(legacy).encode()


class BitsIoctlHeaderTests(unittest.TestCase):
    def test_x86_generic_header_matches_musl_and_non_x86_stays_frozen(self) -> None:
        x86, legacy = split_x86_branch(BITS / "ioctl.h")
        self.assertEqual(hashlib.sha256(x86).hexdigest(), MUSL_GENERIC_IOCTL_SHA256)
        self.assertEqual(hashlib.sha256(legacy).hexdigest(), LEGACY_IOCTL_SHA256)

    def test_x86_generic_fix_header_is_the_empty_pinned_musl_sidecar(self) -> None:
        self.assertEqual((BITS / "ioctl_fix.h").read_bytes(), b"")


if __name__ == "__main__":
    unittest.main()
