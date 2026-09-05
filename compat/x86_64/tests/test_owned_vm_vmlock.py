#!/usr/bin/env python3
"""Regression contract for the owned VM lifetime barrier."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "memory_mapping.rs"


def body_after(source: str, marker: str) -> str:
    start = source.index(marker)
    next_function = source.find("\n/// ", start + len(marker))
    return source[start:] if next_function < 0 else source[start:next_function]


class OwnedVmVmlockTests(unittest.TestCase):
    def test_owned_fixed_mapping_and_unmap_use_the_existing_vmlock_wait(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")

        self.assertRegex(
            source,
            re.compile(
                r'#\[cfg\(feature = "x86-owned-static-runtime"\)\]\n'
                r'#\[inline\]\n'
                r'fn selected_owned_vm_wait\(\) \{\n'
                r'    // SAFETY: the existing pthread vmlock owns the selected'
            ),
        )
        self.assertIn("pthread_vmlock::wait()", source)

        mmap = body_after(source, "pub unsafe extern \"C\" fn mmap(")
        munmap = body_after(source, "pub unsafe extern \"C\" fn munmap(")
        self.assertIn("selected_owned_vm_wait();", mmap)
        self.assertIn("selected_owned_vm_wait();", munmap)


if __name__ == "__main__":
    unittest.main()
