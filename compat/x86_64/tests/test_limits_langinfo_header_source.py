#!/usr/bin/env python3
"""Regression checks for the pinned musl limits/langinfo source forms."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]


class LimitsLanginfoHeaderSourceTests(unittest.TestCase):
    def test_limits_keeps_musl_x86_branch_and_aarch64_fallback(self) -> None:
        source = (ROOT / "include" / "limits.h").read_text(encoding="utf-8")
        self.assertIn("#if defined(__x86_64__)", source)
        self.assertIn("#include <bits/alltypes.h> /* __LONG_MAX */", source)
        self.assertIn("#include <bits/limits.h>", source)
        self.assertIn("#define LONG_MAX __LONG_MAX", source)
        self.assertIn("#else\n#include <features.h>\n\n/* musl 1.2.6 limits used by the strict public-header contract. */", source)
        self.assertEqual(source.count("#ifndef _LIMITS_H"), 1)

    def test_langinfo_reuses_nl_types_and_preserves_item_signature(self) -> None:
        source = (ROOT / "include" / "langinfo.h").read_text(encoding="utf-8")
        self.assertIn("#include <nl_types.h>", source)
        self.assertNotIn("typedef int nl_item;", source)
        self.assertIn("#define CRNCYSTR 0x4000F", source)
        self.assertIn("char *nl_langinfo(nl_item);", source)


if __name__ == "__main__":
    unittest.main()
