#!/usr/bin/env python3
"""Keep lastlog.h aligned with the pinned musl source and record contract."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HEADER = ROOT / "include" / "lastlog.h"


class LastlogHeaderTests(unittest.TestCase):
    def test_header_is_the_pinned_musl_include_form(self) -> None:
        self.assertEqual(HEADER.read_text(encoding="utf-8"), "#include <utmp.h>\n")

    def test_lastlog_record_contract_is_proved_by_the_transitive_gate(self) -> None:
        probe = (ROOT / "compat" / "x86_64" / "timeval_transitive_header_abi_probe.c").read_text(
            encoding="utf-8"
        )
        self.assertIn("#include <lastlog.h>", probe)
        self.assertIn("sizeof(struct lastlog) == 296", probe)
        self.assertIn("offsetof(struct lastlog, ll_time) == 0", probe)
        self.assertIn("offsetof(struct lastlog, ll_line) == 8", probe)
        self.assertIn("offsetof(struct lastlog, ll_host) == 40", probe)


if __name__ == "__main__":
    unittest.main()
