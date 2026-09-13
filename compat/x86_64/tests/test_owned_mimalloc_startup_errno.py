#!/usr/bin/env python3
"""Installed-product mode contract for the mimalloc lifecycle runner."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_mimalloc_startup_errno.sh"


class OwnedMimallocStartupErrnoTests(unittest.TestCase):
    def test_supplied_static_product_keeps_both_static_lifecycle_entries(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn(
            "usage: %s [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]",
            runner,
        )
        self.assertIn("--static-sysroot)", runner)
        self.assertIn('[ -z "$provided_static" ] || [ -n "$provided_dynamic" ] || usage', runner)
        self.assertIn('run_static_mode "$provided_static" "$mode"', runner)
        self.assertIn('(cd "$work" && "$product/bin/crabc-cc" "-$mode"', runner)
        self.assertIn('--link-receipt "static-$mode.crabc-link.json"', runner)
        self.assertIn('(cd "$work" && "$product/bin/crabc-cc-dynamic" "--dynamic-$mode"', runner)
        self.assertIn('"$work/workload.o" -o "$candidate")', runner)
        self.assertNotIn('--link-receipt "dynamic-$mode.crabc-link.json"', runner)
        self.assertNotIn('--link-receipt "$work/static-$mode.crabc-link.json"', runner)
        self.assertNotIn('--link-receipt "$work/dynamic-$mode.crabc-link.json"', runner)
        self.assertIn('for mode in static static-pie; do', runner)
        self.assertIn('for mode in pie non-pie; do', runner)
        self.assertIn('"$provided_dynamic/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin', runner)
        self.assertIn('"$work/workload.o" -o "$candidate"', runner)
        self.assertNotIn('"$PROBE" -o "$candidate"', runner)
        self.assertIn('readelf -hW "$work/workload.o" >"$work/workload.header"', runner)
        self.assertIn('readelf -rW "$work/workload.o" >"$work/workload.relocations"', runner)


if __name__ == "__main__":
    unittest.main()
