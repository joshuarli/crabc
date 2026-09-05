#!/usr/bin/env python3
"""Owned legacy-time qualification has one bounded source and live runner."""

from __future__ import annotations

import tomllib
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]
LEDGER = ROOT / "compat/x86_64/parity.toml"
DISPOSITION = ROOT / "compat/x86_64/header_callable_disposition.toml"
QUALIFICATION = ROOT / "compat/x86_64/owned_dynamic_qualification.py"
PRODUCT = ROOT / "compat/x86_64/dynamic-product.toml"
DISPATCHER = ROOT / "scripts/dev-x86_64.sh"


class OwnedLegacyTimeTests(unittest.TestCase):
    def test_owned_legacy_time_has_complete_provider_and_product_accounting(self) -> None:
        ledger = tomllib.loads(LEDGER.read_text(encoding="utf-8"))
        owned_static = next(
            row
            for row in ledger["feature_archive"]
            if row["id"] == "x86-owned-static-runtime"
        )
        verified = {
            row["id"]: set(row["additive_callables"])
            for row in ledger["feature_archive"]
            if row["state"] == "verified"
        }
        disposition = tomllib.loads(DISPOSITION.read_text(encoding="utf-8"))
        deferred = {
            member
            for group in disposition["deferred_owner_group"]
            for member in group["members"]
        }

        self.assertTrue({"times", "adjtime", "adjtimex", "settimeofday", "stime"} <= set(owned_static["additive_callables"]))
        self.assertTrue({"getitimer", "setitimer"} <= verified["x86-interval-timers"])
        self.assertIn("ualarm", verified["x86-ualarm"])
        self.assertFalse({"times", "adjtime", "adjtimex", "settimeofday", "stime"} & deferred)

        for path in (QUALIFICATION, PRODUCT, DISPATCHER):
            self.assertIn("legacy-time", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
