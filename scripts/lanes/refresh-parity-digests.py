#!/usr/bin/env python3
"""Regenerate the source-derived x86 parity inventory after merging ledger changes.

The AArch64 parity inventory is fully derived from the ledgers, so concurrent
lanes conflict on it; take either side, run this from the checkout root, and
rerun the validators.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
X86 = ROOT / "compat" / "x86_64"


sys.path.insert(0, str(X86))
import aarch64_parity_inventory  # noqa: E402

(X86 / "aarch64_parity_inventory.json").write_text(
    json.dumps(aarch64_parity_inventory.build_inventory(), indent=2, sort_keys=True) + "\n")
