#!/usr/bin/env python3
"""Regenerate the source-derived x86 parity inventory after merging ledger changes.

The AArch64 parity inventory is fully derived from the ledgers, so concurrent
lanes conflict on it; take either side, run this from the checkout root, and
rerun the validators. It also re-pins the callable-inventory digest held by
the disposition and visibility-matrix reports.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
X86 = ROOT / "compat" / "x86_64"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def set_field(path: Path, key: str, value: str) -> None:
    text = path.read_text()
    path.write_text(re.sub(r'("%s": ")[0-9a-f]{64}(")' % re.escape(key),
                           lambda m: m.group(1) + value + m.group(2), text))


inventory = sha(X86 / "header_callable_inventory.json")
set_field(X86 / "header_callable_disposition.json", "callable_inventory_sha256", inventory)
set_field(X86 / "generated" / "header_callable_visibility_matrix" / "report.json",
          "callable_inventory_sha256", inventory)
sys.path.insert(0, str(X86))
import aarch64_parity_inventory  # noqa: E402

(X86 / "aarch64_parity_inventory.json").write_text(
    json.dumps(aarch64_parity_inventory.build_inventory(), indent=2, sort_keys=True) + "\n")
