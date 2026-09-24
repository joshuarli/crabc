#!/usr/bin/env python3
"""Recompute the derived x86 parity digest chain after merging ledger changes.

Several checked-in files pin the SHA-256 of `compat/x86_64/parity.toml` or of
another derived file, and the AArch64 parity inventory is fully source-derived.
Concurrent lanes each regenerate these, so they always conflict at
integration; resolve by taking either side, then run this from the checkout
root and rerun the ledger validators.
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


ledger = sha(X86 / "parity.toml")
set_field(X86 / "header_callable_inventory.json", "parity_ledger_sha256", ledger)
set_field(X86 / "aarch64_parity_inventory.json", "x86_parity_ledger", ledger)
inventory = sha(X86 / "header_callable_inventory.json")
set_field(X86 / "header_callable_disposition.json", "parity_ledger_sha256", ledger)
set_field(X86 / "header_callable_disposition.json", "callable_inventory_sha256", inventory)
set_field(X86 / "generated" / "header_callable_visibility_matrix" / "report.json",
          "callable_inventory_sha256", inventory)
sys.path.insert(0, str(X86))
import aarch64_parity_inventory  # noqa: E402

(X86 / "aarch64_parity_inventory.json").write_text(
    json.dumps(aarch64_parity_inventory.build_inventory(), indent=2, sort_keys=True) + "\n")
