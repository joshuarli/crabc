#!/usr/bin/env python3
"""Pinned case runner for one ordered x86 qualification gate.

Every promotion-chain case manifest names this file and one fixed gate id.
The conditions and their readers live in ``qualification_gates.py``; this
entry stays small so registering a reader does not re-pin every case
manifest. The final stdout line is the exact completion marker only when every
condition is met natively; otherwise it names the unmet conditions and exits 1.
"""

import sys
from pathlib import Path

# Qualification cases run with PYTHONSAFEPATH=1, so the runner directory is
# not implicitly importable.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import qualification_gates  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(qualification_gates.main())
