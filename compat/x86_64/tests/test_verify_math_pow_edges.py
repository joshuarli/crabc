#!/usr/bin/env python3
"""Regression checks for accepted finite pow identity corrections."""

from __future__ import annotations

import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
VERIFIER = ROOT / "compat" / "x86_64" / "verify_math_pow_edges.py"


class MathPowEdgeVerifierTests(unittest.TestCase):
    def test_binary64_true_min_identity_accepts_corrected_flags(self) -> None:
        oracle_record = struct.pack(
            "<5Q", 1, 0x3FF0000000000000, 1, 0, (0x5A5 << 32) | 0x32
        )
        candidate_record = struct.pack(
            "<5Q", 1, 0x3FF0000000000000, 1, 0, 0x5A5 << 32
        )

        scratch = ROOT / ".work" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            oracle = Path(directory) / "oracle.records"
            candidate = Path(directory) / "candidate.records"
            oracle.write_bytes(oracle_record)
            candidate.write_bytes(candidate_record)
            result = subprocess.run(
                [sys.executable, str(VERIFIER), str(oracle), str(candidate)],
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotIn("pow edge mismatch at 0", result.stderr)
        self.assertIn("pow rounding coverage changed", result.stderr)


if __name__ == "__main__":
    unittest.main()
