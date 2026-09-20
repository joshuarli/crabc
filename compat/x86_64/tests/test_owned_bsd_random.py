#!/usr/bin/env python3
"""Focused contract checks for installed BSD random-family evidence."""
from __future__ import annotations

from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[3]
PROBE = ROOT / "compat/x86_64/owned_bsd_random_probe.c"
RUNNER = ROOT / "compat/x86_64/run_owned_bsd_random.sh"


class OwnedBsdRandomContracts(unittest.TestCase):
    def test_probe_covers_state_classes_errno_and_fork_lock_recovery(self) -> None:
        source = PROBE.read_text(encoding="utf-8")
        for boundary in (
            "initstate", "setstate", "srandom", "random", "index < 8",
            "STATE_SIZES", "0U, 1U, 0x80000000U, 0xffffffffU",
            "errno != E2BIG", "memcmp", "qsort", "concurrent-random",
            "concurrent-state", "fork-active", "alarm(2)",
            "setstate(initial_state)",
        ):
            self.assertIn(boundary, source)
        self.assertNotIn("6364136223846793005", source)

    def test_runner_retains_same_object_musl_and_all_owned_product_routes(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        for boundary in (
            "crabc-x86_64-musl-gcc", "owned_posix_product_evidence",
            "--static-sysroot", "static-et-exec", "static-pie", "--dynamic-$mode",
            "ORACLE_SCENARIOS=(core state fork-active)",
            "INVARIANT_SCENARIOS=(concurrent-random concurrent-state)",
            "--extracted", "source/oracle/installed", "link-receipt",
            "source-before.json", "source-after.json", "product-inputs.json",
            "extracted_provenance", "supplied roles",
        ):
            self.assertIn(boundary, source)

    def test_runner_has_valid_shell_syntax(self) -> None:
        result = subprocess.run(["bash", "-n", str(RUNNER)], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
