#!/usr/bin/env python3
"""Contract checks for the x86 installed scalar-math completion consumer."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class OwnedStaticMathScalarConsumerTests(unittest.TestCase):
    def test_probe_covers_scalar_fusion_norm_and_near_one_fenv_boundaries(self) -> None:
        probe = (
            ROOT / "compat" / "x86_64" / "owned_static_math_scalar_consumer.c"
        ).read_text(encoding="utf-8")

        for required in (
            "direct_fma",
            "direct_fmaf",
            "direct_hypot",
            "direct_hypotf",
            "direct_log1p",
            "direct_log1pf",
            "FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO",
            "feclearexcept(FE_ALL_EXCEPT)",
            "fetestexcept(FE_ALL_EXCEPT)",
            "0x7ff0000000000042",
            "0x7f800042",
            "0x7fefffffffffffff",
            "0x7f7fffff",
            "RECORD_COUNT",
            "write_all(scalar_records, sizeof(scalar_records))",
        ):
            self.assertIn(required, probe)
        for forbidden in ("fmal", "hypotl", "log1pl", "__builtin_fma", "vfmadd"):
            self.assertNotIn(forbidden, probe)

    def test_scalar_completion_has_a_private_generated_leaf_and_installed_runner(self) -> None:
        leaf = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_scalar_completion.rs"
        assembly = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_scalar_completion_musl_x86_64.S"
        generator = ROOT / "compat" / "x86_64" / "generate_libc_math_scalar_completion.py"
        runner = ROOT / "compat" / "x86_64" / "run_owned_static_math_scalar_consumer.sh"

        self.assertTrue(leaf.is_file())
        self.assertTrue(assembly.is_file())
        self.assertTrue(generator.is_file())
        self.assertTrue(runner.is_file())


if __name__ == "__main__":
    unittest.main()
