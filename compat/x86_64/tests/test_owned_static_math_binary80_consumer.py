#!/usr/bin/env python3
"""Regression contract for the x86 installed binary80 math consumer."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
PROBE_PATH = ROOT / "compat" / "x86_64" / "owned_static_math_binary80_consumer.c"
START_PATH = ROOT / "compat" / "x86_64" / "owned_static_math_binary80_consumer_start.S"
RUNNER_PATH = ROOT / "compat" / "x86_64" / "run_owned_static_math_binary80_consumer.sh"
ELEMENTARY_MODULE_PATH = (
    ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_elementary_long_double.rs"
)
ELEMENTARY_GENERATOR_PATH = (
    ROOT
    / "compat"
    / "x86_64"
    / "generate_libc_math_elementary_long_double.py"
)
X87_MODULE_PATH = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_x87_extended.rs"


class OwnedStaticMathBinary80ConsumerTests(unittest.TestCase):
    def assertIn(self, member: object, container: object, msg: object = None) -> None:
        """Keep dispatcher-source failures concise."""

        if (
            isinstance(member, str)
            and isinstance(container, str)
            and len(container) > 4096
            and member not in container
        ):
            self.fail(
                msg
                or f"{member!r} is missing from a {len(container)}-byte source contract"
            )
        super().assertIn(member, container, msg)

    def test_exact_binary80_oracle_and_installed_gate_are_present(self) -> None:
        self.assertTrue(PROBE_PATH.is_file())
        self.assertTrue(START_PATH.is_file())
        self.assertTrue(RUNNER_PATH.is_file())

        probe = PROBE_PATH.read_text(encoding="utf-8")
        for required in (
            "direct_fmal",
            "direct_hypotl",
            "direct_log1pl",
            "sizeof(long double) == 16",
            "LDBL_MANT_DIG == 64",
            "FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO",
            "feclearexcept(FE_ALL_EXCEPT)",
            "fetestexcept(FE_ALL_EXCEPT)",
            "fegetround()",
            "LDBL_TRUE_MIN",
            "LDBL_MAX",
            "__builtin_nanl",
            "RECORD_COUNT",
            "write_all(binary80_records, sizeof(binary80_records))",
        ):
            self.assertIn(required, probe)
        for forbidden in ("__builtin_fmal", "-lm", "vfmadd"):
            self.assertNotIn(forbidden, probe)

    def test_runner_is_executable_and_syntax_valid(self) -> None:
        self.assertEqual(stat.S_IMODE(RUNNER_PATH.stat().st_mode), 0o755)
        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER_PATH)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_runner_proves_rust_owned_source_provenance_and_both_installed_modes(self) -> None:
        runner = RUNNER_PATH.read_text(encoding="utf-8")
        elementary_module = ELEMENTARY_MODULE_PATH.read_text(encoding="utf-8")
        elementary_generator = ELEMENTARY_GENERATOR_PATH.read_text(encoding="utf-8")
        x87_module = X87_MODULE_PATH.read_text(encoding="utf-8")
        dispatcher = (ROOT / "scripts" / "dev-x86_64.sh").read_text(encoding="utf-8")

        for required in (
            "SYMBOLS=(fmal hypotl log1pl)",
            "src/math/fmal.c",
            "src/math/hypotl.c",
            "src/math/x86_64/{logl,log1pl,log2l,log10l}.s",
            "Rust global_asm build input",
            "raw binary80 result/fenv/rounding",
            "installed binary80 result/fenv/rounding",
            "raw-component-members",
            "TMPDIR physically escapes checkout .work",
            "run_installed_mode -static-pie static-pie",
        ):
            self.assertIn(required, runner)
        self.assertNotIn('-lm -o "$candidate_raw"', runner)
        self.assertIn('include_str!("math_elementary_long_double_musl_x86_64.S")', elementary_module)
        self.assertIn('"src/math/fmal.c"', elementary_generator)
        self.assertIn('"src/math/hypotl.c"', elementary_generator)
        self.assertIn(".global log1pl", x87_module)
        self.assertIn("libc-owned-binary80-math)", dispatcher)
        self.assertIn(
            "run_in_container bash /workspace/compat/x86_64/"
            "run_owned_static_math_binary80_consumer.sh",
            dispatcher,
        )


if __name__ == "__main__":
    unittest.main()
