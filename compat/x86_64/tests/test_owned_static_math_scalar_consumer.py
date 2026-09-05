#!/usr/bin/env python3
"""Contract checks for the x86 installed scalar-math completion consumer."""

from __future__ import annotations

import importlib.util
import re
import stat
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
GENERATOR_PATH = ROOT / "compat" / "x86_64" / "generate_libc_math_scalar_completion.py"
MODULE_PATH = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_scalar_completion.rs"
ASSEMBLY_PATH = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_scalar_completion_musl_x86_64.S"
RUNNER_PATH = ROOT / "compat" / "x86_64" / "run_owned_static_math_scalar_consumer.sh"


def load_generator():
    spec = importlib.util.spec_from_file_location("math_scalar_completion_generator", GENERATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


GENERATOR = load_generator()
SYMBOLS = ("fma", "fmaf", "hypot", "hypotf", "log1p", "log1pf")


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
        # Binary80 stays out of this consumer, while its ABI boundary remains
        # documented in the probe comment. Match the call/reference syntax,
        # not descriptive prose that necessarily names that boundary.
        for forbidden in ("(fmal)", "(hypotl)", "(log1pl)", "__builtin_fma", "vfmadd"):
            self.assertNotIn(forbidden, probe)

    def test_scalar_completion_has_a_private_generated_leaf_and_installed_runner(self) -> None:
        for path in (MODULE_PATH, ASSEMBLY_PATH, GENERATOR_PATH, RUNNER_PATH):
            self.assertTrue(path.is_file())

    def test_generator_preserves_the_exact_source_closure_and_scalar_code_shape(self) -> None:
        self.assertEqual(
            GENERATOR.PUBLIC_SOURCES,
            (
                "src/math/x86_64/fma.c",
                "src/math/x86_64/fmaf.c",
                "src/math/hypot.c",
                "src/math/hypotf.c",
                "src/math/log1p.c",
                "src/math/log1pf.c",
            ),
        )
        self.assertEqual(GENERATOR.PRIVATE_SOURCES, ("src/math/scalbn.c",))
        self.assertEqual(GENERATOR.PUBLIC_SYMBOLS, SYMBOLS)
        self.assertEqual(
            GENERATOR.PRIVATE_RENAMES,
            {"scalbn": "crabc_x86_math_scalar_completion_provider_scalbn"},
        )
        self.assertEqual(
            GENERATOR.EXPECTED_MUSL_TREE_DIGEST,
            "2ebc86943f5cdac77729695b304a08f6308e7a218f9d484cec5675006b207d88",
        )
        for flag in (
            "-frounding-math",
            "-ffp-contract=off",
            "-fexcess-precision=standard",
            "-mfpmath=sse",
            "-mno-avx",
            "-mno-fma",
            "-fno-tree-vectorize",
            "-fPIC",
        ):
            self.assertIn(flag, GENERATOR.COMPILE_FLAGS)

    def test_checked_assembly_exports_only_the_component_and_keeps_its_private_closure(self) -> None:
        assembly = ASSEMBLY_PATH.read_text(encoding="utf-8")
        exported = tuple(
            re.findall(r"^\s*\.globl\s+([A-Za-z_][A-Za-z0-9_]*)\s*$", assembly, re.MULTILINE)
        )
        self.assertEqual(exported, SYMBOLS)
        self.assertIn(".local crabc_x86_math_scalar_completion_provider_scalbn", assembly)
        self.assertIn("call\tsqrt@PLT", assembly)
        self.assertIn("call\tsqrtf@PLT", assembly)
        self.assertNotIn("fldt", assembly)
        self.assertNotIn(".ident", assembly)

    def test_leaf_and_native_gate_keep_the_owned_static_boundary_explicit(self) -> None:
        module = MODULE_PATH.read_text(encoding="utf-8")
        runner = RUNNER_PATH.read_text(encoding="utf-8")
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        dispatcher = (ROOT / "scripts" / "dev-x86_64.sh").read_text(encoding="utf-8")

        for required in (
            "x86-owned-static-runtime",
            "generate_libc_math_scalar_completion.py",
            "pinned musl 1.2.6",
            "binary80 `fmal`, `hypotl`, and `log1pl` ABI is intentionally separate",
            "include_str!(\"math_scalar_completion_musl_x86_64.S\")",
        ):
            self.assertIn(required, module)
        self.assertIn(
            '#[cfg(feature = "x86-owned-static-runtime")]\n'
            '#[path = "math_scalar_completion.rs"]\n'
            "mod math_scalar_completion;",
            static_root,
        )
        for required in (
            "--features x86-owned-static-runtime",
            "frozen default archive unexpectedly provides strong",
            "raw result/fenv/rounding",
            "installed result/fenv/rounding",
            "scripts/build_x86_64_owned_sysroot.py",
            "raw-component-members",
            "aggregate archive intentionally has unrelated allocator/runtime TLS",
            "raw scalar-math path calls a binary80 provider",
            "TMPDIR physically escapes checkout .work",
            "input receipt roles drifted",
            "run_installed_mode -static-pie static-pie",
        ):
            self.assertIn(required, runner)
        self.assertNotIn('-lm -o "$candidate_raw"', runner)
        self.assertIn("libc-owned-scalar-math)", dispatcher)
        self.assertIn(
            "run_in_container bash /workspace/compat/x86_64/"
            "run_owned_static_math_scalar_consumer.sh",
            dispatcher,
        )
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


if __name__ == "__main__":
    unittest.main()
