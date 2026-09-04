#!/usr/bin/env python3
"""Source and generated-assembly contracts for owned x86 inverse trig."""

from __future__ import annotations

import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
GENERATOR_PATH = ROOT / "compat" / "x86_64" / "generate_libc_owned_inverse_trig.py"
MODULE_PATH = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "owned_inverse_trig.rs"
ASSEMBLY_PATH = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "owned_inverse_trig_musl_x86_64.S"
PROBE_PATH = ROOT / "compat" / "x86_64" / "libc_owned_inverse_trig_probe.c"
LINK_PROBE_PATH = ROOT / "compat" / "x86_64" / "owned_static_inverse_trig_link_probe.c"
HEADER_PROBE_PATH = ROOT / "compat" / "x86_64" / "owned_inverse_trig_header_abi_probe.cpp"
HEADER_RUNNER_PATH = ROOT / "compat" / "x86_64" / "run_owned_inverse_trig_header_abi.sh"
RUNNER_PATH = ROOT / "compat" / "x86_64" / "run_libc_owned_inverse_trig.sh"


def load_generator():
    spec = importlib.util.spec_from_file_location("owned_inverse_trig_generator", GENERATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


GENERATOR = load_generator()
SYMBOLS = ("asin", "acos", "atan", "atan2", "asinf", "acosf", "atanf", "atan2f")


class OwnedInverseTrigTests(unittest.TestCase):
    def test_generator_has_exact_pinned_source_map_and_scalar_flags(self) -> None:
        self.assertEqual(
            GENERATOR.PUBLIC_SOURCES,
            (
                "src/math/asin.c", "src/math/acos.c", "src/math/atan.c", "src/math/atan2.c",
                "src/math/asinf.c", "src/math/acosf.c", "src/math/atanf.c", "src/math/atan2f.c",
            ),
        )
        self.assertEqual(
            GENERATOR.EXPECTED_MUSL_TREE_DIGEST,
            "2ebc86943f5cdac77729695b304a08f6308e7a218f9d484cec5675006b207d88",
        )
        for flag in (
            "-frounding-math", "-ffp-contract=off", "-fexcess-precision=standard",
            "-mfpmath=sse", "-mno-avx", "-mno-fma", "-fno-tree-vectorize",
            "-fno-builtin-asin", "-fno-builtin-atan2f", "-fno-builtin-sqrtf",
        ):
            self.assertIn(flag, GENERATOR.COMPILE_FLAGS)
        self.assertIn('"-fPIC",', GENERATOR_PATH.read_text(encoding="utf-8"))

    def test_generator_rejects_ambient_or_escaping_checkout_scratch(self) -> None:
        producer = GENERATOR.producer
        with tempfile.TemporaryDirectory(
            prefix="test-inverse-trig-generator.",
            dir=producer.deterministic_environment()["TMPDIR"],
        ) as temporary:
            temporary_root = Path(temporary)
            checkout = temporary_root / "checkout"
            checkout.mkdir()
            with patch.object(producer, "ROOT", checkout), patch.dict(
                os.environ,
                {"TMPDIR": "/outside-checkout/untrusted", "CPATH": "/ambient/include"},
            ):
                environment = GENERATOR.generation_environment()
            self.assertEqual(environment["TMPDIR"], str(checkout / ".work/x86_64/tmp"))
            self.assertTrue(Path(environment["TMPDIR"]).is_dir())
            self.assertNotIn("CPATH", environment)

            escaping_checkout = temporary_root / "escaping-checkout"
            state = escaping_checkout / ".work/x86_64"
            state.mkdir(parents=True)
            (state / "tmp").symlink_to(temporary_root)
            with patch.object(producer, "ROOT", escaping_checkout):
                with self.assertRaisesRegex(producer.BuildError, "escapes checkout"):
                    GENERATOR.generation_environment()
            self.assertFalse((state / "cargo").exists())

    def test_checked_assembly_exports_only_the_eight_component_entries(self) -> None:
        assembly = ASSEMBLY_PATH.read_text(encoding="utf-8")
        exported = tuple(re.findall(r"^\s*\.globl\s+([A-Za-z_][A-Za-z0-9_]*)\s*$", assembly, re.MULTILINE))
        self.assertEqual(exported, SYMBOLS)
        self.assertIn("call\tsqrt", assembly)
        self.assertIn("call\tsqrtf", assembly)
        self.assertIn("jmp\tatan", assembly)
        self.assertIn("jmp\tatanf", assembly)
        self.assertNotIn("fldt", assembly)
        self.assertNotIn(".ident", assembly)

    def test_module_keeps_component_owned_only_and_source_faithful(self) -> None:
        module = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn("x86-owned-static-runtime", module)
        self.assertIn("generate_libc_owned_inverse_trig.py", module)
        self.assertIn("pinned musl 1.2.6", module)
        self.assertIn("`asin`, `acos`, `atan`, and", module)
        self.assertIn("ambient-libm", module)
        self.assertIn("`fabs` and", module)
        self.assertIn("include_str!(\"owned_inverse_trig_musl_x86_64.S\")", module)

    def test_link_and_differential_probes_retain_all_observable_boundaries(self) -> None:
        link_probe = LINK_PROBE_PATH.read_text(encoding="utf-8")
        differential = PROBE_PATH.read_text(encoding="utf-8")
        header = HEADER_PROBE_PATH.read_text(encoding="utf-8")
        for symbol in SYMBOLS:
            self.assertIn(f"direct_{symbol}", link_probe)
            self.assertIn(f"direct_{symbol}", differential)
            self.assertIn(f"direct_{symbol}", header)
        for boundary in (
            "ERRNO_SENTINEL", "fetestexcept", "fesetround", "FE_TOWARDZERO",
            "0x8000000000000000", "0x0000000000000001", "0x7ff0000000000042",
            "0x3ff0000000000001", "0x7f800042", "binary64_atan2_inputs",
            "binary32_atan2_inputs",
        ):
            self.assertIn(boundary, differential)

    def test_native_gate_uses_only_checkout_local_state_and_checks_default_boundary(self) -> None:
        runner = RUNNER_PATH.read_text(encoding="utf-8")
        header_runner = HEADER_RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn('mktemp -d "$TMPDIR/crabc-x86-owned-inverse-trig.', runner)
        self.assertIn('mktemp -d "$TMPDIR/crabc-x86-owned-inverse-trig-header.', header_runner)
        self.assertIn("--features x86-owned-static-runtime", runner)
        self.assertIn("frozen default archive unexpectedly exports", runner)
        self.assertIn("raw result/fenv/rounding", runner)
        self.assertIn("installed result/errno/fenv/rounding", runner)
        self.assertIn("scripts/build_x86_64_owned_sysroot.py", runner)
        self.assertIn("run_owned_inverse_trig_header_abi.sh", runner)
        self.assertIn("raw-component-members", runner)
        self.assertIn("aggregate archive intentionally carries unrelated allocator/runtime TLS", runner)
        self.assertIn("raw inverse-trig path calls a binary80 provider", runner)
        self.assertIn("TMPDIR physically escapes checkout .work", runner)
        self.assertIn("retained failure evidence", runner)
        self.assertIn("ulimit -c 0", runner)
        self.assertIn("input receipt roles drifted", runner)
        self.assertIn("run_installed_mode -static-pie static-pie", runner)
        self.assertIn("static PIE", runner)
        self.assertIn("TMPDIR physically escapes checkout .work", header_runner)
        self.assertNotIn("-lm -o \"$candidate_raw\"", runner)


if __name__ == "__main__":
    unittest.main()
