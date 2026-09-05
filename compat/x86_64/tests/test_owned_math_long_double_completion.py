#!/usr/bin/env python3
"""Regression contract for installed binary80 long-double completion."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_math_long_double_completion.sh"
PROBE = ROOT / "compat/x86_64/libc_math_long_double_completion_probe.c"
VALIDATOR = ROOT / "compat/x86_64/validate_libc_math_long_double_completion.py"
MODULE = ROOT / "libc/src/c_abi/x86_64/math_long_double_completion.rs"
ASSEMBLY = ROOT / "libc/src/c_abi/x86_64/math_long_double_completion_musl_x86_64.S"


class OwnedMathLongDoubleCompletionTests(unittest.TestCase):
    def test_fixed_musl_binary80_source_covers_the_missing_public_spelling_contract(self) -> None:
        source = PROBE.read_text(encoding="utf-8")
        validator = VALIDATOR.read_text(encoding="utf-8")
        module = MODULE.read_text(encoding="utf-8")
        assembly = ASSEMBLY.read_text(encoding="utf-8")

        for required in (
            "direct_fdiml", "direct_exp10l", "direct_pow10l",
            "sizeof(long double) == 16", "LDBL_MANT_DIG == 64",
            "FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO",
            "HUGE_VALL", "binary80_from_parts", "LDBL_TRUE_MIN", "LDBL_MAX",
        ):
            self.assertIn(required, source)
        for required in (
            "fdiml case", "binary80 NaN result", "FE_OVERFLOW|FE_INEXACT",
            "exp10l finite boundary", "exp10l/pow10l record", "complete x87 control word",
        ):
            self.assertIn(required, validator)
        for required in (
            "src/math/fdiml.c", "src/math/exp10l.c", "weak", "same-address",
            "__fpclassifyl", "modfl", "exp2l", "powl",
        ):
            self.assertIn(required, module)
        for required in (".globl\tfdiml", ".globl\texp10l", ".weak\tpow10l", ".set\tpow10l,exp10l"):
            self.assertIn(required, assembly)

    def test_runner_is_supplied_product_only_and_compiles_one_object(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("usage: %s [--static-sysroot STATIC_SYSROOT] DYNAMIC_SYSROOT", runner)
        self.assertNotIn("build_x86_64_owned_dynamic_sysroot.py", runner)
        self.assertNotIn("build_x86_64_owned_sysroot.py", runner)
        self.assertNotIn("-DCRABC_", runner)
        self.assertIn('static = Path(static_text) if static_text else None', runner)
        self.assertIn('"$dynamic_sysroot/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -D_GNU_SOURCE', runner)
        self.assertIn('-c "$SOURCE" -o "$work/workload.o"', runner)
        self.assertNotIn("-frounding-math", runner)
        self.assertIn('"$ORACLE_CC" -static -fno-pie -no-pie "$work/workload.o" -lm', runner)
        for required in (
            '"-$mode" --link-receipt', 'for mode in pie non-pie',
            'for entry in kernel direct', 'validate_link "$dynamic_sysroot"',
            'validate_link "$static_sysroot"', 'audit_execution_root',
            'cmp "$work/execution-$mode-$entry-pre.json"',
        ):
            self.assertIn(required, runner)

    def test_runner_retains_exact_raw_oracle_comparisons_and_copied_runtime_boundary(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        for required in (
            "validate_libc_math_long_double_completion.py", "RECORDS=247",
            "record count drifted", "emitted invalid binary80 records",
            "differs from pinned musl", "stderr differs from pinned musl",
            'cp -a -- "$dynamic_sysroot" "$root"', 'cp -- "$work/dynamic-$mode" "$root/consumer"',
            "source payload drifted", "copied payload drifted", "execution consumer drifted", "manifest-bound product file",
            '"$INTERPRETER" /consumer',
        ):
            self.assertIn(required, runner)
        copied = runner.index('cp -a -- "$dynamic_sysroot" "$root"')
        pre_audit = runner.index('audit_execution_root "$root" "$work/dynamic-$mode" "$mode-$entry-pre"')
        kernel_launch = runner.index('capture "$work/dynamic-$mode-$entry" /usr/sbin/chroot "$root" /consumer')
        self.assertLess(copied, pre_audit)
        self.assertLess(pre_audit, kernel_launch)

    def test_runner_is_executable_and_rejects_ambiguous_inputs_before_product_tools(self) -> None:
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode), 0o755)
        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER)], cwd=ROOT, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        scratch_root = ROOT / ".work/x86_64/tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        for arguments in ((), ("--static-sysroot",), ("one", "two"), ("--unexpected",)):
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
                result = subprocess.run(
                    ["bash", str(RUNNER), *arguments], cwd=ROOT,
                    env={"PATH": os.environ["PATH"], "TMPDIR": temporary},
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertEqual(
                result.stderr,
                f"usage: {RUNNER} [--static-sysroot STATIC_SYSROOT] DYNAMIC_SYSROOT\n",
            )


if __name__ == "__main__":
    unittest.main()
