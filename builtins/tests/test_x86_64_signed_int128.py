"""Static contract checks for the private x86 signed-__int128 proof."""

from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "x86_64_signed_int128_probe.c"
START = ROOT / "fixtures" / "x86_64_signed_int128_start.S"
RUNNER = ROOT / "run_x86_64_signed_int128.sh"
NOTE = ROOT / "x86_64-signed-int128.md"


class SignedInt128ProofTests(unittest.TestCase):
    def test_fixture_uses_defined_signed_cases_through_compiler_helpers(self) -> None:
        source = FIXTURE.read_text(encoding="utf-8")
        self.assertIn("static volatile signed_int128 operand_left;", source)
        self.assertIn("static volatile signed_int128 operand_right;", source)
        self.assertIn("static signed_int128 signed_divide", source)
        self.assertIn("static signed_int128 signed_remainder", source)
        self.assertIn("return left / right;", source)
        self.assertIn("return left % right;", source)
        self.assertIn("check_case(7, -3, -2, 1, 5)", source)
        self.assertIn("check_case(-7, 3, -2, -1, 6)", source)
        self.assertIn("check_case(-7, -3, 2, -1, 7)", source)
        self.assertIn("has a nonzero divisor", source)

    def test_freestanding_start_returns_probe_status_via_exit_syscall(self) -> None:
        source = START.read_text(encoding="utf-8")
        self.assertIn("call crabc_x86_64_signed_int128_probe", source)
        self.assertIn("movl $60, %eax", source)
        self.assertIn("syscall", source)
        self.assertIn(".note.GNU-stack", source)

    def test_runner_requires_and_retains_the_named_helper_boundary(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn('"__divti3", "__modti3"', source)
        self.assertIn("freestanding signed-int128 link unexpectedly succeeded", source)
        self.assertIn("candidate did not retain ${symbol}", source)
        self.assertIn("candidate code does not call ${symbol}", source)
        self.assertIn("run_musl_oracle.sh", source)
        self.assertIn("not a complete compiler runtime or public sysroot", source)
        self.assertIn("candidate link admitted an ambient CRT or compiler runtime", source)
        self.assertIn('nm --defined-only "$candidate" >"$candidate_symbols"', source)
        self.assertIn('grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols"', source)

    def test_note_keeps_the_proof_private_and_source_closed(self) -> None:
        source = NOTE.read_text(encoding="utf-8")
        self.assertIn("`builtins/src/lib.rs::Uint128`", source)
        self.assertIn("`builtins/src/lib.rs::__divti3`", source)
        self.assertIn("`builtins/src/lib.rs::__modti3`", source)
        self.assertIn("not a complete compiler runtime", source)
        self.assertIn("does not promote", source)


if __name__ == "__main__":
    unittest.main()
