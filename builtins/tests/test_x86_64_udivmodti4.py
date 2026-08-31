"""Static contract checks for the private x86 __udivmodti4 proof."""

from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "x86_64_udivmodti4_probe.c"
START = ROOT / "fixtures" / "x86_64_udivmodti4_start.S"
RUNNER = ROOT / "run_x86_64_udivmodti4.sh"
NOTE = ROOT / "x86_64-udivmodti4.md"


class Udivmodti4ProofTests(unittest.TestCase):
    def test_fixture_keeps_the_remainder_pointer_contract_observable(self) -> None:
        source = FIXTURE.read_text(encoding="utf-8")
        self.assertIn("extern unsigned_int128 __udivmodti4", source)
        self.assertIn("unsigned_int128 remainder = ~((unsigned_int128)0);", source)
        self.assertIn("return __udivmodti4(numerator, denominator, remainder);", source)
        self.assertIn("*remainder = numerator % denominator;", source)
        self.assertIn("return numerator / denominator;", source)
        self.assertIn("cross_word_denominator", source)
        self.assertIn("((unsigned_int128)1) << 63", source)
        self.assertIn("~((unsigned_int128)0)", source)

    def test_freestanding_start_returns_probe_status_via_exit_syscall(self) -> None:
        source = START.read_text(encoding="utf-8")
        self.assertIn("call crabc_x86_64_udivmodti4_probe", source)
        self.assertIn("movl $60, %eax", source)
        self.assertIn("syscall", source)
        self.assertIn(".note.GNU-stack", source)

    def test_runner_closes_the_fresh_archive_link_boundary(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn('"__udivmodti4" not in set', source)
        self.assertIn("freestanding udivmodti4 link unexpectedly succeeded", source)
        self.assertIn("candidate link admitted an ambient CRT or compiler runtime", source)
        self.assertIn("candidate did not retain __udivmodti4", source)
        self.assertIn("candidate code does not transfer control to __udivmodti4", source)
        self.assertIn("native C object admitted an unexpected helper boundary", source)
        self.assertIn("CRABC_BUILTINS_REFERENCE", source)
        self.assertIn("run_musl_oracle.sh", source)

    def test_note_keeps_the_proof_private_and_source_closed(self) -> None:
        source = NOTE.read_text(encoding="utf-8")
        self.assertIn("`builtins/src/lib.rs::__udivmodti4`", source)
        self.assertIn("`Uint128::divmod_unsigned`", source)
        self.assertIn("`write_remainder`", source)
        self.assertIn("It is not a complete compiler", source)
        self.assertIn("does not promote", source)


if __name__ == "__main__":
    unittest.main()
