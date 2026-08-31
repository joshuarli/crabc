"""Static contract checks for the private x86 __divmodti4 proof."""

from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "x86_64_divmodti4_probe.c"
START = ROOT / "fixtures" / "x86_64_divmodti4_start.S"
RUNNER = ROOT / "run_x86_64_divmodti4.sh"
NOTE = ROOT / "x86_64-divmodti4.md"


class Divmodti4ProofTests(unittest.TestCase):
    def test_fixture_keeps_the_remainder_pointer_contract_observable(self) -> None:
        source = FIXTURE.read_text(encoding="utf-8")
        self.assertIn("extern signed_int128 __divmodti4", source)
        self.assertIn("signed_int128 remainder = 17;", source)
        self.assertIn("return __divmodti4(numerator, denominator, remainder);", source)
        self.assertIn("*remainder = numerator % denominator;", source)
        self.assertIn("return numerator / denominator;", source)
        self.assertIn("check_case(7, -3, -2, 1, 5)", source)
        self.assertIn("check_case(-7, 3, -2, -1, 6)", source)
        self.assertIn("cross_word_denominator", source)
        self.assertIn("((signed_int128)3) << 62", source)

    def test_freestanding_start_returns_probe_status_via_exit_syscall(self) -> None:
        source = START.read_text(encoding="utf-8")
        self.assertIn("call crabc_x86_64_divmodti4_probe", source)
        self.assertIn("movl $60, %eax", source)
        self.assertIn("syscall", source)
        self.assertIn(".note.GNU-stack", source)

    def test_runner_closes_the_fresh_archive_link_boundary(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn('"__divmodti4" not in set', source)
        self.assertIn("freestanding divmodti4 link unexpectedly succeeded", source)
        self.assertIn("native C object admitted an unexpected helper boundary", source)
        self.assertIn("candidate link admitted an ambient CRT or compiler runtime", source)
        self.assertIn("candidate did not retain __divmodti4", source)
        self.assertIn("candidate code does not transfer control to __divmodti4", source)
        self.assertIn("CRABC_BUILTINS_REFERENCE", source)
        self.assertIn("run_musl_oracle.sh", source)

    def test_note_keeps_the_proof_private_and_source_closed(self) -> None:
        source = NOTE.read_text(encoding="utf-8")
        self.assertIn("`builtins/src/lib.rs::__divmodti4`", source)
        self.assertIn("`Uint128::divmod_signed`", source)
        self.assertIn("`write_remainder`", source)
        self.assertIn("It is not a complete compiler", source)
        self.assertIn("does not promote", source)


if __name__ == "__main__":
    unittest.main()
