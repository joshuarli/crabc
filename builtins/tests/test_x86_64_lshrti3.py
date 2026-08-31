"""Static contract checks for the private x86 __lshrti3 proof."""

from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "x86_64_lshrti3_probe.c"
START = ROOT / "fixtures" / "x86_64_lshrti3_start.S"
RUNNER = ROOT / "run_x86_64_lshrti3.sh"
NOTE = ROOT / "x86_64-lshrti3.md"


class Lshrti3ProofTests(unittest.TestCase):
    def test_fixture_preserves_the_raw_count_and_logical_word_boundary(self) -> None:
        source = FIXTURE.read_text(encoding="utf-8")
        self.assertIn("extern unsigned_int128 __lshrti3", source)
        self.assertIn("if (shift < 0 || shift >= 128)", source)
        self.assertIn("return value >> (unsigned int)shift;", source)
        self.assertIn("return __lshrti3(value, shift);", source)
        self.assertIn("((unsigned_int128)1) << 127", source)
        self.assertIn("check_case(input, 63", source)
        self.assertIn("check_case(input, 64", source)
        self.assertIn("check_case(input, 65", source)
        self.assertIn("check_case(input, 127, 1, 6)", source)
        self.assertIn("check_case(input, 128, 0, 7)", source)
        self.assertIn("check_case(input, 129, 0, 8)", source)
        self.assertIn("check_case(input, -1, 0, 9)", source)

    def test_freestanding_start_returns_probe_status_via_exit_syscall(self) -> None:
        source = START.read_text(encoding="utf-8")
        self.assertIn("call crabc_x86_64_lshrti3_probe", source)
        self.assertIn("movl $60, %eax", source)
        self.assertIn("syscall", source)
        self.assertIn(".note.GNU-stack", source)

    def test_runner_closes_the_fresh_archive_link_boundary(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn('"__lshrti3" not in set', source)
        self.assertIn("freestanding lshrti3 link unexpectedly succeeded", source)
        self.assertIn("native C object admitted an unexpected helper boundary", source)
        self.assertIn("candidate link admitted an ambient CRT or compiler runtime", source)
        self.assertIn("candidate did not retain __lshrti3", source)
        self.assertIn("candidate code does not transfer control to __lshrti3", source)
        self.assertIn("CRABC_BUILTINS_REFERENCE", source)
        self.assertIn("run_musl_oracle.sh", source)

    def test_note_keeps_the_proof_private_and_source_closed(self) -> None:
        source = NOTE.read_text(encoding="utf-8")
        self.assertIn("`builtins/src/lib.rs::__lshrti3`", source)
        self.assertIn("`Uint128::shr`", source)
        self.assertIn("not ordinary C shift\nsemantics", source)
        self.assertIn("It is not a complete compiler", source)
        self.assertIn("does not promote", source)


if __name__ == "__main__":
    unittest.main()
