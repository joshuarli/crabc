"""Static contract checks for the private x86 __ashrti3 proof."""

from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "x86_64_ashrti3_probe.c"
START = ROOT / "fixtures" / "x86_64_ashrti3_start.S"
RUNNER = ROOT / "run_x86_64_ashrti3.sh"
NOTE = ROOT / "x86_64-ashrti3.md"


class Ashrti3ProofTests(unittest.TestCase):
    def test_fixture_preserves_the_raw_signed_shift_boundary(self) -> None:
        source = FIXTURE.read_text(encoding="utf-8")
        self.assertIn("extern unsigned_int128 __ashrti3", source)
        self.assertIn("if (shift < 0 || shift >= 128)", source)
        self.assertIn("negative ? words(~(word)0, ~(word)0) : 0", source)
        self.assertIn("result_low = high >> count", source)
        self.assertIn("return __ashrti3(value, shift);", source)
        self.assertIn("negative_input, 63, words(~(word)0, 2)", source)
        self.assertIn("negative_input,\n        64", source)
        self.assertIn("negative_input,\n        65", source)
        self.assertIn("negative_input, 127, all_ones", source)
        self.assertIn("negative_input, 128, all_ones", source)
        self.assertIn("negative_input, -1, all_ones", source)
        self.assertIn("positive_input, 128, 0", source)
        self.assertIn("positive_input, 129, 0", source)
        self.assertIn("positive_input, -1, 0", source)

    def test_freestanding_start_returns_probe_status_via_exit_syscall(self) -> None:
        source = START.read_text(encoding="utf-8")
        self.assertIn("call crabc_x86_64_ashrti3_probe", source)
        self.assertIn("movl $60, %eax", source)
        self.assertIn("syscall", source)
        self.assertIn(".note.GNU-stack", source)

    def test_runner_closes_the_fresh_archive_link_boundary(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn('"__ashrti3" not in set', source)
        self.assertIn("freestanding ashrti3 link unexpectedly succeeded", source)
        self.assertIn("native C object admitted an unexpected helper boundary", source)
        self.assertIn("candidate link admitted an ambient CRT or compiler runtime", source)
        self.assertIn("candidate did not retain __ashrti3", source)
        self.assertIn("candidate code does not transfer control to __ashrti3", source)
        self.assertIn("CRABC_BUILTINS_REFERENCE", source)
        self.assertIn("run_musl_oracle.sh", source)

    def test_note_keeps_the_proof_private_and_source_closed(self) -> None:
        source = NOTE.read_text(encoding="utf-8")
        self.assertIn("`builtins/src/lib.rs::__ashrti3`", source)
        self.assertIn("`Uint128::sar`", source)
        self.assertIn("not\nordinary C signed-right-shift semantics", source)
        self.assertIn("It is not a complete compiler", source)
        self.assertIn("does not promote", source)


if __name__ == "__main__":
    unittest.main()
