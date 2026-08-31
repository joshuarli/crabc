"""Static contract checks for the private x86 __clzti2 proof."""

from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "x86_64_clzti2_probe.c"
START = ROOT / "fixtures" / "x86_64_clzti2_start.S"
RUNNER = ROOT / "run_x86_64_clzti2.sh"
NOTE = ROOT / "x86_64-clzti2.md"


class Clzti2ProofTests(unittest.TestCase):
    def test_fixture_preserves_the_high_word_then_low_word_boundary(self) -> None:
        source = FIXTURE.read_text(encoding="utf-8")
        self.assertIn("extern int __clzti2", source)
        self.assertIn("static int leading_zeros_word", source)
        self.assertIn("while (bit != 0 && (value & bit) == 0)", source)
        self.assertIn("if (high != 0)", source)
        self.assertIn("return 64 + leading_zeros_word((word)value);", source)
        self.assertIn("return __clzti2(value);", source)
        self.assertIn("check_case(words(0, 0), 128", source)
        self.assertIn("check_case(words((word)1 << 63, 0), 0", source)
        self.assertIn("check_case(words(1, ~(word)0), 63", source)
        self.assertIn("check_case(words(0, (word)1 << 63), 64", source)
        self.assertIn("check_case(words(0, 1), 127", source)

    def test_freestanding_start_returns_probe_status_via_exit_syscall(self) -> None:
        source = START.read_text(encoding="utf-8")
        self.assertIn("call crabc_x86_64_clzti2_probe", source)
        self.assertIn("movl $60, %eax", source)
        self.assertIn("syscall", source)
        self.assertIn(".note.GNU-stack", source)

    def test_runner_closes_the_fresh_archive_link_boundary(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn('"__clzti2" not in set', source)
        self.assertIn("freestanding clzti2 link unexpectedly succeeded", source)
        self.assertIn("native C object admitted an unexpected helper boundary", source)
        self.assertIn("candidate link admitted an ambient CRT or compiler runtime", source)
        self.assertIn("candidate did not retain __clzti2", source)
        self.assertIn("candidate code does not transfer control to __clzti2", source)
        self.assertIn("CRABC_BUILTINS_REFERENCE", source)
        self.assertIn("run_musl_oracle.sh", source)

    def test_note_keeps_the_proof_private_and_source_closed(self) -> None:
        source = NOTE.read_text(encoding="utf-8")
        self.assertIn("`builtins/src/lib.rs::__clzti2`", source)
        self.assertIn("`u64::leading_zeros`", source)
        self.assertIn("all-zero bit pattern", source)
        self.assertIn("It is not a\ncomplete compiler runtime", source)
        self.assertIn("does not promote", source)


if __name__ == "__main__":
    unittest.main()
