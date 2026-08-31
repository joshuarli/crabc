"""Static contract checks for the private x86 __ffsti2 proof."""

from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "x86_64_ffsti2_probe.c"
START = ROOT / "fixtures" / "x86_64_ffsti2_start.S"
RUNNER = ROOT / "run_x86_64_ffsti2.sh"
NOTE = ROOT / "x86_64-ffsti2.md"


class Ffsti2ProofTests(unittest.TestCase):
    def test_fixture_preserves_the_zero_and_ctz_plus_one_boundary(self) -> None:
        source = FIXTURE.read_text(encoding="utf-8")
        self.assertIn("extern int __ffsti2", source)
        self.assertIn("static int trailing_zeros_word", source)
        self.assertIn("if (low == 0 && high == 0)", source)
        self.assertIn("return trailing_zeros_word(low) + 1;", source)
        self.assertIn("return 64 + trailing_zeros_word(high) + 1;", source)
        self.assertIn("return __ffsti2(value);", source)
        self.assertIn("check_case(words(0, 0), 0", source)
        self.assertIn("check_case(words(0, 1), 1", source)
        self.assertIn("check_case(words(1, (word)1 << 63), 64", source)
        self.assertIn("check_case(words(1, 0), 65", source)
        self.assertIn("check_case(words((word)1 << 63, 0), 128", source)

    def test_freestanding_start_returns_probe_status_via_exit_syscall(self) -> None:
        source = START.read_text(encoding="utf-8")
        self.assertIn("call crabc_x86_64_ffsti2_probe", source)
        self.assertIn("movl $60, %eax", source)
        self.assertIn("syscall", source)
        self.assertIn(".note.GNU-stack", source)

    def test_runner_closes_the_fresh_archive_link_boundary(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn('"__ffsti2" not in set', source)
        self.assertIn("freestanding ffsti2 link unexpectedly succeeded", source)
        self.assertIn("native C object admitted an unexpected helper boundary", source)
        self.assertIn("candidate link admitted an ambient CRT or compiler runtime", source)
        self.assertIn("candidate did not retain __ffsti2", source)
        self.assertIn("candidate did not retain the source-owned __ctzti2 dependency", source)
        self.assertIn("candidate code does not transfer control to __ffsti2", source)
        self.assertIn("CRABC_BUILTINS_REFERENCE", source)
        self.assertIn("run_musl_oracle.sh", source)

    def test_note_keeps_the_proof_private_and_source_closed(self) -> None:
        source = NOTE.read_text(encoding="utf-8")
        self.assertIn("`builtins/src/lib.rs::__ffsti2`", source)
        self.assertIn("`__ctzti2(value) + 1`", source)
        self.assertIn("all-zero bit pattern", source)
        self.assertIn("It is not a\ncomplete compiler runtime", source)
        self.assertIn("does not promote", source)


if __name__ == "__main__":
    unittest.main()
