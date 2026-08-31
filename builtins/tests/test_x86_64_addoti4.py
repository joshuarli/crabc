"""Static contract checks for the private x86 __addoti4 proof."""

from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "x86_64_addoti4_probe.c"
START = ROOT / "fixtures" / "x86_64_addoti4_start.S"
RUNNER = ROOT / "run_x86_64_addoti4.sh"
NOTE = ROOT / "x86_64-addoti4.md"


class Addoti4ProofTests(unittest.TestCase):
    def test_fixture_keeps_the_helper_pointer_contract_observable(self) -> None:
        source = FIXTURE.read_text(encoding="utf-8")
        self.assertIn("extern signed_int128 __addoti4", source)
        self.assertIn("int overflow = -77;", source)
        self.assertIn("return __addoti4(left, right, overflow);", source)
        self.assertIn("__builtin_add_overflow(left, right, &result)", source)
        self.assertIn("check_case(maximum, 1, minimum, 1, 2)", source)
        self.assertIn("check_case(minimum, -1, maximum, 1, 3)", source)
        self.assertIn("check_case(maximum, minimum, -1, 0, 4)", source)

    def test_freestanding_start_returns_probe_status_via_exit_syscall(self) -> None:
        source = START.read_text(encoding="utf-8")
        self.assertIn("call crabc_x86_64_addoti4_probe", source)
        self.assertIn("movl $60, %eax", source)
        self.assertIn("syscall", source)
        self.assertIn(".note.GNU-stack", source)

    def test_runner_closes_the_fresh_archive_link_boundary(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn('"__addoti4" not in set', source)
        self.assertIn("freestanding addoti4 link unexpectedly succeeded", source)
        self.assertIn("candidate link admitted an ambient CRT or compiler runtime", source)
        self.assertIn("candidate did not retain __addoti4", source)
        self.assertIn("candidate code does not transfer control to __addoti4", source)
        self.assertIn("CRABC_BUILTINS_REFERENCE", source)
        self.assertIn("run_musl_oracle.sh", source)

    def test_note_keeps_the_proof_private_and_source_closed(self) -> None:
        source = NOTE.read_text(encoding="utf-8")
        self.assertIn("`builtins/src/lib.rs::__addoti4`", source)
        self.assertIn("`Uint128::add`", source)
        self.assertIn("It is not a complete compiler", source)
        self.assertIn("does not promote", source)


if __name__ == "__main__":
    unittest.main()
