"""Pure-Python contract tests for the synthetic ldso runner."""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest


RUNNER = pathlib.Path(__file__).resolve().parents[1] / "run.py"
SPEC = importlib.util.spec_from_file_location("crabc_ldso_runner", RUNNER)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


class RelocationEvidenceTests(unittest.TestCase):
    def test_collects_complete_aarch64_relocation_names_from_wide_readelf(self) -> None:
        output = b"""\
Relocation section '.rela.dyn' at offset 0x123 contains 2 entries:
    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend
0000000000020000  0000000000000402 R_AARCH64_RELATIVE                        1000
0000000000020008  0000000200000401 R_AARCH64_GLOB_DAT     0000000000000000 leaf + 0
Relocation section '.rela.plt' at offset 0x456 contains 1 entry:
0000000000020010  0000000200000402 R_AARCH64_JUMP_SLOT   0000000000000000 leaf + 0
"""
        self.assertEqual(
            runner.relocation_types(output),
            {"R_AARCH64_RELATIVE", "R_AARCH64_GLOB_DAT", "R_AARCH64_JUMP_SLOT"},
        )

    def test_ignores_non_relocation_words(self) -> None:
        self.assertEqual(runner.relocation_types(b"no ELF data\n"), set())


class ProcessResultTests(unittest.TestCase):
    def test_json_preserves_raw_streams_and_timeout(self) -> None:
        result = runner.ProcessResult(("fixture",), -11, b"\x00out", b"err\xff", True)
        self.assertEqual(
            result.json(),
            {
                "argv": ["fixture"],
                "returncode": -11,
                "stdout_hex": "006f7574",
                "stderr_hex": "657272ff",
                "timed_out": True,
            },
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
