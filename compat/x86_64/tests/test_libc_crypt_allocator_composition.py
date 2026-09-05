#!/usr/bin/env python3
"""Regression boundary for the private x86 crypt/allocator artifact judge."""

from __future__ import annotations

from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_libc_crypt_allocator_composition.sh"


class X86LibcCryptAllocatorCompositionTests(unittest.TestCase):
    def test_pipefail_can_reject_a_present_symbol_after_grep_quits_early(self) -> None:
        producer = (
            "import os, time\n"
            "os.write(1, b'00000000 T mi_free\\n')\n"
            "time.sleep(0.1)\n"
            "os.write(1, b'00000000 T retained_symbol\\n' * 400000)\n"
        )
        completed = subprocess.run(
            [
                "bash",
                "-c",
                "set -o pipefail; python3 -c \"$1\" | grep -Eq "
                "'[[:space:]][TW][[:space:]]mi_free$'",
                "--",
                producer,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertNotEqual(
            completed.returncode,
            0,
            "pipefail must expose the producer's SIGPIPE after grep -q finds mi_free",
        )

    def test_runner_drains_nm_output_before_matching_symbols(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertNotIn(
            'nm --undefined-only "$selected_crypt_member" |', runner
        )
        self.assertNotIn(
            'nm -g --defined-only "$selected_member_dir/${backend_members[0]}" |',
            runner,
        )
        self.assertNotIn(
            'nm -g --defined-only "$selected_member_dir/${allocator_members[0]}" \\\n        "$selected_member_dir/${backend_members[0]}" |',
            runner,
        )
        for table in (
            "crypt_undefined_symbols",
            "backend_symbols",
            "selected_provider_symbols",
        ):
            self.assertIn(f'{table}="$work_dir/', runner)


if __name__ == "__main__":
    unittest.main()
