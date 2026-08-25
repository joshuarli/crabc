#!/usr/bin/env python3
"""Regression tests for the x86-64 TLS witness evidence boundary."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = ROOT / "compat/allocator/tls-codegen/run-x86_64.py"
SPEC = importlib.util.spec_from_file_location("crabc_tls_codegen_x86_64", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class X86_64TlsWitnessEvidenceTests(unittest.TestCase):
    def test_identity_requires_an_exact_fs_zero_load_without_tls_relocation(self) -> None:
        evidence = RUNNER.witness_access_evidence(
            RUNNER.IDENTITY_WITNESS,
            "   0: 64 48 8b 04 25 00 00 00 00 mov    %fs:0x0,%rax\n",
        )

        self.assertEqual(
            evidence,
            {
                "access_model": "direct-thread-pointer-fs-zero",
                "exact_fs_zero_read": True,
                "fs_segment_access": True,
                "tlsie_relocation": False,
            },
        )

    def test_identity_rejects_a_register_derived_fs_offset(self) -> None:
        with self.assertRaisesRegex(RUNNER.VerificationError, r"%fs:0 identity word"):
            RUNNER.witness_access_evidence(
                RUNNER.IDENTITY_WITNESS,
                "   0: 64 48 8b 00 mov    %fs:(%rax),%rax\n",
            )

    def test_identity_rejects_an_indexed_zero_displacement_fs_offset(self) -> None:
        for operand in ("%fs:0x0(%rax)", "%fs:0(%rax)"):
            with self.subTest(operand=operand), self.assertRaisesRegex(
                RUNNER.VerificationError, r"%fs:0 identity word"
            ):
                RUNNER.witness_access_evidence(
                    RUNNER.IDENTITY_WITNESS,
                    f"   0: 64 48 8b 00 mov    {operand},%rax\n",
                )

    def test_root_witness_requires_fs_segment_access_and_gottpoff(self) -> None:
        evidence = RUNNER.witness_access_evidence(
            "crabc_mimalloc_tls_probe_dynamic_get",
            "   0: 48 8b 05 00 00 00 00 mov 0x0(%rip),%rax\n"
            "\t\t\t3: R_X86_64_GOTTPOFF DYNAMIC_BACKING_ROOT\n"
            "   7: 64 48 8b 00 mov %fs:(%rax),%rax\n",
        )

        self.assertEqual(
            evidence,
            {
                "access_model": "initial-exec-tls-fs-segment-gottpoff",
                "fs_segment_access": True,
                "tlsie_relocation": True,
            },
        )

    def test_root_witness_rejects_gottpoff_without_fs_segment_access(self) -> None:
        with self.assertRaisesRegex(RUNNER.VerificationError, r"%fs-segment access"):
            RUNNER.witness_access_evidence(
                "crabc_mimalloc_tls_probe_dynamic_get",
                "\t\t\t3: R_X86_64_GOTTPOFF DYNAMIC_BACKING_ROOT\n",
            )

    def test_root_witness_rejects_fs_segment_access_without_gottpoff(self) -> None:
        with self.assertRaisesRegex(RUNNER.VerificationError, r"initial-exec TLS relocation"):
            RUNNER.witness_access_evidence(
                "crabc_mimalloc_tls_probe_dynamic_get",
                "   0: 64 48 8b 00 mov %fs:(%rax),%rax\n",
            )


if __name__ == "__main__":
    unittest.main()
