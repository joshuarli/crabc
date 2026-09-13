#!/usr/bin/env python3
"""Regression coverage for exact ELF syscall alias identity checks."""

from __future__ import annotations

import sys
import unittest
import json
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_DIR))

from owned_syscall_alias_contract_reader import (
    ALIASES,
    CURRENT_COMMAND_STEMS,
    GLOBAL_HIDDEN,
    LOCAL_BODIES,
    PUBLIC_ALIAS_SOURCE_CALLERS,
    ReceiptError,
    SymbolRow,
    component_projection,
    main,
    require_same_probe_object,
    same,
    same_definition,
    validate_report,
)


class OwnedSyscallAliasContractReaderTests(unittest.TestCase):
    def test_oracle_source_recompile_cannot_pass_same_object_evidence(self) -> None:
        object_path = "/workspace/.work/probe/contract.o"
        commands = {
            f"{prefix}-contract-link": ["cc", object_path, "-o", f"/out/{prefix}"]
            for prefix in (
                "oracle", "oracle-dynamic-pie", "oracle-dynamic-non-pie",
                "static", "static-pie", "dynamic-pie", "dynamic-non-pie",
            )
        }
        require_same_probe_object("contract", object_path, commands)
        for replacement in ("/source/contract.c", "/elsewhere/contract.o"):
            with self.subTest(replacement=replacement):
                changed = dict(commands)
                changed["oracle-contract-link"] = ["cc", replacement, "-o", "/out/oracle"]
                with self.assertRaisesRegex(ValueError, "same compiled probe object"):
                    require_same_probe_object("contract", object_path, changed)
        commands.pop("oracle-dynamic-non-pie-contract-link")
        with self.assertRaisesRegex(ValueError, "incomplete or additional probe links"):
            require_same_probe_object("contract", object_path, commands)

    def test_same_member_zero_value_different_sections_is_not_an_alias(self) -> None:
        alias = SymbolRow(
            member="clock_gettime.o",
            value="0000000000000000",
            symbol_type="FUNC",
            binding="WEAK",
            visibility="DEFAULT",
            section="17",
            name="clock_gettime",
        )
        forwarding_body = alias._replace(
            binding="GLOBAL",
            section="18",
            name="__clock_gettime",
        )

        self.assertFalse(same_definition(alias, forwarding_body))

    def test_public_source_caller_roster_includes_both_sigset_branches(self) -> None:
        self.assertEqual(
            PUBLIC_ALIAS_SOURCE_CALLERS,
            (
                ("__fxstat", "fstat"),
                ("__fxstatat", "fstatat"),
                ("ftime", "clock_gettime"),
                ("getloadavg", "sysinfo"),
                ("sigignore", "sigaction"),
                ("siginterrupt", "sigaction"),
                ("sigset", "sigaction"),
            ),
        )

    def test_component_projection_keeps_private_and_source_local_bodies_distinct(self) -> None:
        self.assertEqual(len(ALIASES), 14)
        self.assertEqual(len(GLOBAL_HIDDEN), 13)
        self.assertEqual(LOCAL_BODIES, ("__statfs", "__fstatfs"))
        self.assertIn("__libc_sigaction", GLOBAL_HIDDEN)

    def test_collect_rejects_an_unbound_elf_input_boundary(self) -> None:
        self.assertEqual(main(["collect"]), 2)

    def test_component_projection_survives_json_round_trip(self) -> None:
        projection = component_projection()
        self.assertTrue(same(json.loads(json.dumps(projection)), projection))

    def test_current_runner_envelope_roster_is_fixed_at_forty_seven(self) -> None:
        self.assertEqual(len(CURRENT_COMMAND_STEMS), 47)
        self.assertEqual(len(set(CURRENT_COMMAND_STEMS)), 47)
        self.assertIn("probe-object-link-proof", CURRENT_COMMAND_STEMS)
        self.assertIn("dynamic-non-pie-override-direct", CURRENT_COMMAND_STEMS)

    def test_review_forged_receipt_is_rejected_after_json_normalization(self) -> None:
        report = SOURCE_DIR.parents[1] / ".work/x86_64/receipt-review/forged-receipt-5ci97ja5/report.json"
        with self.assertRaises(ReceiptError):
            validate_report(report)


if __name__ == "__main__":
    unittest.main()
