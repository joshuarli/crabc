#!/usr/bin/env python3
"""Regression coverage for exact ELF syscall alias identity checks."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_DIR))

from owned_syscall_alias_contract_reader import SymbolRow, same_definition


class OwnedSyscallAliasContractReaderTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
