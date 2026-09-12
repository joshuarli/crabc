#!/usr/bin/env python3
"""Regression coverage for exact ELF pthread/C11 alias identity checks."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_DIR))

from owned_pthread_alias_contract_reader import SymbolRow, same_definition


class OwnedPthreadAliasContractReaderTests(unittest.TestCase):
    def test_same_member_zero_value_different_sections_is_not_an_alias(self) -> None:
        alias = SymbolRow(
            member="pthread_mutex_lock.o",
            value="0000000000000000",
            symbol_type="FUNC",
            binding="WEAK",
            visibility="DEFAULT",
            section="17",
            name="pthread_mutex_lock",
        )
        forwarding_body = alias._replace(
            binding="GLOBAL",
            section="18",
            name="__pthread_mutex_lock",
        )

        self.assertFalse(same_definition(alias, forwarding_body))


if __name__ == "__main__":
    unittest.main()
