#!/usr/bin/env python3
"""Finite selector guards for the loader structural-owner component receipt."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import native_abi_selection as selection

NAMES = selection.LOADER_STRUCTURAL_OWNER_IDENTITIES
REQUIREMENT = selection.LOADER_STRUCTURAL_OWNER_REQUIREMENT


class LoaderStructuralOwnerPolicyTests(unittest.TestCase):
    def _accounting(self):
        contract = selection.load_contract(selection.CONTRACT_PATH)
        inputs = selection.load_source_inputs(contract, selection.CONTRACT_PATH)
        records = [copy.deepcopy(row) for row in selection.expand_obligations(contract, inputs)
                   if row['identity']['name'] in NAMES]
        blockers = [{'code': 'identity-unresolved', 'identity': copy.deepcopy(row['identity']),
                     'reason': REQUIREMENT} for row in records]
        return {'identities': records, 'placement_joins': [], 'occurrences': [], 'blockers': blockers}

    def _companion(self, *, count=0, unnamed=0):
        return {
            'status': 'loader-structural-owner-observed-with-boundaries', 'reader': {}, 'report': {},
            'source': {}, 'products': {}, 'measurement_reports': {}, 'limits': list(selection.LOADER_STRUCTURAL_OWNER_LIMITS),
            'receipt': {'coverage': {'identities': list(NAMES), 'fact_filter': {
                'full_occurrence_count': count, 'unnamed_occurrence_count': unnamed,
            }}},
        }

    def test_missing_receipt_preserves_all_eight_existing_requirements(self):
        accounting = self._accounting()
        self.assertEqual(selection.attach_loader_structural_owner(accounting, None), [])
        self.assertEqual([row['unresolved'] for row in accounting['identities']], [[REQUIREMENT]] * 8)
        self.assertEqual(len(accounting['blockers']), 8)

    def test_exact_receipt_discharges_only_the_eight_structural_rows(self):
        accounting = self._accounting()
        raw_before = copy.deepcopy(accounting['occurrences'])
        joins = selection.attach_loader_structural_owner(accounting, self._companion())
        self.assertEqual(len(joins), 1)
        self.assertEqual([row['identity']['name'] for row in joins[0]['identities']], list(NAMES))
        self.assertEqual([row['unresolved'] for row in accounting['identities']], [[]] * 8)
        self.assertEqual(accounting['blockers'], [])
        self.assertEqual(accounting['occurrences'], raw_before)

    def test_partial_extra_or_wrong_raw_accounting_is_rejected(self):
        for label, change in (
            ('partial', lambda companion: companion['receipt']['coverage']['identities'].pop()),
            ('extra', lambda companion: companion['receipt']['coverage']['identities'].append('foreign')),
            ('wrong-count', lambda companion: companion['receipt']['coverage']['fact_filter'].__setitem__('full_occurrence_count', 1)),
        ):
            with self.subTest(label=label):
                accounting = self._accounting()
                companion = self._companion()
                change(companion)
                with self.assertRaises(selection.SelectionError):
                    selection.attach_loader_structural_owner(accounting, companion)

    def test_unrelated_raw_row_is_preserved_and_must_match_receipt_count(self):
        accounting = self._accounting()
        accounting['occurrences'].append({'index': 41, 'artifact_key': 'candidate-static', 'table': '.symtab',
                                           'role': 'definition', 'row': {'name': None}})
        with self.assertRaises(selection.SelectionError):
            selection.attach_loader_structural_owner(accounting, self._companion(count=1, unnamed=0))
        joins = selection.attach_loader_structural_owner(accounting, self._companion(count=1, unnamed=1))
        self.assertEqual(joins[0]['complete_elf_occurrence_count'], 1)
        self.assertEqual(accounting['occurrences'][0]['index'], 41)


if __name__ == '__main__':
    unittest.main()
