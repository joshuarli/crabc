#!/usr/bin/env python3
"""Regression guards for the finite headers/layouts family admission."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import native_abi_selection as selection


REPORT = ROOT / 'compat/x86_64/generated/headers_layouts_aggregate/report.json'
# The adapter reconstructs the report's inputs and rejects stale or modified
# reports below; the digest here only names the checked-in report.
REPORT_SHA256 = hashlib.sha256(REPORT.read_bytes()).hexdigest()
FAMILY = 'libc.headers-layouts'
BASE_REPORT = (ROOT.parent / 'resolver_alias_selector_integration/.work/x86_64/native-abi-selection/'
               'clean-36642df1/report.json')
BASE_REPORT_SHA256 = 'f1c8a46ad6b2918b5951979b1c7b74aa84bb667f725bc22d24e75d6a656e2d34'


class HeadersLayoutsAggregateAttachmentTests(unittest.TestCase):
    """Admit only the current aggregate into its one family-evidence row."""

    def _report(self) -> dict[str, object]:
        self.assertTrue(REPORT.is_file())
        self.assertEqual(hashlib.sha256(REPORT.read_bytes()).hexdigest(), REPORT_SHA256)
        return json.loads(REPORT.read_text(encoding='utf-8'))

    def _temporary_report(self, report: dict[str, object]) -> Path:
        parent = ROOT / '.work/x86_64/headers-layouts-aggregate-attachment-tests'
        parent.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / 'report.json'
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        return path

    def _adapter_at(self, report: dict[str, object]):
        path = self._temporary_report(report)
        with mock.patch.object(selection.headers_layouts_aggregate, 'REPORT_PATH', path):
            return selection.headers_layouts_aggregate_adapter(path)

    def test_current_report_is_the_exact_positive_headers_only_companion(self) -> None:
        report = self._report()
        companion = selection.headers_layouts_aggregate_adapter(REPORT)
        self.assertIsNotNone(companion)
        assert companion is not None
        self.assertEqual(companion['status'], 'headers-layouts-aggregate-observed-with-boundaries')
        self.assertEqual(companion['report'], selection.selecting_source_file_identity(REPORT))
        self.assertEqual(companion['result']['schema'], report['schema'])
        self.assertEqual(companion['result']['family'], FAMILY)
        self.assertTrue(companion['result']['family_completion'])
        self.assertFalse(companion['result']['promotion_ready'])
        self.assertFalse(companion['result']['public_support'])
        self.assertIn('runtime-semantics', companion['result']['explicit_nonrequirements'])
        self.assertIn('final-provider-archive-closure', companion['result']['explicit_nonrequirements'])

    def _ordinary_boundary(self):
        reviewed = selection.callable_declarations.REVIEWED_CPP_LINKAGE_DIFFERENCE
        classification = {**copy.deepcopy(reviewed), 'disposition': 'oracle-declared-no-provider',
                          'reference_job_indices': [4, 5]}
        joins = []
        for index, profile in enumerate(reviewed['profiles']):
            joins.append({
                'ordinary_job_ordinal': index + 20, 'boundary_job_index': index + 4,
                'observation': {
                    'ordinal': index + 20, 'tree': 'reference', 'header': reviewed['header'],
                    'profile': profile, 'category': 'reference-backed',
                    'expected_symbol': reviewed['candidate_symbol'],
                    'holder': 'crabc_native_declaration_abi_reference_0',
                    'observed_symbol': reviewed['reference_symbol'],
                    'relocation_type': 'R_X86_64_64', 'status': 'ordinary-linkage-identity-mismatch',
                },
            })
        return {'classification': classification, 'ordinary_job_joins': joins}

    def test_reviewed_header_rows_join_exact_original_ordinary_linkage_observations(self):
        companion = selection.headers_layouts_aggregate_adapter(REPORT)
        rows = self._report()['reviewed_cpp_linkage_differences']
        self.assertEqual(companion['result']['reviewed_cpp_linkage_differences'], rows)
        boundary = self._ordinary_boundary()
        retained = copy.deepcopy(boundary)
        joined = selection.reviewed_cpp_header_linkage_joins(companion, boundary)
        self.assertEqual([row['profile'] for row in joined], [row['profile'] for row in rows])
        self.assertEqual([row['header_difference'] for row in joined], rows)
        self.assertEqual([row['ordinary_job_join'] for row in joined], boundary['ordinary_job_joins'])
        self.assertEqual(boundary, retained)
        self.assertIsNone(selection.reviewed_cpp_header_linkage_joins(None, boundary))
        self.assertIsNone(selection.reviewed_cpp_header_linkage_joins(companion, None))

    def test_header_linkage_crossjoin_rejects_tampered_rows_signatures_and_ordinary_jobs(self):
        companion = selection.headers_layouts_aggregate_adapter(REPORT)
        boundary = self._ordinary_boundary()
        for change in ('signature', 'raw row', 'index', 'report', 'profile', 'duplicate',
                       'classification', 'ordinary symbol', 'ordinary header', 'ordinary ordinal',
                       'ordinary duplicate', 'ordinary missing'):
            with self.subTest(change=change):
                header, ordinary = copy.deepcopy(companion), copy.deepcopy(boundary)
                rows = header['result']['reviewed_cpp_linkage_differences']
                jobs = ordinary['ordinary_job_joins']
                if change == 'signature': rows[0]['reference_signature'] = rows[0]['candidate_signature']
                elif change == 'raw row': rows[0]['declaration_row']['row']['source_form_comparison'] = 'matched'
                elif change == 'index': rows[0]['prototype_row']['index'] += 1
                elif change == 'report': rows[0]['prototype_row']['report'] = rows[0]['declaration_row']['report']
                elif change == 'profile': rows[0]['profile'] = 'c11-gnu'
                elif change == 'duplicate': rows[1] = copy.deepcopy(rows[0])
                elif change == 'classification': ordinary['classification']['reference_symbol'] = 'membarrier'
                elif change == 'ordinary symbol': jobs[0]['observation']['observed_symbol'] = 'membarrier'
                elif change == 'ordinary header': jobs[0]['observation']['header'] = 'other.h'
                elif change == 'ordinary ordinal': jobs[0]['ordinary_job_ordinal'] += 1
                elif change == 'ordinary duplicate': jobs[1] = copy.deepcopy(jobs[0])
                else: jobs.pop()
                with self.assertRaises(selection.SelectionError):
                    selection.reviewed_cpp_header_linkage_joins(header, ordinary)

    def test_missing_or_noncanonical_report_does_not_admit_the_family(self) -> None:
        self.assertIsNone(selection.headers_layouts_aggregate_adapter(None))
        with self.assertRaises(selection.SelectionError):
            selection.headers_layouts_aggregate_adapter(ROOT / '.work/x86_64/not-headers-layouts.json')
        copied_current_report = self._temporary_report(self._report())
        with self.assertRaisesRegex(selection.SelectionError, 'current physical source report'):
            selection.headers_layouts_aggregate_adapter(copied_current_report)

    def test_adapter_rejects_wrong_schema_stale_input_incomplete_extra_missing_and_nonheader_reports(self) -> None:
        cases = (
            ('schema', lambda report: report.__setitem__('schema', 'wrong'), 'schema'),
            ('stale-input', lambda report: report['inputs'][0].__setitem__('sha256', '0' * 64), 'input'),
            ('incomplete', lambda report: (report.__setitem__('family_completion', False),
                                            report['header_completion'].__setitem__('complete', False)), 'header'),
            ('extra', lambda report: report.__setitem__('unexpected', True), 'top-level'),
            ('missing', lambda report: report.pop('evidence'), 'top-level'),
            ('nonheader', lambda report: report.__setitem__('family', 'libc.posix-runtime'), 'family'),
        )
        for name, mutate, message in cases:
            with self.subTest(case=name):
                report = copy.deepcopy(self._report())
                mutate(report)
                with self.assertRaisesRegex(selection.SelectionError, message):
                    self._adapter_at(report)

    def test_adapter_rejects_a_report_changed_during_owner_output_validation(self) -> None:
        report = self._report()
        path = self._temporary_report(report)
        original_validate = selection.headers_layouts_aggregate.validate_report
        changed = False

        def validate_then_change(value):
            nonlocal changed
            original_validate(value)
            if not changed:
                changed = True
                path.write_text('{"changed":true}\n', encoding='utf-8')

        with mock.patch.object(selection.headers_layouts_aggregate, 'REPORT_PATH', path), \
             mock.patch.object(selection.headers_layouts_aggregate, 'validate_report', side_effect=validate_then_change), \
             self.assertRaisesRegex(selection.SelectionError, 'aggregate output drifted'):
            selection.headers_layouts_aggregate_adapter(path)

    def test_final_recheck_rejects_a_changed_closed_companion(self) -> None:
        companion = selection.headers_layouts_aggregate_adapter(REPORT)
        assert companion is not None
        changed = copy.deepcopy(companion)
        changed['result']['family_completion'] = False
        with self.assertRaisesRegex(selection.SelectionError, 'changed during final recheck'):
            selection._recheck_headers_layouts_aggregate(changed)

    def test_exact_family_evidence_replaces_only_the_headers_unavailable_blocker(self) -> None:
        companion = selection.headers_layouts_aggregate_adapter(REPORT)
        contract = selection.load_contract(selection.CONTRACT_PATH)
        inputs = selection.load_source_inputs(contract, selection.CONTRACT_PATH)
        without, without_evidence = selection.headers_layouts_family_evidence(inputs['families'], None)
        with_headers, evidence = selection.headers_layouts_family_evidence(inputs['families'], companion)
        self.assertEqual(without_evidence, [])
        self.assertEqual(len(without), 26)
        self.assertEqual(len(with_headers), 25)
        self.assertEqual(
            {row['family'] for row in without} - {row['family'] for row in with_headers}, {FAMILY}
        )
        self.assertEqual(evidence, [{
            'family': FAMILY,
            'status': 'headers-layouts-aggregate-attached',
            'requirements_discharged': ['family-semantic-evidence-unavailable'],
        }])
        self.assertTrue(all(row['family'] != FAMILY for row in with_headers))

    def test_header_only_helper_keeps_legacy_partial_rosters_without_text_evidence(self) -> None:
        blockers, evidence = selection.headers_layouts_family_evidence([
            {'id': FAMILY, 'status': 'planned'},
        ], None)
        self.assertEqual(blockers, [{
            'code': 'family-semantic-evidence-unavailable', 'family': FAMILY, 'ledger_status': 'planned',
        }])
        self.assertEqual(evidence, [])

    def test_actual_36642_accounting_loses_exactly_one_family_row_and_no_global_receipt(self) -> None:
        if not BASE_REPORT.is_file():
            self.skipTest('requires retained 36642 selection report')
        self.assertEqual(hashlib.sha256(BASE_REPORT.read_bytes()).hexdigest(), BASE_REPORT_SHA256)
        report = json.loads(BASE_REPORT.read_text(encoding='utf-8'))
        blockers = report['closure']['blockers']
        self.assertEqual(len(blockers), 341)
        family_rows = [row for row in blockers if row['code'] == 'family-semantic-evidence-unavailable']
        self.assertEqual(len(family_rows), 26)
        companion = selection.headers_layouts_aggregate_adapter(REPORT)
        contract = selection.load_contract(selection.CONTRACT_PATH)
        inputs = selection.load_source_inputs(contract, selection.CONTRACT_PATH)
        retained_rows, evidence = selection.headers_layouts_family_evidence(inputs['families'], companion)
        self.assertEqual(len(retained_rows), 25)
        removed = [row for row in family_rows if row['family'] == FAMILY]
        self.assertEqual(len(removed), 1)
        successor = [row for row in blockers if row not in removed]
        self.assertEqual(len(successor), 340)
        self.assertEqual(
            len([row for row in successor if row['code'] == 'semantic-receipts-missing']), 1
        )
        self.assertEqual(
            len([row for row in successor if row['code'] == 'family-receipts-missing']), 1
        )
        self.assertEqual(evidence[0]['family'], FAMILY)


if __name__ == '__main__':
    unittest.main()
