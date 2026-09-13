"""Compose the installed compiler-helper proof without broadening ABI closure."""
import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import compiler_helper_evidence as helpers
import native_abi_selection as selection


def import_accounting():
    identity = {'name': '__popcountdi2', 'version': None, 'version_default': False}
    return {
        'identities': [{'identity': identity, 'selection': {'owner': 'builtins'},
                        'unresolved': [selection.ORDINARY_IMPORT_REASON, 'shared placement remains unselected']}],
        'occurrences': [{
            'index': 7, 'artifact_key': 'candidate-static', 'role': 'import',
            'member_name': 'allocator.o', 'member_index': 1, 'member_occurrence': 0,
            'table': '.symtab', 'row': {'name': '__popcountdi2', 'row_index': 979},
            'accounting': {'disposition': 'private-provider', 'owner': 'builtins', 'scope': 'candidate-static'},
        }],
        'blockers': [
            {'code': 'identity-unresolved', 'identity': identity, 'reason': selection.ORDINARY_IMPORT_REASON},
            {'code': 'identity-unresolved', 'identity': identity, 'reason': 'shared placement remains unselected'},
        ],
    }


def supplied_account():
    return {
        'aggregate_c_abi': {'status': 'joined'},
        'shared_placement_selected': False, 'family_completion': False, 'public_support': False,
        'ordinary_popcount_import': {
            'identity': '__popcountdi2', 'consumer_artifact': 'candidate-static',
            'consumer_member': 'allocator.o', 'consumer_member_index': 1,
            'consumer_member_occurrence': 0, 'consumer_symtab_row': 979,
            'provider_placement': 'static-builtins', 'provider_member': 'crabc-builtins.o',
            'provider_section': '.text.__popcountdi2',
        },
    }


class NativeAbiCompilerHelperTests(unittest.TestCase):
    def setUp(self):
        work = ROOT / '.work/x86_64/native-abi-helper-selection-tests'
        work.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=work)
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.report = self.work / 'report.json'
        self.report.write_text('{}\n')
        self.paths = {key: self.work / key for key in
                      ('base_inventory', 'elf_report', 'static_preparation', 'static_product', 'dynamic_product')}
        self.paths['measurement_checkout'] = ROOT
        patch = mock.patch.object(selection, '_common_checkout', return_value=ROOT)
        patch.start()
        self.addCleanup(patch.stop)

    def adapter(self, report, ordinary=None):
        return selection.compiler_helper_adapter(report, ordinary_report_path=ordinary, paths=self.paths)

    def test_absent_aggregate_does_not_open_a_component_or_discharge_an_import(self):
        with mock.patch.object(helpers, 'validate_supplied_product_evidence') as reader:
            self.assertIsNone(self.adapter(None))
        reader.assert_not_called()
        accounting = import_accounting()
        before = copy.deepcopy(accounting)
        self.assertEqual(selection.attach_compiler_helper_import(accounting, None), [])
        self.assertEqual(accounting, before)

    def test_component_reader_receives_exact_selected_products_and_retained_reports(self):
        ordinary = self.work / 'ordinary.json'
        with mock.patch.object(helpers, 'validate_supplied_product_evidence', return_value=supplied_account()) as reader:
            result = self.adapter(self.report, ordinary)
        reader.assert_called_once_with(root=ROOT, **{key: self.paths[key] for key in
            ('base_inventory', 'elf_report', 'static_preparation', 'static_product', 'dynamic_product')},
            ordinary_link_report=ordinary, aggregate_report=self.report)
        self.assertEqual(result['account'], supplied_account())
        self.assertEqual(result['report'], selection.file_identity(self.report))

    def test_changed_report_and_partial_or_promoted_component_are_rejected(self):
        def mutate(**_):
            self.report.write_text('{"changed":true}\n')
            return supplied_account()
        with mock.patch.object(helpers, 'validate_supplied_product_evidence', side_effect=mutate):
            with self.assertRaisesRegex(selection.SelectionError, 'changed'):
                self.adapter(self.report)
        for key, value in [('aggregate_c_abi', {'status': 'not-supplied-partial'}),
                           ('shared_placement_selected', True), ('family_completion', True), ('public_support', True)]:
            account = supplied_account()
            account[key] = value
            with self.subTest(key=key), mock.patch.object(helpers, 'validate_supplied_product_evidence', return_value=account):
                with self.assertRaises(selection.SelectionError):
                    self.adapter(self.report)

    def test_only_exact_static_import_is_discharged_and_shared_obligation_survives(self):
        accounting = import_accounting()
        joins = selection.attach_compiler_helper_import(accounting, {'account': supplied_account()})
        self.assertTrue(joins[0]['ordinary_link_covered'])
        self.assertEqual(joins[0]['occurrence_indices'], [7])
        self.assertEqual(accounting['identities'][0]['unresolved'], ['shared placement remains unselected'])
        self.assertEqual(len(accounting['blockers']), 1)

    def test_an_uncovered_candidate_import_or_changed_member_cannot_borrow_the_proof(self):
        for change in ('extra-shared', 'other-member', 'other-row', 'other-owner'):
            accounting = import_accounting()
            occurrence = accounting['occurrences'][0]
            if change == 'extra-shared':
                extra = copy.deepcopy(occurrence)
                extra.update(index=8, artifact_key='candidate-shared')
                accounting['occurrences'].append(extra)
            elif change == 'other-member':
                occurrence['member_name'] = 'different.o'
            elif change == 'other-row':
                occurrence['row']['row_index'] += 1
            else:
                occurrence['accounting']['owner'] = 'another-owner'
            with self.subTest(change=change):
                joins = selection.attach_compiler_helper_import(accounting, {'account': supplied_account()})
                self.assertFalse(joins[0]['ordinary_link_covered'])
                self.assertIn(selection.ORDINARY_IMPORT_REASON, accounting['identities'][0]['unresolved'])
                self.assertEqual(len(accounting['blockers']), 2)

    def test_aggregate_without_ordinary_receipt_cannot_discharge_imports(self):
        account = supplied_account()
        account['ordinary_popcount_import'] = None
        accounting = import_accounting()
        before = copy.deepcopy(accounting)
        self.assertEqual(selection.attach_compiler_helper_import(accounting, {'account': account}), [])
        self.assertEqual(accounting, before)


if __name__ == '__main__':
    unittest.main()
