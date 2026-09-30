"""Compose the installed compiler-helper proof without broadening ABI closure."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
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
            'source_object_sha256': 'a' * 64,
            'source_calls': [{'section': '.text.caller', 'offset': 4}],
            'final_links': {
                mode: {'provider_address': 0x1000, 'resolved_calls': [
                    {'section': '.text.caller', 'offset': 4,
                     'call_address': 0x2000, 'target_address': 0x1000}],
                       'discarded_calls': []}
                for mode in ('static', 'static-pie', 'shared-libc')
            },
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
        self.assertEqual(result['installed_links']['status'], 'pending')

    def test_installed_links_cannot_be_supplied_without_the_aggregate(self):
        with self.assertRaises(selection.SelectionError):
            selection.compiler_helper_adapter(None, ordinary_report_path=None, paths=self.paths,
                                              installed_links={'static': self.report})

    def test_shared_placement_covers_the_complete_helper_contract_roster(self):
        contract = helpers.load_contract(ROOT)
        names = helpers.helper_names(contract)
        metadata = {key: helpers.HELPER_METADATA[key] for key in ('type', 'binding', 'visibility')}
        shared = {key: contract['shared_libc'][key] for key in ('type', 'binding', 'visibility')}
        records = [{
            'identity': selection.identity(name),
            'selection': {'group': selection.COMPILER_HELPER_GROUP,
                          'disposition': 'private-provider', 'owner': 'builtins'},
            'expected_placements': [
                {'artifact_key': placement, 'metadata_rule': 'explicit', 'metadata': metadata}
                for placement in helpers.ARCHIVE_PLACEMENTS],
        } for name in names]
        projection = {name: {'table': '.symtab', 'row_index': index,
                            'section_index': 1, 'section': '.text', 'metadata': shared}
                      for index, name in enumerate(names)}
        with mock.patch.object(selection, '_compiler_helper_shared_contract', return_value=(contract, {}, shared)), \
                mock.patch.object(selection, '_validated_compiler_helper_shared_projection', return_value=projection):
            pending = selection.attach_compiler_helper_shared_placement(records, {}, {}, {})
            self.assertEqual({row['identity']['name'] for row in pending}, set(names))
            self.assertTrue(all(row['expected_placements'][-1]['artifact_key'] ==
                                selection.COMPILER_HELPER_SHARED_ARTIFACT for row in records))
            with self.assertRaisesRegex(selection.SelectionError, 'identity differs'):
                selection.attach_compiler_helper_shared_placement(records[:-1], {}, {}, {})

    def test_product_reader_rejection_stays_at_the_selection_boundary(self):
        error = selection.product_evidence.ProductEvidenceError('retained linkage differs')
        with mock.patch.object(helpers, 'validate_supplied_product_evidence', side_effect=error):
            with self.assertRaisesRegex(selection.SelectionError, 'retained linkage differs'):
                self.adapter(self.report)

    def test_cli_forwards_each_installed_receipt_and_rejects_missing_or_duplicate_modes(self):
        arguments = ['build-report', '--measurement-checkout', str(ROOT), '--base-inventory', str(self.report),
                     '--elf-facts', str(self.report), '--static-product', str(self.work),
                     '--dynamic-product', str(self.work), '--static-preparation', str(self.report),
                     '--compiler-helper-aggregate-report', str(self.report), '--crt-startup-report', str(self.report),
                     '--output', str(self.work / 'selection.json')]
        modes = ('static', 'static-pie', 'pie', 'non-pie')
        installed = [value for mode in modes for value in
                     ('--compiler-helper-installed-link', mode, str(self.work / (mode + '.json')))]
        result = {'identities': [], 'occurrences': [], 'closure': {'blockers': [], 'complete': False}}
        with mock.patch.object(selection, 'build_report', return_value=result) as build:
            self.assertEqual(selection.main(arguments + installed), 0)
        self.assertEqual(build.call_args.kwargs['compiler_helper_installed_links'],
                         {mode: self.work / (mode + '.json') for mode in modes})
        self.assertEqual(build.call_args.kwargs['crt_startup_report'], self.report)
        for malformed in (installed[:-3], installed[:-3] + installed[:3]):
            with self.subTest(arguments=malformed), mock.patch.object(selection, 'build_report') as build:
                with self.assertRaises(SystemExit):
                    selection.main(arguments + malformed)
                build.assert_not_called()

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

    def test_changed_final_target_or_missing_shared_call_cannot_discharge_import(self):
        for change in ('foreign-target', 'missing-shared-call', 'duplicate-source-call'):
            account = supplied_account()
            claim = account['ordinary_popcount_import']
            if change == 'foreign-target':
                claim['final_links']['static']['resolved_calls'][0]['target_address'] = 0x3000
            elif change == 'missing-shared-call':
                claim['final_links']['shared-libc']['resolved_calls'] = []
            else:
                claim['source_calls'].append(copy.deepcopy(claim['source_calls'][0]))
            with self.subTest(change=change), self.assertRaises(selection.SelectionError):
                selection.attach_compiler_helper_import(import_accounting(), {'account': account})


@unittest.skipUnless(os.environ.get('CRABC_COMPILER_SELECTOR_COHORT'),
                     'requires a genuine same-source supplied compiler product cohort')
class SuppliedCompilerHelperAdapterPhysicalTests(unittest.TestCase):
    def test_complete_installed_calls_and_counterfeit_controls(self):
        prefix = ROOT / os.environ['CRABC_COMPILER_SELECTOR_COHORT']
        self.assertTrue(prefix.is_relative_to(ROOT / '.work/x86_64'))
        paths = {key: Path(str(prefix) + suffix) for key, suffix in (
            ('base_inventory', '-inventory/report.json'), ('elf_report', '-elf-facts/report.json'),
            ('static_preparation', '-static/preparation.json'), ('static_product', '-static/products/primary'),
            ('dynamic_product', '-dynamic'),
        )}
        paths['measurement_checkout'] = ROOT
        links = {mode: Path(str(prefix) + '-links/' + mode +
                            ('.json' if mode in {'static', 'static-pie'} else '.crabc-link.json'))
                 for mode in ('static', 'static-pie', 'pie', 'non-pie')}
        arguments = dict(report_path=Path(str(prefix) + '-aggregate/report.json'),
                         ordinary_report_path=None, paths=paths, installed_links=links,
                         crt_startup_report=Path(str(prefix) + '-startup/report.json'))
        complete = selection.compiler_helper_adapter(**arguments)['installed_links']
        self.assertEqual(complete['status'], 'verified')
        names = set(helpers.helper_names(helpers.load_contract(ROOT)))
        for mode in links:
            proof = complete['links'][mode]['proof']
            self.assertEqual(set(proof['transfers']), names)
            self.assertTrue(all(row['resolved_calls'] and row['provider_closure']['code']
                                for row in proof['transfers'].values()))
        for replacement in ({key: value for key, value in links.items() if key != 'non-pie'},
                            {**links, 'static': links['static-pie']}):
            with self.subTest(receipts=replacement), self.assertRaises(selection.SelectionError):
                selection.compiler_helper_adapter(**{**arguments, 'installed_links': replacement})
        with self.assertRaises(selection.SelectionError):
            selection.compiler_helper_adapter(**{**arguments, 'crt_startup_report': None})

        parent = ROOT / '.work/x86_64/compiler-selector-controls'
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as temporary:
            work = Path(temporary)
            record = json.loads(links['static'].read_text())
            original = ROOT / record['output']['path'].removeprefix('/workspace/')
            before = hashlib.sha256(original.read_bytes()).hexdigest()
            executable = work / 'static'
            receipt = work / 'static.json'
            shutil.copy2(original, executable)
            for key in ('map', 'trace'):
                shutil.copy2(links['static'].parent / record[key]['path'], work / record[key]['path'])
            record['output']['path'] = '/workspace/' + executable.relative_to(ROOT).as_posix()
            receipt.write_text(json.dumps(record))
            copied = {**links, 'static': receipt}
            self.assertEqual(selection.compiler_helper_adapter(**{**arguments, 'installed_links': copied})
                             ['installed_links']['status'], 'verified')
            binary = executable.read_bytes()
            elf = helpers.Elf(executable)
            transfer = complete['links']['static']['proof']['transfers']['__divti3']
            controls = (('provider-code', transfer['provider_address'], 1, b'\x00', 'provider code bytes'),
                        ('foreign-call', transfer['resolved_calls'][0]['call_address'] + 1, 4,
                         b'\x00\x00\x00\x00', 'foreign provider'))
            for label, address, size, changed, error in controls:
                segment = next(row for row in elf.programs if row[0] == 1
                               and row[3] <= address and address + size <= row[3] + row[5])
                offset = segment[2] + address - segment[3]
                mutated = bytearray(binary)
                mutated[offset:offset + size] = changed
                executable.write_bytes(mutated)
                record['output']['sha256'] = hashlib.sha256(mutated).hexdigest()
                receipt.write_text(json.dumps(record))
                with self.subTest(control=label), self.assertRaisesRegex(selection.SelectionError, error):
                    selection.compiler_helper_adapter(**{**arguments, 'installed_links': copied})
            self.assertEqual(hashlib.sha256(original.read_bytes()).hexdigest(), before)


if __name__ == '__main__':
    unittest.main()
