from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import native_abi_selection as selection
import abi_differential_evidence as evidence
import owned_math_fenv_all_entry_receipt as math
import owned_stdio_component_receipt as stdio
import owned_signal_process_evidence as signal_process
import owned_posix_native_observations as bootstrap


class ComponentAttachmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        contract = selection.load_contract()
        inputs = selection.load_source_inputs(contract, selection.CONTRACT_PATH)
        cls.records = {row['identity']['name']: row for row in selection.expand_obligations(contract, inputs)}

    def setUp(self):
        parent = ROOT / '.work/tmp'
        parent.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.paths = {'static_product': self.work / 'static', 'dynamic_product': self.work / 'dynamic'}
        for path in self.paths.values():
            path.mkdir()
        common = mock.patch.object(selection, '_common_checkout', return_value=ROOT)
        common.start()
        self.addCleanup(common.stop)

    def accounting(self, names):
        records = [copy.deepcopy(self.records[name]) for name in names]
        return {'identities': records, 'placement_joins': [], 'occurrences': [],
                'blockers': [{'code': 'identity-unresolved', 'identity': row['identity'], 'reason': reason}
                             for row in records for reason in row['unresolved']] + [{'code': 'unrelated'}]}

    def test_math_joins_only_three_structural_requirements_and_retains_full_facts(self):
        names = ('__invtrigl_R', '__pio2_hi', '__pio2_lo')
        accounting = self.accounting((*names, 'pow10l'))
        accounting['occurrences'] = [{'index': 0, 'artifact_key': 'reference-static',
                                      'row': {'name': '__pio2_lo'}},
                                     {'index': 1, 'artifact_key': 'candidate-static', 'row': {'name': ''}}]
        before = copy.deepcopy(accounting)
        joins = selection.attach_installed_math(accounting, {'report': {'sha256': 'a'}})
        self.assertEqual([row['identity']['name'] for row in joins], list(names))
        self.assertEqual(accounting['identities'][-1], before['identities'][-1])
        self.assertEqual(accounting['occurrences'], before['occurrences'])
        self.assertEqual(accounting['placement_joins'], before['placement_joins'])
        self.assertEqual(accounting['blockers'][-1], {'code': 'unrelated'})
        self.assertTrue(all(row['unresolved'] == [] for row in accounting['identities'][:3]))

    def test_structural_join_rejects_every_candidate_legacy_occurrence(self):
        for artifact in ('candidate-static', 'candidate-shared', 'candidate-loader'):
            for name, owner in (('__invtrigl_R', 'native-inverse-trig-owners'),
                                ('fopen64', 'largefile-fopen-macro'),
                                ('__sigsetjmp_tail', 'local-sigsetjmp-tail'),
                                ('__restore', 'native-signal-restorer')):
                with self.subTest(artifact=artifact, name=name):
                    accounting = self.accounting((name,))
                    accounting['occurrences'] = [{'index': 0, 'artifact_key': artifact, 'row': {'name': name}}]
                    with self.assertRaisesRegex(selection.SelectionError, 'legacy candidate occurrence'):
                        selection._component_structural_join(accounting, name=name, owner=owner,
                                                             sources=self.records[name]['selection']['sources'],
                                                             component='test', evidence={})

    def test_structural_join_rejects_a_different_selected_source_owner(self):
        for name in ('__invtrigl_R', '__pio2_hi', '__pio2_lo', 'fopen64', '__restore', '__sigsetjmp_tail'):
            with self.subTest(name=name):
                accounting = self.accounting((name,))
                selected = self.records[name]['selection']
                accounting['identities'][0]['selection']['sources'] = ['libc/src/c_abi.rs']
                with self.assertRaisesRegex(selection.SelectionError, 'selected structural identity differs'):
                    selection._component_structural_join(
                        accounting, name=name, owner=selected['owner'], sources=selected['sources'],
                        component='test', evidence={})

    def test_stdio_joins_once_with_independently_validated_text_receipt(self):
        row = stdio.fopen64_row(static=True)
        companion = {'fopen64_structural': row, 'report': {'sha256': 'b'}}
        accounting = self.accounting(('fopen64',))
        joins = selection.attach_installed_stdio(accounting, companion, text_joins=[])
        self.assertEqual(len(joins), 1)
        self.assertEqual(accounting['identities'][0]['unresolved'], [])
        text_joins = [{'identity': selection.identity('fopen64'), 'row': copy.deepcopy(row)}]
        self.assertEqual(selection.attach_installed_stdio(accounting, companion, text_joins=text_joins), [])
        text_joins[0]['row']['object_import'] = 'fopen64'
        with self.assertRaisesRegex(selection.SelectionError, 'evidence differ'):
            selection.attach_installed_stdio(accounting, companion, text_joins=text_joins)

    def restorer_accounting(self):
        accounting = self.accounting(('__restore', 'crabc_x86_64_signal_restorer'))
        for index, (artifact, binding) in enumerate((('candidate-static', 'GLOBAL'), ('candidate-shared', 'LOCAL'))):
            accounting['placement_joins'].append({
                'identity': selection.identity('crabc_x86_64_signal_restorer'), 'artifact_key': artifact,
                'placement_observed': True, 'definition_count': 1, 'occurrence_indices': [index],
            })
            accounting['occurrences'].append({
                'index': index, 'artifact_key': artifact, 'table': '.symtab',
                'row': {'name': 'crabc_x86_64_signal_restorer', 'type': 'FUNC', 'binding': binding,
                        'visibility': 'HIDDEN', 'section_index': '7'},
            })
        return accounting

    def test_signal_restorer_requires_both_exact_selected_hidden_placements(self):
        accounting = self.restorer_accounting()
        joins = selection.attach_signal_process(accounting, {'report': {'sha256': 'c'}})
        self.assertEqual(joins[0]['evidence']['provider_occurrence_indices'], [0, 1])
        self.assertEqual(accounting['identities'][0]['unresolved'], [])
        for field, value in (('binding', 'GLOBAL'), ('visibility', 'DEFAULT'), ('section_index', 'UND')):
            with self.subTest(field=field):
                accounting = self.restorer_accounting()
                accounting['occurrences'][1]['row'][field] = value
                with self.assertRaisesRegex(selection.SelectionError, 'full-facts occurrence differs'):
                    selection.attach_signal_process(accounting, {'report': {}})
        accounting = self.restorer_accounting()
        accounting['placement_joins'][0]['placement_observed'] = False
        with self.assertRaisesRegex(selection.SelectionError, 'selected placement differs'):
            selection.attach_signal_process(accounting, {'report': {}})

    def test_signal_restorer_preserves_four_undefined_caller_imports_and_their_blockers(self):
        accounting = self.restorer_accounting()
        provider = accounting['identities'][1]
        reason = 'exact ordinary import/provider or optional weak/null resolution proof is missing'
        provider['unresolved'].append(reason)
        blocker = {'code': 'identity-unresolved', 'identity': provider['identity'], 'reason': reason}
        accounting['blockers'].append(blocker)
        for index in range(2, 6):
            accounting['occurrences'].append({
                'index': index, 'artifact_key': 'candidate-static', 'table': '.symtab',
                'role': 'import', 'member_name': f'caller-{index}.o',
                'row': {'name': 'crabc_x86_64_signal_restorer', 'type': 'NOTYPE', 'binding': 'GLOBAL',
                        'visibility': 'DEFAULT', 'section_index': 'UND'},
            })
        before = copy.deepcopy(accounting)
        joins = selection.attach_signal_process(accounting, {'report': {}})
        self.assertEqual(joins[0]['evidence']['provider_occurrence_indices'], [0, 1])
        self.assertEqual(accounting['occurrences'], before['occurrences'])
        self.assertEqual(accounting['placement_joins'], before['placement_joins'])
        self.assertEqual(accounting['identities'][1], before['identities'][1])
        self.assertIn(blocker, accounting['blockers'])

    def test_signal_restorer_rejects_extra_definitions_and_exports(self):
        for artifact, table, binding, visibility in (
            ('candidate-static', '.symtab', 'GLOBAL', 'HIDDEN'),
            ('candidate-shared', '.dynsym', 'GLOBAL', 'DEFAULT'),
            ('candidate-loader', '.symtab', 'GLOBAL', 'HIDDEN'),
        ):
            with self.subTest(artifact=artifact, table=table):
                accounting = self.restorer_accounting()
                accounting['occurrences'].append({
                    'index': 2, 'artifact_key': artifact, 'table': table,
                    'row': {'name': 'crabc_x86_64_signal_restorer', 'type': 'FUNC', 'binding': binding,
                            'visibility': visibility, 'section_index': '7'},
                })
                with self.assertRaisesRegex(selection.SelectionError, 'unselected candidate definition'):
                    selection.attach_signal_process(accounting, {'report': {}})

    def test_bootstrap_joins_exact_source_owner_without_export(self):
        source = ROOT / 'libc/src/c_abi/x86_64/setjmp.rs'
        owner = {'path': source.relative_to(ROOT).as_posix(), 'sha256': bootstrap.digest(source),
                 'byte_length': source.stat().st_size}
        companion = {'result': {'source_owners': {'__sigsetjmp_tail': owner}}}
        accounting = self.accounting(('__sigsetjmp_tail',))
        joins = selection.attach_bootstrap_primitives(accounting, companion)
        self.assertEqual(joins[0]['evidence']['source_owner'], owner)
        self.assertEqual(accounting['placement_joins'], [])
        owner['sha256'] = '0' * 64
        with self.assertRaisesRegex(selection.SelectionError, 'source owner differs'):
            selection.attach_bootstrap_primitives(self.accounting(('__sigsetjmp_tail',)), companion)

    def feature(self):
        symbol = {'member_index': 1, 'member': 'math.o', 'section': '4', 'value': '0000000000000000',
                  'binding': 'GLOBAL', 'type': 'FUNC', 'visibility': 'DEFAULT'}
        return {'baseline_features': [], 'enabled_features': ['x86-math-long-double-completion'],
                'additions': ['exp10l', 'fdiml', 'pow10l'],
                'archive_symbols': {'exp10l': symbol, 'pow10l': {**symbol, 'binding': 'WEAK'}}}

    def test_pow10l_keeps_current_product_placement_blockers(self):
        accounting = self.accounting(('pow10l',))
        accounting['identities'][0]['unresolved'].append('missing selected provider placement')
        joins = selection.attach_binary80_feature(accounting, {'result': self.feature()}, installed_math={'report': {}})
        self.assertEqual(len(joins), 1)
        self.assertEqual(accounting['identities'][0]['unresolved'], ['missing selected provider placement'])
        with self.assertRaisesRegex(selection.SelectionError, 'requires current selected-product'):
            selection.attach_binary80_feature(self.accounting(('pow10l',)), {'result': self.feature()}, installed_math=None)

    def test_binary80_reader_rejects_profile_or_same_address_alias_drift(self):
        for field, value in (('baseline_features', ['x86-owned-static-runtime']),
                             ('enabled_features', []), ('additions', ['pow10l'])):
            feature = self.feature()
            feature[field] = value
            with mock.patch.object(math, 'validate_binary80_feature_work', return_value=feature):
                with self.assertRaisesRegex(selection.SelectionError, 'profile differs'):
                    selection.binary80_feature_adapter(self.work, paths=self.paths)
        feature = self.feature()
        feature['archive_symbols']['pow10l']['member_index'] = 2
        with mock.patch.object(math, 'validate_binary80_feature_work', return_value=feature):
            with self.assertRaisesRegex(selection.SelectionError, 'archive alias differs'):
                selection.binary80_feature_adapter(self.work, paths=self.paths)

    def test_leaf_adapters_forward_selected_products_and_reject_stale_proof(self):
        report_path = self.work / 'owned-math-fenv-all-entry.json'
        report_path.write_text('{}')
        result = {'scope': [], 'products': {}, 'seals': {}, 'source_objects': {}}
        with mock.patch.object(math, 'validate_report', return_value=(result, {})) as replay:
            selection.installed_math_adapter(self.work, paths=self.paths)
            replay.assert_called_once_with(ROOT, report_path, {'static': self.paths['static_product'],
                                                               'dynamic': self.paths['dynamic_product']})
        for adapter, reader, method in ((selection.installed_math_adapter, math, 'validate_report'),
                                        (selection.installed_stdio_adapter, stdio, 'validate_report'),
                                        (selection.signal_process_adapter, signal_process, 'validate_observations'),
                                        (selection.bootstrap_primitives_adapter, bootstrap, 'collect_bootstrap_primitives'),
                                        (selection.binary80_feature_adapter, math, 'validate_binary80_feature_work')):
            with self.subTest(adapter=adapter.__name__), mock.patch.object(reader, method, side_effect=RuntimeError('stale source or products')):
                with self.assertRaisesRegex(selection.SelectionError, 'stale source or products'):
                    adapter(self.work, paths=self.paths)

    def test_rejected_component_restores_partial_structural_discharges(self):
        accounting = self.accounting(('__invtrigl_R', '__pio2_hi', '__pio2_lo'))
        accounting['occurrences'] = [{'index': 0, 'artifact_key': 'candidate-static', 'row': {'name': '__pio2_lo'}}]
        before = copy.deepcopy(accounting)
        rejected = {}
        companion = {'report': {}}
        joins, admitted = selection._attach(
            rejected, 'installed_math_work', accounting, companion,
            lambda: selection.attach_installed_math(accounting, companion))
        self.assertEqual(joins, [])
        self.assertIsNone(admitted)
        self.assertIn('legacy candidate occurrence', rejected['installed_math_work'])
        self.assertEqual(accounting, before)

    def test_stdio_and_signal_adapters_require_exact_installed_cells(self):
        (self.work / 'report.json').write_text('{}')
        row = stdio.fopen64_row(static=True)
        result = {'products': {'static': str(self.paths['static_product']), 'dynamic': str(self.paths['dynamic_product'])},
                  'rows': {'stdio.fopen64-alias': row}}
        with mock.patch.object(stdio, 'validate_report', return_value=result) as replay:
            companion = selection.installed_stdio_adapter(self.work, paths=self.paths)
            replay.assert_called_once_with(self.work / 'report.json', ROOT, require_static=True)
            self.assertEqual(companion['fopen64_structural'], row)
        row['object_import'] = 'fopen64'
        with mock.patch.object(stdio, 'validate_report', return_value=result):
            with self.assertRaisesRegex(selection.SelectionError, 'structural boundary differs'):
                selection.installed_stdio_adapter(self.work, paths=self.paths)
        (self.work / 'signal-process-observations.json').write_text('{}')
        with mock.patch.object(signal_process, 'validate_observations', return_value={'observations': [{}] * 72}) as replay:
            selection.signal_process_adapter(self.work, paths=self.paths)
            self.assertEqual(replay.call_args.kwargs['static_product'], self.paths['static_product'])
            self.assertEqual(replay.call_args.kwargs['dynamic_product_path'], self.paths['dynamic_product'])
        with mock.patch.object(signal_process, 'validate_observations', return_value={'observations': [{}] * 48}):
            with self.assertRaisesRegex(selection.SelectionError, 'lacks six-mode observations'):
                selection.signal_process_adapter(self.work, paths=self.paths)

    def test_stdio_rejects_another_product_pair_after_leaf_replay(self):
        result = {'products': {'static': str(self.paths['static_product']), 'dynamic': '/other/product'}}
        with mock.patch.object(stdio, 'validate_report', return_value=result):
            with self.assertRaisesRegex(selection.SelectionError, 'another selected product pair'):
                selection.installed_stdio_adapter(self.work, paths=self.paths)

    def test_missing_companions_leave_accounting_unchanged(self):
        accounting = self.accounting(('__restore', '__sigsetjmp_tail', '__invtrigl_R', 'pow10l', 'fopen64'))
        before = copy.deepcopy(accounting)
        for attach in (selection.attach_installed_math, selection.attach_signal_process, selection.attach_bootstrap_primitives):
            self.assertEqual(attach(accounting, None), [])
        self.assertEqual(selection.attach_installed_stdio(accounting, None, text_joins=[]), [])
        self.assertEqual(selection.attach_binary80_feature(accounting, None, installed_math=None), [])
        self.assertEqual(accounting, before)

    def test_copied_loader_alias_hash_rejects_target_payload_and_unrelated_symlinks(self):
        library = self.work / 'execution/lib'
        library.mkdir(parents=True)
        loader = library / 'ld-crabc-x86_64.so.1'
        loader.write_bytes(b'selected loader')
        alias = library / 'ld-musl-x86_64.so.1'
        alias.symlink_to(loader.name)
        policy = ('lib/' + alias.name, loader.name, hashlib.sha256(loader.read_bytes()).hexdigest())
        evidence._tree_sha256(self.work, copied_loader=policy)
        with self.assertRaisesRegex(evidence.EvidenceError, 'non-physical entry'):
            evidence._tree_sha256(self.work)
        loader.write_bytes(b'wrong loader')
        with self.assertRaisesRegex(evidence.EvidenceError, 'non-physical entry'):
            evidence._tree_sha256(self.work, copied_loader=policy)
        loader.write_bytes(b'selected loader')
        extra = library / 'unrelated'
        extra.symlink_to(loader.name)
        with self.assertRaisesRegex(evidence.EvidenceError, 'non-physical entry'):
            evidence._tree_sha256(self.work, copied_loader=policy)


if __name__ == '__main__':
    unittest.main()
