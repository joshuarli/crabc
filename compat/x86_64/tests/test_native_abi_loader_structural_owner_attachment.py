#!/usr/bin/env python3
"""Finite selector guards for the loader structural-owner component receipt."""
from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path
import sys
import unittest
from unittest import mock

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

class LoaderStructuralOwnerAdapterEntryTests(unittest.TestCase):
    """Exercise adapter replay, not only the final accounting join."""

    def _fixture(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT / '.work/x86_64/tmp')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        static, dynamic = root / 'static', root / 'dynamic'
        static.mkdir(); dynamic.mkdir()
        def write(path: Path, mode: int = 0o644) -> None:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(path.as_posix().encode())
            path.chmod(mode)
        for name, relative in selection.loader_structural_owner_evidence.STATIC_ROLES.items():
            write(static / relative, 0o755 if name == 'static_driver' else 0o644)
        for name, relative in selection.loader_structural_owner_evidence.DYNAMIC_ROLES.items():
            write(dynamic / relative, 0o755 if name in {'dynamic_driver', 'dynamic_loader'} else 0o644)
        preparation, inventory, full_facts, debug, registry = (root / name for name in
            ('preparation.json', 'inventory.json', 'facts.json', 'debug.json', 'registry.json'))
        for path in (preparation, inventory, full_facts, debug, registry):
            write(path)
        paths = {'static_product': static, 'dynamic_product': dynamic, 'static_preparation': preparation,
                 'base_inventory': inventory, 'elf_report': full_facts}
        products = selection._loader_structural_owner_product_identities(paths)
        source = {'revision': 'current', 'content_sha256': 'source', 'clean': True}
        selected = {'revision': 'current', 'tree': 'tree', 'source_sha256': 'source'}
        startup = []
        for name in selection.LOADER_STRUCTURAL_OWNER_IDENTITIES[:3]:
            for table in ('.dynsym', '.symtab'):
                startup.append({'name': name, 'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'DEFAULT',
                                'section_index': '1'})
        facts = {'artifacts': {
            'candidate-static': {'identity': products['static_libc']},
            'candidate-shared': {'identity': products['dynamic_libc']},
            'candidate-loader': {'identity': products['dynamic_loader']},
        }, 'facts': {'reference-shared': {'symbol_tables': [
            {'name': '.dynsym', 'rows': [row for row in startup if row['name'] in selection.LOADER_STRUCTURAL_OWNER_IDENTITIES[:3]]},
            {'name': '.symtab', 'rows': [row for row in startup if row['name'] in selection.LOADER_STRUCTURAL_OWNER_IDENTITIES[:3]]},
        ]}}}
        # Use exact table rows rather than a summary: reader flattening is the adapter's raw-schema boundary.
        facts['facts']['reference-shared']['symbol_tables'][0]['rows'] = [
            {'name': name, 'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'DEFAULT', 'section_index': '1'}
            for name in selection.LOADER_STRUCTURAL_OWNER_IDENTITIES[:3]]
        facts['facts']['reference-shared']['symbol_tables'][1]['rows'] = [
            {'name': name, 'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'DEFAULT', 'section_index': '1'}
            for name in selection.LOADER_STRUCTURAL_OWNER_IDENTITIES[:3]]
        reader = selection.loader_structural_owner_evidence
        inputs = {}
        for name in reader.INPUT_NAMES:
            if name in products:
                identity = products[name]
            else:
                identity = {'path': name, 'sha256': '0' * 64, 'size': 0, 'mode': 0o644}
            inputs[name] = {**identity, 'retained': f'retained/inputs/{name}'}
        projection = {'full_occurrence_count': 6, 'unnamed_occurrence_count': 0,
                      'named_identity_filter': list(reader.IDENTITIES), 'reference_startup_rows': 6,
                      'candidate_rows': []}
        report = {
            'schema': reader.SCHEMA, 'status': reader.STATUS, 'component': reader.COMPONENT, 'target': reader.TARGET,
            'collection': {}, 'selected_source': selected, 'collector': selected, 'inputs': inputs,
            'selected_products': {'static': inputs['static_libc'], 'dynamic_libc': inputs['dynamic_libc'],
                                  'dynamic_loader': inputs['dynamic_loader'], 'loader_debug': selection.file_identity(debug),
                                  'loader_runtime_registry': selection.file_identity(registry)},
            'static_preparation': products['static_preparation'], 'base_inventory': products['base_inventory'],
            'full_facts': products['full_facts'], 'source_contract': {},
            'source_cohort': {'relation': 'one-current-clean-source', 'identity': selected}, 'source_algorithm': {},
            'selected_runtime': {}, 'normal_consumer_matrix': {}, 'commands': {}, 'runtime': {}, 'artifacts': {},
            'coverage': {'identities': list(reader.IDENTITIES), 'groups': list(selection.LOADER_STRUCTURAL_OWNER_GROUPS),
                         'fact_filter': projection, 'source_functions': [], 'selected_runtime_cells': [],
                         'normal_consumer_cells': [], 'normal_consumer_pairs': []},
            'limits': {'family_completion': False, 'promotion_ready': False, 'public_support': False,
                       'runtime_qualification': False, 'selector_admission': False},
        }
        report_path = root / 'report.json'
        report_path.write_text(json.dumps(report, sort_keys=True) + '\n', encoding='utf-8')
        measurement = {'candidate_build': {'revision': 'current', 'source_content_sha256': 'source'},
                       'reports': {name: selection.file_identity(paths[path]) for name, path in
                                   (('elf_report', 'elf_report'), ('base_inventory', 'base_inventory'),
                                    ('static_preparation', 'static_preparation'))}}
        return report_path, report, facts, measurement, paths, source, debug, registry

    def _adapter(self, fixture):
        report_path, report, facts, measurement, paths, source, debug, registry = fixture
        with mock.patch.object(selection.loader_structural_owner_evidence, 'validate_report', return_value=report) as replay:
            result = selection.native_loader_structural_owner_adapter(
                report_path, facts=facts, measurement=measurement, paths=paths, source=source,
                loader_debug_report=debug, loader_runtime_registry_report=registry)
        self.replay = replay
        return result

    def test_adapter_replays_the_raw_fact_schema_and_current_cohort(self):
        fixture = self._fixture()
        companion = self._adapter(fixture)
        assert companion is not None
        self.assertEqual(companion['receipt']['coverage']['fact_filter']['full_occurrence_count'], 6)
        self.assertEqual(companion['status'], 'loader-structural-owner-observed-with-boundaries')
        self.replay.assert_called_once()
        kwargs = self.replay.call_args.kwargs
        self.assertEqual(kwargs['static_product'], fixture[4]['static_product'])
        self.assertEqual(kwargs['dynamic_product'], fixture[4]['dynamic_product'])
        self.assertEqual(kwargs['full_facts'], fixture[4]['elf_report'])

    def test_adapter_rejects_absent_stale_report_or_product_substitution(self):
        fixture = self._fixture()
        report_path, report, facts, measurement, paths, source, debug, registry = fixture
        self.assertIsNone(selection.native_loader_structural_owner_adapter(
            None, facts=facts, measurement=measurement, paths=paths, source=source,
            loader_debug_report=debug, loader_runtime_registry_report=registry))
        report['selected_source']['source_sha256'] = 'stale'
        report_path.write_text(json.dumps(report, sort_keys=True) + '\n', encoding='utf-8')
        with self.assertRaisesRegex(selection.SelectionError, 'source differs'):
            self._adapter(fixture)
        report['selected_source']['source_sha256'] = 'source'
        report['collector']['source_sha256'] = 'source'
        report['inputs']['static_libc']['sha256'] = 'f' * 64
        report_path.write_text(json.dumps(report, sort_keys=True) + '\n', encoding='utf-8')
        with self.assertRaisesRegex(selection.SelectionError, 'static_libc bytes or mode differ'):
            self._adapter(fixture)
        fixture = self._fixture()
        report_path, report, facts, measurement, paths, source, debug, registry = fixture
        with mock.patch.object(selection.loader_structural_owner_evidence, 'validate_report',
                               side_effect=selection.loader_structural_owner_evidence.LoaderStructuralOwnerError('replay failed')):
            with self.assertRaisesRegex(selection.SelectionError, 'component rejected: replay failed'):
                selection.native_loader_structural_owner_adapter(
                    report_path, facts=facts, measurement=measurement, paths=paths, source=source,
                    loader_debug_report=debug, loader_runtime_registry_report=registry)
        fixture = self._fixture()
        report_path, report, facts, measurement, paths, source, debug, registry = fixture
        def replay_then_mutate(*_args, **_kwargs):
            report_path.write_text('{"changed":true}\n', encoding='utf-8')
            return report
        with mock.patch.object(selection.loader_structural_owner_evidence, 'validate_report',
                               side_effect=replay_then_mutate):
            with self.assertRaisesRegex(selection.SelectionError, 'report changed during replay'):
                selection.native_loader_structural_owner_adapter(
                    report_path, facts=facts, measurement=measurement, paths=paths, source=source,
                    loader_debug_report=debug, loader_runtime_registry_report=registry)
