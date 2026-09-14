#!/usr/bin/env python3
"""Policy and receipt-join guards for the finite resolver alias boundary."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import native_abi_selection as selection


PRIVATE_BODIES = ('__res_mkquery', '__res_send')
ALIASES = (
    ('res_mkquery', '__res_mkquery'),
    ('res_send', '__res_send'),
    ('res_search', 'res_query'),
)
PROTECTED_CONTROLS = ('res_query', 'res_querydomain')
GROUP = 'component-owned-resolver-private-bodies'
OWNER = 'x86-owned-resolver-private-bodies'
REQUIREMENT = 'current source-bound resolver alias/private-body receipt'
PRIVATE_SOURCES = [
    'libc/src/c_abi/x86_64/resolver_runtime.rs',
    'compat/x86_64/owned-resolver-alias-contract.md',
]
RECEIPT = (ROOT.parent / 'owned_resolver_alias_receipt/.work/x86_64/resolver-alias-receipt/'
           'clean-67a0c564/report.json')
COMPONENT_ROOT = ROOT.parent / 'owned_resolver_alias_receipt'
FACTS = (ROOT.parent / 'owned_resolver_alias_receipt/.work/x86_64/native-abi-elf-facts/'
         'clean-67a0c564/report.json')
INVENTORY = (ROOT.parent / 'owned_resolver_alias_receipt/.work/x86_64/native-abi-inventory/'
             'clean-67a0c564/report.json')
PREPARATION = (ROOT.parent / 'owned_resolver_alias_receipt/.work/x86_64/public-data-products/'
               'static-67a0c564/preparation.json')
STATIC_PRODUCT = PREPARATION.parent / 'products/primary'
LOADER_REPORT = (ROOT.parent / 'owned_resolver_alias_receipt/.work/x86_64/loader-debug-abi/'
                 'clean-67a0c564/component/report.json')
DYNAMIC_PRODUCT = LOADER_REPORT.parent / 'dynamic-product'
RECEIPT_SHA256 = 'dabde3568aa8eddb5ca19c690217fbf6e6afd288cc3eb91cf4ad8b6033a38e26'
FACTS_SHA256 = 'ffe0db14d7490be9069524c2cc9f7043edfef203db7f36ddf3b5b7b49e23a797'


class FrozenResolverReader:
    """Return the real frozen producer payload while recording adapter replay."""

    def __init__(self, report: dict[str, object], replay_result: dict[str, object] | None = None):
        self.report = report
        self.calls: list[tuple[Path, dict[str, object]]] = []
        self._reader = selection._resolver_alias_reader()
        projection = self._reader.validate_candidate_occurrences(
            report['observations']['candidate_occurrences']
        )
        expected_result = {
            'status': self._reader.STATUS,
            'coverage': copy.deepcopy(report['coverage']),
            'candidate_occurrence_count': projection['candidate_occurrence_count'],
            'full_occurrence_count': report['measurement_reports']['occurrence_count'],
            'unnamed_occurrence_count': report['measurement_reports']['unnamed_count'],
            'source_alias_routes': copy.deepcopy(report['source_alias_routes']),
        }
        self.result = copy.deepcopy(replay_result) if replay_result is not None else expected_result
        if replay_result is not None and replay_result != expected_result:
            raise AssertionError('frozen resolver reader result differs from its producer report')

    def __getattr__(self, name: str):
        return getattr(self._reader, name)

    def validate_report(self, report_path: Path, **kwargs: object) -> dict[str, object]:
        self.calls.append((report_path, kwargs))
        return copy.deepcopy(self.result)


class ResolverAliasOwnerPolicyTests(unittest.TestCase):
    """Keep private selection finite before a receipt can discharge it."""

    def test_two_private_bodies_have_only_the_explicit_receipt_owner_route(self) -> None:
        contract = selection.load_contract(selection.CONTRACT_PATH)
        inputs = selection.load_source_inputs(contract, selection.CONTRACT_PATH)
        records = {row['identity']['name']: row for row in selection.expand_obligations(contract, inputs)}

        for name in PRIVATE_BODIES:
            with self.subTest(name=name):
                record = records[name]
                self.assertEqual(record['selection']['disposition'], 'private-provider')
                self.assertEqual(record['selection']['group'], GROUP)
                self.assertEqual(record['selection']['owner'], OWNER)
                self.assertEqual(record['selection']['sources'], PRIVATE_SOURCES)
                self.assertEqual(record['unresolved'], [REQUIREMENT])
                self.assertEqual(record['expected_placements'], [
                    {
                        'artifact_key': 'candidate-static',
                        'metadata': {'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'HIDDEN'},
                        'metadata_rule': 'explicit',
                    },
                    {
                        'artifact_key': 'candidate-shared',
                        'metadata': {'type': 'FUNC', 'binding': 'LOCAL', 'visibility': 'HIDDEN'},
                        'metadata_rule': 'explicit',
                    },
                ])

        for name, _target in ALIASES:
            with self.subTest(public_alias=name):
                record = records[name]
                self.assertEqual(record['selection']['disposition'], 'public-provider')
                self.assertEqual(record['selection']['owner'], 'checked-header-provider-routing')
                self.assertEqual(record['unresolved'], [
                    'source-selected alias requires exact feature archive selection and component receipt',
                ])
                self.assertEqual(len(record['function_alias_requirements']), 1)
                self.assertEqual(
                    set(record['function_alias_requirements'][0]),
                    {
                        'name', 'target', 'binding', 'owner', 'state', 'evidence_record', 'runner',
                        'feature_selection_source', 'sources', 'baseline_features', 'enabled_features',
                    },
                )

        for name in PROTECTED_CONTROLS:
            with self.subTest(control=name):
                record = records[name]
                self.assertEqual(record['selection']['disposition'], 'public-provider')
                self.assertEqual(record['selection']['owner'], 'checked-header-provider-routing')
                self.assertEqual(record['unresolved'], [])


class ResolverAliasReceiptAttachmentTests(unittest.TestCase):
    """Exercise actual producer rows and the source-matched adapter boundary."""

    _frozen_reader_result: dict[str, object] | None = None

    @classmethod
    def _replay_frozen_component(cls) -> dict[str, object]:
        """Run the real reader in its clean receipt checkout once per suite.

        The selector worktree deliberately differs from the 67a0 component
        source, so this is retained producer evidence for composition rather
        than a current-source selector admission.
        """
        if cls._frozen_reader_result is not None:
            return copy.deepcopy(cls._frozen_reader_result)
        if not all(path.is_file() for path in (RECEIPT, FACTS, INVENTORY, PREPARATION, LOADER_REPORT)):
            raise unittest.SkipTest('requires the retained 67a0 resolver component cohort')
        script = '''
import json
from pathlib import Path
import sys

root = Path.cwd()
sys.path.insert(0, str(root / 'compat/x86_64'))
import owned_resolver_alias_contract_reader as reader

preparation = root / '.work/x86_64/public-data-products/static-67a0c564/preparation.json'
product_report = root / '.work/x86_64/loader-debug-abi/clean-67a0c564/component/report.json'
result = reader.validate_report(
    root / '.work/x86_64/resolver-alias-receipt/clean-67a0c564/report.json',
    root=root,
    static_product=preparation.parent / 'products/primary',
    dynamic_product=product_report.parent / 'dynamic-product',
    product_report=product_report,
    static_preparation=preparation,
    elf_facts=root / '.work/x86_64/native-abi-elf-facts/clean-67a0c564/report.json',
    base_inventory=root / '.work/x86_64/native-abi-inventory/clean-67a0c564/report.json',
)
print(json.dumps(result, sort_keys=True))
'''
        environment = dict(os.environ)
        environment['PYTHONDONTWRITEBYTECODE'] = '1'
        completed = subprocess.run(
            [sys.executable, '-c', script], cwd=COMPONENT_ROOT, env=environment,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )
        if completed.returncode != 0:
            raise AssertionError(completed.stderr)
        result = json.loads(completed.stdout)
        cls._frozen_reader_result = result
        return copy.deepcopy(result)

    def _actual_accounting_and_companion(self):
        if not all(path.is_file() for path in (RECEIPT, FACTS)):
            self.skipTest('requires the retained 67a0 resolver receipt and complete ELF facts')
        self.assertEqual(hashlib.sha256(RECEIPT.read_bytes()).hexdigest(), RECEIPT_SHA256)
        self.assertEqual(hashlib.sha256(FACTS.read_bytes()).hexdigest(), FACTS_SHA256)
        receipt = json.loads(RECEIPT.read_text())
        facts = json.loads(FACTS.read_text())
        contract = selection.load_contract(selection.CONTRACT_PATH)
        inputs = selection.load_source_inputs(contract, selection.CONTRACT_PATH)
        accounting = selection.account_placements(selection.expand_obligations(contract, inputs), facts)
        reader = selection._resolver_alias_reader()
        companion = {
            'status': 'resolver-alias-observed-with-boundaries',
            'reader': {}, 'report': {}, 'source': {}, 'products': {}, 'measurement_reports': {},
            'source_inputs': {
                name: selection.file_identity(ROOT / name)
                for name in selection._resolver_alias_source_files(reader)
            },
            'result': {
                'status': reader.STATUS, 'coverage': reader.coverage_projection(),
                'candidate_occurrence_count': 19, 'full_occurrence_count': 30667,
                'unnamed_occurrence_count': 1365, 'source_alias_routes': list(reader.SOURCE_ALIAS_ROUTES),
            },
            'receipt': {
                key: copy.deepcopy(receipt[key])
                for key in (
                    'collection', 'selected_source', 'collector', 'inputs', 'selected_products',
                    'static_preparation', 'product_input_modes', 'measurement_reports',
                    'source_alias_routes', 'observations', 'coverage',
                )
            },
            'limits': list(selection.RESOLVER_ALIAS_LIMITS),
        }
        return accounting, companion

    def test_policy_only_replaces_four_generic_private_reasons_with_two_receipt_reasons(self) -> None:
        if not FACTS.is_file():
            self.skipTest('requires the retained 67a0 complete ELF facts')
        facts = json.loads(FACTS.read_text())
        contract = selection.load_contract(selection.CONTRACT_PATH)
        contract['owner_groups'] = [
            group for group in contract['owner_groups'] if group['id'] != GROUP
        ]
        inputs = selection.load_source_inputs(contract, selection.CONTRACT_PATH)
        old_records = {
            row['identity']['name']: row
            for row in selection.account_placements(selection.expand_obligations(contract, inputs), facts)['identities']
        }
        self.assertEqual(
            [old_records[name]['unresolved'] for name in PRIVATE_BODIES],
            [
                ['candidate binding ownership is unresolved', 'candidate definition placement is not selected: candidate-static'],
                ['candidate binding ownership is unresolved', 'candidate definition placement is not selected: candidate-static'],
            ],
        )
        current_accounting, _companion = self._actual_accounting_and_companion()
        current = {row['identity']['name']: row for row in current_accounting['identities']}
        self.assertEqual([current[name]['unresolved'] for name in PRIVATE_BODIES], [[REQUIREMENT], [REQUIREMENT]])
        self.assertEqual(
            [current[name]['unresolved'] for name, _target in ALIASES],
            [['source-selected alias requires exact feature archive selection and component receipt']] * 3,
        )

    def test_without_a_receipt_the_new_policy_leaves_all_five_requirements_open(self) -> None:
        accounting, _companion = self._actual_accounting_and_companion()
        self.assertEqual(selection.attach_native_resolver_alias(accounting, None), [])
        records = {row['identity']['name']: row for row in accounting['identities']}
        self.assertEqual([records[name]['unresolved'] for name in PRIVATE_BODIES], [[REQUIREMENT], [REQUIREMENT]])
        self.assertEqual(
            [records[name]['unresolved'] for name, _target in ALIASES],
            [['source-selected alias requires exact feature archive selection and component receipt']] * 3,
        )

    def test_retained_67_projection_joins_exact_rows_and_discharges_only_five_reasons(self) -> None:
        accounting, companion = self._actual_accounting_and_companion()
        original_count = len(accounting['occurrences'])
        original_unnamed = sum(row['role'] == 'unnamed' for row in accounting['occurrences'])
        unselected = next(
            row for row in accounting['occurrences']
            if row['accounting']['disposition'] == 'unselected-observation'
        )
        original_unselected = copy.deepcopy(unselected)
        joins = selection.attach_native_resolver_alias(accounting, companion)
        self.assertEqual(len(joins), 1)
        self.assertEqual(len(joins[0]['aliases']), 3)
        self.assertEqual(len(joins[0]['private_bodies']), 2)
        self.assertEqual(len(joins[0]['protected_controls']), 2)
        self.assertEqual(joins[0]['complete_elf_occurrence_count'], original_count)
        self.assertEqual(original_count, 30667)
        self.assertEqual(original_unnamed, 1365)
        self.assertEqual(len(accounting['occurrences']), original_count)
        self.assertEqual(sum(row['role'] == 'unnamed' for row in accounting['occurrences']), original_unnamed)
        self.assertEqual(accounting['occurrences'][original_unselected['index']], original_unselected)
        records = {row['identity']['name']: row for row in accounting['identities']}
        for name in (*PRIVATE_BODIES, *(name for name, _target in ALIASES), *PROTECTED_CONTROLS):
            self.assertEqual(records[name]['unresolved'], [], name)

    def test_retained_67_projection_rejects_private_visibility_role_and_extra_named_rows(self) -> None:
        mutations = (
            ('visibility', lambda accounting: next(
                row['row'].__setitem__('visibility', 'DEFAULT')
                for row in accounting['occurrences']
                if row['artifact_key'] == 'candidate-shared' and row['row']['name'] == '__res_mkquery'
                and row['table'] == '.symtab'
            )),
            ('role', lambda accounting: next(
                row.__setitem__('role', 'definition')
                for row in accounting['occurrences']
                if row['artifact_key'] == 'candidate-shared' and row['row']['name'] == '__res_mkquery'
                and row['table'] == '.symtab'
            )),
            ('duplicate', lambda accounting: accounting['occurrences'].append({
                **copy.deepcopy(next(
                    row for row in accounting['occurrences']
                    if row['artifact_key'] == 'candidate-static' and row['row']['name'] == 'res_mkquery'
                )),
                'index': max(row['index'] for row in accounting['occurrences']) + 1,
            })),
        )
        for name, mutate in mutations:
            with self.subTest(mutation=name):
                accounting, companion = self._actual_accounting_and_companion()
                mutate(accounting)
                with self.assertRaises(selection.SelectionError):
                    selection.attach_native_resolver_alias(accounting, companion)

    def test_attachment_rejects_unrelated_complete_or_unnamed_row_changes(self) -> None:
        for name, mutate in (
            ('missing-unselected', lambda accounting: accounting['occurrences'].pop(next(
                index for index, row in enumerate(accounting['occurrences'])
                if row['accounting']['disposition'] == 'unselected-observation'
            ))),
            ('changed-unselected-role', lambda accounting: next(
                row.__setitem__('role', 'unnamed') for row in accounting['occurrences']
                if row['accounting']['disposition'] == 'unselected-observation'
            )),
        ):
            with self.subTest(mutation=name):
                accounting, companion = self._actual_accounting_and_companion()
                mutate(accounting)
                with self.assertRaisesRegex(selection.SelectionError, 'complete occurrence accounting differs'):
                    selection.attach_native_resolver_alias(accounting, companion)

    def test_attachment_rejects_a_reduced_source_feature_record_and_receipt_scope(self) -> None:
        for name, mutate in (
            ('source-feature', lambda accounting, companion: accounting['identities'][
                next(index for index, row in enumerate(accounting['identities'])
                     if row['identity']['name'] == 'res_search')
            ]['function_alias_requirements'][0].__setitem__('enabled_features', [])),
            ('receipt-private-scope', lambda _accounting, companion: companion['receipt']['coverage']
             ['private_bodies'].append('__not_a_resolver_body')),
        ):
            with self.subTest(mutation=name):
                accounting, companion = self._actual_accounting_and_companion()
                mutate(accounting, companion)
                with self.assertRaises(selection.SelectionError):
                    selection.attach_native_resolver_alias(accounting, companion)

    def _adapter_inputs(self):
        if not all(path.is_file() for path in (RECEIPT, FACTS, INVENTORY, PREPARATION, LOADER_REPORT)):
            self.skipTest('requires the retained 67a0 resolver component cohort')
        receipt = json.loads(RECEIPT.read_text())
        source = {
            'revision': receipt['selected_source']['revision'],
            'content_sha256': receipt['selected_source']['source_sha256'],
            'clean': True,
        }
        paths = {
            'measurement_checkout': ROOT,
            'static_product': STATIC_PRODUCT,
            'dynamic_product': DYNAMIC_PRODUCT,
            'static_preparation': PREPARATION,
            'elf_report': FACTS,
            'base_inventory': INVENTORY,
        }
        measurement = {
            'candidate_build': {
                'revision': source['revision'], 'source_content_sha256': source['content_sha256'],
            },
            'reports': {
                'elf_report': selection.file_identity(FACTS),
                'base_inventory': selection.file_identity(INVENTORY),
                'static_preparation': selection.file_identity(PREPARATION),
            },
        }
        facts = json.loads(FACTS.read_text())
        return receipt, source, paths, measurement, facts

    def _copy_receipt(self, payload: dict[str, object]) -> Path:
        parent = ROOT / '.work/x86_64/native-abi-resolver-alias-attachment-tests'
        parent.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / 'report.json'
        path.write_text(json.dumps(payload, sort_keys=True), encoding='utf-8')
        return path

    def test_adapter_consumes_the_real_producer_shape_and_full_current_cohort(self) -> None:
        receipt, source, paths, measurement, facts = self._adapter_inputs()
        report_path = self._copy_receipt(receipt)
        replay_result = self._replay_frozen_component()
        reader = FrozenResolverReader(receipt, replay_result)
        with mock.patch.object(selection, '_resolver_alias_reader', return_value=reader):
            companion = selection.native_resolver_alias_adapter(
                report_path, facts=facts, measurement=measurement, paths=paths, source=source,
                product_report=LOADER_REPORT,
            )
        self.assertIsNotNone(companion)
        assert companion is not None
        self.assertEqual(companion['result'], replay_result)
        self.assertEqual(companion['receipt']['coverage'], receipt['coverage'])
        self.assertEqual(len(reader.calls), 1)
        _path, kwargs = reader.calls[0]
        self.assertEqual(kwargs, {
            'root': ROOT, 'static_product': STATIC_PRODUCT, 'dynamic_product': DYNAMIC_PRODUCT,
            'product_report': LOADER_REPORT, 'static_preparation': PREPARATION,
            'elf_facts': FACTS, 'base_inventory': INVENTORY,
        })

    def test_adapter_rejects_report_changed_while_its_consumed_projection_is_read(self) -> None:
        receipt, source, paths, measurement, facts = self._adapter_inputs()
        report_path = self._copy_receipt(receipt)
        reader = FrozenResolverReader(receipt, self._replay_frozen_component())
        original_read_json = selection.read_json
        changed = False

        def read_then_change(path: Path):
            nonlocal changed
            value = original_read_json(path)
            if Path(path) == report_path and not changed:
                changed = True
                report_path.write_text('{"changed":true}\n', encoding='utf-8')
            return value

        with mock.patch.object(selection, '_resolver_alias_reader', return_value=reader), \
             mock.patch.object(selection, 'read_json', side_effect=read_then_change), \
             self.assertRaisesRegex(selection.SelectionError, 'changed while reading its projection'):
            selection.native_resolver_alias_adapter(
                report_path, facts=facts, measurement=measurement, paths=paths, source=source,
                product_report=LOADER_REPORT,
            )

    def test_adapter_rejects_a_changed_finite_reader_input_api(self) -> None:
        receipt, source, paths, measurement, facts = self._adapter_inputs()
        report_path = self._copy_receipt(receipt)
        reader = FrozenResolverReader(receipt, self._replay_frozen_component())
        reader.INPUT_NAMES = tuple(reader.INPUT_NAMES[:-1])
        with mock.patch.object(selection, '_resolver_alias_reader', return_value=reader), \
             self.assertRaisesRegex(selection.SelectionError, 'current v1 boundary'):
            selection.native_resolver_alias_adapter(
                report_path, facts=facts, measurement=measurement, paths=paths, source=source,
                product_report=LOADER_REPORT,
            )

    def test_adapter_rejects_wrong_current_source_product_and_measurement_bindings(self) -> None:
        cases = (
            ('source', lambda receipt, source, measurement: (
                source.__setitem__('content_sha256', '0' * 64),
                measurement['candidate_build'].__setitem__('source_content_sha256', '0' * 64),
            ), 'resolver alias selected or collector source differs from selection'),
            ('product', lambda receipt, _source, _measurement: receipt['inputs']['dynamic_libc']
             .__setitem__('sha256', '0' * 64), 'resolver alias current dynamic_libc bytes or mode differ'),
            ('measurement', lambda _receipt, _source, measurement: measurement['reports']['elf_report']
             .__setitem__('sha256', '0' * 64), 'resolver alias current ELF facts bytes or mode differ'),
        )
        for name, mutate, message in cases:
            with self.subTest(binding=name):
                receipt, source, paths, measurement, facts = self._adapter_inputs()
                receipt = copy.deepcopy(receipt)
                source = copy.deepcopy(source)
                measurement = copy.deepcopy(measurement)
                mutate(receipt, source, measurement)
                report_path = self._copy_receipt(receipt)
                reader = FrozenResolverReader(receipt, self._replay_frozen_component())
                with mock.patch.object(selection, '_resolver_alias_reader', return_value=reader), \
                     self.assertRaisesRegex(selection.SelectionError, message):
                    selection.native_resolver_alias_adapter(
                        report_path, facts=facts, measurement=measurement, paths=paths, source=source,
                        product_report=LOADER_REPORT,
                    )


if __name__ == '__main__':
    unittest.main()
