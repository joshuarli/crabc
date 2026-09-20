#!/usr/bin/env python3
"""Regression guards for the finite POSIX ``__sysv_signal`` ABI attachment."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import native_abi_selection as selection


class PosixSysvSignalAttachmentTests(unittest.TestCase):
    """The POSIX family reader may discharge one alias route, not its family."""

    def setUp(self) -> None:
        common_checkout = mock.patch.object(selection, '_common_checkout', return_value=ROOT)
        common_checkout.start()
        self.addCleanup(common_checkout.stop)
        parent = ROOT / '.work/x86_64/native-abi-posix-sysv-signal-attachment-tests'
        parent.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.source = {'revision': 'a' * 40, 'content_sha256': 'b' * 64, 'clean': True}
        self.static_preparation = self.work / 'static/preparation.json'
        self.static_product = self.work / 'static/products/primary'
        self.dynamic_product = self.work / 'dynamic/products/installed'
        self.alternate_static_product = self.work / 'alternate/static'
        self.alternate_dynamic_product = self.work / 'alternate/dynamic'
        for product, manifest in (
                (self.static_product, 'static-primary'),
                (self.dynamic_product, 'dynamic-installed'),
                (self.alternate_static_product, 'static-alternate'),
                (self.alternate_dynamic_product, 'dynamic-alternate')):
            path = product / 'share/crabc/manifest.json'
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(manifest + '\n', encoding='utf-8')
        self.static_preparation.parent.mkdir(parents=True, exist_ok=True)
        self.static_preparation.write_text('{"static":"preparation"}\n', encoding='utf-8')
        self.request = self.work / 'matrix/request.json'
        self.request.parent.mkdir(parents=True, exist_ok=True)
        self.request.write_text('{"request":"matrix"}\n', encoding='utf-8')
        self.matrix = self.work / 'matrix/family-execution.json'
        self.matrix.write_text('{"matrix":"physical"}\n', encoding='utf-8')
        self.native = self.work / 'native/native-execution.json'
        self.native.parent.mkdir(parents=True, exist_ok=True)
        self.native.write_text('{"native":"physical"}\n', encoding='utf-8')
        self.admission_request = self.work / 'admission/request.json'
        self.admission_request.parent.mkdir(parents=True, exist_ok=True)
        self.admission_request.write_text('{"admission":"request"}\n', encoding='utf-8')
        self.receipt = self.work / 'admission/family-admission.json'
        self.paths = {
            'static_preparation': self.static_preparation,
            'static_product': self.static_product,
            'dynamic_product': self.dynamic_product,
        }
        self.receipt.write_text(json.dumps(self._record(), sort_keys=True) + '\n', encoding='utf-8')

    @staticmethod
    def _identity(path: Path) -> dict[str, object]:
        return {
            'path': path.relative_to(ROOT).as_posix(),
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'size': path.stat().st_size,
        }

    def _matrix_inputs(self) -> dict[str, object]:
        return {
            'static_preparation': self._identity(self.static_preparation),
            'source': {key: self.source[key] for key in ('revision', 'content_sha256')},
        }

    def _cells(self, *, dynamic: bool) -> dict[str, object]:
        labels = (selection.POSIX_SYSV_SIGNAL_DYNAMIC_CELLS if dynamic
                  else selection.POSIX_SYSV_SIGNAL_STATIC_CELLS)
        return {
            'workload': 'signal-helpers',
            'cells': {
                label: {
                    'path': (self.work / 'cells' / label).relative_to(ROOT).as_posix(),
                    'sha256': hashlib.sha256(label.encode('ascii')).hexdigest(),
                    'size': len(label),
                }
                for label in labels
            },
        }

    def _matrix(self) -> dict[str, object]:
        return {
            'inputs': self._matrix_inputs(),
            'request': self._identity(self.request),
            'spelling_evidence': {
                'static': {'__sysv_signal': self._cells(dynamic=False)},
                'dynamic': {'__sysv_signal': self._cells(dynamic=True)},
            },
        }

    def _record(self) -> dict[str, object]:
        return {
            'schema': 'crabc.x86_64-owned-posix-runtime-admission/v1',
            'status': 'family-admission-verified', 'family': 'libc.posix-runtime',
            'inputs': {
                'native_execution': self._identity(self.native),
                'family_execution': self._identity(self.matrix),
                'source': {key: self.source[key] for key in ('revision', 'content_sha256')},
                'source_files': {},
            },
            'request': self._identity(self.admission_request),
            'source_seals': {'before': {'sealed': 'before'}, 'after': {'sealed': 'after'}},
            'proof': {
                'catalog': {'path': 'compat/x86_64/owned-posix-runtime-catalog.toml'},
                'catalog_schema': 'crabc.x86_64-owned-posix-runtime-catalog/v1',
                'ledger_dependencies': [], 'capability_count': 1, 'symbol_count': 1,
                'capability_symbols': {'process.signal': ['__sysv_signal']},
                'symbol_workloads': {
                    '__sysv_signal': {
                        'static': 'signal-helpers', 'dynamic': 'signal-helpers',
                        'dynamic_case': 'signal-helpers',
                    },
                },
                'closure_workloads': ['signal-helpers'],
                'static_cells': list(selection.POSIX_SYSV_SIGNAL_STATIC_CELLS),
                'dynamic_cells': list(selection.POSIX_SYSV_SIGNAL_DYNAMIC_CELLS),
                'static_spelling_cell_count': 6, 'dynamic_spelling_cell_count': 12,
                'native_components': ['signal-helpers'], 'native_io_cancellation_cells': 18,
            },
            'family_completion': True, 'native_aggregate_complete': True,
            'campaign_complete': False, 'promotion_ready': False, 'public_support': False,
        }

    def _reader(self, *, product_pairs: dict[str, dict[str, Path]] | None = None,
                mutate_output: bool = False):
        pairs = product_pairs or {
            'primary': {'static': self.static_product, 'dynamic': self.dynamic_product},
        }

        def validate_admission(root: Path, supplied: Path) -> dict[str, object]:
            self.assertEqual(root, ROOT)
            self.assertEqual(supplied, self.receipt.relative_to(ROOT))
            record = json.loads(self.receipt.read_text(encoding='utf-8'))
            if mutate_output:
                self.receipt.write_text('{"changed":true}\n', encoding='utf-8')
            return record

        def admission_inputs(root: Path, supplied: Path):
            self.assertEqual(root, ROOT)
            self.assertEqual(supplied, self.native)
            return {'native': 'validated'}, self._matrix(), self._matrix_inputs()['source'], self.matrix

        def read_request(supplied: Path) -> dict[str, object]:
            self.assertEqual(supplied, self.request)
            return json.loads(self.request.read_text(encoding='utf-8'))

        def input_products(root: Path, request: dict[str, object]):
            self.assertEqual(root, ROOT)
            self.assertEqual(request, json.loads(self.request.read_text(encoding='utf-8')))
            return self._matrix_inputs(), pairs

        family = SimpleNamespace(
            file_identity=lambda root, path: self._identity(path),
            source_file=lambda root, path: {'path': path, 'sha256': 'source'},
            read=read_request,
            input_products=input_products,
        )
        return SimpleNamespace(
            ADMISSION_SCHEMA='crabc.x86_64-owned-posix-runtime-admission/v1',
            ADMISSION_SOURCES=(), family=family,
            validate_admission_receipt=validate_admission, admission_inputs=admission_inputs,
        )

    def _adapter(self, **reader_kwargs: object) -> dict[str, object]:
        with mock.patch.object(selection, '_posix_sysv_signal_reader', return_value=self._reader(**reader_kwargs)):
            companion = selection.posix_sysv_signal_admission_adapter(
                self.receipt, paths=self.paths, source=self.source,
            )
        self.assertIsNotNone(companion)
        assert companion is not None
        return companion

    @staticmethod
    def _row(name: str, *, binding: str) -> dict[str, object]:
        return {
            'name': name, 'version': None, 'version_default': False,
            'type': 'FUNC', 'binding': binding, 'visibility': 'DEFAULT',
            'size_bytes': 80, 'section_index': '1', 'value': '0000000000000001',
        }

    def _accounting(self) -> dict[str, object]:
        contract = selection.load_contract(selection.CONTRACT_PATH)
        inputs = selection.load_source_inputs(contract, selection.CONTRACT_PATH)
        record = next(copy.deepcopy(row) for row in selection.expand_obligations(contract, inputs)
                      if row['identity']['name'] == '__sysv_signal')
        alias_static = {
            'index': 1, 'artifact_key': 'candidate-static', 'table': '.symtab', 'role': 'definition',
            'row': self._row('__sysv_signal', binding='WEAK'), 'definition_section': None,
            'table_section_index': '1', 'member_index': None, 'member_occurrence': None,
        }
        alias_shared = {
            'index': 2, 'artifact_key': 'candidate-shared', 'table': '.dynsym', 'role': 'definition',
            'row': self._row('__sysv_signal', binding='WEAK'), 'definition_section': None,
            'table_section_index': '1', 'member_index': None, 'member_occurrence': None,
        }
        target_static = {
            'index': 3, 'artifact_key': 'candidate-static', 'table': '.symtab', 'role': 'definition',
            'row': self._row('signal', binding='GLOBAL'), 'definition_section': None,
            'table_section_index': '1', 'member_index': None, 'member_occurrence': None,
        }
        target_shared = {
            'index': 4, 'artifact_key': 'candidate-shared', 'table': '.dynsym', 'role': 'definition',
            'row': self._row('signal', binding='GLOBAL'), 'definition_section': None,
            'table_section_index': '1', 'member_index': None, 'member_occurrence': None,
        }
        def placement(artifact_key: str, index: int) -> dict[str, object]:
            return {
                'identity': copy.deepcopy(record['identity']), 'artifact_key': artifact_key,
                'placement_observed': True, 'definition_count': 1, 'occurrence_indices': [index],
                'metadata_differences': [{'occurrence_index': index, 'fields': []}],
                'expected_metadata': {'type': 'FUNC', 'binding': 'WEAK', 'visibility': 'DEFAULT'},
            }
        feature = copy.deepcopy(record['function_alias_requirements'][0])
        return {
            'identities': [record], 'placement_joins': [
                placement('candidate-static', 1), placement('candidate-shared', 2),
            ],
            'occurrences': [alias_static, alias_shared, target_static, target_shared],
            'function_alias_observations': [{
                'identity': copy.deepcopy(record['identity']), 'target': selection.identity('signal'),
                'artifact_key': 'candidate-static', 'same_domain_pairs': [[1, 3]],
                'feature_contract': feature, 'feature_archive_receipt_proven': False,
                'runtime_semantics_proven': False,
            }],
            'blockers': [{
                'code': 'identity-unresolved', 'identity': copy.deepcopy(record['identity']),
                'reason': selection.POSIX_SYSV_SIGNAL_REQUIREMENT,
            }],
        }

    def test_admission_receipt_projects_only_signal_helper_component(self) -> None:
        companion = self._adapter()
        self.assertEqual(companion['status'], 'posix-sysv-signal-component-attached')
        self.assertTrue(companion['result']['family_completion'])
        self.assertFalse(companion['result']['promotion_ready'])
        self.assertFalse(companion['result']['public_support'])
        self.assertEqual(companion['result']['static']['workload'], 'signal-helpers')
        self.assertEqual(set(companion['result']['dynamic']['cells']),
                         set(selection.POSIX_SYSV_SIGNAL_DYNAMIC_CELLS))
        self.assertEqual(companion['product_cohort']['primary']['static']['path'],
                         self.static_product.relative_to(ROOT).as_posix())

    def test_attachment_discharges_only_the_exact_alias_requirement(self) -> None:
        accounting = self._accounting()
        self.assertEqual(selection.attach_posix_sysv_signal_admission(accounting, None, paths=self.paths), [])
        companion = self._adapter()
        with mock.patch.object(selection, '_posix_sysv_signal_reader', return_value=self._reader()):
            joins = selection.attach_posix_sysv_signal_admission(accounting, companion, paths=self.paths)
        self.assertEqual(accounting['identities'][0]['unresolved'], [])
        self.assertEqual(accounting['blockers'], [])
        self.assertTrue(accounting['function_alias_observations'][0]['feature_archive_receipt_proven'])
        self.assertTrue(accounting['function_alias_observations'][0]['runtime_semantics_proven'])
        self.assertEqual(joins[0]['requirements_discharged'], [selection.POSIX_SYSV_SIGNAL_REQUIREMENT])
        self.assertEqual(set(joins[0]['signal_helper_static_cells']),
                         set(selection.POSIX_SYSV_SIGNAL_STATIC_CELLS))
        self.assertEqual(joins[0]['shared_target_occurrence_index'], 4)
        self.assertEqual(len(accounting['occurrences']), 4)

    def test_attachment_rejects_a_shared_alias_with_another_definition_domain(self) -> None:
        accounting = self._accounting()
        # Keep the selected static alias/target pair intact. Only the shared
        # alias moves, so metadata checks alone would still accept it.
        accounting['occurrences'][1]['row']['value'] = '0000000000000002'
        companion = self._adapter()
        with mock.patch.object(selection, '_posix_sysv_signal_reader', return_value=self._reader()), \
                self.assertRaisesRegex(selection.SelectionError, 'selected shared target differs'):
            selection.attach_posix_sysv_signal_admission(accounting, companion, paths=self.paths)

    def test_same_source_different_primary_products_are_rejected(self) -> None:
        alternate = {
            'primary': {'static': self.alternate_static_product, 'dynamic': self.alternate_dynamic_product},
        }
        with mock.patch.object(selection, '_posix_sysv_signal_reader', return_value=self._reader(product_pairs=alternate)), \
                self.assertRaisesRegex(selection.SelectionError, 'primary static product differs'):
            selection.posix_sysv_signal_admission_adapter(self.receipt, paths=self.paths, source=self.source)

    def test_weakened_signal_helper_route_is_rejected(self) -> None:
        record = self._record()
        record['proof']['symbol_workloads']['__sysv_signal']['dynamic'] = 'signal-full'
        self.receipt.write_text(json.dumps(record, sort_keys=True) + '\n', encoding='utf-8')
        with mock.patch.object(selection, '_posix_sysv_signal_reader', return_value=self._reader()), \
                self.assertRaisesRegex(selection.SelectionError, 'workload route'):
            selection.posix_sysv_signal_admission_adapter(self.receipt, paths=self.paths, source=self.source)

    def test_final_recheck_rejects_changed_admission_receipt(self) -> None:
        companion = self._adapter()
        changed = self._record()
        changed['source_seals']['after'] = {'sealed': 'changed'}
        self.receipt.write_text(json.dumps(changed, sort_keys=True) + '\n', encoding='utf-8')
        with mock.patch.object(selection, '_posix_sysv_signal_reader', return_value=self._reader()), \
                self.assertRaisesRegex(selection.SelectionError, 'changed during final recheck'):
            selection._recheck_posix_sysv_signal_admission(companion, paths=self.paths, source=self.source)


if __name__ == '__main__':
    unittest.main()
