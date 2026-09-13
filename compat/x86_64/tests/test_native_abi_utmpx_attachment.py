"""Focused selector attachment tests for the finite utmpx receipt."""
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
import owned_utmpx_receipt as utmpx_reader
import owned_posix_product_evidence as product_evidence

ALIASES = tuple(utmpx_reader.ALIASES)
PROVIDERS = (*utmpx_reader.STRONG, *utmpx_reader.WEAK)
STATIC_LINK_INPUTS = {
    'static_crt1': 'usr/lib/crt1.o', 'static_rcrt1': 'usr/lib/rcrt1.o',
    'static_crti': 'usr/lib/crti.o', 'static_crtn': 'usr/lib/crtn.o',
    'static_libc': 'usr/lib/libc.a', 'static_builtins': 'usr/lib/libcrabc-builtins.a',
}
DYNAMIC_LINK_INPUTS = {
    'dynamic_crt1': 'usr/lib/crt1.o', 'dynamic_Scrt1': 'usr/lib/Scrt1.o',
    'dynamic_crti': 'usr/lib/crti.o', 'dynamic_crtn': 'usr/lib/crtn.o',
    'dynamic_libc': 'usr/lib/libc.so', 'dynamic_builtins': 'usr/lib/libcrabc-builtins.a',
    'dynamic_attach': 'usr/lib/crabc-dynamic-attach.o',
}


class FakeUtmpxReader:
    ROOT = ROOT
    __file__ = str(ROOT / 'compat/x86_64/owned_utmpx_receipt.py')
    SCHEMA = 'crabc.x86_64-owned-utmpx-receipt/v3'
    PINNED_IMAGE = utmpx_reader.PINNED_IMAGE
    ALIASES = ALIASES
    STRONG = utmpx_reader.STRONG
    WEAK = utmpx_reader.WEAK
    SOURCES = utmpx_reader.SOURCES
    LINK_INPUT_MODES = product_evidence.link_input_mode_projection()
    ReceiptError = ValueError

    def __init__(self, report: dict[str, object]):
        self.report = report

    def validate_report(self, report_path: Path) -> dict[str, object]:
        return copy.deepcopy(self.report)


def _symbol(name: str, binding: str) -> dict[str, object]:
    return {
        'name': name, 'raw_name': name, 'version': None, 'version_default': False,
        'binding': binding, 'visibility': 'DEFAULT', 'section_index': '1',
        'type': 'FUNC', 'value': '0000000000000010', 'size_bytes': 4, 'size': '4',
        'row_index': 1, 'raw': name, 'other': None, 'version_index': None,
        'common_alignment': None,
    }


def _occurrence(index: int, name: str, artifact: str, table: str, binding: str) -> dict[str, object]:
    return {
        'index': index, 'artifact_key': artifact, 'member_name': None,
        'member_index': None, 'member_occurrence': None, 'table': table,
        'table_section_index': 1, 'definition_section': {'name': '.text'},
        'role': 'definition', 'row': _symbol(name, binding),
    }


class NativeUtmpxAttachmentTests(unittest.TestCase):
    def setUp(self) -> None:
        checkout = mock.patch.object(selection, '_common_checkout', return_value=ROOT)
        checkout.start()
        self.addCleanup(checkout.stop)
        parent = ROOT / '.work/x86_64/native-abi-utmpx-attachment-tests'
        parent.mkdir(parents=True, exist_ok=True)
        temp = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(temp.cleanup)
        self.work = Path(temp.name)
        self.static, self.dynamic = self.work / 'static', self.work / 'dynamic'
        files = (
            (self.static / 'bin/crabc-cc', b'static driver\n'),
            (self.static / 'share/crabc/libc-static.provenance.json', b'static provenance\n'),
            (self.dynamic / 'bin/crabc-cc-dynamic', b'dynamic driver\n'),
            (self.dynamic / 'usr/lib/libc.so', b'dynamic shared\n'),
            (self.dynamic / 'lib/ld-crabc-x86_64.so.1', b'dynamic loader\n'),
            (self.dynamic / 'share/crabc/dynamic-product-state.json', b'dynamic state\n'),
            (self.dynamic / 'share/crabc/libc-shared.provenance.json', b'dynamic provenance\n'),
            (self.dynamic / 'share/crabc/producer-tools.json', b'dynamic tools\n'),
        )
        for path, data in files:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (self.dynamic / 'usr/lib/libc.so').chmod(0o755)
        for key, relative in STATIC_LINK_INPUTS.items():
            path = self.static / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists(): path.write_bytes((key + '\n').encode())
        for key, relative in DYNAMIC_LINK_INPUTS.items():
            path = self.dynamic / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists(): path.write_bytes((key + '\n').encode())
        self._write_manifests()
        self.base = self._write('base.json', b'base\n')
        self.elf = self._write('elf.json', b'elf\n')
        self.preparation = self._write('preparation.json', b'preparation\n')
        self.report_path = self._write('receipt.json', b'{}\n')
        self.paths = {
            'measurement_checkout': ROOT, 'base_inventory': self.base, 'elf_report': self.elf,
            'static_preparation': self.preparation, 'static_product': self.static,
            'dynamic_product': self.dynamic,
        }
        self.source = {'revision': 'a' * 40, 'content_sha256': 'b' * 64, 'clean': True}
        reports = {
            'elf_report': selection.file_identity(self.elf),
            'base_inventory': selection.file_identity(self.base),
            'static_preparation': selection.file_identity(self.preparation),
        }
        self.measurement = {'candidate_build': {'revision': self.source['revision'],
                            'source_content_sha256': self.source['content_sha256']}, 'reports': reports}
        self.facts = {'artifacts': {
            'candidate-static': {'identity': selection.file_identity(self.static / 'usr/lib/libc.a')},
            'candidate-shared': {'identity': selection.file_identity(self.dynamic / 'usr/lib/libc.so')},
            'candidate-loader': {'identity': selection.file_identity(self.dynamic / 'lib/ld-crabc-x86_64.so.1')},
        }}

    def _write(self, name: str, data: bytes) -> Path:
        path = self.work / name
        path.write_bytes(data)
        return path

    def _write_manifests(self) -> None:
        static = self.static / 'share/crabc/manifest.json'
        static.parent.mkdir(parents=True, exist_ok=True)
        static.write_text(json.dumps({'installed': {'files': {
            relative: hashlib.sha256((self.static / relative).read_bytes()).hexdigest()
            for relative in (*STATIC_LINK_INPUTS.values(), 'bin/crabc-cc')
        }}}, sort_keys=True))
        dynamic = self.dynamic / 'share/crabc/manifest.json'
        dynamic.write_text(json.dumps({'files': {
            relative: hashlib.sha256((self.dynamic / relative).read_bytes()).hexdigest()
            for relative in (*DYNAMIC_LINK_INPUTS.values(), 'bin/crabc-cc-dynamic',
                             'lib/ld-crabc-x86_64.so.1', 'share/crabc/dynamic-product-state.json',
                             'share/crabc/libc-shared.provenance.json', 'share/crabc/producer-tools.json')
        }}, sort_keys=True))

    @staticmethod
    def _identity(path: Path) -> dict[str, object]:
        return selection.file_identity(path)

    def _copy_retained(self, source: Path, retained: Path, names: tuple[str, ...]) -> dict[str, object]:
        tree: dict[str, object] = {}
        for relative in names:
            src, destination = source / relative, retained / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(src.read_bytes())
            destination.chmod(src.stat().st_mode & 0o777)
            identity = self._identity(destination)
            tree[relative] = {'kind': 'file', 'sha256': identity['sha256'], 'size': identity['size'], 'mode': identity['mode']}
        return tree

    def _receipt(self) -> dict[str, object]:
        workspace = self.report_path.parent / 'workspace'
        static_root = workspace / '.work/utmpx-receipt/inputs/static'
        dynamic_root = workspace / '.work/utmpx-receipt/inputs/dynamic'
        static_names = ('share/crabc/manifest.json', 'bin/crabc-cc', *STATIC_LINK_INPUTS.values())
        dynamic_names = ('share/crabc/manifest.json', 'bin/crabc-cc-dynamic',
                         'lib/ld-crabc-x86_64.so.1', 'share/crabc/dynamic-product-state.json',
                         'share/crabc/libc-shared.provenance.json', 'share/crabc/producer-tools.json',
                         *DYNAMIC_LINK_INPUTS.values())
        static_tree = self._copy_retained(self.static, static_root, static_names)
        dynamic_tree = self._copy_retained(self.dynamic, dynamic_root, dynamic_names)
        cohort = {
            'source': {'revision': self.source['revision'], 'content_sha256': self.source['content_sha256']},
            'static_preparation': self._identity(self.preparation),
            'static_source_before': self._identity(self.preparation),
            'static_source_after': self._identity(self.preparation),
            'static_manifest': self._identity(static_root / 'share/crabc/manifest.json'),
            'dynamic_manifest': self._identity(dynamic_root / 'share/crabc/manifest.json'),
            'dynamic_state': self._identity(dynamic_root / 'share/crabc/dynamic-product-state.json'),
        }
        return {
            'schema': FakeUtmpxReader.SCHEMA,
            'image': {'id': FakeUtmpxReader.PINNED_IMAGE, 'manifest': self._identity(self.report_path)},
            'source_tree': {'revision': self.source['revision'], 'entries': {name: {} for name in FakeUtmpxReader.SOURCES}},
            'sources': {name: self._identity(ROOT / name) for name in FakeUtmpxReader.SOURCES},
            'products': {
                'static': {'workspace_path': '.work/utmpx-receipt/inputs/static', 'retained_tree': static_tree},
                'dynamic': {'workspace_path': '.work/utmpx-receipt/inputs/dynamic', 'retained_tree': dynamic_tree},
            },
            'product_cohort': cohort, 'link_input_modes': copy.deepcopy(FakeUtmpxReader.LINK_INPUT_MODES), 'tools': {}, 'commands': {},
            'symbols': {
                'headers': {},
                'archive': {name: ('T' if name in FakeUtmpxReader.STRONG else 'W') for name in PROVIDERS},
                'shared': {name: ('GLOBAL' if name in FakeUtmpxReader.STRONG else 'WEAK') for name in PROVIDERS},
                'executables': {mode: {name: ('T' if name in FakeUtmpxReader.STRONG else 'W') for name in PROVIDERS}
                                for mode in ('static', 'static-pie')},
                'dynamic_imports': {mode: {name: 'GLOBAL DEFAULT UND' for name in PROVIDERS}
                                    for mode in ('pie', 'non-pie')},
            },
            'runtime': {label: {} for label in ('oracle', 'static', 'static-pie', 'pie-direct', 'pie-kernel', 'non-pie-direct', 'non-pie-kernel')},
            'links': {mode: {} for mode in ('static', 'static-pie', 'pie', 'non-pie')},
            'projection': {
                'selected_aliases': [list(pair) for pair in ALIASES], 'component_complete': True,
                'family_complete': False, 'runtime_qualified': False, 'public_support': False,
                'linkages': ['non-pie', 'pie', 'static', 'static-pie'],
                'runtime_streams': ['non-pie-direct', 'non-pie-kernel', 'oracle', 'pie-direct', 'pie-kernel', 'static', 'static-pie'],
            },
        }

    def _accounting(self, unknown: bool = False) -> dict[str, object]:
        occurrences, index = [], 0
        for name in PROVIDERS:
            binding = 'GLOBAL' if name in FakeUtmpxReader.STRONG else 'WEAK'
            for artifact, table in (('candidate-static', '.symtab'),
                                    ('candidate-shared', '.dynsym'), ('candidate-shared', '.symtab')):
                occurrences.append(_occurrence(index, name, artifact, table, binding)); index += 1
        if unknown:
            occurrences += [_occurrence(index, 'unowned_utmpx', 'candidate-static', '.symtab', 'GLOBAL'),
                            _occurrence(index + 1, '', 'candidate-shared', '.symtab', 'LOCAL')]
        identities, blockers, function = [], [], []
        for alias, target in ALIASES:
            identity = {'name': alias, 'version': None, 'version_default': False}
            feature = {'name': alias, 'target': target, 'binding': 'weak-same-address', 'owner': 'x86-owned-static-runtime'}
            identities.append({'identity': identity, 'selection': {'disposition': 'public-provider'},
                               'function_alias_requirements': [feature],
                               'unresolved': [selection.UTMPX_ALIAS_RECEIPT_REQUIREMENT]})
            blockers.append({'code': 'identity-unresolved', 'identity': copy.deepcopy(identity),
                             'reason': selection.UTMPX_ALIAS_RECEIPT_REQUIREMENT})
            a = next(row['index'] for row in occurrences if row['row']['name'] == alias and row['artifact_key'] == 'candidate-static')
            b = next(row['index'] for row in occurrences if row['row']['name'] == target and row['artifact_key'] == 'candidate-static')
            function.append({'identity': copy.deepcopy(identity),
                             'target': {'name': target, 'version': None, 'version_default': False},
                             'artifact_key': 'candidate-static', 'same_domain_pairs': [[a, b]],
                             'feature_contract': feature, 'feature_archive_receipt_proven': False,
                             'runtime_semantics_proven': False})
        provider_identity = {'name': 'utmpname', 'version': None, 'version_default': False}
        identities.append({'identity': provider_identity, 'selection': {'disposition': 'public-provider'},
                           'unresolved': [selection.ORDINARY_IMPORT_REASON]})
        blockers.append({'code': 'identity-unresolved', 'identity': copy.deepcopy(provider_identity),
                         'reason': selection.ORDINARY_IMPORT_REASON})
        return {'identities': identities, 'placement_joins': [], 'occurrences': occurrences,
                'function_alias_observations': function, 'blockers': blockers}

    def _companion(self) -> dict[str, object]:
        return {'status': 'utmpx-observed-with-boundaries', 'reader': {}, 'report': {}, 'source': {},
                'source_inputs': {name: selection.file_identity(ROOT / name) for name in selection._utmpx_source_files()},
                'products': {}, 'measurement_reports': {}, 'projection': self._receipt()['projection'],
                'symbols': self._receipt()['symbols'], 'limits': list(selection.UTMPX_LIMITS)}

    def _adapter(self, receipt: dict[str, object] | None = None) -> dict[str, object] | None:
        with mock.patch.object(selection, '_utmpx_reader', return_value=FakeUtmpxReader(receipt or self._receipt())):
            return selection.native_utmpx_adapter(self.report_path, facts=self.facts, measurement=self.measurement,
                                                  paths=self.paths, source=self.source)

    def test_adapter_is_absent_without_a_receipt(self) -> None:
        self.assertIsNone(selection.native_utmpx_adapter(None, facts=self.facts, measurement=self.measurement,
                                                         paths=self.paths, source=self.source))

    def test_adapter_binds_current_source_product_and_all_link_inputs(self) -> None:
        companion = self._adapter()
        assert companion is not None
        self.assertEqual(companion['status'], 'utmpx-observed-with-boundaries')
        self.assertEqual(set(companion['products']), set(selection._utmpx_product_identities(self.paths)))
        self.assertEqual(companion['projection']['selected_aliases'], [list(pair) for pair in ALIASES])

        wrong_source = self._receipt(); wrong_source['source_tree']['revision'] = 'c' * 40
        with self.assertRaisesRegex(selection.SelectionError, 'source Git tree differs'):
            self._adapter(wrong_source)
        wrong_product = self._receipt(); wrong_product['product_cohort']['dynamic_manifest']['sha256'] = '0' * 64
        with self.assertRaisesRegex(selection.SelectionError, 'dynamic manifest'):
            self._adapter(wrong_product)

    def test_adapter_rejects_state_crt_attach_builtins_and_mode_substitution(self) -> None:
        cases = (
            (self.dynamic / 'share/crabc/dynamic-product-state.json', 'dynamic_state'),
            (self.static / STATIC_LINK_INPUTS['static_crt1'], 'static_crt1'),
            (self.dynamic / DYNAMIC_LINK_INPUTS['dynamic_attach'], 'dynamic_attach'),
            (self.dynamic / DYNAMIC_LINK_INPUTS['dynamic_builtins'], 'dynamic_builtins'),
        )
        for path, label in cases:
            with self.subTest(label=label):
                receipt = self._receipt(); old = path.read_bytes(); old_mode = path.stat().st_mode & 0o777
                try:
                    path.write_bytes(b'forged current input\n')
                    with self.assertRaisesRegex(selection.SelectionError, label.replace('_', '[_ ]')):
                        self._adapter(receipt)
                    path.write_bytes(old)
                    path.chmod(0o700)
                    with self.assertRaisesRegex(selection.SelectionError, label.replace('_', '[_ ]')):
                        self._adapter(receipt)
                finally:
                    path.write_bytes(old)
                    path.chmod(old_mode)

    def test_adapter_rejects_a_resealed_retained_mode_without_source_policy_change(self) -> None:
        receipt = self._receipt()
        retained = self.report_path.parent / 'workspace/.work/utmpx-receipt/inputs/dynamic/usr/lib/crabc-dynamic-attach.o'
        old = retained.stat().st_mode & 0o777
        try:
            retained.chmod(0o600)
            receipt['products']['dynamic']['retained_tree']['usr/lib/crabc-dynamic-attach.o']['mode'] = 0o600
            with self.assertRaisesRegex(selection.SelectionError, 'source-bound mode'):
                self._adapter(receipt)
        finally:
            retained.chmod(old)

    def test_adapter_rejects_unsealed_retained_link_input_and_final_recheck_mutation(self) -> None:
        receipt = self._receipt()
        retained = self.report_path.parent / 'workspace/.work/utmpx-receipt/inputs/dynamic/usr/lib/crabc-dynamic-attach.o'
        retained.write_bytes(b'forged retained attach\n')
        with self.assertRaisesRegex(selection.SelectionError, 'retained dynamic_attach differs from reader-sealed tree'):
            self._adapter(receipt)
        receipt = self._receipt(); companion = self._adapter(receipt)
        assert companion is not None
        changed = self.static / STATIC_LINK_INPUTS['static_crti']; old = changed.read_bytes(); changed.write_bytes(b'after attach\n')
        with mock.patch.object(selection, 'selection_source', return_value=copy.deepcopy(self.source)), \
             self.assertRaisesRegex(selection.SelectionError, 'utmpx static_crti changed'):
            selection._recheck_runtime_receipt_cohort(paths=self.paths, facts=self.facts, measurement=self.measurement,
                source=self.source, registry=None, pthread=None, utmpx=companion)
        changed.write_bytes(old)

    def test_attachment_discharges_only_eight_existing_alias_requirements(self) -> None:
        accounting = self._accounting(); companion = self._companion()
        with mock.patch.object(selection, '_utmpx_reader', return_value=FakeUtmpxReader({})):
            joins = selection.attach_native_utmpx(accounting, companion)
        self.assertEqual(len(joins), 1); self.assertEqual(len(joins[0]['aliases']), 8)
        alias_records = [row for row in accounting['identities'] if row['identity']['name'] != 'utmpname']
        self.assertTrue(all(not row['unresolved'] for row in alias_records))
        retained_provider = next(row for row in accounting['identities'] if row['identity']['name'] == 'utmpname')
        self.assertEqual(retained_provider['unresolved'], [selection.ORDINARY_IMPORT_REASON])
        self.assertTrue(any(row['reason'] == selection.ORDINARY_IMPORT_REASON for row in accounting['blockers']))
        self.assertEqual({row['target'] for row in joins[0]['aliases']}, {target for _, target in ALIASES})
        self.assertNotIn('utmpname', {row['alias'] for row in joins[0]['aliases']})

    def test_attachment_rejects_alias_domain_and_preserves_unknown_and_unnamed_rows(self) -> None:
        companion = self._companion()
        wrong = self._accounting()
        next(row for row in wrong['occurrences'] if row['row']['name'] == 'endutent' and row['artifact_key'] == 'candidate-shared' and row['table'] == '.symtab')['row']['value'] = '0000000000000020'
        with mock.patch.object(selection, '_utmpx_reader', return_value=FakeUtmpxReader({})), \
             self.assertRaisesRegex(selection.SelectionError, 'definition domain'):
            selection.attach_native_utmpx(wrong, companion)
        accounting = self._accounting(unknown=True); count = len(accounting['occurrences'])
        with mock.patch.object(selection, '_utmpx_reader', return_value=FakeUtmpxReader({})):
            selection.attach_native_utmpx(accounting, companion)
        self.assertEqual(len(accounting['occurrences']), count)
        self.assertTrue(any(row['row']['name'] == '' for row in accounting['occurrences']))
        self.assertTrue(any(row['row']['name'] == 'unowned_utmpx' for row in accounting['occurrences']))

    def test_cli_and_report_roundtrip_thread_receipt(self) -> None:
        arguments = ['build-report']
        for flag in ('measurement-checkout', 'elf-facts', 'base-inventory', 'static-product', 'dynamic-product', 'static-preparation'):
            arguments += ['--' + flag, '.work/not-present']
        arguments += ['--output', '.work/output', '--utmpx-receipt-report', '.work/utmpx/report.json']
        report = {'identities': [], 'occurrences': [], 'closure': {'complete': False, 'blockers': []}}
        with mock.patch.object(selection, 'build_report', return_value=report) as build:
            self.assertEqual(selection.main(arguments), 0)
        self.assertEqual(build.call_args.kwargs['utmpx_receipt_report'], Path('.work/utmpx/report.json'))
        output = self.work / 'roundtrip'; expected = {'roundtrip': True}
        with mock.patch.object(selection, 'validate_measurement_paths', return_value=self.paths), \
             mock.patch.object(selection, '_build_report', return_value=expected) as build_internal:
            self.assertEqual(selection.build_report(output=output, utmpx_receipt_report=self.report_path,
                elf_report=self.elf, base_inventory=self.base, static_preparation=self.preparation,
                static_product=self.static, dynamic_product=self.dynamic, measurement_checkout=ROOT), expected)
            self.assertEqual(selection.validate_report(output / 'report.json', utmpx_receipt_report=self.report_path,
                elf_report=self.elf, base_inventory=self.base, static_preparation=self.preparation,
                static_product=self.static, dynamic_product=self.dynamic, measurement_checkout=ROOT), expected)
        self.assertEqual(build_internal.call_count, 2)
        self.assertTrue(all(call.kwargs['utmpx_receipt_report'] == self.report_path for call in build_internal.call_args_list))

    def test_frozen_40f_receipt_cannot_waive_current_source(self) -> None:
        frozen = ROOT.parent / 'owned_utmpx_receipt_boundary/.work/x86_64/owned-utmpx-fed397b0-40f05ab5/receipt-40f05ab5/report.json'
        if not frozen.is_file(): self.skipTest('retained 40f receipt unavailable')
        with self.assertRaises(utmpx_reader.ReceiptError): utmpx_reader.validate_report(frozen)


if __name__ == '__main__':
    unittest.main()
