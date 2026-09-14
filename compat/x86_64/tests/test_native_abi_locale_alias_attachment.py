#!/usr/bin/env python3
"""Policy guards for the finite locale/time alias selector attachment.

The receipt may discharge only four hidden time bodies and the three matching
public feature-alias requirements.  The rest of the 98-name component remains
validated by its own reader; it is not a blanket selector provider route.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import native_abi_selection as selection
import locale_alias_contract_receipt as locale_reader


PRIVATE_BODIES = ('__asctime_r', '__gmtime_r', '__localtime_r', '__strftime_l')
PUBLIC_FEATURE_ALIASES = ('asctime_r', 'localtime_r', 'strftime_l')
GROUP = 'component-owned-locale-time-private-bodies'
OWNER = 'x86-owned-locale-time-private-bodies'
REQUIREMENT = 'current source-bound locale/time alias and normal consumer receipt'


class LocaleAliasOwnerPolicyTests(unittest.TestCase):
    """Keep the receipt admission narrow before any native evidence exists."""

    def test_four_private_bodies_require_the_exact_locale_receipt(self) -> None:
        contract = selection.load_contract(selection.CONTRACT_PATH)
        inputs = selection.load_source_inputs(contract, selection.CONTRACT_PATH)
        records = {row['identity']['name']: row for row in selection.expand_obligations(contract, inputs)}

        for name in PRIVATE_BODIES:
            with self.subTest(name=name):
                record = records[name]
                self.assertEqual(record['selection']['disposition'], 'private-provider')
                self.assertEqual(record['selection']['group'], GROUP)
                self.assertEqual(record['selection']['owner'], OWNER)
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

    def test_no_receipt_keeps_exactly_seven_locale_requirements_open(self) -> None:
        contract = selection.load_contract(selection.CONTRACT_PATH)
        inputs = selection.load_source_inputs(contract, selection.CONTRACT_PATH)
        records = {row['identity']['name']: row for row in selection.expand_obligations(contract, inputs)}
        for name in PRIVATE_BODIES:
            self.assertEqual(records[name]['unresolved'], [REQUIREMENT])
        for name in PUBLIC_FEATURE_ALIASES:
            self.assertEqual(records[name]['unresolved'], [
                'source-selected alias requires exact feature archive selection and component receipt',
            ])
        self.assertNotIn('__tzset', records)
        self.assertNotEqual(records['wcsftime_l']['unresolved'], [])

    def test_product_tree_join_preserves_setgid_descendants_but_not_the_product_root(self) -> None:
        """Match the existing product-owner tree convention exactly."""
        parent = ROOT / '.work/x86_64/native-abi-locale-alias-attachment-tests'
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as temporary:
            product = Path(temporary) / 'product'
            product.mkdir(mode=0o700)
            child = product / 'usr'
            child.mkdir(mode=0o755)
            child.chmod(0o2755)
            payload = child / 'libc.a'
            payload.write_bytes(b'locale product\n')
            actual = selection._locale_alias_tree(product, 'test product')
            retained = []
            for row in actual:
                copied = dict(row)
                copied['path'] = 'receipt/products/static/' + copied['path']
                retained.append(copied)
            self.assertEqual(
                selection._locale_alias_normalized_tree(retained, 'receipt/products/static', 'retained test product'),
                actual,
            )
            self.assertEqual(actual[0], {'path': 'usr', 'kind': 'directory', 'mode': 0o2755})
            self.assertNotIn({'path': '.', 'kind': 'directory', 'mode': 0o700}, actual)


class _FakeLocaleReader:
    """Exercise the public reader call boundary with a sealed synthetic receipt."""

    __file__ = locale_reader.__file__
    SCHEMA = locale_reader.SCHEMA
    STATUS = locale_reader.STATUS
    CONTRACT_PATH = locale_reader.CONTRACT_PATH
    STATIC_PRODUCT_DIRECTORY = locale_reader.STATIC_PRODUCT_DIRECTORY
    DYNAMIC_PRODUCT_DIRECTORY = locale_reader.DYNAMIC_PRODUCT_DIRECTORY
    RUNNER_STEMS = locale_reader.RUNNER_STEMS
    RUNNER_ARTIFACTS = locale_reader.RUNNER_ARTIFACTS
    SELECTED_SOURCES = locale_reader.SELECTED_SOURCES
    LocaleAliasReceiptError = locale_reader.LocaleAliasReceiptError

    def __init__(self, validated: dict[str, object]):
        self.validated = validated
        self.calls: list[tuple[Path, Path]] = []

    def validate_report(self, root: Path, report: Path) -> dict[str, object]:
        self.calls.append((root, report))
        return self.validated

    @staticmethod
    def validate_source_contract(root: Path) -> dict[str, object]:
        return locale_reader.validate_source_contract(root)


class LocaleAliasAdapterTests(unittest.TestCase):
    """Keep product/source joins in the public selector adapter, not filenames."""

    def setUp(self) -> None:
        parent = ROOT / '.work/x86_64/native-abi-locale-alias-adapter-tests'
        parent.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.static = self.work / 'static'
        self.dynamic = self.work / 'dynamic'
        for path, data in (
            (self.static / 'share/crabc/manifest.json', b'{"static":true}\n'),
            (self.static / 'usr/lib/libc.a', b'static libc\n'),
            (self.dynamic / 'share/crabc/manifest.json', b'{"dynamic":true}\n'),
            (self.dynamic / 'usr/lib/libc.so', b'dynamic libc\n'),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.dynamic.chmod(0o2755)
        self.source = {'revision': 'a' * 40, 'content_sha256': 'b' * 64, 'clean': True}
        state = self.dynamic / 'share/crabc/dynamic-product-state.json'
        state.write_text('{"source_sha256":"' + self.source['content_sha256'] + '"}\n', encoding='utf-8')
        self.preparation = self.work / 'preparation.json'
        self.preparation.write_text(__import__('json').dumps({
            'source': {key: self.source[key] for key in ('revision', 'content_sha256')},
            'products': {
                'primary': {
                    'path': 'products/primary', 'manifest': {},
                    'tree': self._static_owner_tree(), 'producer_tools': {}, 'toolchain': 'test',
                },
                'reproduction': {}, 'extracted': {},
            },
        }), encoding='utf-8')
        self.base = self._write('base.json', b'base\n')
        self.elf = self._write('elf.json', b'elf\n')
        self.paths = {
            'measurement_checkout': ROOT, 'static_product': self.static, 'dynamic_product': self.dynamic,
            'static_preparation': self.preparation, 'base_inventory': self.base, 'elf_report': self.elf,
        }
        self.measurement = {
            'candidate_build': {
                'revision': self.source['revision'], 'source_content_sha256': self.source['content_sha256'],
            },
            'reports': {
                'elf_report': selection.file_identity(self.elf),
                'base_inventory': selection.file_identity(self.base),
                'static_preparation': selection.file_identity(self.preparation),
            },
        }
        self.facts: dict[str, object] = {}

    def _write(self, name: str, data: bytes) -> Path:
        path = self.work / name
        path.write_bytes(data)
        return path

    def _static_owner_tree(self) -> dict[str, object]:
        result: dict[str, object] = {}
        for row in selection._locale_alias_tree(self.static, 'test static product'):
            result[row['path']] = ({'kind': 'directory', 'mode': row['mode']}
                                   if row['kind'] == 'directory' else {
                                       'kind': 'file', 'mode': row['mode'],
                                       'sha256': row['sha256'], 'size': row['bytes'],
                                   })
        return result

    @staticmethod
    def _receipt_tree(rows: list[dict[str, object]], prefix: str) -> list[dict[str, object]]:
        result = []
        for row in rows:
            copied = dict(row)
            copied['path'] = prefix + '/' + str(copied['path'])
            result.append(copied)
        return result

    def _receipt(self) -> tuple[Path, _FakeLocaleReader]:
        static_tree = selection._locale_alias_tree(self.static, 'test static product')
        dynamic_tree = selection._locale_alias_tree(self.dynamic, 'test dynamic product')
        source = {**self.source, 'tree': 'c' * 64, 'paths': {}}
        commands = [
            {'role': role, 'status': 0, 'argv': [role]}
            for role in locale_reader.RUNNER_STEMS
        ]
        artifacts = {name: {'sealed': name} for name in locale_reader.RUNNER_ARTIFACTS}
        raw = {
            'schema': locale_reader.SCHEMA, 'status': locale_reader.STATUS,
            'mode_policy': locale_reader.MODE_POLICY, 'image_inputs': {'image': 'test'},
            'source_before': {key: source[key] for key in ('revision', 'tree', 'content_sha256', 'clean')},
            'source_after': {key: source[key] for key in ('revision', 'tree', 'content_sha256', 'clean')},
            'source_contract': locale_reader.validate_source_contract(ROOT),
            'products': {
                'static': {
                    'root_mode': selection._locale_alias_product_root_mode(self.static, 'test static product'),
                    'tree': self._receipt_tree(static_tree, locale_reader.STATIC_PRODUCT_DIRECTORY),
                    'manifest': selection.file_identity(self.static / 'share/crabc/manifest.json'),
                    'preparation': {},
                },
                'dynamic': {
                    'root_mode': selection._locale_alias_product_root_mode(self.dynamic, 'test dynamic product'),
                    'tree': self._receipt_tree(dynamic_tree, locale_reader.DYNAMIC_PRODUCT_DIRECTORY),
                    'manifest': selection.file_identity(self.dynamic / 'share/crabc/manifest.json'),
                    'source_before': {key: source[key] for key in ('revision', 'tree', 'content_sha256', 'clean')},
                    'source_after': {key: source[key] for key in ('revision', 'tree', 'content_sha256', 'clean')},
                    'state': selection.file_identity(self.dynamic / 'share/crabc/dynamic-product-state.json'),
                },
            },
            'collector_commands': [], 'runner_commands': commands, 'snapshots': {}, 'artifacts': artifacts,
            'runtime': {'normal_consumers': True}, 'symbols': {'complete_98_name_contract': True},
            'nonclaims': list(locale_reader.NONCLAIMS),
        }
        report = self._write('receipt.json', __import__('json').dumps(raw, sort_keys=True).encode() + b'\n')
        validated = {
            'source': source, 'image_inputs': raw['image_inputs'], 'products': raw['products'],
            'collector_commands': raw['collector_commands'], 'runner_commands': commands,
            'artifacts': artifacts, 'runtime': raw['runtime'], 'symbols': raw['symbols'],
            'status': locale_reader.STATUS,
        }
        return report, _FakeLocaleReader(validated)

    def test_adapter_calls_the_public_reader_and_requires_full_tree_identity(self) -> None:
        report, reader = self._receipt()
        with mock.patch.object(selection, '_locale_alias_reader', return_value=reader):
            companion = selection.native_locale_alias_adapter(
                report, facts=self.facts, measurement=self.measurement, paths=self.paths, source=self.source,
            )
        assert companion is not None
        self.assertEqual(reader.calls, [(ROOT, report.resolve())])
        self.assertEqual(companion['result']['runner_command_count'], 35)
        self.assertEqual(companion['products']['static_tree'], selection._locale_alias_tree(self.static, 'static'))
        self.assertEqual(companion['products']['dynamic_tree'], selection._locale_alias_tree(self.dynamic, 'dynamic'))
        self.assertEqual(companion['products']['dynamic_root_mode'], 0o2755)

    def test_adapter_rejects_a_receipt_tree_that_only_matches_source_revision(self) -> None:
        report, reader = self._receipt()
        raw = __import__('json').loads(report.read_text(encoding='utf-8'))
        raw['products']['dynamic']['tree'][-1]['sha256'] = '0' * 64
        report.write_text(__import__('json').dumps(raw, sort_keys=True), encoding='utf-8')
        reader.validated['products'] = raw['products']
        with mock.patch.object(selection, '_locale_alias_reader', return_value=reader), \
             self.assertRaisesRegex(selection.SelectionError, 'dynamic product differs from selector supplied product'):
            selection.native_locale_alias_adapter(
                report, facts=self.facts, measurement=self.measurement, paths=self.paths, source=self.source,
            )

    def test_adapter_rejects_a_dynamic_root_mode_not_retained_by_the_receipt(self) -> None:
        report, reader = self._receipt()
        raw = __import__('json').loads(report.read_text(encoding='utf-8'))
        raw['products']['dynamic']['root_mode'] = 0o755
        report.write_text(__import__('json').dumps(raw, sort_keys=True), encoding='utf-8')
        reader.validated['products'] = raw['products']
        with mock.patch.object(selection, '_locale_alias_reader', return_value=reader), \
             self.assertRaisesRegex(selection.SelectionError, 'product root mode differs'):
            selection.native_locale_alias_adapter(
                report, facts=self.facts, measurement=self.measurement, paths=self.paths, source=self.source,
            )

    @staticmethod
    def _symbol(name: str, binding: str, visibility: str, value: str, row_index: int) -> dict[str, object]:
        return {
            'name': name, 'version': None, 'version_default': False, 'type': 'FUNC',
            'binding': binding, 'visibility': visibility, 'section_index': '1',
            'value': value, 'size_bytes': 4, 'row_index': row_index,
        }

    def _accounting(self) -> dict[str, object]:
        contract = selection.load_contract(selection.CONTRACT_PATH)
        inputs = selection.load_source_inputs(contract, selection.CONTRACT_PATH)
        selected = {row['identity']['name']: copy.deepcopy(row)
                    for row in selection.expand_obligations(contract, inputs)
                    if row['identity']['name'] in {
                        '__asctime_r', '__gmtime_r', '__localtime_r', '__strftime_l',
                        'asctime_r', 'gmtime_r', 'localtime_r', 'strftime_l',
                    }}
        occurrences: list[dict[str, object]] = []
        placements: list[dict[str, object]] = []
        index = 0
        for public, private in (
            ('asctime_r', '__asctime_r'), ('gmtime_r', '__gmtime_r'),
            ('localtime_r', '__localtime_r'), ('strftime_l', '__strftime_l'),
        ):
            def append(artifact: str, table: str, binding: str, visibility: str, name: str, value: str) -> int:
                nonlocal index
                role = 'local-definition' if binding == 'LOCAL' else 'definition'
                occurrences.append({
                    'index': index, 'artifact_key': artifact, 'table': table, 'role': role,
                    'member_index': None, 'member_occurrence': None, 'table_section_index': 1,
                    'definition_section': {'name': '.text'},
                    'row': self._symbol(name, binding, visibility, value, index + 1),
                })
                index += 1
                return index - 1
            static_public = append('candidate-static', '.symtab', 'WEAK', 'DEFAULT', public, f'{index + 1:016x}')
            shared_dyn_public = append('candidate-shared', '.dynsym', 'WEAK', 'DEFAULT', public, f'{index + 1:016x}')
            shared_public = append('candidate-shared', '.symtab', 'WEAK', 'DEFAULT', public, f'{index + 1:016x}')
            # Same-domain rows use the public row's definition value; table
            # position is not an address identity across separate products.
            occurrences[static_public]['row']['value'] = f'{100 + static_public:016x}'
            occurrences[shared_public]['row']['value'] = f'{200 + shared_public:016x}'
            static_private = append('candidate-static', '.symtab', 'GLOBAL', 'HIDDEN', private,
                                    occurrences[static_public]['row']['value'])
            shared_private = append('candidate-shared', '.symtab', 'LOCAL', 'HIDDEN', private,
                                    occurrences[shared_public]['row']['value'])
            for artifact, occurrence_index, metadata in (
                ('candidate-static', static_private, {'type': 'FUNC', 'binding': 'GLOBAL', 'visibility': 'HIDDEN'}),
                ('candidate-shared', shared_private, {'type': 'FUNC', 'binding': 'LOCAL', 'visibility': 'HIDDEN'}),
            ):
                placements.append({
                    'identity': copy.deepcopy(selected[private]['identity']), 'artifact_key': artifact,
                    'expected_metadata': metadata, 'placement_observed': True, 'definition_count': 1,
                    'occurrence_indices': [occurrence_index], 'metadata_differences': [],
                })
        blockers = [
            {'code': 'identity-unresolved', 'identity': copy.deepcopy(record['identity']), 'reason': reason}
            for record in selected.values() for reason in record['unresolved']
        ]
        return {'identities': list(selected.values()), 'placement_joins': placements,
                'occurrences': occurrences, 'blockers': blockers}

    def test_attachment_discharges_only_the_seven_locale_reasons(self) -> None:
        report, reader = self._receipt()
        with mock.patch.object(selection, '_locale_alias_reader', return_value=reader):
            companion = selection.native_locale_alias_adapter(
                report, facts=self.facts, measurement=self.measurement, paths=self.paths, source=self.source,
            )
            assert companion is not None
            accounting = self._accounting()
            before = copy.deepcopy(accounting)
            self.assertEqual(selection.attach_native_locale_alias(accounting, None), [])
            self.assertEqual(accounting, before)
            joins = selection.attach_native_locale_alias(accounting, companion)
        self.assertEqual(len(joins), 1)
        self.assertEqual(len(joins[0]['time_aliases']), 4)
        self.assertEqual(joins[0]['complete_elf_occurrence_count'], 20)
        records = {row['identity']['name']: row for row in accounting['identities']}
        for name in PRIVATE_BODIES + PUBLIC_FEATURE_ALIASES:
            self.assertEqual(records[name]['unresolved'], [])
        self.assertEqual(records['gmtime_r']['unresolved'], [])

    def test_selector_cli_forwards_the_optional_locale_receipt_path(self) -> None:
        report, _reader = self._receipt()
        output = self.work / 'selection-output'
        argv = [
            'build-report', '--output', str(output),
            '--measurement-checkout', str(ROOT), '--elf-facts', str(self.elf),
            '--base-inventory', str(self.base), '--static-product', str(self.static),
            '--dynamic-product', str(self.dynamic), '--static-preparation', str(self.preparation),
            '--locale-alias-contract-report', str(report),
        ]
        result = {'identities': [], 'occurrences': [], 'closure': {'blockers': [], 'complete': False}}
        with mock.patch.object(selection, 'build_report', return_value=result) as build:
            self.assertEqual(selection.main(argv), 0)
        self.assertEqual(build.call_args.kwargs['locale_alias_contract_report'], report)


if __name__ == '__main__':
    unittest.main()
