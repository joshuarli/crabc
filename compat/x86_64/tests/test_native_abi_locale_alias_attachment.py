#!/usr/bin/env python3
"""Policy guards for the finite locale/time alias selector attachment.

The receipt may discharge only four hidden time bodies and the four matching
public feature-alias requirements. The rest of the 100-name component remains
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
PUBLIC_FEATURE_ALIASES = ('asctime_r', 'localtime_r', 'strftime_l', 'wcsftime_l')
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

    def test_no_receipt_keeps_exactly_eight_locale_requirements_open(self) -> None:
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
        self.assertEqual(records['wcsftime_l']['unresolved'], [
            'source-selected alias requires exact feature archive selection and component receipt',
        ])

    def test_wcsftime_alias_uses_the_planned_owned_static_feature_route(self) -> None:
        feature = selection._locale_alias_source_feature_requirements()['wcsftime_l']
        self.assertEqual(feature['target'], '__wcsftime_l')
        self.assertEqual(feature['binding'], 'weak-same-address')
        self.assertEqual(feature['owner'], 'x86-owned-static-runtime')
        self.assertEqual(feature['state'], 'planned')
        self.assertEqual(feature['feature_selection_source'], 'scripts/build_x86_64_owned_sysroot.py')

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

    @staticmethod
    def _receipt_identity(path: Path, relative: str) -> dict[str, object]:
        """Render the receipt's relative byte identity from a selected file."""

        selected = selection.file_identity(path)
        return {
            'path': relative,
            'bytes': selected['size'],
            'sha256': selected['sha256'],
            'mode': selected['mode'],
        }

    def _receipt(self, schema: str = locale_reader.SCHEMA) -> tuple[Path, _FakeLocaleReader]:
        static_tree = selection._locale_alias_tree(self.static, 'test static product')
        dynamic_tree = selection._locale_alias_tree(self.dynamic, 'test dynamic product')
        source = {
            **self.source,
            'tree': 'c' * 40,
            'paths': [{
                'path': 'compat/x86_64/locale_alias_contract.json',
                'bytes': 2071,
                'sha256': 'd' * 64,
                'mode': 0o644,
            }],
        }
        commands = [
            {'role': role, 'status': 0, 'argv': [role]}
            for role in locale_reader.RUNNER_STEMS
        ]
        artifacts = {name: {'sealed': name} for name in locale_reader.RUNNER_ARTIFACTS}
        raw = {
            'schema': schema, 'status': locale_reader.STATUS,
            'mode_policy': locale_reader.MODE_POLICY, 'image_inputs': {'image': 'test'},
            'source_before': copy.deepcopy(source),
            'source_after': copy.deepcopy(source),
            'source_contract': locale_reader.validate_source_contract(ROOT),
            'products': {
                'static': {
                    'root_mode': selection._locale_alias_product_root_mode(self.static, 'test static product'),
                    'tree': self._receipt_tree(static_tree, locale_reader.STATIC_PRODUCT_DIRECTORY),
                    'manifest': self._receipt_identity(
                        self.static / 'share/crabc/manifest.json',
                        locale_reader.STATIC_PRODUCT_DIRECTORY + '/share/crabc/manifest.json',
                    ),
                    'preparation': {
                        'directory': locale_reader.STATIC_PREPARATION_DIRECTORY,
                        'tree': self._receipt_tree(static_tree, locale_reader.STATIC_PRODUCT_DIRECTORY),
                        'record': self._receipt_identity(
                            self.preparation,
                            locale_reader.STATIC_PREPARATION_DIRECTORY + '/preparation.json',
                        ),
                    },
                },
                'dynamic': {
                    'root_mode': selection._locale_alias_product_root_mode(self.dynamic, 'test dynamic product'),
                    'tree': self._receipt_tree(dynamic_tree, locale_reader.DYNAMIC_PRODUCT_DIRECTORY),
                    'manifest': self._receipt_identity(
                        self.dynamic / 'share/crabc/manifest.json',
                        locale_reader.DYNAMIC_PRODUCT_DIRECTORY + '/share/crabc/manifest.json',
                    ),
                    'source_before': copy.deepcopy(source),
                    'source_after': copy.deepcopy(source),
                    'state': self._receipt_identity(
                        self.dynamic / 'share/crabc/dynamic-product-state.json',
                        locale_reader.DYNAMIC_PRODUCT_DIRECTORY + '/share/crabc/dynamic-product-state.json',
                    ),
                },
            },
            'collector_commands': [], 'runner_commands': commands, 'snapshots': {}, 'artifacts': artifacts,
            'runtime': {'normal_consumers': True}, 'symbols': {'complete_100_name_contract': True},
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

    def test_adapter_accepts_product_paths_with_different_component_and_byte_order(self) -> None:
        for product in (self.static, self.dynamic):
            for directory in ('asm', 'asm-generic'):
                path = product / 'usr/include' / directory / 'example.h'
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'unchanged header bytes\n')
        preparation = selection.read_json(self.preparation)
        preparation['products']['primary']['tree'] = self._static_owner_tree()
        self.preparation.write_text(__import__('json').dumps(preparation), encoding='utf-8')
        report, reader = self._receipt()
        with mock.patch.object(selection, '_locale_alias_reader', return_value=reader):
            companion = selection.native_locale_alias_adapter(
                report, facts=self.facts, measurement=self.measurement, paths=self.paths, source=self.source,
            )
        self.assertEqual(companion['products']['static_tree'], selection._locale_alias_tree(self.static, 'static'))
        self.assertEqual(companion['products']['dynamic_tree'], selection._locale_alias_tree(self.dynamic, 'dynamic'))

    def test_adapter_calls_the_public_reader_and_requires_full_tree_identity(self) -> None:
        """Use the receipt-local source, product, and file-identity schemas together."""

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
        for name in ('selector_static_preparation', 'selector_static_manifest',
                     'selector_dynamic_manifest', 'selector_dynamic_state'):
            self.assertEqual(set(companion['products'][name]), {'path', 'sha256', 'size', 'mode'})

    def test_adapter_admits_only_the_current_collector_schema_and_binds_its_roster(self) -> None:
        """Only the collector's own schema is admitted and its source roster is the one bound."""

        report, reader = self._receipt()
        with mock.patch.object(selection, '_locale_alias_reader', return_value=reader):
            companion = selection.native_locale_alias_adapter(
                report, facts=self.facts, measurement=self.measurement, paths=self.paths, source=self.source,
            )
        assert companion is not None
        self.assertEqual(set(companion['source_inputs']) - set(locale_reader.SELECTED_SOURCES),
                         {'compat/x86_64/native_abi_selection.py', 'compat/x86_64/native-abi-selection.toml',
                          'compat/x86_64/native-abi-selection.md',
                          'compat/x86_64/tests/test_native_abi_locale_alias_attachment.py'})
        self.assertIn('rust-toolchain.toml', companion['source_inputs'])
        self.assertNotIn('compat/x86_64/owned_utmpx_receipt.py', companion['source_inputs'])
        foreign, reader = self._receipt(schema=locale_reader.SCHEMA + '-foreign')
        with mock.patch.object(selection, '_locale_alias_reader', return_value=reader):
            with self.assertRaisesRegex(selection.SelectionError, 'schema or status differs'):
                selection.native_locale_alias_adapter(
                    foreign, facts=self.facts, measurement=self.measurement, paths=self.paths, source=self.source,
                )

    def test_adapter_rejects_receipt_product_file_identity_mismatches(self) -> None:
        for product, field, description in (
            ('static', 'manifest', 'locale static manifest'),
            ('dynamic', 'manifest', 'locale dynamic manifest'),
            ('dynamic', 'state', 'locale dynamic state'),
        ):
            with self.subTest(product=product, field=field):
                report, reader = self._receipt()
                raw = __import__('json').loads(report.read_text(encoding='utf-8'))
                raw['products'][product][field]['bytes'] += 1
                report.write_text(__import__('json').dumps(raw, sort_keys=True), encoding='utf-8')
                reader.validated['products'] = raw['products']
                with mock.patch.object(selection, '_locale_alias_reader', return_value=reader), \
                     self.assertRaisesRegex(selection.SelectionError, description + ' bytes or mode differ'):
                    selection.native_locale_alias_adapter(
                        report, facts=self.facts, measurement=self.measurement, paths=self.paths, source=self.source,
                    )

    def test_adapter_rejects_a_raw_static_preparation_identity_not_returned_by_the_reader(self) -> None:
        report, reader = self._receipt()
        raw = __import__('json').loads(report.read_text(encoding='utf-8'))
        raw['products']['static']['preparation']['record']['bytes'] += 1
        report.write_text(__import__('json').dumps(raw, sort_keys=True), encoding='utf-8')
        with mock.patch.object(selection, '_locale_alias_reader', return_value=reader), \
             self.assertRaisesRegex(selection.SelectionError, 'locale reader product reconstruction differs from receipt'):
            selection.native_locale_alias_adapter(
                report, facts=self.facts, measurement=self.measurement, paths=self.paths, source=self.source,
            )

    def test_adapter_rejects_a_receipt_source_path_mismatch(self) -> None:
        report, reader = self._receipt()
        raw = __import__('json').loads(report.read_text(encoding='utf-8'))
        for name in ('source_before', 'source_after'):
            raw[name]['paths'][0]['sha256'] = '0' * 64
        report.write_text(__import__('json').dumps(raw, sort_keys=True), encoding='utf-8')
        with mock.patch.object(selection, '_locale_alias_reader', return_value=reader), \
             self.assertRaisesRegex(selection.SelectionError, 'locale alias selected or collector source differs'):
            selection.native_locale_alias_adapter(
                report, facts=self.facts, measurement=self.measurement, paths=self.paths, source=self.source,
            )

    def test_adapter_rejects_a_dynamic_receipt_source_path_mismatch(self) -> None:
        report, reader = self._receipt()
        raw = __import__('json').loads(report.read_text(encoding='utf-8'))
        for name in ('source_before', 'source_after'):
            raw['products']['dynamic'][name]['paths'][0]['sha256'] = '0' * 64
        report.write_text(__import__('json').dumps(raw, sort_keys=True), encoding='utf-8')
        reader.validated['products'] = raw['products']
        with mock.patch.object(selection, '_locale_alias_reader', return_value=reader), \
             self.assertRaisesRegex(selection.SelectionError, 'locale dynamic receipt source_before differs'):
            selection.native_locale_alias_adapter(
                report, facts=self.facts, measurement=self.measurement, paths=self.paths, source=self.source,
            )

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
                        'wcsftime_l', '__wcsftime_l',
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
        visible_indices = {}
        for artifact, table, name, binding, member in (
            ('candidate-static', '.symtab', 'wcsftime_l', 'WEAK', True),
            ('candidate-static', '.symtab', '__wcsftime_l', 'GLOBAL', True),
            ('candidate-shared', '.dynsym', 'wcsftime_l', 'WEAK', False),
            ('candidate-shared', '.dynsym', '__wcsftime_l', 'GLOBAL', False),
            ('candidate-shared', '.symtab', 'wcsftime_l', 'WEAK', False),
            ('candidate-shared', '.symtab', '__wcsftime_l', 'GLOBAL', False),
        ):
            occurrence_index = len(occurrences)
            occurrences.append({
                'index': occurrence_index,
                'artifact_key': artifact,
                'table': table,
                'role': 'definition',
                'member_index': 0 if member else None,
                'member_occurrence': 0 if member else None,
                'member_name': 'c.owned_wcsftime.o' if member else None,
                'table_section_index': 1,
                'definition_section': {'name': '.text'},
                'row': self._symbol(name, binding, 'DEFAULT', f'{300 if member else 400:016x}',
                                    occurrence_index + 1),
            })
            visible_indices[(artifact, table, name)] = occurrence_index
        function_alias_observations = [{
            'identity': copy.deepcopy(selected['wcsftime_l']['identity']),
            'target': selection.identity('__wcsftime_l'),
            'artifact_key': 'candidate-static',
            'same_domain_pairs': [[
                visible_indices[('candidate-static', '.symtab', 'wcsftime_l')],
                visible_indices[('candidate-static', '.symtab', '__wcsftime_l')],
            ]],
            'feature_contract': copy.deepcopy(
                selected['wcsftime_l']['function_alias_requirements'][0]
            ),
            'feature_archive_receipt_proven': False,
            'runtime_semantics_proven': False,
        }]
        blockers = [
            {'code': 'identity-unresolved', 'identity': copy.deepcopy(record['identity']), 'reason': reason}
            for record in selected.values() for reason in record['unresolved']
        ]
        return {'identities': list(selected.values()), 'placement_joins': placements,
                'occurrences': occurrences, 'function_alias_observations': function_alias_observations,
                'blockers': blockers}

    def _companion(self) -> dict[str, object]:
        report, reader = self._receipt()
        with mock.patch.object(selection, '_locale_alias_reader', return_value=reader):
            companion = selection.native_locale_alias_adapter(
                report, facts=self.facts, measurement=self.measurement, paths=self.paths, source=self.source,
            )
        assert companion is not None
        return companion

    def _visible_row(self, accounting: dict[str, object], artifact: str,
                     table: str, name: str) -> dict[str, object]:
        rows = [row for row in accounting['occurrences']
                if row['artifact_key'] == artifact and row['table'] == table
                and row['row']['name'] == name]
        self.assertEqual(len(rows), 1)
        return rows[0]

    def test_adapter_projects_the_complete_100_name_locale_contract(self) -> None:
        projection = self._companion()['result']['source_contract']
        self.assertEqual(len(projection['names']), 100)
        self.assertIn('wcsftime_l', projection['names'])
        self.assertIn('__wcsftime_l', projection['names'])
        self.assertTrue(projection['wcsftime_l_in_contract'])

    def test_attachment_discharges_only_the_eight_locale_reasons(self) -> None:
        accounting = self._accounting()
        before = copy.deepcopy(accounting)
        self.assertEqual(selection.attach_native_locale_alias(accounting, None), [])
        self.assertEqual(accounting, before)
        joins = selection.attach_native_locale_alias(accounting, self._companion())
        self.assertEqual(len(joins), 1)
        self.assertEqual(len(joins[0]['time_aliases']), 4)
        self.assertEqual(len(joins[0]['visible_aliases']), 1)
        self.assertEqual(joins[0]['complete_elf_occurrence_count'], 26)
        records = {row['identity']['name']: row for row in accounting['identities']}
        for name in PRIVATE_BODIES + PUBLIC_FEATURE_ALIASES:
            self.assertEqual(records[name]['unresolved'], [])
        self.assertEqual(records['gmtime_r']['unresolved'], [])
        self.assertEqual(joins[0]['wcsftime_l_in_contract'], True)
        self.assertEqual(accounting['blockers'], [])

    def test_visible_wcsftime_pair_joins_strong_provider_in_all_selected_tables(self) -> None:
        accounting = self._accounting()
        joins = selection.attach_native_locale_alias(accounting, self._companion())
        visible = joins[0]['visible_aliases'][0]
        self.assertEqual(visible['public_identity']['name'], 'wcsftime_l')
        self.assertEqual(visible['provider_identity']['name'], '__wcsftime_l')
        self.assertEqual(visible['static_member']['name'], 'c.owned_wcsftime.o')
        self.assertEqual(visible['shared_tables'], ['.dynsym', '.symtab'])
        self.assertEqual(visible['feature_contract']['owner'], 'x86-owned-static-runtime')
        self.assertFalse(visible['feature_archive_receipt_proven'])
        self.assertFalse(visible['runtime_semantics_proven'])

    def test_visible_pair_rejects_invalid_rows_and_stale_feature_proof(self) -> None:
        cases = (
            ('hidden provider', lambda a: self._visible_row(a, 'candidate-static', '.symtab', '__wcsftime_l')['row'].update(visibility='HIDDEN')),
            ('missing provider', lambda a: a['occurrences'].remove(self._visible_row(a, 'candidate-shared', '.dynsym', '__wcsftime_l'))),
            ('weak provider', lambda a: self._visible_row(a, 'candidate-static', '.symtab', '__wcsftime_l')['row'].update(binding='WEAK')),
            ('strong public alias', lambda a: self._visible_row(a, 'candidate-static', '.symtab', 'wcsftime_l')['row'].update(binding='GLOBAL')),
            ('wrong member', lambda a: self._visible_row(a, 'candidate-static', '.symtab', '__wcsftime_l').update(member_name='c.other.o')),
            ('wrong section', lambda a: self._visible_row(a, 'candidate-static', '.symtab', '__wcsftime_l')['row'].update(section_index='2')),
            ('wrong address', lambda a: self._visible_row(a, 'candidate-static', '.symtab', '__wcsftime_l')['row'].update(value='000000000000012d')),
            ('extra dynsym row', lambda a: a['occurrences'].append({
                **copy.deepcopy(self._visible_row(a, 'candidate-shared', '.dynsym', '__wcsftime_l')),
                'index': max(row['index'] for row in a['occurrences']) + 1,
            })),
            ('foreign planned feature', lambda a: a['identities'][next(
                index for index, row in enumerate(a['identities'])
                if row['identity']['name'] == 'wcsftime_l'
            )]['function_alias_requirements'][0].update(owner='x86-owned-dynamic-runtime')),
            ('stale aggregate proof', lambda a: a['function_alias_observations'][0].update(same_domain_pairs=[])),
        )
        for label, mutate in cases:
            with self.subTest(label=label):
                accounting = self._accounting()
                mutate(accounting)
                with self.assertRaises(selection.SelectionError):
                    selection.attach_native_locale_alias(accounting, self._companion())

    def test_attachment_preserves_unrelated_wcsftime_and_identity_blockers(self) -> None:
        accounting = self._accounting()
        public = next(row for row in accounting['identities'] if row['identity']['name'] == 'wcsftime_l')
        public['unresolved'].append('unrelated proof remains open')
        unrelated = {
            'code': 'identity-unresolved', 'identity': copy.deepcopy(public['identity']),
            'reason': 'unrelated proof remains open',
        }
        accounting['blockers'].append(unrelated)
        joins = selection.attach_native_locale_alias(accounting, self._companion())
        self.assertEqual(len(joins), 1)
        self.assertEqual(public['unresolved'], ['unrelated proof remains open'])
        self.assertIn(unrelated, accounting['blockers'])

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
