"""Focused selector joins for the finite installed FILE alias receipt."""
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
import owned_stdio_alias_contract_reader as stdio_alias_evidence


class NativeStdioAliasAttachmentContractTests(unittest.TestCase):
    """The FILE receipt is a finite private/provider attachment, not a rule."""

    _F168_RECEIPT = (
        ROOT.parent / 'native_stdio_alias_receipt_repair/.work/x86_64/stdio-alias-evidence/'
        'clean-f16806d1/report.json'
    )
    _B525_FACTS = (
        ROOT.parent / 'native_stdio_alias_receipt_repair/.work/x86_64/stdio-alias-inputs-b52538c5/'
        'historical-facts/report.json'
    )

    def setUp(self) -> None:
        common_checkout = mock.patch.object(selection, '_common_checkout', return_value=ROOT)
        common_checkout.start()
        self.addCleanup(common_checkout.stop)
        parent = ROOT / '.work/x86_64/native-abi-stdio-alias-attachment-tests'
        parent.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.static = self.work / 'static'
        self.dynamic = self.work / 'dynamic'
        for path, payload in (
            (self.static / 'share/crabc/manifest.json', b'static manifest\n'),
            (self.static / 'share/crabc/libc-static.provenance.json', b'static provenance\n'),
            (self.static / 'bin/crabc-cc', b'static driver\n'),
            (self.static / 'usr/lib/libc.a', b'static libc\n'),
            (self.dynamic / 'share/crabc/manifest.json', b'dynamic manifest\n'),
            (self.dynamic / 'share/crabc/dynamic-product-state.json', b'dynamic state\n'),
            (self.dynamic / 'share/crabc/libc-shared.provenance.json', b'dynamic provenance\n'),
            (self.dynamic / 'bin/crabc-cc-dynamic', b'dynamic driver\n'),
            (self.dynamic / 'usr/lib/libc.so', b'dynamic libc\n'),
            (self.dynamic / 'lib/ld-crabc-x86_64.so.1', b'dynamic loader\n'),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        self.base = self._write('base-inventory.json', b'base\n')
        self.elf = self._write('elf-facts.json', b'elf\n')
        self.preparation = self._write('preparation.json', b'preparation\n')
        self.report_path = self._write('stdio-alias-report.json', b'{}\n')
        self.paths = {
            'measurement_checkout': ROOT,
            'base_inventory': self.base,
            'elf_report': self.elf,
            'static_preparation': self.preparation,
            'static_product': self.static,
            'dynamic_product': self.dynamic,
        }
        self.source = {'revision': 'a' * 40, 'content_sha256': 'b' * 64, 'clean': True}
        self.measurement = {
            'candidate_build': {
                'revision': self.source['revision'],
                'source_content_sha256': self.source['content_sha256'],
            },
            'reports': {
                key: selection.file_identity(self.paths[key])
                for key in ('base_inventory', 'elf_report', 'static_preparation')
            },
        }
        self.current = selection._stdio_alias_identities(self.paths)
        self.facts = {
            'artifacts': {
                'candidate-static': {'identity': self.current['static_libc']},
                'candidate-shared': {'identity': self.current['dynamic_libc']},
            },
            'facts': {
                'candidate-static': [],
                'reference-static': [],
                'candidate-shared': {'sections': [], 'symbol_tables': []},
                'reference-shared': {'sections': [], 'symbol_tables': []},
            },
        }

    def _write(self, name: str, payload: bytes) -> Path:
        path = self.work / name
        path.write_bytes(payload)
        return path

    @staticmethod
    def _receipt_identity(path: Path) -> dict[str, object]:
        value = selection.file_identity(path)
        return {
            'path': str(path.relative_to(ROOT)),
            'sha256': value['sha256'],
            'size': value['size'],
        }

    @staticmethod
    def _tree_row(path: Path) -> dict[str, object]:
        value = selection.file_identity(path)
        return {'kind': 'file', 'mode': value['mode'], 'sha256': value['sha256'], 'size': value['size']}

    def _tree(self, root: Path, relatives: tuple[str, ...]) -> dict[str, object]:
        return {relative: self._tree_row(root / relative) for relative in relatives}

    @staticmethod
    def _source_records(names: tuple[str, ...]) -> dict[str, object]:
        result = {}
        for name in names:
            value = selection.file_identity(ROOT / name)
            result[name] = {'path': name, 'sha256': value['sha256'], 'size': value['size']}
        return result

    def _receipt(self) -> dict[str, object]:
        static_relatives = (
            'share/crabc/manifest.json', 'share/crabc/libc-static.provenance.json',
            'bin/crabc-cc', 'usr/lib/libc.a',
        )
        dynamic_relatives = (
            'share/crabc/manifest.json', 'share/crabc/dynamic-product-state.json',
            'share/crabc/libc-shared.provenance.json', 'bin/crabc-cc-dynamic',
            'usr/lib/libc.so', 'lib/ld-crabc-x86_64.so.1',
        )
        aliases = {
            artifact: {'aliases': {}, 'protected': {}}
            for artifact in ('candidate-static', 'reference-static', 'candidate-shared', 'reference-shared')
        }
        source_record = {
            'revision': self.source['revision'], 'content_sha256': self.source['content_sha256'],
        }
        inputs = {
            'selected_source': copy.deepcopy(source_record),
            'producer_commands': {},
            'preparation': self._receipt_identity(self.preparation),
            'historical_facts': self._receipt_identity(self.elf),
            'static_preparation': {
                'primary': {
                    'path': str(self.static.relative_to(ROOT)),
                    'manifest': self._receipt_identity(self.static / 'share/crabc/manifest.json'),
                },
            },
            'dynamic_product': {
                'path': str(self.dynamic.relative_to(ROOT)),
                'manifest': self._receipt_identity(self.dynamic / 'share/crabc/manifest.json'),
            },
            'static_tree': self._tree(self.static, static_relatives),
            'dynamic_tree': self._tree(self.dynamic, dynamic_relatives),
            'state': self._receipt_identity(self.dynamic / 'share/crabc/dynamic-product-state.json'),
        }
        return {
            'schema': stdio_alias_evidence.SCHEMA,
            'status': copy.deepcopy(stdio_alias_evidence.STATUS),
            'image': 'sha256:' + '0' * 64,
            'contract': stdio_alias_evidence.contract(ROOT),
            'collector_source': source_record,
            'collector_files': self._source_records(stdio_alias_evidence.COLLECTOR_SOURCES),
            'selected_files': self._source_records(stdio_alias_evidence.RUNTIME_SOURCES),
            'inputs_before': inputs,
            'inputs_after': copy.deepcopy(inputs),
            'oracle': {}, 'oracle_static': {}, 'tools': {}, 'commands': {},
            'observations': {
                'complete_elf_facts': copy.deepcopy(self.facts['facts']),
                'aliases': aliases,
                'objects': {}, 'executables': {},
                'candidate_links': {
                    name: {}
                    for name in stdio_alias_evidence.binaries()
                    if name.startswith('candidate-')
                },
                'execution_roots': {},
                'runtime_labels': [row['label'] for row in stdio_alias_evidence.runtime_cells()],
            },
            'files': {},
        }

    def test_three_hidden_bodies_are_finite_private_receipt_owned_providers(self) -> None:
        contract = selection.load_contract(selection.CONTRACT_PATH)
        inputs = selection.load_source_inputs(contract, selection.CONTRACT_PATH)
        records = {row['identity']['name']: row for row in selection.expand_obligations(contract, inputs)}
        for name in stdio_alias_evidence.HIDDEN:
            with self.subTest(name=name):
                record = records[name]
                self.assertEqual(record['selection']['disposition'], 'private-provider')
                self.assertEqual(record['selection']['owner'], selection.STDIO_ALIAS_PRIVATE_OWNER)
                self.assertEqual(record['selection']['group'], selection.STDIO_ALIAS_PRIVATE_GROUP)
                self.assertEqual(record['unresolved'], [selection.STDIO_ALIAS_RECEIPT_REQUIREMENT])
                self.assertEqual(
                    record['expected_placements'],
                    [
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
                    ],
                )

    def test_adapter_binds_current_source_product_tree_and_complete_elf_facts(self) -> None:
        receipt = self._receipt()
        with mock.patch.object(stdio_alias_evidence, 'validate_report', return_value=receipt) as replay:
            companion = selection.native_stdio_alias_adapter(
                self.report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )
        replay.assert_called_once_with(ROOT, self.report_path)
        self.assertEqual(companion['status'], 'stdio-alias-observed-with-boundaries')
        self.assertEqual(
            set(companion['products']),
            {
                'static_manifest', 'static_driver', 'static_libc', 'static_provenance',
                'dynamic_manifest', 'dynamic_state', 'dynamic_driver', 'dynamic_libc',
                'dynamic_loader', 'dynamic_shared_provenance',
            },
        )

        changed_source = copy.deepcopy(receipt)
        source_path = stdio_alias_evidence.COLLECTOR_SOURCES[0]
        changed_source['collector_files'][source_path]['sha256'] = '0' * 64
        with mock.patch.object(stdio_alias_evidence, 'validate_report', return_value=changed_source), \
             self.assertRaisesRegex(selection.SelectionError, 'FILE collector source differs'):
            selection.native_stdio_alias_adapter(
                self.report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )

        changed_facts = copy.deepcopy(receipt)
        changed_facts['observations']['complete_elf_facts']['candidate-static'] = [{}]
        with mock.patch.object(stdio_alias_evidence, 'validate_report', return_value=changed_facts), \
             self.assertRaisesRegex(selection.SelectionError, 'FILE candidate-static archive path differs'):
            selection.native_stdio_alias_adapter(
                self.report_path, facts=self.facts, measurement=self.measurement,
                paths=self.paths, source=self.source,
            )

    def _actual_f168_accounting_and_companion(self):
        if not self._F168_RECEIPT.is_file() or not self._B525_FACTS.is_file():
            self.skipTest('requires the retained f168 FILE receipt and b525 complete ELF facts')
        self.assertEqual(
            hashlib.sha256(self._F168_RECEIPT.read_bytes()).hexdigest(),
            '82b02f29c1715d4896ce8e04d0576b8d6ebbfdfb7f3205c01fd704ded264b48b',
        )
        receipt = json.loads(self._F168_RECEIPT.read_text())
        facts = json.loads(self._B525_FACTS.read_text())
        contract = selection.load_contract(selection.CONTRACT_PATH)
        inputs = selection.load_source_inputs(contract, selection.CONTRACT_PATH)
        accounting = selection.account_placements(selection.expand_obligations(contract, inputs), facts)
        companion = {
            'status': 'stdio-alias-observed-with-boundaries',
            'reader': {}, 'contract': {}, 'report': {}, 'source': {},
            'source_inputs': {
                name: selection.file_identity(ROOT / name)
                for name in selection._stdio_alias_source_files()
            },
            'products': {}, 'measurement_reports': {},
            'account': {
                'aliases': receipt['observations']['aliases'],
                'runtime_labels': [row['label'] for row in stdio_alias_evidence.runtime_cells()],
                'candidate_link_labels': sorted(
                    name for name in stdio_alias_evidence.binaries() if name.startswith('candidate-')
                ),
            },
            'limits': list(selection.STDIO_ALIAS_LIMITS),
        }
        return accounting, companion

    def test_retained_f168_projection_joins_all_aliases_private_bodies_and_controls(self) -> None:
        accounting, companion = self._actual_f168_accounting_and_companion()
        joins = selection.attach_native_stdio_alias(accounting, companion)
        self.assertEqual(len(joins), 1)
        self.assertEqual(len(joins[0]['aliases']), len(stdio_alias_evidence.ALIASES))
        self.assertEqual(len(joins[0]['private_bodies']), len(stdio_alias_evidence.HIDDEN))
        self.assertEqual(len(joins[0]['protected_controls']), len(stdio_alias_evidence.PROTECTED))
        records = {row['identity']['name']: row for row in accounting['identities']}
        for name in stdio_alias_evidence.ALIASES:
            self.assertNotIn(
                'source-selected alias requires exact feature archive selection and component receipt',
                records[name]['unresolved'],
            )
        for name in stdio_alias_evidence.HIDDEN:
            self.assertNotIn(selection.STDIO_ALIAS_RECEIPT_REQUIREMENT, records[name]['unresolved'])

    def test_retained_f168_projection_rejects_changed_named_alias_target(self) -> None:
        accounting, companion = self._actual_f168_accounting_and_companion()
        companion = copy.deepcopy(companion)
        companion['account']['aliases']['candidate-static']['aliases']['fdopen']['target'] = 'fseeko'
        with self.assertRaisesRegex(selection.SelectionError, 'alias target differs: fdopen'):
            selection.attach_native_stdio_alias(accounting, companion)


if __name__ == '__main__':
    unittest.main()
