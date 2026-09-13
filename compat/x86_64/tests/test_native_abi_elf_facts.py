#!/usr/bin/env python3
"""Closed, source-bound ELF supplement receipt and complete table regressions."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('native_abi_elf_facts_test', ROOT / 'compat/x86_64/native_abi_elf_facts.py')
assert SPEC is not None and SPEC.loader is not None
facts = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = facts
SPEC.loader.exec_module(facts)

from compat.x86_64.tests.test_native_abi_inventory import HEADER, SECTIONS, STATIC


class CompleteElfFactTests(unittest.TestCase):
    def test_complete_shared_fact_join_does_not_accept_an_omitted_symbol_table(self):
        header = HEADER.replace('REL (Relocatable file)', 'DYN (Shared object file)')
        observed = facts.inventory.parse_elf_facts(header, SECTIONS, STATIC, expected_type='DYN')
        self.assertEqual(len(observed['symbol_tables']), 1)
        self.assertEqual(observed['symbol_tables'][0]['section_index'], 3)
        with self.assertRaises(facts.inventory.InventoryError):
            facts.inventory.parse_elf_facts(header, SECTIONS, '', expected_type='DYN')

    def test_closed_roster_preserves_static_and_dynamic_placements(self):
        self.assertEqual(len(facts.ARTIFACTS), 17)
        self.assertEqual(len({row.key for row in facts.ARTIFACTS}), 17)
        self.assertEqual(sum(4 if row.kind == 'archive' else 3 for row in facts.ARTIFACTS), 55)
        for relative in ('usr/lib/crt1.o', 'usr/lib/Scrt1.o', 'usr/lib/crti.o', 'usr/lib/crtn.o', 'usr/lib/libcrabc-builtins.a'):
            owners = {row.owner for row in facts.ARTIFACTS if row.relative == relative}
            self.assertEqual(owners, {'candidate-static', 'candidate-dynamic'})

    def test_shared_dynsym_and_symtab_both_require_independent_section_rows(self):
        header = HEADER.replace('REL (Relocatable file)', 'DYN (Shared object file)')
        header = header.replace('Number of section headers:         5', 'Number of section headers:         6')
        sections = SECTIONS.replace('5 section headers', '6 section headers')
        sections = sections.replace('.symtab', '.dynsym').replace('SYMTAB', 'DYNSYM')
        sections = sections.replace('Key to Flags:',
            '  [ 5] .symtab           SYMTAB          0000000000000000 000110 0000a8 18      4   3  8\nKey to Flags:')
        dynamic = STATIC.replace("'.symtab'", "'.dynsym'")
        observed = facts.inventory.parse_elf_facts(header, sections, dynamic + STATIC, expected_type='DYN')
        self.assertEqual([(t['name'], t['section_index']) for t in observed['symbol_tables']], [('.dynsym', 3), ('.symtab', 5)])
        with self.assertRaisesRegex(facts.inventory.InventoryError, 'counts differ'):
            facts.inventory.parse_elf_facts(header, sections, dynamic, expected_type='DYN')


# The v1 validation boundary is mocked in these receipt-unit tests; native
# acceptance independently invokes the real reader on sealed products. Artifact,
# raw stream, source-snapshot and supplement replay validation remain real here.
class ElfFactReceiptTests(unittest.TestCase):
    def setUp(self):
        work = ROOT / '.work/x86_64/native-abi-elf-facts-tests'
        work.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=work)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root / 'facts'
        self.output.mkdir()
        self.static = self.root / 'static'
        self.dynamic = self.root / 'dynamic'
        self.base_root = self.root / 'base'
        self.base_root.mkdir()
        self.base_path = self.base_root / 'report.json'
        self.preparation = self.root / 'preparation.json'
        self.preparation.write_text('{}\n')
        self.seal = {'revision': 'a' * 40, 'content_sha256': 'b' * 64, 'clean': True}
        self.base = {'image': 'crabc-core-evidence@sha256:' + 'c' * 64,
                     'collector_execution_source': self.seal,
                     'inputs': {'pinned_musl': {'regular_files': {}}}, 'tools': {},
                     'product_provenance': {'candidate_build': {'revision': 'd' * 40, 'source_content_sha256': 'e' * 64}},
                     'inventories': {'reference': {}, 'candidate': {}}}
        for owner, root, logical, key in (
            ('candidate-static', self.static, facts.inventory.STATIC_PRODUCT_PATH, 'static_product'),
            ('candidate-dynamic', self.dynamic, facts.inventory.DYNAMIC_PRODUCT_PATH, 'dynamic_product'),
        ):
            payloads = {}
            for item in facts.ARTIFACTS:
                if item.owner != owner:
                    continue
                path = root / item.relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'same fixture artifact bytes\n')
                payloads[item.relative] = facts.inventory.sha256(path)
            manifest = root / 'share/crabc/manifest.json'
            manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps(payloads))
            self.base['inputs'][key] = {'payload_files': payloads,
                'manifest': facts.inventory.file_record(manifest, logical_path=str(logical / 'share/crabc/manifest.json'))}
        for item in facts.ARTIFACTS:
            if item.owner == 'reference':
                path = self.root / item.key
                path.write_bytes(b'reference fixture artifact bytes\n')
                self.base['inputs']['pinned_musl']['regular_files'][item.relative] = facts.inventory._snapshot_regular(
                    self.base_root, path, 'inputs/musl-1.2.6/' + item.relative, str(facts.inventory.MUSL_ROOT / item.relative))
        tool_records = {}
        for name in facts.TOOL_NAMES:
            path = self.root / ('tool-' + name)
            path.write_bytes(b'fixture tool bytes\n')
            path.chmod(0o755)
            logical = str(facts.inventory.TOOL_PATHS[name])
            self.base['tools'][name] = facts.inventory._snapshot_regular(self.base_root, path, 'inputs/tools/' + name, logical)
            tool_records[name] = facts.inventory._snapshot_regular(self.output, path, 'inputs/tools/' + name, logical)
        dynamic = STATIC.replace("'.symtab'", "'.dynsym'").replace('<OS specific>: 12', 'NOTYPE').replace('<processor specific>: 13', 'GLOBAL')
        public = facts.inventory.parse_dynamic_symbols(dynamic)
        self.base['inventories']['reference']['shared'] = {'dynamic_symbols': public}
        self.base['inventories']['candidate']['shared'] = {'dynamic_symbols': public}
        self.base['inventories']['candidate']['loader'] = {'dynamic_symbols': public}
        self.base_path.write_bytes(facts.inventory._stable_json(self.base))
        source_records = facts._snapshot_sources(self.output)
        base_snapshot = facts.inventory._snapshot_regular(self.output, self.base_path, 'inputs/base-inventory-report.json', str(facts.BASE_REPORT))
        artifacts = facts._artifact_records(self.base, self.static, self.dynamic)
        commands, projected = {}, {}
        for item in facts.ARTIFACTS:
            artifact = artifacts[item.key]
            if item.kind == 'archive':
                def wrap(text):
                    return ''.join(f"\nFile: {artifact['identity']['path']}(same.o)\n{text}" for _ in range(2))
                raw = {'members': 'same.o\nsame.o\n', 'header': wrap(HEADER), 'sections': wrap(SECTIONS), 'symbols': wrap(STATIC)}
            elif item.elf_type == 'DYN':
                raw = {'header': HEADER.replace('REL (Relocatable file)', 'DYN (Shared object file)'),
                       'sections': SECTIONS.replace('.symtab', '.dynsym').replace('SYMTAB', 'DYNSYM'), 'symbols': dynamic}
            else:
                raw = {'header': HEADER, 'sections': SECTIONS, 'symbols': STATIC}
            for suffix, tool, flag in facts._command_specs(item):
                key = f'{item.key}-{suffix}'
                commands[key] = {'key': key, 'tool': tool, 'tool_identity': tool_records[tool],
                    'argv': [str(facts.inventory.TOOL_PATHS[tool]), flag, artifact['identity']['path']],
                    'cwd': '/workspace', 'artifact_key': item.key, 'artifact_before': artifact['identity'],
                    'artifact_after': artifact['identity'], 'collector_execution_source': self.seal,
                    'environment': dict(facts.inventory.TOOL_ENVIRONMENT), 'returncode': 0,
                    'stdout': facts.inventory._write_raw(self.output, key + '.stdout', raw[suffix]),
                    'stderr': facts.inventory._write_raw(self.output, key + '.stderr', '')}
            projected[item.key] = facts._project(item, raw, artifact, self.base)
        self.report = {'schema': facts.SCHEMA, 'target': facts.inventory.TARGET, 'image': self.base['image'],
            'status': dict(facts.STATUS), 'collector_execution_source': self.seal, 'collector_sources': source_records,
            'base_inventory': facts._base_binding(self.output, base_snapshot, self.base_path, self.base),
            'artifacts': artifacts, 'tools': tool_records, 'commands': commands, 'facts': projected}
        self.path = self.output / 'report.json'
        self.source_mock = mock.patch.object(facts.inventory, 'collector_source_seal', return_value=self.seal)
        self.source_mock.start()
        self.addCleanup(self.source_mock.stop)
        self.base_mock = mock.patch.object(facts.inventory, 'validate_report', return_value=self.base)
        self.validated_base = self.base_mock.start()
        self.addCleanup(self.base_mock.stop)

    def replay(self, report=None):
        self.path.write_bytes(facts.inventory._stable_json(self.report if report is None else report))
        return facts.validate_report(self.path, base_inventory=self.base_path, static_product=self.static,
                                     dynamic_product=self.dynamic, static_preparation=self.preparation)

    def test_valid_report_replays_full_rows_and_duplicate_member_occurrences(self):
        observed = self.replay()
        self.assertEqual(len(observed['artifacts']), 17)
        self.assertEqual(len(observed['commands']), 55)
        self.assertEqual([m['member_occurrence'] for m in observed['facts']['candidate-static']], [0, 1])
        rows = observed['facts']['candidate-shared']['symbol_tables'][0]['rows']
        self.assertTrue(any(row['visibility'] == 'HIDDEN' for row in rows))
        self.assertTrue(any(row['section_index'] == 'UND' and row['name'] is not None for row in rows))
        self.validated_base.assert_called_once_with(self.base_path, static_product=self.static,
                                                     dynamic_product=self.dynamic, static_preparation=self.preparation)

    def test_json_boolean_and_numeric_substitutions_are_not_equivalent_receipts(self):
        for change in ('status', 'row-index', 'raw-size'):
            report = copy.deepcopy(self.report)
            if change == 'status':
                report['status']['public_support'] = 0
            elif change == 'row-index':
                report['facts']['candidate-shared']['symbol_tables'][0]['rows'][0]['row_index'] = False
            else:
                report['commands']['candidate-shared-header']['stderr']['size'] = False
            with self.subTest(change=change), self.assertRaises(facts.inventory.InventoryError):
                self.replay(report)

    def test_missing_extra_and_duplicate_fact_rosters_are_rejected(self):
        for change in ('artifact-missing', 'artifact-extra', 'command-missing', 'command-extra', 'facts-missing', 'member-duplicate', 'row-dropped'):
            report = copy.deepcopy(self.report)
            if change == 'artifact-missing':
                del report['artifacts']['dynamic-builtins']
            elif change == 'artifact-extra':
                report['artifacts']['unselected'] = report['artifacts']['candidate-static']
            elif change == 'command-missing':
                del report['commands']['dynamic-builtins-symbols']
            elif change == 'command-extra':
                report['commands']['invented-command'] = report['commands']['candidate-shared-symbols']
            elif change == 'facts-missing':
                del report['facts']['static-crti.o']
            elif change == 'member-duplicate':
                report['facts']['candidate-static'].append(report['facts']['candidate-static'][0])
            else:
                report['facts']['candidate-shared']['symbol_tables'][0]['rows'].pop(3)
            with self.subTest(change=change), self.assertRaises(facts.inventory.InventoryError):
                self.replay(report)

    def test_source_build_and_command_authority_substitutions_are_rejected(self):
        for change in ('collector', 'build', 'argv', 'environment', 'tool', 'placement', 'returncode', 'raw-path'):
            report = copy.deepcopy(self.report)
            command = report['commands']['static-crt1.o-header']
            if change == 'collector':
                command['collector_execution_source']['revision'] = 'f' * 40
            elif change == 'build':
                report['base_inventory']['candidate_build']['revision'] = self.seal['revision']
            elif change == 'argv':
                command['argv'][1] = '-sW'
            elif change == 'environment':
                command['environment']['LC_ALL'] = 'en_US.UTF-8'
            elif change == 'tool':
                command['tool_identity']['original']['sha256'] = '0' * 64
            elif change == 'placement':
                command['artifact_before'] = report['artifacts']['dynamic-crt1.o']['identity']
            elif change == 'returncode':
                command['returncode'] = 1
            else:
                command['stderr'] = report['commands']['dynamic-crt1.o-header']['stderr']
            with self.subTest(change=change), self.assertRaises(facts.inventory.InventoryError):
                self.replay(report)

    def test_raw_hash_rebinding_cannot_admit_a_truncated_legend(self):
        report = copy.deepcopy(self.report)
        key = 'candidate-shared-sections'
        path = self.output / report['commands'][key]['stdout']['path']
        lines = path.read_text().splitlines()
        title = lines.index('Key to Flags:')
        report['commands'][key]['stdout'] = facts.inventory._write_raw(self.output, key + '.stdout', '\n'.join(lines[:title + 2]) + '\n')
        with self.assertRaisesRegex(facts.inventory.InventoryError, 'legend'):
            self.replay(report)

    def test_nonempty_diagnostics_are_rejected_even_with_success_and_matching_hash(self):
        report = copy.deepcopy(self.report)
        key = 'candidate-static-header'
        report['commands'][key]['stderr'] = facts.inventory._write_raw(self.output, key + '.stderr', 'readelf: unsupported member\n')
        with self.assertRaisesRegex(facts.inventory.InventoryError, 'diagnostic'):
            self.replay(report)

    def test_stale_base_source_or_failed_v1_validation_cannot_be_resealed(self):
        stale = copy.deepcopy(self.base)
        stale['collector_execution_source']['revision'] = 'f' * 40
        self.validated_base.return_value = stale
        with self.assertRaisesRegex(facts.inventory.InventoryError, 'same-current-collector'):
            self.replay()
        self.validated_base.side_effect = facts.inventory.InventoryError('base product receipt rejected')
        with self.assertRaisesRegex(facts.inventory.InventoryError, 'base product receipt rejected'):
            self.replay()

    def test_substituted_base_report_or_product_bytes_are_rejected(self):
        self.base_path.write_text('{}\n')
        with self.assertRaisesRegex(facts.inventory.InventoryError, 'base inventory report changed'):
            self.replay()
        self.base_path.write_bytes(facts.inventory._stable_json(self.base))
        (self.dynamic / 'usr/lib/crt1.o').write_bytes(b'different bytes')
        with self.assertRaisesRegex(facts.inventory.InventoryError, 'payload identity'):
            self.replay()

    def test_host_replay_never_runs_an_elf_inspection_command(self):
        with mock.patch.object(facts.subprocess, 'run', side_effect=AssertionError('native tool invoked by replay')):
            self.replay()

    def test_duplicate_json_keys_are_rejected_before_projection(self):
        self.path.write_text('{"schema":"first","schema":"second"}\n')
        with self.assertRaises(facts.inventory.InventoryError):
            facts.validate_report(self.path, base_inventory=self.base_path, static_product=self.static,
                                  dynamic_product=self.dynamic, static_preparation=self.preparation)


if __name__ == '__main__':
    unittest.main()
