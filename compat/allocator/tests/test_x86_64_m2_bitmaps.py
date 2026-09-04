"""Fail-closed native bitmap fragment assembly, independent of Docker."""

import copy
import contextlib
import importlib.util
import unittest
from pathlib import Path
from unittest import mock

from test_runner import RUNNER


class NativeBitmapAssemblyTests(unittest.TestCase):
    @staticmethod
    def bitmap_evidence():
        pin = RUNNER.load_pin()
        return {
            'schema': 'crabc-mimalloc-x86_64-m2-bitmaps-evidence', 'format': 1,
            'status': 'passed', 'architecture': 'x86_64', 'profile': 'scalar-release-stat0',
            'upstream': {'revision': pin['revision'], 'archive_sha256': pin['sha256']},
            'rust_passed_test_count': 41, 'rust_execution_count': 1, 'rust_build_reused': True,
            'rust_tests': [f'bitmap::fixture_{index}' for index in range(41)],
            'rust_command': ['/workspace/.work/prepared-test', 'bitmap::', '--test-threads=1', '--nocapture'],
            'compared_value_count': 132184,
            'transcript_sha256': '78ff33552d928c12a9bd1e234d409e5d4dabaa77bd1ee9b7b9ee9b84966ceddb',
        }

    def summary(self):
        return RUNNER.validate_x86_64_m2_memory_substrate_contract(
            RUNNER.read_json(RUNNER.M2_X86_64_MEMORY_SUBSTRATE_CONTRACT), RUNNER.load_pin())

    def test_bitmap_fragment_is_complete_but_six_components_are_not(self):
        summary = self.summary()
        complete = [c['id'] for c in summary['components'] if c['native_status'] == 'complete']
        self.assertEqual(complete, ['bitmaps', 'page-map'])
        self.assertEqual(summary['milestone']['status'], 'partial')
        bitmap = summary['components'][2]
        self.assertEqual(len(bitmap['bounded_source_definitions']), 9)
        self.assertEqual(len(bitmap['failure_matrix']), 8)
        self.assertEqual([c['expected_passed_test_count'] for c in bitmap['checks']], [41, 41])

    def test_fragment_schema_anchor_failure_check_and_status_mutations_fail(self):
        original = RUNNER.read_json
        fragment = original(RUNNER.M2_X86_64_BITMAP_FRAGMENT)
        for mutation in ('schema', 'anchor', 'failure', 'check', 'status', 'predicate'):
            changed = copy.deepcopy(fragment)
            component = changed['component']
            if mutation == 'schema': changed['schema'] = 'aarch64-evidence'
            if mutation == 'anchor': component['bounded_source_definitions'].pop()
            if mutation == 'failure': component['failure_matrix'].pop()
            if mutation == 'check': component['checks'][0]['expected_passed_test_count'] = 40
            if mutation == 'status': component['completion_status'] = 'partial'
            if mutation == 'predicate': component['source_map_records'][0]['required_status'] = 'partial'
            with self.subTest(mutation=mutation), mock.patch.object(
                RUNNER, 'read_json', side_effect=lambda path: changed if path == RUNNER.M2_X86_64_BITMAP_FRAGMENT else original(path)
            ), self.assertRaises(RUNNER.HarnessError):
                self.summary()

    def test_partial_component_cannot_be_promoted_by_bitmap_evidence(self):
        contract = RUNNER.read_json(RUNNER.M2_X86_64_MEMORY_SUBSTRATE_CONTRACT)
        contract['components'][0]['native_status'] = 'complete'
        contract['components'][0]['remaining_conditions'] = []
        with self.assertRaises(RUNNER.HarnessError):
            RUNNER.validate_x86_64_m2_memory_substrate_contract(contract, RUNNER.load_pin())

    def test_bitmap_source_predicates_must_be_current(self):
        original = RUNNER.read_json
        for unit_id in ('bitmap-algorithms', 'bitmap-layout'):
            source_map = copy.deepcopy(original(RUNNER.X86_64_SOURCE_MAP_CONTRACT))
            next(row for row in source_map['units'] if row['id'] == unit_id)['status'] = 'partial'
            with self.subTest(unit=unit_id), mock.patch.object(
                RUNNER, 'read_json', side_effect=lambda path: source_map if path == RUNNER.X86_64_SOURCE_MAP_CONTRACT else original(path)
            ), self.assertRaisesRegex(RUNNER.HarnessError, 'source-map predicate is not current'):
                self.summary()

    def test_prepared_bitmap_producer_executes_the_supplied_binary_without_building(self):
        spec = importlib.util.spec_from_file_location('bitmap_producer_test', RUNNER.ALLOCATOR_ROOT / 'm2_bitmaps_x86_64.py')
        producer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(producer)
        harness = mock.MagicMock()
        harness.load_pin.return_value = RUNNER.load_pin()
        harness.CONFIGURATION_PROFILES = {'release': []}
        harness.temporary_directory.return_value = contextlib.nullcontext('.work/source-fixture')
        harness.safe_extract.return_value = Path('.work/source-fixture')
        harness.parse_rust_test_count.return_value = 41
        harness._m1_foundations_test_program.side_effect = AssertionError('a second build is forbidden')
        harness.command_record.side_effect = [
            {}, {'stdout': 'oracle'},
            {'stdout': '\n'.join(f'bitmap::fixture_{i}: test' for i in range(41))},
            {'stdout': 'rust', 'stderr': ''},
        ]
        prepared = {'path': Path('.work/prepared-test'), 'build_command': ['cargo', 'test', '--no-run']}
        # This test isolates build/execute routing, not the independently
        # tested transcript parser or pinned native differential values.
        with mock.patch.object(producer, 'transcript', return_value=[1]), mock.patch.object(producer, 'EXPECTED_OBSERVATION_COUNT', 1):
            evidence = producer.run_evidence(harness, offline=True, test_program=prepared)
        harness._m1_foundations_test_program.assert_not_called()
        self.assertTrue(evidence['rust_build_reused'])
        self.assertEqual(evidence['rust_execution_count'], 1)
        self.assertEqual(harness.command_record.call_args_list[-1].args[0],
            ['.work/prepared-test', 'bitmap::', '--test-threads=1', '--nocapture'])

    def report_arguments(self):
        summary = self.summary()
        evidence = self.bitmap_evidence()
        checks = RUNNER._m2_x86_64_bitmap_check_records(summary, evidence)
        for check in summary['components'][3]['checks']:
            row = {'component': 'page-map', 'command': ['/workspace/.work/prepared-test'],
                   'id': check['id'], 'passed_test_count': 1, 'target': check['target']}
            if check['kind'] != 'rust-unit':
                row['comparison_status'] = ('modeled-safety-divergence'
                    if check['id'] == 'cold-page-map-initialization-failure' else 'matched')
            checks.append(row)
        records = [{'component': component['id'], 'id': definition['id'],
                    'source_anchor': dict(definition['source_anchor'])}
                   for component in summary['components']
                   for definition in component.get('bounded_source_definitions', [])]
        return {
            'contract': RUNNER.read_json(RUNNER.M2_X86_64_MEMORY_SUBSTRATE_CONTRACT),
            'pin': RUNNER.load_pin(), 'summary': summary, 'source_attestation': {'status': 'clean'},
            'source_contract_evidence': {'status': 'passed'},
            'bounded_source_evidence': {'status': 'passed', 'record_count': len(records), 'records': records},
            'focused_checks': checks, 'bitmap_evidence': evidence,
        }

    def test_report_contains_actual_bitmap_checks_without_promoting_partial_components(self):
        report = RUNNER.m2_x86_64_memory_substrate_report(**self.report_arguments())
        self.assertEqual(len(report['milestone']['unmet_component_ids']), 6)
        self.assertEqual(report['milestone']['status'], 'partial')
        bitmap = report['components'][2]
        self.assertEqual(bitmap['status'], 'complete')
        self.assertEqual(len(bitmap['executed_checks']), 2)
        self.assertEqual({row['shared_execution_id'] for row in bitmap['executed_checks']}, {'native-bitmap-module'})

    def test_missing_result_count_schema_comparison_and_build_reuse_fail_closed(self):
        summary = self.summary()
        with self.assertRaises(RUNNER.HarnessError):
            RUNNER._m2_x86_64_bitmap_check_records(summary, None)
        for field, replacement in (
            ('schema', 'aarch64'), ('format', True), ('status', 'partial'),
            ('rust_passed_test_count', 40), ('rust_passed_test_count', True),
            ('rust_execution_count', 2), ('rust_build_reused', False),
            ('compared_value_count', 132183), ('transcript_sha256', '0' * 64),
            ('rust_tests', []), ('rust_command', []),
        ):
            evidence = self.bitmap_evidence()
            evidence[field] = replacement
            with self.subTest(field=field, value=replacement), self.assertRaises(RUNNER.HarnessError):
                RUNNER._m2_x86_64_bitmap_check_records(summary, evidence)

    def test_report_rejects_missing_or_weakened_executed_checks_and_source_anchors(self):
        for mutation in ('missing-result', 'missing-check', 'count', 'target', 'anchor', 'missing-anchor', 'duplicate-anchor'):
            args = self.report_arguments()
            if mutation == 'missing-result': args.pop('bitmap_evidence')
            if mutation == 'missing-check': args['focused_checks'].pop(0)
            if mutation == 'count': args['focused_checks'][0]['passed_test_count'] = 40
            if mutation == 'target': args['focused_checks'][0]['target'] = 'page_map::'
            records = args['bounded_source_evidence']['records']
            if mutation == 'anchor': records[0]['source_anchor']['sha256'] = '0' * 64
            if mutation == 'missing-anchor': records.pop()
            if mutation == 'duplicate-anchor': records[-1] = records[0]
            with self.subTest(mutation=mutation), self.assertRaises(RUNNER.HarnessError):
                RUNNER.m2_x86_64_memory_substrate_report(**args)


if __name__ == '__main__':
    unittest.main()
