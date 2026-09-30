"""Check attached-worker Heap observations and exact diagnostic retention."""

import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import x86_64_m6_heap_delete_with_attached_worker as attached
import x86_64_m6_heap_destroy_with_attached_worker as destroy


class AttachedWorkerProducerTests(unittest.TestCase):
    def setUp(self):
        root = attached.harness.ROOT / '.work' / 'tmp'
        root.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(temporary.cleanup)
        self.output = Path(temporary.name)
        self.drivers = {side: self.output / side for side in ('c', 'rust')}

    def observation(self, fixture, *, stderr='', status=0):
        return {'status': status, 'stdout': '\n'.join([fixture.BEGIN,
            *(f'{key}={value}' for key, value in fixture.EXPECTED.items()), fixture.END]) + '\n',
            'stderr': stderr}

    def test_equal_public_trace_with_different_diagnostic_bytes_is_rejected_and_retained(self):
        for fixture in (attached, destroy):
            with self.subTest(fixture=fixture.RUNNER):
                records = [self.observation(fixture, stderr='source diagnostic\n'),
                           self.observation(fixture, stderr='different diagnostic\n')]
                with mock.patch.object(attached.harness, 'command_record', side_effect=records):
                    with self.assertRaisesRegex(attached.harness.HarnessError, 'diagnostics differ'):
                        attached.observe(fixture, self.drivers, self.output, [], 'debug-1')
                self.assertEqual(json.loads((self.output / 'c.json').read_text()), records[0])
                self.assertEqual(json.loads((self.output / 'rust.json').read_text()), records[1])
                self.assertEqual((self.output / 'rust.log').read_text(), records[1]['stdout'] + records[1]['stderr'])

    def test_source_runtime_abort_stops_before_native_driver_and_preserves_stderr(self):
        record = self.observation(destroy, status=-6, stderr='source assertion\n')
        with mock.patch.object(attached.harness, 'command_record', return_value=record) as execute:
            with self.assertRaises(attached.harness.HarnessError):
                attached.observe(destroy, self.drivers, self.output, [], 'debug-1')
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(json.loads((self.output / 'c.json').read_text()), record)
        self.assertFalse((self.output / 'rust.json').exists())

    def test_matrix_stops_at_diagnostic_failure_without_publishing_receipt(self):
        def run(fixture, profile, cases):
            output = self.output / profile
            output.mkdir()
            records = [self.observation(fixture), self.observation(fixture,
                stderr='native diagnostic\n' if profile == 'debug-1' else '')]
            with mock.patch.object(attached.harness, 'command_record', side_effect=records):
                count = attached.observe(fixture, self.drivers, output, cases, profile)
            return count, {}
        with mock.patch.object(attached.receipts, 'source_seal', return_value={}), \
             mock.patch.object(attached, 'run_profile', side_effect=run) as execute, \
             mock.patch.object(attached.receipts, 'write_receipt') as publish:
            with self.assertRaises(attached.harness.HarnessError):
                attached.main(destroy, ['--matrix'])
        self.assertEqual([call.args[1] for call in execute.call_args_list], ['release', 'debug-1'])
        publish.assert_not_called()
        self.assertTrue((self.output / 'release/rust.json').is_file())
        self.assertTrue((self.output / 'debug-1/rust.json').is_file())

    def test_release_only_receipt_cannot_replay_as_full_profile_matrix(self):
        receipt = SimpleNamespace(parameters=attached.parameters(('release',)))
        with mock.patch.object(attached.receipts, 'read_receipt', return_value=receipt), \
             mock.patch.object(attached.harness, 'command_record') as execute:
            with self.assertRaises(attached.harness.HarnessError):
                attached.main(destroy, ['--matrix', '--replay'])
        execute.assert_not_called()


    def retained_profile(self, profile, *, c_status=0, rust_stderr='', native=True):
        output = self.output if profile == 'release' else self.output / profile
        output.mkdir(exist_ok=True)
        attached.harness.write_json(output / 'inputs.json', {'source': {'revision': 'original-frozen-source'}})
        attached.harness.write_json(output / 'c.json', self.observation(destroy, status=c_status))
        if native:
            attached.harness.write_json(output / 'rust.json', self.observation(destroy, stderr=rust_stderr))
        return output

    def test_collector_reports_failure_and_missing_sides_then_collects_later_available_profiles(self):
        self.retained_profile('release')
        self.retained_profile('debug-1', c_status=-11, native=False)
        self.retained_profile('stat-2')
        before = {p: p.read_bytes() for p in self.output.rglob('*.json')}
        with mock.patch.object(destroy, 'ARTIFACTS', self.output), \
             mock.patch.object(attached.harness, 'command_record') as execute, \
             mock.patch.object(attached.receipts, 'write_receipt') as publish, \
             mock.patch('builtins.print') as output:
            self.assertEqual(attached.main(destroy, ['--matrix', '--collect']), 1)
        execute.assert_not_called()
        publish.assert_not_called()
        printed = '\n'.join(str(call.args[0]) for call in output.call_args_list)
        self.assertIn('recorded status -11', printed)
        self.assertIn('debug-1 rust: missing observation', printed)
        self.assertIn('stat-1 c: missing observation', printed)
        self.assertIn('stat-2: existing traces and exact diagnostics match', printed)
        self.assertIn('original-frozen-source', printed)
        self.assertEqual(before, {p: p.read_bytes() for p in self.output.rglob('*.json')})

    def test_collector_rejects_exact_diagnostic_difference_without_any_execution_or_publication(self):
        self.retained_profile('release', rust_stderr='additional native diagnostic\n')
        with mock.patch.object(destroy, 'ARTIFACTS', self.output), \
             mock.patch.object(attached.harness, 'command_record') as execute, \
             mock.patch.object(attached.receipts, 'write_receipt') as publish:
            self.assertEqual(attached.main(destroy, ['--collect']), 1)
        execute.assert_not_called()
        publish.assert_not_called()

    def test_successful_existing_collection_preserves_default_cli_and_publishes_no_receipt(self):
        self.retained_profile('release')
        with mock.patch.object(destroy, 'ARTIFACTS', self.output), \
             mock.patch.object(attached.harness, 'command_record') as execute, \
             mock.patch.object(attached.receipts, 'write_receipt') as publish:
            self.assertEqual(attached.main(destroy, ['--collect']), 0)
        execute.assert_not_called()
        publish.assert_not_called()
        with mock.patch.object(attached, 'run_fixture', return_value=5) as run:
            self.assertEqual(attached.main(destroy, []), 0)
        self.assertEqual(run.call_args.args, (destroy, ('release',)))


if __name__ == '__main__':
    unittest.main()
