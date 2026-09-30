"""Exercise Theap profile execution and observable failure retention."""

import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import x86_64_m6_public_theap as theap


class TheapProducerTests(unittest.TestCase):
    def setUp(self):
        root = theap.harness.ROOT / '.work' / 'tmp'
        root.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(temporary.cleanup)
        self.output = Path(temporary.name)
        self.drivers = {side: self.output / side for side in ('c', 'rust')}

    def observation(self, *, visitor=None):
        trace = dict(theap.SOURCE_TRACE)
        if visitor is not None:
            trace['main.visitor'] = visitor
        return {'status': 0, 'stdout': '\n'.join([theap.BEGIN,
            *(f'{key}={value}' for key, value in trace.items()), theap.END]) + '\n',
            'stderr': '\n'.join(f'source.{context}=1,1,1\nsource.{context}.collect_empty=1'
                for context in ('main', 'worker', 'child', 'fork')) + '\n'}

    def test_successful_process_with_wrong_visitor_geometry_is_retained_and_rejected(self):
        changed = self.observation(visitor='0,0,1,1,1,1,1,1')
        with mock.patch.object(theap.harness, 'command_record',
             side_effect=[self.observation(), changed]):
            with self.assertRaises(theap.harness.HarnessError):
                theap.observe(self.drivers, self.output, 'debug-1', False, [])
        self.assertEqual(json.loads((self.output / 'rust.json').read_text()), changed)
        self.assertEqual((self.output / 'rust.log').read_text(), changed['stdout'] + changed['stderr'])
        self.assertEqual(json.loads((self.output / 'c.json').read_text())['status'], 0)

    def test_matrix_stops_at_callback_mismatch_without_publishing_a_receipt(self):
        def run(profile, guarded, cases):
            directory = self.output / profile
            directory.mkdir()
            records = [self.observation(), self.observation(
                visitor='0,0,1,1,1,1,1,1' if profile == 'debug-1' else None)]
            with mock.patch.object(theap.harness, 'command_record', side_effect=records):
                count = theap.observe(self.drivers, directory, profile, guarded, cases)
            return count, {}
        with mock.patch.object(theap.receipts, 'source_seal', return_value={}), \
             mock.patch.object(theap, 'run_profile', side_effect=run) as execute, \
             mock.patch.object(theap.receipts, 'write_receipt') as publish:
            with self.assertRaises(theap.harness.HarnessError):
                theap.cli(['--matrix'])
        self.assertEqual([call.args[0] for call in execute.call_args_list], ['release', 'debug-1'])
        publish.assert_not_called()
        self.assertTrue((self.output / 'release/c.json').is_file())
        self.assertTrue((self.output / 'debug-1/rust.json').is_file())

    def test_guarded_only_receipt_cannot_replay_as_full_allocation_contract(self):
        receipt = SimpleNamespace(parameters=theap.parameters(theap.PROFILES, True))
        with mock.patch.object(theap.receipts, 'read_receipt', return_value=receipt), \
             mock.patch.object(theap.harness, 'command_record') as execute:
            with self.assertRaises(theap.harness.HarnessError):
                theap.cli(['--matrix', '--replay'])
        execute.assert_not_called()

    def test_successful_cargo_exit_with_zero_executed_tests_is_rejected(self):
        record = {'status': 0, 'stdout': 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;\n',
                  'stderr': ''}
        with mock.patch.object(theap.harness, 'require_tool', return_value='cargo'), \
             mock.patch.object(theap.harness, 'command_record', return_value=record) as execute:
            with self.assertRaises(theap.harness.HarnessError):
                theap.native_controls(self.output, 'stat-2', [])
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(json.loads((self.output / 'native_theap_contract.json').read_text()), record)


if __name__ == '__main__':
    unittest.main()
