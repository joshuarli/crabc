"""Exercise full arena ownership producer observations and failure retention."""

import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import x86_64_m6_child_heap_in_arena as arena
import x86_64_m6_child_heap_in_arena_two_worker as two


class ArenaOwnershipProducerTests(unittest.TestCase):
    def setUp(self):
        root = arena.harness.ROOT / '.work' / 'tmp'
        root.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(temporary.cleanup)
        self.output = Path(temporary.name)
        self.drivers = {side: self.output / side for side in ('c', 'rust')}

    def observed(self, fixture, *, status=0, source=None):
        rows = fixture.SOURCE if source is None else source
        return {'status': status,
            'stdout': '\n'.join([fixture.BEGIN,
                *(f'{key}={value}' for key, value in fixture.EXPECTED.items()), fixture.END]) + '\n',
            'stderr': '\n'.join(f'{key}={value}' for key, value in rows.items())}

    def test_failed_owner_lifetime_run_retains_both_raw_records_and_stops_comparison(self):
        for fixture in (arena, two):
            with self.subTest(fixture=fixture.RUNNER):
                failure = self.observed(fixture, status=-6)
                with mock.patch.object(arena.harness, 'command_record',
                     side_effect=[self.observed(fixture), failure]) as execute, \
                     mock.patch.object(arena.m7, 'compare_options_traces') as compare:
                    with self.assertRaises(arena.harness.HarnessError):
                        arena.observe(fixture, self.drivers, self.output, [], 'debug-1')
                compare.assert_not_called()
                self.assertEqual(execute.call_count, 2)
                self.assertEqual(json.loads((self.output / 'rust.json').read_text()), failure)
                self.assertEqual((self.output / 'rust.log').read_text(), failure['stdout'] + failure['stderr'])
                self.assertEqual(json.loads((self.output / 'c.json').read_text())['status'], 0)

    def test_pinned_source_detach_drift_stops_before_native_driver(self):
        changed = dict(two.SOURCE, **{'source.two_detached': '0,1,1,1'})
        record = self.observed(two, source=changed)
        with mock.patch.object(arena.harness, 'command_record', return_value=record) as execute:
            with self.assertRaises(arena.harness.HarnessError):
                arena.observe(two, self.drivers, self.output, [], 'stat-2')
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(json.loads((self.output / 'c.json').read_text()), record)
        self.assertFalse((self.output / 'rust.json').exists())

    def test_matrix_aborts_failed_profile_without_publishing_receipt(self):
        def run(fixture, profile, cases):
            output = self.output / profile
            output.mkdir()
            records = [self.observed(fixture), self.observed(fixture, status=-6 if profile == 'debug-1' else 0)]
            with mock.patch.object(arena.harness, 'command_record', side_effect=records):
                count = arena.observe(fixture, self.drivers, output, cases, profile)
            return count, {}
        with mock.patch.object(arena.receipts, 'source_seal', return_value={}), \
             mock.patch.object(arena, 'run_profile', side_effect=run) as run_profile, \
             mock.patch.object(arena.receipts, 'write_receipt') as publish:
            with self.assertRaises(arena.harness.HarnessError):
                arena.main(two, ['--matrix'])
        self.assertEqual([call.args[1] for call in run_profile.call_args_list], ['release', 'debug-1'])
        publish.assert_not_called()
        self.assertEqual(json.loads((self.output / 'release/rust.json').read_text())['status'], 0)
        self.assertEqual(json.loads((self.output / 'debug-1/rust.json').read_text())['status'], -6)

    def test_release_receipt_cannot_replay_as_four_profile_evidence(self):
        receipt = SimpleNamespace(parameters={'profiles': 'release', 'watchdog-seconds': '60',
            'workload-assertions': 'active'})
        with mock.patch.object(arena.receipts, 'read_receipt', return_value=receipt), \
             mock.patch.object(arena.harness, 'command_record') as execute:
            with self.assertRaises(arena.harness.HarnessError):
                arena.main(two, ['--matrix', '--replay'])
        execute.assert_not_called()

    def test_release_receipt_missing_native_owner_run_cannot_replay(self):
        receipt = SimpleNamespace(parameters={'profiles': 'release', 'watchdog-seconds': '60',
            'workload-assertions': 'active'}, case_ids=lambda prefix: ['release-c-build', 'release-rust-link', 'release-c-run'])
        with mock.patch.object(arena.receipts, 'read_receipt', return_value=receipt), \
             mock.patch.object(arena.harness, 'command_record') as execute:
            with self.assertRaises(arena.harness.HarnessError):
                arena.main(arena, ['--replay'])
        execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
