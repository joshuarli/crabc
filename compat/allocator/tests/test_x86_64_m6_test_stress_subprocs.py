"""Check authentic subprocess stress dispatch and failure retention."""

import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import x86_64_m6_test_stress_subprocs as stress


class SubprocessStressDispatchTests(unittest.TestCase):
    def setUp(self):
        root = stress.harness.ROOT / '.work' / 'tmp'
        root.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(self.directory.cleanup)
        self.artifacts = Path(self.directory.name)
        self.drivers = {'c': self.artifacts / 'c', 'rust': self.artifacts / 'rust'}

    def observation(self, case, status=0, stdout=None):
        return {'status': status, 'stdout': stress.expected_stdout(case) if stdout is None else stdout,
                'stderr': 'source statistics\n'}

    def test_failed_smallest_rust_case_retains_raw_failure_and_stops_before_larger_case(self):
        smallest = (1, 1, 1)
        failure = self.observation(smallest, status=-6, stdout='before abort\n')
        with mock.patch.object(stress.harness, 'command_record', side_effect=[self.observation(smallest), failure]) as execute:
            with self.assertRaises(stress.harness.HarnessError):
                stress.run_cases(self.drivers, self.artifacts, (smallest, (2, 1, 1)))
        self.assertEqual(execute.call_count, 2)
        retained = json.loads((self.artifacts / 'case-1-1-1-rust.json').read_text())
        self.assertEqual(retained, failure)
        self.assertEqual((self.artifacts / 'case-1-1-1-rust.log').read_text(), 'before abort\nsource statistics\n')

    def test_successful_exit_with_wrong_source_mode_does_not_start_rust(self):
        large = (1, 101, 5)
        wrong = self.observation(large, stdout=stress.expected_stdout((1, 100, 5)))
        with mock.patch.object(stress.harness, 'command_record', return_value=wrong) as execute:
            with self.assertRaises(stress.harness.HarnessError):
                stress.run_cases(self.drivers, self.artifacts, (large,))
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(json.loads((self.artifacts / 'case-1-101-5-c.json').read_text()), wrong)

    def test_each_case_runs_both_backends_in_order_with_source_cli_and_no_cleanup_process(self):
        cases = ((1, 1, 1), (2, 10, 10), (8, 150, 20))
        observations = [self.observation(case) for case in cases for _ in self.drivers]
        with mock.patch.object(stress.harness, 'command_record', side_effect=observations) as execute:
            self.assertEqual(stress.run_cases(self.drivers, self.artifacts, cases), len(cases))
        self.assertEqual([call.args[0] for call in execute.call_args_list],
                         [[str(self.drivers[side]), *map(str, case)] for case in cases for side in self.drivers])
        self.assertTrue(all(call.kwargs['env'] == {} for call in execute.call_args_list))


    def test_debug_allocator_mode_does_not_disable_unchanged_workload_assertions(self):
        translations = stress.build_translations('musl-gcc', self.artifacts,
            self.artifacts / 'workload.o', self.artifacts / 'allocator.o', 'debug-1')
        caller = translations['workload']
        allocator = translations['pinned-allocator']
        self.assertFalse(any(argument.startswith('-DNDEBUG') for argument in caller))
        self.assertIn('-DMI_DEBUG=0', caller)
        self.assertIn('-DMI_STAT=0', caller)
        self.assertIn('-DMI_DEBUG=1', allocator)
        self.assertIn('-DMI_STAT=2', allocator)
        self.assertIn('-DMI_PADDING=1', allocator)

    def test_matrix_stops_at_debug_failure_retains_both_profiles_and_publishes_no_pass(self):
        smallest = (1, 1, 1)
        failure = self.observation(smallest, status=-6, stdout='debug assertion before abort\n')
        def run_profile(profile, receipt_cases):
            directory = self.artifacts / profile
            directory.mkdir()
            drivers = {side: directory / side for side in ('c', 'rust')}
            records = [self.observation(smallest),
                       failure if profile == 'debug-1' else self.observation(smallest)]
            with mock.patch.object(stress.harness, 'command_record', side_effect=records):
                stress.run_cases(drivers, directory, (smallest,), receipt_cases=receipt_cases, profile=profile)
            return {}
        with mock.patch.object(stress.receipts, 'source_seal', return_value={'revision': 'source'}), \
             mock.patch.object(stress, 'run_profile', side_effect=run_profile) as run, \
             mock.patch.object(stress.receipts, 'write_receipt') as publish:
            with self.assertRaises(stress.harness.HarnessError):
                stress.main(['--matrix'])
        self.assertEqual([call.args[0] for call in run.call_args_list], ['release', 'debug-1'])
        publish.assert_not_called()
        self.assertEqual(json.loads((self.artifacts / 'debug-1/case-1-1-1-rust.json').read_text()), failure)
        self.assertEqual(json.loads((self.artifacts / 'release/case-1-1-1-rust.json').read_text())['status'], 0)
        self.assertFalse((self.artifacts / 'stat-1').exists())

    def test_release_receipt_cannot_satisfy_requested_four_profile_cohort(self):
        receipt = SimpleNamespace(parameters={'profiles': 'release', 'watchdog-seconds': '300',
            'boundary': 'unprefixed-native-mi-adapter', 'workload-assertions': 'active'})
        with mock.patch.object(stress.receipts, 'read_receipt', return_value=receipt), \
             mock.patch.object(stress.harness, 'command_record') as execute:
            with self.assertRaises(stress.harness.HarnessError):
                stress.main(['--matrix', '--replay'])
        execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
