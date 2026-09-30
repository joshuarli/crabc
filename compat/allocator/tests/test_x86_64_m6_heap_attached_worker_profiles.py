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
import x86_64_m6_heap_destroy_racing_detach as racing


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

    def test_timing_only_joined_trace_cannot_qualify_lock_contention(self):
        source = self.output / 'source'
        source.mkdir()
        baseline = self.observation(racing)
        observed = dict(baseline, stdout=baseline['stdout'].replace(racing.END,
            'race.destroy_before_drain=0\nrace.finish=128,0,0,0,0\n'
            'race.refusal=0,0,0,0\n' + racing.END))
        success = {'status': 0, 'stdout': '', 'stderr': ''}
        with mock.patch.object(racing, 'REPETITIONS', 1), \
             mock.patch.object(racing, 'ARTIFACTS', self.output / 'race'), \
             mock.patch.object(racing.harness, 'require_native_x86_64'), \
             mock.patch.object(racing.harness, 'load_pin', return_value={'archive_root': 'pinned'}), \
             mock.patch.object(racing.harness, 'fetch_archive', return_value=self.output / 'archive'), \
             mock.patch.object(racing.harness, 'safe_extract', return_value=source), \
             mock.patch.object(racing.harness, 'require_tool', side_effect=lambda name: name), \
             mock.patch.object(racing.harness, 'command_record',
                               side_effect=[success, baseline, success, success, observed]):
            with self.assertRaisesRegex(racing.harness.HarnessError, 'contention|rendezvous|overlap'):
                racing.run_differential(True, True)

    def causal_observation(self, *, waits='1', preserved='1', finish='129,0,0,0,0', side='c'):
        record = self.observation(racing)
        fields = f'race.destroy_before_drain=0\nrace.contention_waits={waits}\nrace.preserved_before_retry={preserved}\n'
        if side == 'rust':
            fields += f'race.finish={finish}\nrace.refusal=0,0,0,0\n'
        record['stdout'] = record['stdout'].replace(racing.END, fields + racing.END)
        return record

    def test_counter_without_failed_try_lock_cannot_release_the_proof(self):
        for waits in ('0', '-1', 'missing'):
            with self.subTest(waits=waits):
                with self.assertRaisesRegex(racing.harness.HarnessError, 'failed try-lock'):
                    racing.observed_trace(self.causal_observation(waits=waits), 'c', interleave=True)

    def test_failed_lock_must_preserve_live_clients_until_retry(self):
        with self.assertRaisesRegex(racing.harness.HarnessError, 'observations differ'):
            racing.observed_trace(self.causal_observation(preserved='0'), 'c', interleave=True)

    def test_joined_refusal_is_not_hidden_by_matching_owner_totals(self):
        with self.assertRaisesRegex(racing.harness.HarnessError, 'teardown refused'):
            racing.observed_trace(self.causal_observation(side='rust', finish='128,0,0,1,0'),
                                  'rust', audit=True, interleave=True)

    def test_scheduling_dependent_retry_totals_remain_raw_and_both_require_contention(self):
        source = self.causal_observation(waits='2')
        native = self.causal_observation(waits='37', side='rust')
        before = [record['stdout'] for record in (source, native)]
        self.assertEqual(racing.observed_trace(source, 'c', interleave=True),
                         racing.observed_trace(native, 'rust', audit=True, interleave=True))
        self.assertEqual(before, [record['stdout'] for record in (source, native)])

    def test_default_preserves_original_uncontrolled_workload_and_requires_all_causal_profiles(self):
        with mock.patch.object(racing, 'run_differential') as baseline, \
             mock.patch.object(racing, 'run_cohort', return_value=512) as causal:
            self.assertEqual(racing.main([]), 0)
        baseline.assert_called_once_with()
        causal.assert_called_once_with(racing.PROFILES)

    def test_retained_reader_binds_each_run_to_its_profile_compiler_output(self):
        profile = 'release'
        labels = ['c-build', 'c-run-00', 'rust-build', 'rust-link', 'rust-run-00']
        receipt = SimpleNamespace(path=self.output / 'receipt.json', source={},
            parameters=racing.parameters((profile,)),
            cases=[{'id': f'{profile}-{label}', 'logs': [f'{label}.json']} for label in labels],
            case_ids=lambda prefix: [f'{profile}-{label}' for label in labels])
        flags = list(racing.m4.api_profile_flags(profile))
        inputs = {'source': {}, 'upstream': {}, 'archive_sha256': 'hash',
            'profile': profile, 'allocator_flags': flags, 'execution': {'image_id': 'image'},
            'driver_sha256': 'hash', 'parameters': racing.parameters((profile,)),
            'rustflags': racing.AUDIT_RUSTFLAGS, 'compiler_sha256': 'hash'}
        receipt.parameters['repetitions'] = '1'
        inputs['parameters']['repetitions'] = '1'
        records = {}
        for label, side in [('c-build', 'c'), ('rust-link', 'rust')]:
            prefix = ['musl-gcc', '-std=c11', '-D_GNU_SOURCE']
            if side == 'c':
                prefix += ['-ftls-model=initial-exec', '-DMI_LIBC_MUSL=1']
            prefix += flags + ['-UNDEBUG']
            prefix += (['-DCRABC_C_THREAD_DONE_INTERLEAVE=1'] if side == 'c' else
                ['-DCRABC_NATIVE_THREAD_DONE_AUDIT=1', '-DCRABC_NATIVE_THREAD_DONE_INTERLEAVE=1'])
            records[label + '.json'] = {'status': 0, 'command': prefix + ['driver.c', '-pthread', '-o', side]}
        records['rust-build.json'] = {'status': 0, 'command': ['cargo', 'build', '--locked',
            '--release', '--target', racing.m4.RUST_TARGET, '-p', racing.m4.ADAPTER_PACKAGE,
            '--target-dir', 'private-target']}
        for side in ('c', 'rust'):
            records[f'{side}-run-00.json'] = dict(self.causal_observation(side=side), command=[side])
        def read(path):
            if path.name == 'release-inputs.json':
                return inputs
            if path.name == 'release-native-execution-provenance.json':
                return {}
            return records[path.name]
        with mock.patch.object(racing, 'REPETITIONS', 1), \
             mock.patch.object(racing.receipts, 'read_receipt', return_value=receipt), \
             mock.patch.object(racing.harness, 'require_native_x86_64', return_value={'image_id': 'image'}), \
             mock.patch.object(racing.harness, 'load_pin', return_value={}), \
             mock.patch.object(racing.harness, 'sha256_file', return_value='hash'), \
             mock.patch.object(racing.harness, 'require_tool', side_effect=lambda name: name), \
             mock.patch.object(racing.harness, 'validate_native_execution_provenance'), \
             mock.patch.object(racing.harness, 'read_json', side_effect=read):
            self.assertEqual(racing.read_cohort((profile,)), 0)
            records['rust-run-00.json']['command'] = ['c']
            with self.assertRaisesRegex(racing.harness.HarnessError, 'executable differs'):
                racing.read_cohort((profile,))

    def test_selected_profile_reader_cannot_silently_expand_or_shrink_its_profile_request(self):
        with mock.patch.object(racing, 'read_cohort', return_value=0) as reader:
            self.assertEqual(racing.main(['--profile', 'stat-2', '--replay']), 0)
        reader.assert_called_once_with(('stat-2',), True)


if __name__ == '__main__':
    unittest.main()
