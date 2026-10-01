"""Check child-Heap profile selection and retained execution boundaries."""

from contextlib import ExitStack
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import x86_64_m6_public_child_heap as public
import x86_64_m6_child_main_heap_reuse as reuse
import x86_64_m6_heap_visit_profiles as heap_visit
import x86_64_m6_child_main_heap_visitor as child_visit
import x86_64_m6_child_abandoned_visitor as abandoned_visit


class ChildHeapProfileTests(unittest.TestCase):
    def test_default_remains_the_full_release_differential(self):
        for runner in (public, reuse):
            with self.subTest(runner=runner.__name__), mock.patch.object(
                runner, 'run_differential', return_value=17
            ) as differential, mock.patch.object(runner, 'run_matrix', create=True) as matrix:
                runner.main([])
                differential.assert_called_once_with('release')
                matrix.assert_not_called()

    def test_matrix_executes_the_complete_profile_set(self):
        for runner in (public, reuse):
            with self.subTest(runner=runner.__name__), mock.patch.object(
                runner, 'run_matrix', create=True
            ) as matrix, mock.patch.object(runner, 'run_differential') as differential:
                runner.main(['--matrix'])
                matrix.assert_called_once_with()
                differential.assert_not_called()

    def test_conflicting_execution_or_reader_selection_is_rejected_before_work(self):
        selections = (['--matrix', '--profile', 'debug-1'], ['--read', '--profile', 'stat-1'],
                      ['--replay', '--matrix'], ['--read', '--replay'])
        for runner in (public, reuse):
            for arguments in selections:
                with self.subTest(runner=runner.__name__, arguments=arguments), mock.patch.object(
                    runner, 'run_differential'
                ) as differential, mock.patch.object(runner, 'run_matrix', create=True) as matrix:
                    with self.assertRaises(SystemExit) as error:
                        runner.main(arguments)
                    self.assertEqual(error.exception.code, 2)
                    differential.assert_not_called()
                    matrix.assert_not_called()

    def test_development_profile_runs_without_claiming_a_canonical_matrix(self):
        for runner in (public, reuse):
            with self.subTest(runner=runner.__name__), mock.patch.object(
                runner, 'run_differential', return_value=10
            ) as differential, mock.patch.object(runner, 'run_matrix', create=True) as matrix:
                runner.main(['--profile', 'debug-1'])
                differential.assert_called_once_with('debug-1')
                matrix.assert_not_called()


    def test_source_ownership_assertions_remain_required_in_every_c_profile(self):
        for runner in (public, reuse):
            trace = public.EXPECTED if runner is public else reuse.SOURCE_TRACE
            stdout = runner.BEGIN + "\n" + "\n".join(f"{key}={value}" for key, value in trace.items()) + "\n" + runner.END + "\n"
            stderr = ("\n".join(f"{key}={value}" for key, value in public.SOURCE.items()) + "\n"
                      if runner is public else "source.reuse=1,1,1,1,1,1,1,1,1,1\n")
            self.assertEqual(runner.observations(stdout, stderr, 'c'), trace)
            wrong = (stderr.replace('source.theaps=1,1,1,0', 'source.theaps=0,1,1,0')
                     if runner is public else stderr.replace('source.reuse=1,', 'source.reuse=0,'))
            with self.subTest(runner=runner.__name__), self.assertRaises(runner.harness.HarnessError):
                runner.observations(stdout, wrong, 'c')

    def test_partial_profile_receipt_cannot_be_read_as_the_complete_matrix(self):
        for runner in (public, reuse):
            receipt = SimpleNamespace(parameters={'profiles': ','.join(runner.PROFILES)},
                case_ids=lambda: [f'{profile}-{backend}-run' for profile in runner.PROFILES[:-1]
                                  for backend in ('c', 'native')])
            with self.subTest(runner=runner.__name__), mock.patch.object(
                runner.receipts, 'read_receipt', return_value=receipt
            ), self.assertRaises(runner.receipts.ReceiptError):
                runner.main(['--read'])

    def test_failed_c_profile_retains_exact_raw_bytes_and_cannot_publish_a_receipt(self):
        for runner in (public, reuse):
            work = runner.harness.ROOT / '.work/tmp'
            work.mkdir(parents=True, exist_ok=True)
            with self.subTest(runner=runner.__name__), tempfile.TemporaryDirectory(dir=work) as name, ExitStack() as stack:
                root = Path(name)
                source = root / 'source'
                (source / 'include').mkdir(parents=True)
                (source / 'include/mimalloc.h').write_text('test header\n')
                (source / 'LICENSE').write_text('test license\n')
                artifacts = root / 'artifacts'
                build = {'kind': 'process', 'status': 0, 'stdout': runner.stress.bytes_record(b''),
                         'stderr': runner.stress.bytes_record(b'')}
                raw = b'before abort\xff\n'
                failed = {'kind': 'process', 'status': -6, 'stdout': runner.stress.bytes_record(raw),
                          'stderr': runner.stress.bytes_record(b'upstream assertion\n')}
                stack.enter_context(mock.patch.object(runner, 'ARTIFACTS', artifacts))
                stack.enter_context(mock.patch.object(runner.harness, 'require_native_x86_64', return_value={}))
                stack.enter_context(mock.patch.object(runner.receipts, 'source_seal', return_value={}))
                stack.enter_context(mock.patch.object(runner.harness, 'fetch_archive', return_value=root / 'archive'))
                stack.enter_context(mock.patch.object(runner.harness, 'safe_extract', return_value=source))
                stack.enter_context(mock.patch.object(runner.harness, 'require_tool', return_value='test-compiler'))
                execute = stack.enter_context(mock.patch.object(runner.stress, 'command_record', side_effect=[build, failed]))
                publish = stack.enter_context(mock.patch.object(runner.receipts, 'write_receipt'))
                with self.assertRaises(runner.harness.HarnessError):
                    runner.run_matrix()
                self.assertEqual(execute.call_count, 2)
                publish.assert_not_called()
                output = next(artifacts.glob('matrix-*'))
                self.assertEqual(json.loads((output / 'release-c-run.json').read_text()), failed)
                self.assertEqual((output / 'release-c-run.stdout').read_bytes(), raw)


    def test_replay_rejects_a_different_native_image_before_executing_a_caller(self):
        for runner in (public, reuse):
            work = runner.harness.ROOT / '.work/tmp'
            with self.subTest(runner=runner.__name__), tempfile.TemporaryDirectory(dir=work) as name:
                root = Path(name)
                (root / 'products').mkdir()
                recorded = {'execution_mode': 'native', 'host_architecture': 'x86_64',
                            'image_id': 'sha256:' + '0' * 64}
                (root / 'products/inputs.json').write_text(json.dumps({'execution': recorded}))
                receipt = SimpleNamespace(path=root / 'receipt.json', parameters={'profiles': ','.join(runner.PROFILES)},
                    cases=[], case_ids=lambda: [f'{profile}-{backend}-run' for profile in runner.PROFILES
                                               for backend in ('c', 'native')])
                current = dict(recorded, image_id='sha256:' + '1' * 64)
                with mock.patch.object(runner.receipts, 'read_receipt', return_value=receipt), mock.patch.object(
                    runner.harness, 'require_native_x86_64', return_value=current
                ), mock.patch.object(runner, 'record') as execute:
                    with self.assertRaisesRegex(runner.harness.HarnessError, 'image differs'):
                        runner.main(['--replay'])
                    execute.assert_not_called()


class VisitationProfileSelectionTests(unittest.TestCase):
    runners = (heap_visit, child_visit, abandoned_visit)
    defaults = ('release', 'debug-1', 'stat-1', 'stat-2')

    def execute(self, runner, arguments):
        with mock.patch.object(sys, 'argv', [runner.__name__, *arguments]):
            runner.main()

    def test_secure_single_profile_routes_the_exact_development_selection(self):
        for runner in self.runners:
            for profile in ('secure-1', 'secure-2'):
                method = 'run' if runner is heap_visit else 'run_profiles'
                with self.subTest(runner=runner.__name__, profile=profile), mock.patch.object(runner, method) as run:
                    self.execute(runner, ['--profile', profile])
                    run.assert_called_once_with((profile,))

    def test_explicit_secure_cohort_routes_the_closed_requested_roster(self):
        for runner in self.runners:
            method = 'run' if runner is heap_visit else 'run_profiles'
            with self.subTest(runner=runner.__name__), mock.patch.object(runner, method) as run:
                self.execute(runner, ['--profiles', 'secure-1', 'secure-2'])
                run.assert_called_once_with(('secure-1', 'secure-2'), canonical=True)

    def test_default_workload_preserves_the_historical_profile_selection(self):
        for runner in self.runners:
            method = 'run' if runner is heap_visit else 'run_profiles'
            arguments = [] if runner is heap_visit else ['--matrix']
            with self.subTest(runner=runner.__name__), mock.patch.object(runner, method) as run:
                self.execute(runner, arguments)
                run.assert_called_once_with(self.defaults)

    def test_unknown_duplicate_or_conflicting_profiles_fail_before_work(self):
        for runner in self.runners:
            method = 'run' if runner is heap_visit else 'run_profiles'
            for arguments in (['--profiles'], ['--profiles', 'secure-3'],
                              ['--profiles', 'secure-1', 'secure-1'],
                              ['--profiles', 'secure-1', '--profile', 'release']):
                with self.subTest(runner=runner.__name__, arguments=arguments), \
                     mock.patch.object(runner, method) as run, mock.patch('sys.stderr'):
                    with self.assertRaises(SystemExit) as stopped:
                        self.execute(runner, arguments)
                    self.assertEqual(stopped.exception.code, 2)
                    run.assert_not_called()

    def receipt(self, root, profiles, parameters=None, cases=None):
        (root / 'products').mkdir()
        (root / 'products/inputs.json').write_text(json.dumps({'profiles': list(profiles)}))
        case_ids = [f'{profile}-{backend}-run' for profile in profiles for backend in ('c', 'native')]
        return SimpleNamespace(path=root / 'receipt.json',
            parameters={'profiles': ','.join(profiles) if parameters is None else parameters},
            case_ids=lambda: case_ids if cases is None else cases)

    def test_direct_cohort_rejects_empty_unknown_or_duplicate_selection_before_execution(self):
        for runner in self.runners:
            method = runner.run if runner is heap_visit else runner.run_profiles
            for profiles in ((), ('secure-3',), ('secure-1', 'secure-1')):
                with self.subTest(runner=runner.__name__, profiles=profiles), \
                     mock.patch.object(runner.harness, 'require_native_x86_64') as execute:
                    with self.assertRaises(runner.harness.HarnessError):
                        method(profiles, canonical=True)
                    execute.assert_not_called()

    def test_reader_rejects_retained_inputs_with_another_profile_roster(self):
        for runner in self.runners:
            work = runner.harness.ROOT / '.work/tmp'
            with self.subTest(runner=runner.__name__), tempfile.TemporaryDirectory(dir=work) as name:
                root = Path(name)
                receipt = self.receipt(root, self.defaults)
                (root / 'products/inputs.json').write_text(json.dumps({'profiles': ['secure-1', 'secure-2']}))
                with mock.patch.object(runner.receipts, 'read_receipt', return_value=receipt), \
                     self.assertRaises(runner.receipts.ReceiptError):
                    self.execute(runner, ['--read'])

    def test_reader_rejects_wrong_replay_image_before_executing_products(self):
        for runner in self.runners:
            work = runner.harness.ROOT / '.work/tmp'
            with self.subTest(runner=runner.__name__), tempfile.TemporaryDirectory(dir=work) as name:
                root = Path(name)
                receipt = self.receipt(root, ('secure-1', 'secure-2'))
                prior = {'execution_mode': 'native', 'host_architecture': 'x86_64', 'image_id': 'sha256:' + '0' * 64}
                (root / 'products/inputs.json').write_text(json.dumps({'profiles': ['secure-1', 'secure-2'], 'execution': prior}))
                current = dict(prior, image_id='sha256:' + '1' * 64)
                with mock.patch.object(runner.receipts, 'read_receipt', return_value=receipt), \
                     mock.patch.object(runner.harness, 'require_native_x86_64', return_value=current), \
                     mock.patch.object(runner, 'record') as execute:
                    with self.assertRaisesRegex(runner.harness.HarnessError, 'image differs'):
                        self.execute(runner, ['--profiles', 'secure-1', 'secure-2', '--replay'])
                    execute.assert_not_called()

    def test_reader_rejects_a_wrong_or_missing_declared_profile_selector(self):
        for runner in self.runners:
            work = runner.harness.ROOT / '.work/tmp'
            work.mkdir(parents=True, exist_ok=True)
            for selector in (None, 'secure-1', ','.join(reversed(self.defaults))):
                with self.subTest(runner=runner.__name__, selector=selector), tempfile.TemporaryDirectory(dir=work) as name:
                    receipt = self.receipt(Path(name), self.defaults)
                    receipt.parameters = {} if selector is None else {'profiles': selector}
                    with mock.patch.object(runner.receipts, 'read_receipt', return_value=receipt), \
                         self.assertRaises(runner.receipts.ReceiptError):
                        self.execute(runner, ['--read'])

    def test_secure_reader_cannot_accept_old_or_partial_runtime_roster(self):
        profiles = ('secure-1', 'secure-2')
        for runner in self.runners:
            work = runner.harness.ROOT / '.work/tmp'
            for cases in ([f'{profile}-{backend}-run' for profile in self.defaults for backend in ('c', 'native')],
                          ['secure-1-c-run', 'secure-1-native-run', 'secure-2-c-run']):
                with self.subTest(runner=runner.__name__, cases=cases), tempfile.TemporaryDirectory(dir=work) as name:
                    receipt = self.receipt(Path(name), profiles, cases=cases)
                    with mock.patch.object(runner.receipts, 'read_receipt', return_value=receipt), \
                         self.assertRaises(runner.receipts.ReceiptError):
                        self.execute(runner, ['--profiles', *profiles, '--read'])

    def test_reader_rejects_runtime_order_that_disagrees_with_requested_cohort(self):
        profiles = ('secure-1', 'secure-2')
        for runner in self.runners:
            work = runner.harness.ROOT / '.work/tmp'
            cases = [f'{profile}-{backend}-run' for profile in profiles for backend in ('c', 'native')]
            cases[0], cases[1] = cases[1], cases[0]
            with self.subTest(runner=runner.__name__), tempfile.TemporaryDirectory(dir=work) as name:
                receipt = self.receipt(Path(name), profiles, cases=cases)
                with mock.patch.object(runner.receipts, 'read_receipt', return_value=receipt), \
                     self.assertRaises(runner.receipts.ReceiptError):
                    self.execute(runner, ['--profiles', *profiles, '--read'])

    def test_complete_requested_cohort_and_historical_reader_are_accepted(self):
        for runner in self.runners:
            work = runner.harness.ROOT / '.work/tmp'
            for profiles in (self.defaults, ('secure-1', 'secure-2')):
                with self.subTest(runner=runner.__name__, profiles=profiles), tempfile.TemporaryDirectory(dir=work) as name:
                    receipt = self.receipt(Path(name), profiles)
                    with mock.patch.object(runner.receipts, 'read_receipt', return_value=receipt):
                        self.execute(runner, ['--profiles', *profiles, '--read'])


if __name__ == '__main__':
    unittest.main()
