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


if __name__ == '__main__':
    unittest.main()
