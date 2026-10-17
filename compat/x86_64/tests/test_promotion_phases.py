"""Host promotion joins both image readers with physical input custody."""
import hashlib
import json
import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import campaign_runner as runner
import campaign_promotion_closure as closure


class PromotionPhaseTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.work/tmp'
        scratch.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = {'revision': 'revision', 'content_sha256': 'source'}
        self.patch = patch.object(runner, 'ROOT', self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        identity = patch.object(closure.qualification, 'source_identity', side_effect=lambda: dict(self.source))
        identity.start()
        self.addCleanup(identity.stop)
        allocator = self.root / '.work/allocator-x86_64'
        for name in ('reports/allocator/x86_64', 'target/compat/allocator/x86_64',
                     'integrated', 'm10-native', 'allocator-cache'):
            (allocator / name).mkdir(parents=True)
        self.receipt = self.write('.work/x86_64/qualification-receipts/current/receipt.json', '{}')
        for pointer in ('owned-static-qualification.json', 'owned-dynamic-qualification.json',
                        'qualification-evidence/performance.release/performance-release.json'):
            selected = self.write('.work/selected/' + pointer + '/receipt.json', '{}')
            self.write('.work/x86_64/' + pointer, json.dumps({'receipt': str(selected)}))
        self.report = self.write('.work/allocator-x86_64/target/compat/allocator/x86_64/m9-gate/report.json', '{}')
        self.dependencies = [self.write('.work/performance/' + name, name)
                             for name in ('attempt/report.json', 'binary', 'diagnostics', 'source/input.rs')]
        self.expected = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in self.dependencies}
        self.partial = {'qualification_profile': 'full', 'source': dict(self.source),
                        'qualification_receipt': '/workspace/' + self.receipt.relative_to(self.root).as_posix(),
                        'functional_readiness': False, 'native_allocator_pending': True,
                        'allocator_qualification_profile': 'baseline', 'public_support': False}
        self.calls = []
        self.mutate = lambda phase: None
        self.actual_run = subprocess.run

    def write(self, name, contents):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
        return path

    def phase(self, command, **options):
        phase = 'core' if command == ['core'] else 'allocator'
        self.calls.append(phase)
        if phase == 'core':
            program = ('import hashlib,json,pathlib,sys; '
                       'expected=json.loads(sys.argv[1]); '
                       'sys.exit(0 if all(hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()==h '
                       'for p,h in expected.items()) else 1)')
            checked = self.actual_run([sys.executable, '-c', program, json.dumps(self.expected)], capture_output=True)
            result = subprocess.CompletedProcess(command, 3 if checked.returncode == 0 else 1,
                                                 json.dumps(self.partial), '')
        else:
            result = subprocess.CompletedProcess(command, 0, json.dumps({
                'qualification_profile': 'baseline', 'report': self.report.relative_to(self.root).as_posix(),
                'report_sha256': hashlib.sha256(self.report.read_bytes()).hexdigest(),
                'source': {'head': 'revision', 'clean': True, 'dirty_paths': []}, 'm0': 'checked'}), '')
        self.mutate(phase)
        return result

    def execute(self, receipt=None):
        with patch.object(runner.subprocess, 'run', side_effect=self.phase):
            return runner.execute_native_promotion(['core'], receipt or self.receipt)

    def test_terminal_core_reader_rechecks_transitive_performance_inputs(self):
        for path in self.dependencies:
            with self.subTest(path=path):
                original = path.read_text()
                self.mutate = lambda phase: path.write_text('changed') if phase == 'allocator' else None
                with self.assertRaises(runner.CampaignRunnerError):
                    self.execute()
                path.write_text(original)

    def test_source_and_direct_input_mutation_stop_between_phases(self):
        for phase in ('core', 'allocator'):
            for path in (self.receipt, self.report):
                with self.subTest(phase=phase, path=path):
                    self.mutate = lambda current: path.write_text('changed') if current == phase else None
                    with self.assertRaises(runner.CampaignRunnerError):
                        self.execute()
                    path.write_text('{}')
            self.mutate = lambda current: self.source.update(content_sha256='changed') if current == phase else None
            with self.assertRaises(runner.CampaignRunnerError):
                self.execute()
            self.source['content_sha256'] = 'source'

    def test_receipt_spellings_share_the_same_physical_identity(self):
        relative = self.receipt.relative_to(self.root)
        for receipt in (self.receipt, relative, Path('/workspace') / relative):
            with self.subTest(receipt=receipt):
                self.calls.clear()
                self.assertEqual(self.execute(receipt), 0)
                self.assertEqual(self.calls, ['core', 'allocator', 'core'])

    def test_direct_core_partial_readiness_exits_pending_without_pass(self):
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(closure, 'validate_promotion_closure', return_value=self.partial), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            self.assertEqual(closure.main(['--qualification-receipt', str(self.receipt)]), 3)
        self.assertEqual(json.loads(output.getvalue()), self.partial)
        self.assertIn('pending', errors.getvalue())
        self.assertNotIn('PASS', output.getvalue() + errors.getvalue())

    def test_forged_core_readiness_never_reaches_allocator(self):
        self.partial['functional_readiness'] = True
        with self.assertRaises(runner.CampaignRunnerError):
            self.execute()
        self.assertEqual(self.calls, ['core'])


if __name__ == '__main__':
    unittest.main()
