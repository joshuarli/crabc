"""The native aggregate consumes one matrix and a fresh isolated output."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class OwnedPosixNativeDispatchTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.work/x86_64/tmp'
        scratch.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.state = self.work / 'state'
        self.state.mkdir()
        self.receipt = self.state / 'family execution.json'
        self.receipt.write_text('{}\n')
        self.output = self.state / 'fresh native'
        self.capture = self.work / 'docker.jsonl'
        docker = self.work / 'docker'
        docker.write_text(f'#!{sys.executable}\n'
            'import json, os, sys\n'
            "with open(os.environ['DISPATCH_CAPTURE'], 'a') as out: out.write(json.dumps(sys.argv[1:])+'\\n')\n"
            "if sys.argv[1:3] == ['image', 'inspect']: print('linux/amd64')\n"
            "elif sys.argv[1] != 'run': raise SystemExit('unexpected Docker operation')\n")
        docker.chmod(0o755)
        self.environment = {k: v for k, v in os.environ.items() if not k.startswith('CRABC_X86_64_')}
        self.environment.update(PATH=f'{self.work}{os.pathsep}{os.environ["PATH"]}',
            DISPATCH_CAPTURE=str(self.capture), CRABC_X86_64_WORK_DIR=str(self.state))

    def invoke(self, arguments):
        self.capture.unlink(missing_ok=True)
        return subprocess.run(['bash', str(ROOT / 'scripts/dev-x86_64.sh'),
            'owned-posix-native', *arguments], cwd=ROOT, env=self.environment,
            capture_output=True, text=True)

    def test_paths_reach_only_the_fixed_isolated_native_runner(self):
        expected = ['--family-execution', '/workspace/.work/x86_64/family execution.json',
                    '--output', '/workspace/.work/x86_64/fresh native']
        for receipt, output in ((self.receipt, self.output),
                (self.receipt.relative_to(ROOT), self.output.relative_to(ROOT)),
                (expected[1], expected[3])):
            with self.subTest(receipt=receipt):
                result = self.invoke(['--family-execution', str(receipt), '--output', str(output)])
                self.assertEqual(result.returncode, 0, result.stderr)
                runs = [a for a in map(json.loads, self.capture.read_text().splitlines()) if a[0] == 'run']
                self.assertEqual(len(runs), 1)
                argv = runs[0]
                self.assertEqual(argv[-8:], ['python3', '-B',
                    '/workspace/compat/x86_64/owned_posix_native_execution.py', 'run', *expected])
                for flag in ('--network=none', '--cap-add=SYS_ADMIN', '--cap-add=SYS_CHROOT',
                             '--security-opt=apparmor=unconfined', '--security-opt=seccomp=unconfined'):
                    self.assertIn(flag, argv)
                for flag in ('--privileged', '--pid=host', '--ipc=host', '--userns=host'):
                    self.assertNotIn(flag, argv)
                self.assertFalse(self.output.exists())

    def test_bad_requests_do_not_invoke_docker_or_create_output(self):
        valid = ['--family-execution', str(self.receipt), '--output', str(self.output)]
        alias = self.state / 'alias'
        alias.symlink_to(self.receipt)
        invalid = [[], valid[:2], valid[:-1], valid + valid[:2], valid + ['--timeout', '1'],
                   ['--family-execution', '', *valid[2:]],
                   ['--family-execution', str(alias), *valid[2:]],
                   ['--family-execution', str(self.state), *valid[2:]],
                   [*valid[:2], '--output', str(self.receipt)],
                   [*valid[:2], '--output', str(self.state / 'missing/fresh')],
                   [*valid[:2], '--output', '/workspace/etc/fresh']]
        before = set(self.state.rglob('*'))
        for arguments in invalid:
            with self.subTest(arguments=arguments):
                result = self.invoke(arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(self.capture.exists())
                self.assertEqual(set(self.state.rglob('*')), before)


if __name__ == '__main__':
    unittest.main()
