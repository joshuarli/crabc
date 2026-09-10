"""The native aggregate requires its matrix, two companions, and fresh output."""
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
        self.crypt = self.state / 'crypt profile.json'
        self.crypt.write_text('{}\n')
        self.atomic = self.state / 'atomic addressable profile.json'
        self.atomic.write_text('{}\n')
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
                    '--crypt-profile', '/workspace/.work/x86_64/crypt profile.json',
                    '--atomic-addressable-profile', '/workspace/.work/x86_64/atomic addressable profile.json',
                    '--output', '/workspace/.work/x86_64/fresh native']
        for receipt, crypt, atomic, output in ((self.receipt, self.crypt, self.atomic, self.output),
                (self.receipt.relative_to(ROOT), self.crypt.relative_to(ROOT), self.atomic.relative_to(ROOT),
                 self.output.relative_to(ROOT)),
                (expected[1], expected[3], expected[5], expected[7])):
            with self.subTest(receipt=receipt):
                result = self.invoke(['--family-execution', str(receipt),
                    '--crypt-profile', str(crypt), '--atomic-addressable-profile', str(atomic),
                    '--output', str(output)])
                self.assertEqual(result.returncode, 0, result.stderr)
                runs = [a for a in map(json.loads, self.capture.read_text().splitlines()) if a[0] == 'run']
                self.assertEqual(len(runs), 1)
                argv = runs[0]
                self.assertEqual(argv[-12:], ['python3', '-B',
                    '/workspace/compat/x86_64/owned_posix_native_execution.py', 'run', *expected])
                for flag in ('--network=none', '--cap-add=SYS_ADMIN', '--cap-add=SYS_CHROOT',
                             '--security-opt=apparmor=unconfined', '--security-opt=seccomp=unconfined'):
                    self.assertIn(flag, argv)
                for flag in ('--privileged', '--pid=host', '--ipc=host', '--userns=host'):
                    self.assertNotIn(flag, argv)
                self.assertFalse(self.output.exists())

    def test_bad_requests_do_not_invoke_docker_or_create_output(self):
        valid = ['--family-execution', str(self.receipt), '--crypt-profile', str(self.crypt),
                 '--atomic-addressable-profile', str(self.atomic),
                 '--output', str(self.output)]
        alias = self.state / 'alias'
        alias.symlink_to(self.receipt)
        crypt_alias = self.state / 'crypt alias'
        crypt_alias.symlink_to(self.crypt)
        atomic_alias = self.state / 'atomic alias'
        atomic_alias.symlink_to(self.atomic)
        invalid = [[], valid[:2], valid[:4], valid[:6], valid[:-1], valid + valid[:2], valid + valid[2:4],
                   valid + valid[4:6],
                   valid + ['--timeout', '1'],
                   ['--family-execution', '', *valid[2:]],
                   ['--family-execution', str(alias), *valid[2:]],
                   ['--family-execution', str(self.state), *valid[2:]],
                   [*valid[:2], *valid[4:]],
                   [*valid[:2], '--crypt-profile', str(crypt_alias), *valid[4:]],
                   [*valid[:2], '--crypt-profile', str(self.state), *valid[4:]],
                   [*valid[:2], '--crypt-profile', str(self.state / 'missing.json'), *valid[4:]],
                   [*valid[:2], '--crypt-profile', '/workspace/etc/crypt.json', *valid[4:]],
                   [*valid[:4], *valid[6:]],
                   [*valid[:4], '--atomic-addressable-profile', str(atomic_alias), *valid[6:]],
                   [*valid[:4], '--atomic-addressable-profile', str(self.state), *valid[6:]],
                   [*valid[:4], '--atomic-addressable-profile', str(self.state / 'missing.json'), *valid[6:]],
                   [*valid[:4], '--atomic-addressable-profile', '/workspace/etc/atomic.json', *valid[6:]],
                   [*valid[:6], '--output', str(self.receipt)],
                   [*valid[:6], '--output', str(self.state / 'missing/fresh')],
                   [*valid[:6], '--output', '/workspace/etc/fresh']]
        before = set(self.state.rglob('*'))
        for arguments in invalid:
            with self.subTest(arguments=arguments):
                result = self.invoke(arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(self.capture.exists())
                self.assertEqual(set(self.state.rglob('*')), before)


if __name__ == '__main__':
    unittest.main()
