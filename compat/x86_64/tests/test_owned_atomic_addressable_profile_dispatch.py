"""The installed addressable-atomic companion receives one sealed dynamic product."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]


class OwnedAtomicAddressableProfileDispatchTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.work/x86_64/tmp'
        scratch.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.state = self.work / 'state'
        self.product = self.state / 'dynamic product'
        self.product.mkdir(parents=True)
        self.capture = self.work / 'docker.jsonl'
        docker = self.work / 'docker'
        docker.write_text(f'#!{sys.executable}\n'
            'import json, os, sys\n'
            "with open(os.environ['DISPATCH_CAPTURE'], 'a') as out: out.write(json.dumps(sys.argv[1:])+'\\n')\n"
            "if sys.argv[1:3] == ['image', 'inspect']: print('linux/amd64')\n"
            "elif sys.argv[1] != 'run': raise SystemExit('unexpected Docker operation')\n")
        docker.chmod(0o755)
        self.environment = {key: value for key, value in os.environ.items() if not key.startswith('CRABC_X86_64_')}
        self.environment.update(PATH=f'{self.work}{os.pathsep}{os.environ["PATH"]}',
            DISPATCH_CAPTURE=str(self.capture), CRABC_X86_64_WORK_DIR=str(self.state))

    def invoke(self, arguments):
        self.capture.unlink(missing_ok=True)
        return subprocess.run(['bash', str(ROOT / 'scripts/dev-x86_64.sh'),
            'owned-atomic-addressable-profile', *arguments], cwd=ROOT, env=self.environment,
            capture_output=True, text=True)

    def test_optional_product_reaches_only_the_chrooted_profile_runner(self):
        expected = '/workspace/.work/x86_64/dynamic product'
        for product, tail in (((), []), ((self.product,), [expected]),
                ((self.product.relative_to(ROOT),), [expected]), ((Path(expected),), [expected])):
            with self.subTest(product=product):
                result = self.invoke([str(path) for path in product])
                self.assertEqual(result.returncode, 0, result.stderr)
                runs = [row for row in map(json.loads, self.capture.read_text().splitlines()) if row[0] == 'run']
                self.assertEqual(len(runs), 1)
                argv = runs[0]
                self.assertEqual(argv[-2 - len(tail):], ['bash',
                    '/workspace/compat/x86_64/run_owned_atomic_addressable_profile.sh', *tail])
                self.assertIn('--cap-add=SYS_CHROOT', argv)
                self.assertNotIn('--cap-add=SYS_ADMIN', argv)
                self.assertNotIn('--security-opt=apparmor=unconfined', argv)
                self.assertNotIn('--security-opt=seccomp=unconfined', argv)
                for forbidden in ('--privileged', '--pid=host', '--ipc=host', '--userns=host'):
                    self.assertNotIn(forbidden, argv)

    def test_bad_product_requests_do_not_invoke_docker(self):
        alias = self.state / 'product alias'
        alias.symlink_to(self.product)
        for arguments in ((str(self.product), str(self.product)), ('--static-sysroot', str(self.product)),
                ('--unknown',), (str(alias),), (str(self.state / 'missing'),),
                ('/workspace/etc/product',)):
            with self.subTest(arguments=arguments):
                result = self.invoke(arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(self.capture.exists())


if __name__ == '__main__':
    unittest.main()
