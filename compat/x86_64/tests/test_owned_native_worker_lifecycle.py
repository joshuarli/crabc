"""Worker teardown probes retain allocations through all TSD destructor passes."""
import json
import os
import resource
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
ORACLE_CC = Path('/usr/local/bin/crabc-x86_64-musl-gcc')


def disable_core_dump():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


@unittest.skipUnless(ORACLE_CC.is_file(), 'requires the pinned native musl compiler')
class OwnedNativeWorkerLifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = ROOT / '.work/x86_64/tmp'
        temporary.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=temporary)
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.probe = self.work / 'probe'
        result = subprocess.run([str(ORACLE_CC), '-static', '-fno-pie', '-no-pie', '-std=c11', '-pthread',
                                 str(ROOT / 'compat/x86_64/owned_native_worker_lifecycle_probe.c'),
                                 '-o', str(self.probe)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_four_passes_keep_joined_clients_live(self):
        result = subprocess.run([str(self.probe), 'tsd-four'], capture_output=True, text=True,
                                preexec_fn=disable_core_dump)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'TSD four passes: return and pthread_exit joined clients\n')
        self.assertEqual(result.stderr, '')

    def test_existing_main_and_final_transcripts_remain_distinct(self):
        common = ('attach before user code\nreturn: cleanup 1 destructors 2\n'
                  'pthread_exit: cleanup 1 destructors 2\ncancel: cleanup 1 destructors 2\n'
                  'allocation refusal then valid use\nremote ownership: 12 workers\n'
                  'creation refusal: EAGAIN then success\n')
        for scenario, expected in [('main', common), ('final', common + 'final worker atexit\n'),
                                   ('deferred', 'deferred final worker atexit\n')]:
            with self.subTest(scenario=scenario):
                result = subprocess.run([str(self.probe), scenario], capture_output=True, text=True,
                                        preexec_fn=disable_core_dump)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected)
                self.assertEqual(result.stderr, '')

    def test_runner_dispatches_four_pass_case_in_every_installed_mode(self):
        # Product drivers and chroot are controls: actual probe execution uses
        # the musl executable. This checks dispatch without claiming native ABI.
        root = self.work / 'checkout'
        scripts = root / 'compat/x86_64'
        scripts.mkdir(parents=True)
        for name in ('run_owned_native_worker_lifecycle.sh', 'owned_native_worker_lifecycle_probe.c'):
            shutil.copyfile(ROOT / 'compat/x86_64' / name, scripts / name)
        temporary = root / '.work/tmp'
        temporary.mkdir(parents=True)
        controls = self.work / 'controls'
        controls.mkdir()
        capture = self.work / 'receipt-arguments.json'
        python = controls / 'python3'
        python.write_text(f'#!{sys.executable}\n'
                          'import json, os, sys\n'
                          'if len(sys.argv)>1 and sys.argv[1]=="-B" and sys.argv[2].endswith("native_shadow_receipt.py"):\n'
                          '    with open(os.environ["RECEIPT_ARGUMENTS"],"w") as out: json.dump(sys.argv[3:],out)\n'
                          'else: os.execv(sys.executable,[sys.executable,*sys.argv[1:]])\n')
        python.chmod(0o755)
        chroot = controls / 'chroot'
        chroot.write_text(f'#!{sys.executable}\n'
                          'import os, sys\n'
                          'root, *args=sys.argv[1:]\n'
                          'if args[0]=="/lib/ld-crabc-x86_64.so.1": args.pop(0)\n'
                          'os.execv(root+args[0],[root+args[0],*args[1:]])\n')
        chroot.chmod(0o755)
        static = root / '.work/static'
        dynamic = root / '.work/dynamic'
        for product in (static, dynamic):
            (product / 'bin').mkdir(parents=True)
            (product / 'share/crabc').mkdir(parents=True)
            driver = product / 'bin' / ('crabc-cc' if product == static else 'crabc-cc-dynamic')
            driver.write_text(f'#!{sys.executable}\n'
                              'from pathlib import Path\nimport sys\n'
                              'out=Path(sys.argv[sys.argv.index("-o")+1])\n'
                              'out.write_text("#!/bin/sh\\nexec "+str(out.parent/"oracle")+" \\\"$@\\\"\\n")\n'
                              'out.chmod(0o755)\n')
            driver.chmod(0o755)
        (static / 'share/crabc/manifest.json').write_text(json.dumps({'allocator_backend': 'native-shadow'}))
        (static / 'share/crabc/libc-static.provenance.json').write_text(json.dumps({'allocator_lifecycle_test_audit': True}))
        (dynamic / 'share/crabc/libc-shared.provenance.json').write_text(json.dumps(
            {'allocator_backend': 'native-shadow', 'allocator_lifecycle_test_audit': True}))
        environment = dict(os.environ, PATH=str(controls) + os.pathsep + os.environ['PATH'],
                           TMPDIR=str(temporary), RECEIPT_ARGUMENTS=str(capture))
        result = subprocess.run(['bash', str(scripts / 'run_owned_native_worker_lifecycle.sh'),
                                 '--static-sysroot', str(static), str(dynamic)],
                                env=environment, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = json.loads(capture.read_text())
        cases = [arguments[i+1].split('=')[0] for i, item in enumerate(arguments) if item == '--case']
        modes = ('oracle', 'static', 'static-pie', 'kernel-pie', 'direct-pie', 'kernel-non-pie', 'direct-non-pie')
        for mode in modes:
            for scenario in ('main', 'final', 'deferred', 'tsd-four'):
                self.assertIn(mode + '-' + scenario, cases)


if __name__ == '__main__':
    unittest.main()
