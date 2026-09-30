#!/usr/bin/env python3
"""Supplied products for the existing signal-handler/fork differential."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / 'compat/x86_64/run_owned_signal_handler_fork.sh'


class SignalHandlerForkInputsTests(unittest.TestCase):
    def invoke(self, temporary, *arguments):
        return subprocess.run(
            ['bash', str(RUNNER), *arguments], cwd=ROOT,
            env={**os.environ, 'TMPDIR': str(temporary)},
            capture_output=True, text=True, check=False,
        )

    def test_supplied_static_pair_reaches_payload_validation_before_build(self):
        scratch = ROOT / '.work/x86_64/tmp'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            temporary = Path(directory)
            static, dynamic = temporary / 'static', temporary / 'dynamic'
            static.mkdir()
            dynamic.mkdir()
            result = self.invoke(temporary, '--static-sysroot', str(static), str(dynamic))
            self.assertEqual(result.returncode, 1)
            self.assertIn('signal-handler fork static product payload is invalid', result.stderr)
            self.assertEqual(result.stdout, '')
            self.assertEqual(sorted(path.name for path in temporary.iterdir()), ['dynamic', 'static'])

    def test_malformed_static_pair_is_rejected_before_build(self):
        scratch = ROOT / '.work/x86_64/tmp'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            for arguments in (
                ('--static-sysroot',), ('--static-sysroot', ''),
                ('--static-sysroot', '-x', 'dynamic'),
                ('--static-sysroot', 'static'),
                ('--static-sysroot', 'static', '--static-sysroot', 'other', 'dynamic'),
                ('dynamic', 'other'), ('',), ('--unknown',),
            ):
                with self.subTest(arguments=arguments):
                    result = self.invoke(temporary, *arguments)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, '')
                    self.assertEqual(result.stderr, f'usage: {RUNNER} [[--static-sysroot STATIC_SYSROOT] DYNAMIC_SYSROOT]\n')

    def test_supplied_static_path_cannot_traverse_a_symlink(self):
        scratch = ROOT / '.work/x86_64/tmp'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            temporary = Path(directory)
            product = temporary / 'product'
            product.mkdir()
            alias = temporary / 'alias'
            alias.symlink_to(product, target_is_directory=True)
            result = self.invoke(temporary, '--static-sysroot', str(alias), str(product))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('static product must be a physical checkout .work directory', result.stderr)
            self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
