"""The installed atomic extension receipt has no permissive replay path."""
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import owned_atomic_addressable_profile as atomic
import owned_posix_native_observations as native


class AtomicAddressableProfileTests(unittest.TestCase):
    def test_cxx_reference_contract_is_only_the_six_c_spellings(self):
        self.assertEqual(atomic.MODES, ('pie-kernel', 'pie-direct', 'non-pie-kernel', 'non-pie-direct'))
        self.assertEqual(len(atomic.ATOMIC_SYMBOLS), 6)
        observed = atomic._cxx_undefined(('                 U _GLOBAL_OFFSET_TABLE_\n' +
            ''.join('                 U ' + name + '\n' for name in atomic.ATOMIC_SYMBOLS)).encode())
        self.assertEqual(set(observed), {'_GLOBAL_OFFSET_TABLE_', *atomic.ATOMIC_SYMBOLS})
        for name in ('_Znew', '__cxa_throw', '__tls_get_addr', 'unexpected_import'):
            with self.assertRaises(native.NativeObservationError):
                atomic._cxx_undefined((' U ' + atomic.ATOMIC_SYMBOLS[0] + '\n U ' + name + '\n').encode())

    @unittest.skipUnless(platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.geteuid() == 0,
                         'the installed dynamic companion needs the pinned root container')
    def test_actual_receipt_rejects_cross_product_stale_source_missing_mode_raw_and_extra_artifacts(self):
        scratch = ROOT / '.work/x86_64/atomic-addressable-profile-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        run_root = Path(tempfile.mkdtemp(dir=scratch))
        self.addCleanup(shutil.rmtree, run_root)
        environment = {**os.environ, 'TMPDIR': str(run_root)}
        result = subprocess.run(['bash', str(ROOT / 'compat/x86_64/run_owned_atomic_addressable_profile.sh')],
                                cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = next(run_root.rglob('atomic-addressable-profile.json'))
        self.assertEqual(atomic.validate_receipt(ROOT, receipt)['status'], 'profile-companion-verified')

        def replace(path, data):
            before, mode = path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
            path.chmod(mode | stat.S_IWUSR)
            path.write_bytes(data)
            def restore():
                path.chmod(mode | stat.S_IWUSR)
                path.write_bytes(before)
                path.chmod(mode)
            return restore

        request = receipt.parent / 'profile-request.json'
        source = ROOT / atomic.MAIN_SOURCE
        mutations = (
            ('cross product', request, request.read_bytes().replace(b'dynamic-product', b'evidence/dynamic-pie-root')),
            ('stale source', source, source.read_bytes() + b'/* stale-source test */\n'),
            ('missing mode', receipt.parent / 'dynamic-pie-direct.status', b''),
            ('altered raw pair', receipt.parent / 'dynamic-non-pie-kernel.stdout', b'changed\n'),
        )
        for name, path, data in mutations:
            with self.subTest(name=name):
                restore = replace(path, data)
                try:
                    with self.assertRaises((native.NativeObservationError, atomic.AtomicAddressableProfileError, RuntimeError)):
                        atomic.validate_receipt(ROOT, receipt)
                finally:
                    restore()
        extra = receipt.parent / 'unexpected-artifact'
        extra.write_bytes(b'not sealed')
        try:
            with self.assertRaises((native.NativeObservationError, atomic.AtomicAddressableProfileError, RuntimeError)):
                atomic.validate_receipt(ROOT, receipt)
        finally:
            extra.unlink()


if __name__ == '__main__':
    unittest.main()
