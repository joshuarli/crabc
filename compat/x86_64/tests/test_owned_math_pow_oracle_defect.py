"""Exact finite pow oracle discrepancies never hide other raw failures."""
from pathlib import Path
import copy
import shutil
import tempfile
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import owned_math_oracle_defects as defects
import owned_posix_native_observations as native


class PowOracleDefectTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.work/tmp'
        scratch.mkdir(parents=True, exist_ok=True)
        self.leaf = Path(tempfile.mkdtemp(dir=scratch))
        self.addCleanup(shutil.rmtree, self.leaf)
        self.reader = SimpleNamespace(root=ROOT, leaf=self.leaf, recorded=str,
            identity=lambda path: {'path': str(path), 'sha256': native.digest(path)})
        self.definition = copy.deepcopy(defects.POW_DEFECT)
        prepared = self.leaf / 'source-prepared'
        self.source = prepared / self.definition['source']
        self.source.parent.mkdir(parents=True)
        self.source.write_bytes(b'fixture complete pow unit')
        self.definition['source_sha256'] = native.digest(self.source)
        for relative in self.definition['headers']:
            path = prepared / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            lines = [''] * 800
            if relative == 'src/math/ucb/pow.h':
                for line, base in defects.POW_IDENTITIES:
                    lines[line - 1] = f'T(RN, {base}, 0x1p+0, {base}, 0x0p+0, 0)'
            path.write_text('\n'.join(lines) + '\n')
            self.definition['headers'][relative] = native.digest(path)
        self.values = dict(unit='math/pow', candidate_status=0, candidate_stderr=b'',
            oracle_status=0, oracle_stderr=b'',
            candidate_stdout=defects.expected_pow_stdout(prepared, candidate=True),
            oracle_stdout=defects.expected_pow_stdout(prepared, candidate=False))

    def admit(self, **changes):
        with patch.object(defects, 'POW_DEFECT', self.definition):
            return defects.pow_disposition(self.reader, self.source, **(self.values | changes))

    def test_preserves_ten_candidate_diagnostics_and_fourteen_exact_corrections(self):
        result = self.admit()
        self.assertFalse(result['raw_passed'])
        self.assertEqual(result['candidate']['diagnostic_count'], 10)
        self.assertFalse(result['candidate']['stdout_empty'])
        self.assertEqual(result['oracle']['diagnostic_count'], 24)
        self.assertEqual(len(result['exact_identities']), 14)
        self.assertEqual(result['status'], 'candidate-corrected-oracle-discrepancy')

    def test_rejects_any_stream_status_or_unit_drift(self):
        for side in ('candidate', 'oracle'):
            stream = self.values[side + '_stdout']
            lines = stream.splitlines(keepends=True)
            for changed in (b'', stream + b'extra\n',
                            *(b''.join(lines[:index] + lines[index + 1:]) for index in range(len(lines))),
                            b''.join(reversed(lines)), stream.replace(b'UNDERFLOW', b'INVALID', 1)):
                with self.subTest(side=side, changed=changed), self.assertRaises(native.NativeObservationError):
                    self.admit(**{side + '_stdout': changed})
            for status in (1, -11, True):
                with self.subTest(side=side, status=status), self.assertRaises(native.NativeObservationError):
                    self.admit(**{side + '_status': status})
            with self.assertRaises(native.NativeObservationError):
                self.admit(**{side + '_stderr': b'error'})
        with self.assertRaises(native.NativeObservationError):
            self.admit(unit='math/other')

    def test_rejects_source_header_and_identity_proof_drift(self):
        for path in (self.source, *(self.leaf / 'source-prepared' / relative for relative in self.definition['headers'])):
            original = path.read_bytes()
            path.write_bytes(original + b'drift')
            with self.subTest(path=path), self.assertRaises(native.NativeObservationError):
                self.admit()
            path.write_bytes(original)
        header = self.leaf / 'source-prepared/src/math/ucb/pow.h'
        header.write_text(header.read_text().replace('0x1p+0', '0x1p+1', 1))
        self.definition['headers']['src/math/ucb/pow.h'] = native.digest(header)
        with self.assertRaises(native.NativeObservationError):
            self.admit()


if __name__ == '__main__':
    unittest.main()
