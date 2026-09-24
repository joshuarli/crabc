"""Finite selected-profile accounting cannot hide another upstream failure."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import owned_posix_native_dispositions as dispositions
import owned_posix_native_observations as native


class NativeDispositionTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.work/x86_64/native-disposition-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(dir=scratch))
        self.addCleanup(shutil.rmtree, self.root)
        self.leaf = self.root / '.work/leaf'
        self.leaf.mkdir(parents=True)
        for path in dispositions.PROFILE_SOURCES:
            self.put(self.root / path, (ROOT / path).read_bytes())
        self.reference = (ROOT / dispositions.CRYPT_REFERENCE).read_bytes()
        self.source = self.put(self.leaf / 'source-prepared/src/functional/crypt.c', self.reference)
        self.strptime_reference = (ROOT / 'compat/x86_64/native-strptime-reference/strptime.c').read_bytes()
        self.strptime_source = self.put(self.leaf / 'source-prepared/src/functional/strptime.c',
                                        self.strptime_reference)
        self.mount = '/workspace'
        self.reader = object.__new__(native.Reader)
        self.reader.root, self.reader.leaf, self.reader.mount = self.root, self.leaf, Path(self.mount)

    def put(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else (json.dumps(value) + '\n').encode())
        return path

    def test_all_32_calls_are_accounted_with_four_genuine_source_matches(self):
        rows = dispositions.crypt_vectors(self.root)
        self.assertEqual(len(rows), 32)
        self.assertEqual([r['ordinal'] for r in rows], list(range(1, 33)))
        matches = [r for r in rows if r['disposition'] == 'upstream-match']
        self.assertEqual([r['ordinal'] for r in matches], [6, 7, 23, 32])
        self.assertEqual([r['setting'] for r in matches], [
            '$2a$00$0123456789012345678901', '$2a$08$01234567890123456789',
            '$5$rounds=10$roundstoolow', '$6$rounds=10$roundstoolow'])
        self.assertEqual(sum(r['disposition'] == 'unsupported-legacy-format' for r in rows), 12)
        self.assertEqual(sum(r['disposition'].startswith('unsupported-sha-') for r in rows), 16)
        self.assertTrue(all(r['candidate'] == '*' for r in rows if r['disposition'] != 'upstream-match'))
        self.assertEqual((rows[0]['line'], rows[0]['setting']), (15, '$1$abcd0123$'))
        reference = self.root / dispositions.CRYPT_REFERENCE
        reference.write_bytes(self.reference.replace(b'rounds=10$roundstoolow', b'rounds=11$roundstoolow', 1))
        with self.assertRaisesRegex(native.NativeObservationError, 'source|reference'):
            dispositions.crypt_vectors(self.root)

    def test_multiline_calls_use_invocation_start_in_actual_retained_diagnostics(self):
        raw = (ROOT / 'compat/x86_64/tests/fixtures/native-crypt/candidate.stdout').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
            '95d5eda0a0ba43a027e6ad4bafcf64b0eccfcaaa896d227cf77f91d3fc1a52f9')
        original = b'/workspace/.work/x86_64/tmp/owned-libc-test.GETcCg/source-prepared/src/functional/crypt.c'
        self.assertEqual(raw.count(original), 28)
        raw = raw.replace(original, self.reader.recorded(self.source).encode())
        rows = dispositions.crypt_vectors(self.root)
        proof = {'vectors': rows, 'receipt': {'path': '.work/crypt/crypt-profile.json', 'sha256': 'a'*64}}
        result = dispositions.crypt_disposition(self.reader, self.source,
            candidate_status=1, candidate_stdout=raw, candidate_stderr=b'',
            oracle_status=0, oracle_stdout=b'', oracle_stderr=b'', companion=proof)
        self.assertEqual(len(result['differences']), 28)
        self.assertEqual([(row['ordinal'], row['line']) for row in rows[5:14]],
                         [(6,21),(7,23),(8,25),(9,27),(10,29),(11,31),(12,33),(13,35),(14,37)])
        with self.assertRaises(native.NativeObservationError):
            dispositions.crypt_disposition(self.reader, self.source,
                candidate_status=1, candidate_stdout=raw.replace(b'crypt.c:25:', b'crypt.c:26:'), candidate_stderr=b'',
                oracle_status=0, oracle_stdout=b'', oracle_stderr=b'', companion=proof)

    def test_companion_requires_actual_nonnull_outputs_and_exact_full_roster(self):
        rows = dispositions.crypt_vectors(self.root)
        def output(side):
            return ''.join(f'vector {row["ordinal"]:02d} line={row["line"]} nonnull=1 output={row[side].encode().hex()}\n'
                           for row in rows).encode()
        for side in ('candidate', 'oracle'):
            raw = output(side)
            observed = dispositions.crypt_vector_observations(self.root, raw, side)
            self.assertEqual(len(observed), 32)
            for altered in (raw.replace(b'nonnull=1', b'nonnull=0', 1),
                            raw.split(b'\n', 1)[1], raw + b'unexpected diagnostic\n',
                            raw.replace(b'output=2a', b'output=2b', 1),
                            raw.replace(b'vector 01', b'vector 02', 1), b''):
                with self.assertRaises(native.NativeObservationError):
                    dispositions.crypt_vector_observations(self.root, altered, side)

    def test_original_crypt_keeps_28_failures_and_rejects_missing_or_extra_diagnostics(self):
        rows = dispositions.crypt_vectors(self.root)
        source_name = self.reader.recorded(self.source)
        raw = ''.join(f'{source_name}:{row["line"]}: crypt({row["key_literal"]}, "{row["setting"]}") failed: '
                      f'got "*" want "{row["oracle"]}"\n'
                      for row in rows if row['ordinal'] not in (6, 7, 23, 32)).encode()
        raw += b'FAIL /functional/crypt [status 1]\n'
        proof = {'vectors': rows, 'receipt': {'path': '.work/crypt/crypt-profile.json', 'sha256': 'a'*64}}
        observed = dispositions.crypt_disposition(self.reader, self.source,
            candidate_status=1, candidate_stdout=raw, candidate_stderr=b'',
            oracle_status=0, oracle_stdout=b'', oracle_stderr=b'', companion=proof)
        self.assertEqual(len(observed['differences']), 28)
        self.assertEqual(len(observed['matches']), 4)
        self.assertIs(observed['raw_passed'], False)
        for fields in ({'candidate_status': 0}, {'candidate_status': True}, {'oracle_status': 1},
                       {'candidate_stdout': raw.split(b'\n', 1)[1]}, {'candidate_stdout': raw + b'extra\n'},
                       {'candidate_stdout': raw.replace(b'got "*"', b'got "wrong"', 1)},
                       {'candidate_stderr': b'extra'}, {'oracle_stdout': b'failed'}, {'companion': None}):
            arguments = dict(candidate_status=1, candidate_stdout=raw, candidate_stderr=b'',
                             oracle_status=0, oracle_stdout=b'', oracle_stderr=b'', companion=proof)
            arguments.update(fields)
            with self.assertRaises(native.NativeObservationError):
                dispositions.crypt_disposition(self.reader, self.source, **arguments)
        self.source.write_bytes(self.reference + b'/* altered source */\n')
        with self.assertRaises(native.NativeObservationError):
            dispositions.crypt_disposition(self.reader, self.source,
                candidate_status=1, candidate_stdout=raw, candidate_stderr=b'',
                oracle_status=0, oracle_stdout=b'', oracle_stderr=b'', companion=proof)

    def test_strptime_only_accepts_the_pinned_glibc_block_raw_pair(self):
        source_name = self.reader.recorded(self.strptime_source)
        raw = (
            f'{source_name}:36: "%s": for "683078400" expected 1991-08-25T00:00:00 '
            'but got 1900-01-00T00:00:00\n'
            f'{source_name}:47: "%z": failed to parse "-06"\n'
            'FAIL /functional/strptime [status 1]\n'
        ).encode()
        observed = dispositions.strptime_disposition(
            self.reader, self.strptime_source,
            candidate_status=1, candidate_stdout=raw, candidate_stderr=b'',
            oracle_status=1, oracle_stdout=raw, oracle_stderr=b'')
        self.assertEqual(observed['unit'], 'functional/strptime')
        self.assertEqual(observed['basis'], 'pinned-source-musl-posix')
        self.assertIs(observed['raw_passed'], False)
        for fields in (
            {'candidate_status': 0}, {'oracle_status': 0},
            {'candidate_stdout': b'FAIL /functional/strptime [status 1]\n',
             'oracle_stdout': b'FAIL /functional/strptime [status 1]\n'},
            {'candidate_stdout': raw.replace(b'1900-01-00', b'1900-01-01')},
            {'candidate_stdout': raw + b'extra\n'},
            {'candidate_stderr': b'extra'}, {'oracle_stderr': b'extra'},
            {'oracle_stdout': raw.replace(b'"-06"', b'"-0600"')},
        ):
            arguments = dict(candidate_status=1, candidate_stdout=raw, candidate_stderr=b'',
                             oracle_status=1, oracle_stdout=raw, oracle_stderr=b'')
            arguments.update(fields)
            with self.assertRaises(native.NativeObservationError):
                dispositions.strptime_disposition(self.reader, self.strptime_source, **arguments)
        self.strptime_source.write_bytes(self.strptime_reference + b'/* altered source */\n')
        with self.assertRaises(native.NativeObservationError):
            dispositions.strptime_disposition(
                self.reader, self.strptime_source,
                candidate_status=1, candidate_stdout=raw, candidate_stderr=b'',
                oracle_status=1, oracle_stdout=raw, oracle_stderr=b'')

    def test_only_six_address_taken_atomic_outcomes_have_the_third_boundary(self):
        atomic = {'receipt': {'path': '.work/atomic/atomic-addressable-profile.json', 'sha256': 'c'*64},
                  'selected_dynamic_entries': {mode: {} for mode in dispositions.DYNAMIC_MODES}}
        for symbol, content in dispositions.OS_ATOMIC_SOURCES.items():
            source = self.put(self.leaf / 'source-stage/include/stdatomic' / (symbol + '.c'), content.encode())
            observed = dispositions.os_disposition(self.reader, 'include', 'stdatomic/' + symbol + '.out', source,
                b'good\n', b'undefined\n', {'atomic': atomic})
            self.assertEqual(observed['symbol'], symbol)
            self.assertIs(observed['raw_passed'], False)
            for candidate, oracle in ((b'undefined\n', b'undefined\n'), (b'good\n', b'good\n'),
                                       (b'good\n', b'exit: 0\n'), (b'good\nextra\n', b'undefined\n')):
                with self.assertRaises(native.NativeObservationError):
                    dispositions.os_disposition(self.reader, 'include', 'stdatomic/' + symbol + '.out', source,
                        candidate, oracle, {'atomic': atomic})
        source = self.put(self.leaf / 'source-stage/include/stdatomic/atomic_load.c', b'#include <stdatomic.h>\n')
        with self.assertRaisesRegex(native.NativeObservationError, 'no selected'):
            dispositions.os_disposition(self.reader, 'include', 'stdatomic/atomic_load.out', source,
                b'good\n', b'undefined\n', {'atomic': atomic})
        with self.assertRaisesRegex(native.NativeObservationError, 'complete'):
            dispositions.os_disposition(self.reader, 'include', 'stdatomic/atomic_flag_clear.out',
                self.leaf / 'source-stage/include/stdatomic/atomic_flag_clear.c', b'good\n', b'undefined\n',
                {'atomic': atomic, 'credentials': atomic})
        # Owned credential setters are process-wide as in musl, so OS-test
        # basic setter outcomes must match exactly; none has a disposition.
        source = self.put(self.leaf / 'source-stage/basic/unistd/seteuid.c', b'/* seteuid */\n')
        with self.assertRaisesRegex(native.NativeObservationError, 'no selected'):
            dispositions.os_disposition(self.reader, 'basic', 'unistd/seteuid.out', source,
                b'seteuid: ENOTSUP\n', b'exit: 0\n', {'atomic': atomic})


if __name__ == '__main__':
    unittest.main()
