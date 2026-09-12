"""Finite raw wordexp accounting and full-receipt handoff tests.

The companion-report fixtures deliberately mock only
owned_wordexp_evidence.validate_report. That full validator belongs to the
installed public-C workload; these tests exercise this reader's handoff,
same-product binding, and fixed twenty-row parser without claiming a native
companion qualification from synthetic files.
"""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))

import owned_posix_native_observations as native
import owned_wordexp_upstream_policy as policy


class WordexpUpstreamPolicyTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.work/x86_64/wordexp-upstream-policy-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(dir=scratch))
        self.addCleanup(shutil.rmtree, self.root)
        self.leaf = self.root / '.work/libc-test'
        self.leaf.mkdir(parents=True)
        self.mount = Path('/workspace')
        self.copy_reference()
        self.source = self.put(self.leaf / policy.UPSTREAM_SOURCE, b'fixture untouched wordexp source\n')
        self.source_digest = self.digest(self.source)
        self.reader = object.__new__(native.Reader)
        self.reader.root = self.root
        self.reader.leaf = self.leaf
        self.reader.mount = self.mount
        self.reference = policy._reference(self.root)
        self.candidate = policy._upstream_trace(self.reader, self.source, self.reference, 'candidate')
        self.oracle = policy._upstream_trace(self.reader, self.source, self.reference, 'oracle')
        self.direct_companion = {
            'receipt': {'path': '.work/wordexp/owned-wordexp-products.json', 'sha256': 'a' * 64},
            'expected_native_inputs': {'path': '.work/wordexp-inputs/expected-native-inputs.json', 'sha256': 'b' * 64},
            'product': {'path': '.work/product', 'manifest': {'sha256': 'c' * 64}},
            'selected_dynamic_entries': {mode: {} for mode in policy.DYNAMIC_MODES},
            'source_policy_probe': {'path': policy.SOURCE_POLICY_PROBE, 'sha256': 'd' * 64},
            'diagnostic_reference': {'path': policy.REFERENCE, 'sha256': policy.REFERENCE_SHA256},
        }
        self.product = self.root / '.work/product'
        self.manifest = self.put(self.product / 'share/crabc/manifest.json', b'fixture product manifest\n')
        self.probe = self.put(self.root / policy.SOURCE_POLICY_PROBE, b'fixture installed source-policy probe\n')
        self.report_path = self.put(self.root / '.work/wordexp/owned-wordexp-products.json', b'{}\n')
        self.expected_path = self.put(self.root / '.work/wordexp-inputs/expected-native-inputs.json',
                                      {'seal': 'independently-captured'})
        self.expected = {'seal': 'independently-captured'}
        self.cell_paths = {}
        self.report = self.companion_report()

    def put(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True) + '\n').encode())
        return path

    def digest(self, path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def mounted(self, path):
        return str(self.mount / path.relative_to(self.root))

    def mounted_identity(self, path):
        return {'path': self.mounted(path), 'sha256': self.digest(path), 'mode': stat.S_IMODE(path.stat().st_mode)}

    def copy_reference(self):
        source = ROOT / policy.REFERENCE
        destination = self.root / policy.REFERENCE
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        return destination

    def raw_disposition(self, **changes):
        arguments = {
            'candidate_status': 1,
            'candidate_stdout': self.candidate,
            'candidate_stderr': b'',
            'oracle_status': 1,
            'oracle_stdout': self.oracle,
            'oracle_stderr': b'',
            'companion': self.direct_companion,
        }
        arguments.update(changes)
        with patch.object(policy, 'UPSTREAM_SOURCE_SHA256', self.source_digest), \
             patch.object(policy, '_reference', return_value=self.reference):
            return policy.upstream_disposition(self.reader, self.source, **arguments)

    def companion_report(self):
        dynamic = {
            'root': self.mounted(self.product),
            'manifest': self.mounted_identity(self.manifest),
            'files': {},
        }
        cells = {}
        for mode in policy.DYNAMIC_MODES:
            label = mode + '-' + policy.SOURCE_POLICY_CASE
            row = {'mode': mode, 'case': policy.SOURCE_POLICY_CASE}
            for side, streams in (
                ('candidate', {'status': b'0\n', 'stdout': policy.candidate_trace(), 'stderr': b''}),
                ('oracle', {'status': b'0\n', 'stdout': policy.oracle_trace(), 'stderr': b''}),
            ):
                row[side] = {}
                for stream, data in streams.items():
                    path = self.put(self.root / '.work/wordexp/cells' / label / (side + '.' + stream), data)
                    self.cell_paths[(mode, side, stream)] = path
                    row[side][stream] = self.mounted_identity(path)
            cells[label] = row
        return {
            'source_mount': str(self.mount),
            'inputs': {
                'before': {
                    'products': {'dynamic': copy.deepcopy(dynamic), 'static': None},
                    'sources': {policy.SOURCE_POLICY_PROBE: self.mounted_identity(self.probe)},
                },
                'after': {'products': {'dynamic': copy.deepcopy(dynamic)}},
                'built_products': False,
            },
            'cells': cells,
        }

    def full_receipt(self, root, report_path, expected):
        self.assertEqual((root, report_path, expected), (self.root, self.report_path, self.expected))
        return self.report

    def validate_companion(self):
        with patch.object(policy.wordexp, 'validate_report', side_effect=self.full_receipt) as validator:
            result = policy.validate_companion(self.root, self.report_path, self.expected_path, self.product)
        self.assertEqual(validator.call_count, 1)
        return result

    def replace_cell_stream(self, mode, side, stream, data):
        path = self.cell_paths[(mode, side, stream)]
        self.put(path, data)
        self.report['cells'][mode + '-' + policy.SOURCE_POLICY_CASE][side][stream] = self.mounted_identity(path)

    def test_checked_diagnostic_reference_is_byte_exact_and_complete(self):
        observed = policy._reference(self.root)
        self.assertEqual(self.digest(self.root / policy.REFERENCE), policy.REFERENCE_SHA256)
        self.assertEqual(observed['source_sha256'], policy.UPSTREAM_SOURCE_SHA256)
        self.assertEqual(observed['terminal'], 'FAIL /functional/wordexp [status 1]\n')
        self.assertEqual([len(observed['sides'][side]['diagnostics']) for side in ('candidate', 'oracle')], [20, 104])
        reference = self.root / policy.REFERENCE
        original = reference.read_bytes()
        for replacement in (original[:-1], original.replace(b'wordexp', b'wordXexp', 1), original + b'\n'):
            reference.write_bytes(replacement)
            with self.assertRaises(native.NativeObservationError):
                policy._reference(self.root)
        reference.write_bytes(original)

    def test_original_raw_failures_have_a_finite_posix_policy_disposition(self):
        observed = self.raw_disposition()
        self.assertEqual(observed['unit'], 'functional/wordexp')
        self.assertEqual(observed['status'], 'posix-policy-qualified')
        self.assertEqual(observed['basis'], 'pinned-source-posix-policy')
        self.assertIs(observed['raw_passed'], False)
        self.assertEqual([observed['candidate_diagnostic_count'], observed['oracle_diagnostic_count']], [20, 104])
        self.assertEqual(observed['product'], self.direct_companion['product'])
        self.assertEqual(observed['source_policy_probe'], self.direct_companion['source_policy_probe'])

    def test_original_raw_failures_reject_changed_source_status_stderr_and_diagnostics(self):
        altered_rows = self.candidate.splitlines(keepends=True)
        reordered = b''.join([altered_rows[1], altered_rows[0], *altered_rows[2:]])
        altered_oracle_rows = self.oracle.splitlines(keepends=True)
        reordered_oracle = b''.join([altered_oracle_rows[1], altered_oracle_rows[0], *altered_oracle_rows[2:]])
        for changes in (
            {'candidate_status': 0},
            {'candidate_status': True},
            {'oracle_status': 0},
            {'candidate_stderr': b'unexpected\n'},
            {'oracle_stderr': b'unexpected\n'},
            {'candidate_stdout': self.candidate[1:]},
            {'candidate_stdout': self.candidate + b'extra diagnostic\n'},
            {'candidate_stdout': self.candidate.replace(b'wordexp(', b'wordXexp(', 1)},
            {'candidate_stdout': reordered},
            {'oracle_stdout': self.oracle[1:]},
            {'oracle_stdout': self.oracle + b'extra diagnostic\n'},
            {'oracle_stdout': self.oracle.replace(b'wordexp(', b'wordXexp(', 1)},
            {'oracle_stdout': reordered_oracle},
            {'companion': {key: value for key, value in self.direct_companion.items() if key != 'receipt'}},
        ):
            with self.subTest(changes=sorted(changes)):
                with self.assertRaises(native.NativeObservationError):
                    self.raw_disposition(**changes)
        original = self.source.read_bytes()
        self.source.write_bytes(original + b'changed\n')
        with self.assertRaises(native.NativeObservationError):
            self.raw_disposition()
        other_source = self.put(self.leaf / 'source-prepared/src/functional/another-unit.c', original)
        arguments = {
            'candidate_status': 1,
            'candidate_stdout': self.candidate,
            'candidate_stderr': b'',
            'oracle_status': 1,
            'oracle_stdout': self.oracle,
            'oracle_stderr': b'',
            'companion': self.direct_companion,
        }
        with patch.object(policy, 'UPSTREAM_SOURCE_SHA256', self.source_digest), \
             patch.object(policy, '_reference', return_value=self.reference):
            with self.assertRaises(native.NativeObservationError):
                policy.upstream_disposition(self.reader, other_source, **arguments)

    def test_full_receipt_requires_same_product_all_modes_and_exact_companion_rows(self):
        observed = self.validate_companion()
        self.assertEqual(observed['product']['path'], '.work/product')
        self.assertEqual(set(observed['selected_dynamic_entries']), set(policy.DYNAMIC_MODES))
        self.assertEqual(observed['diagnostic_reference']['sha256'], policy.REFERENCE_SHA256)

        mode = policy.DYNAMIC_MODES[0]
        self.replace_cell_stream(mode, 'candidate', 'stdout', policy.candidate_trace() + b'changed\n')
        with patch.object(policy.wordexp, 'validate_report', return_value=self.report):
            with self.assertRaises(native.NativeObservationError):
                policy.validate_companion(self.root, self.report_path, self.expected_path, self.product)

    def test_full_receipt_rejects_partial_mode_wrong_product_and_process_status(self):
        mode = policy.DYNAMIC_MODES[0]
        partial = copy.deepcopy(self.report)
        partial['cells'].pop(mode + '-' + policy.SOURCE_POLICY_CASE)
        with patch.object(policy.wordexp, 'validate_report', return_value=partial):
            with self.assertRaises(native.NativeObservationError):
                policy.validate_companion(self.root, self.report_path, self.expected_path, self.product)

        wrong_product = copy.deepcopy(self.report)
        wrong_product['inputs']['before']['products']['dynamic']['root'] = '/workspace/.work/other-product'
        wrong_product['inputs']['after']['products']['dynamic']['root'] = '/workspace/.work/other-product'
        with patch.object(policy.wordexp, 'validate_report', return_value=wrong_product):
            with self.assertRaises(native.NativeObservationError):
                policy.validate_companion(self.root, self.report_path, self.expected_path, self.product)

        self.replace_cell_stream(mode, 'oracle', 'status', b'1\n')
        with patch.object(policy.wordexp, 'validate_report', return_value=self.report):
            with self.assertRaises(native.NativeObservationError):
                policy.validate_companion(self.root, self.report_path, self.expected_path, self.product)

    def test_full_receipt_requires_an_independently_captured_expected_input(self):
        self.put(self.expected_path, {'seal': 'report-derived'})

        def reject_changed_expected(root, report_path, expected):
            self.assertEqual(expected, {'seal': 'report-derived'})
            raise policy.wordexp.EvidenceError('expected native input differs')

        with patch.object(policy.wordexp, 'validate_report', side_effect=reject_changed_expected):
            with self.assertRaisesRegex(native.NativeObservationError, 'full receipt rejected'):
                policy.validate_companion(self.root, self.report_path, self.expected_path, self.product)


if __name__ == '__main__':
    unittest.main()
