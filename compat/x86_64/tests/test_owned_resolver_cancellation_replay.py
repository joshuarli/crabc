"""Diagnostic replay cannot replace the complete cancellation evidence."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'compat/x86_64'))
import owned_resolver_cancellation as cancellation
import owned_resolver_cancellation_receipt as receipt
import test_owned_resolver_cancellation_receipt as fixtures


class ResolverCancellationReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = fixtures.OwnedResolverCancellationReceiptTests()
        self.data.setUp()
        self.addCleanup(self.data.tearDown)
        self.provider_bytes = b''.join(
            f'1: 1 1 FUNC GLOBAL DEFAULT 1 {name}\n'.encode()
            for name in sorted(cancellation.PROVIDERS))
        for raw, _binary, _dynamic in receipt.PROVIDER_FILES:
            (self.data.work / raw).write_bytes(self.provider_bytes)

    def replay(self, *, entry='dynamic-pie-kernel', api='query', scenario='udp', static=True) -> str:
        output = io.StringIO()
        run = subprocess.run
        def readelf_only(command, **kwargs):
            if command[0] == 'readelf':
                return subprocess.CompletedProcess(command, 0, self.provider_bytes, b'')
            return run(command, **kwargs)
        with patch.object(cancellation, 'fixture_module', return_value=self.data.fixture), \
             patch.object(cancellation.subprocess, 'run', side_effect=readelf_only), \
             contextlib.redirect_stdout(output):
            cancellation.replay_case(self.data.work, self.data.static if static else None,
                                     self.data.dynamic, entry=entry, api=api, scenario=scenario)
        return output.getvalue()

    def test_selected_case_ignores_other_transcripts_and_never_changes_evidence(self) -> None:
        other = self.data.work / 'dynamic-pie-kernel-query-tcp.stdout'
        other.write_bytes(b'invalid unselected transcript\n')
        before = self.data.fixture.tree_identity(self.data.work)
        output = self.replay()
        self.assertEqual(output, 'resolver cancellation dynamic-pie-kernel-query-udp: PASS '
                                 '(diagnostic only; no component receipt)\n')
        self.assertEqual(self.data.fixture.tree_identity(self.data.work), before)
        selected = self.data.work / 'dynamic-pie-kernel-query-udp.stdout'
        original = selected.read_bytes()
        selected.write_bytes(original.replace(b'cleanup=0', b'cleanup=1'))
        with self.assertRaisesRegex(RuntimeError, 'observation differs'):
            self.replay()
        selected.write_bytes(original)
        with self.assertRaises(receipt.ReceiptError):
            self.data._validate()

    def test_missing_unselected_status_is_rejected(self) -> None:
        self.data._write(receipt.STATUS, json.dumps(receipt._expected_status(cancellation)[:-1]).encode())
        with self.assertRaisesRegex(RuntimeError, 'status matrix'):
            self.replay()

    def test_missing_unselected_raw_cell_is_rejected(self) -> None:
        (self.data.work / 'dynamic-non-pie-direct-reverse-tcp.stderr').unlink()
        with self.assertRaises(receipt.ReceiptError):
            self.replay()

    def test_case_selection_cannot_shrink_the_canonical_run(self) -> None:
        arguments = ['resolver', 'run', '--work', str(self.data.work),
                     '--dynamic-sysroot', str(self.data.dynamic), '--entry', 'dynamic-pie-kernel',
                     '--api', 'query', '--scenario', 'udp']
        with patch.object(sys, 'argv', arguments), contextlib.redirect_stderr(io.StringIO()), \
             patch.object(cancellation, 'run', side_effect=AssertionError('partial run')):
            with self.assertRaises(SystemExit) as error:
                cancellation.main()
        self.assertEqual(error.exception.code, 2)

    def test_dynamic_only_roster_is_diagnostic_only(self) -> None:
        audit = receipt.read_json(self.data.work / receipt.ARTIFACT_AUDIT, 'audit')
        del audit['products']['static']
        for mode, _flag, _elf in receipt.STATIC_ARTIFACTS:
            del audit['artifacts'][mode]
        self.data._write(receipt.ARTIFACT_AUDIT, json.dumps(audit).encode())
        rows = [row for row in receipt._expected_status(cancellation) if not row['entry'].startswith('static')]
        self.data._write(receipt.STATUS, json.dumps(rows).encode())
        self.assertIn('diagnostic only', self.replay(static=False))
        with self.assertRaisesRegex(RuntimeError, 'entry mode'):
            self.replay(static=False, entry='static-pie')
        with self.assertRaisesRegex(receipt.ReceiptError, 'installed product tree'):
            self.data._validate()

    def test_unknown_api_scenario_pair_is_rejected_before_reading_evidence(self) -> None:
        with patch.object(cancellation, 'fixture_module', side_effect=AssertionError('unexpected input read')):
            with self.assertRaisesRegex(RuntimeError, 'unknown.*case'):
                cancellation.replay_case(self.data.work, self.data.static, self.data.dynamic,
                    entry='dynamic-pie-kernel', api='query',
                    scenario=cancellation.POST_TCP_LATER_EAGAIN_CASE[1])

    def test_product_object_and_probe_drift_are_rejected(self) -> None:
        for field in ('source_sha256', 'source', 'object', 'products'):
            with self.subTest(field=field):
                path = self.data.work / receipt.ARTIFACT_AUDIT
                original = path.read_bytes()
                audit = receipt.read_json(path, 'audit')
                audit[field] = 'forged'
                self.data._write(receipt.ARTIFACT_AUDIT, json.dumps(audit).encode())
                with self.assertRaises(RuntimeError):
                    self.replay()
                path.write_bytes(original)
        (self.data.dynamic / 'product').write_bytes(b'changed product\n')
        with self.assertRaisesRegex(RuntimeError, 'product tree'):
            self.replay()

    def test_provider_binding_and_bytes_are_rejected(self) -> None:
        path = self.data.work / 'dynamic-provider-symbols.txt'
        path.write_bytes(self.provider_bytes.replace(b'FUNC', b'OBJECT'))
        with self.assertRaisesRegex(RuntimeError, 'provider'):
            self.replay()

    def test_matching_provider_bytes_still_require_function_binding(self) -> None:
        self.provider_bytes = self.provider_bytes.replace(b'FUNC', b'OBJECT')
        for raw, _binary, _dynamic in receipt.PROVIDER_FILES:
            (self.data.work / raw).write_bytes(self.provider_bytes)
        with self.assertRaisesRegex(RuntimeError, 'incorrect binding'):
            self.replay()

    def test_changed_same_object_is_rejected(self) -> None:
        (self.data.work / 'workload.o').write_bytes(b'changed application object\n')
        with self.assertRaisesRegex(RuntimeError, 'workload object'):
            self.replay()
