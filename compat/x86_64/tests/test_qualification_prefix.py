#!/usr/bin/env python3
"""Execution, dependency and receipt boundaries for qualification prefixes."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]

def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'compat/x86_64' / filename)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value

manifest = module('generate_qualification_manifest', 'generate_qualification_manifest.py')
runner = module('qualification_prefix_runner', 'run_qualification_manifest.py')

class QualificationPrefixTests(unittest.TestCase):
    def test_claim_only_receipt_cannot_declare_a_completed_gate(self):
        document = json.loads(manifest.CONTRACT_PATH.read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_path = root / manifest.PRIVATE_ADMISSION[0][1]
            private_path.parent.mkdir(parents=True)
            private_path.write_bytes((ROOT / manifest.PRIVATE_ADMISSION[0][1]).read_bytes())
            (root / manifest.PRIVATE_ADMISSION[0][3][1]).write_text('pass\n')
            case_runner = root / 'runner.py'
            case_runner.write_text("print('case: PASS')\n")
            gate = document['promotion_chain'][0]
            case = {
                'schema': manifest.CASE_SCHEMA, 'gate': gate['id'], 'target': manifest.TARGET,
                **{key: gate[key] for key in ('oracle', 'provenance', 'purity', 'isolation')},
                'cases': [{'id': 'claimed', 'command': ['python3', 'runner.py'],
                    'runner_sha256': hashlib.sha256(case_runner.read_bytes()).hexdigest(),
                    'expected_stdout_line': 'case: PASS', 'timeout_seconds': 1}],
            }
            case_path = root / 'cases.json'; case_path.write_text(json.dumps(case))
            case_hash = manifest.sha256_file(case_path)
            receipt = {
                'schema': manifest.RECEIPT_SCHEMA, 'gate': gate['id'], 'target': manifest.TARGET,
                'case_manifest_sha256': case_hash, 'case_count': 1, 'outcome': 'passed',
                **{key: gate[key] for key in ('oracle', 'provenance', 'purity', 'isolation')},
            }
            receipt_path = root / 'claims.json'; receipt_path.write_text(json.dumps(receipt))
            gate.update(state='complete', case_manifest={'path': 'cases.json', 'sha256': case_hash},
                receipt={'path': 'claims.json', 'sha256': manifest.sha256_file(receipt_path)})
            contract = root / 'contract.json'; contract.write_text(json.dumps(document))
            with patch.object(manifest, 'ROOT', root), patch.object(manifest, 'CONTRACT_PATH', contract):
                with self.assertRaises(manifest.QualificationManifestError):
                    manifest.validate_contract(document)

    def test_ready_prefix_does_not_require_a_planned_suffix(self):
        rows = [{'id': identifier, 'state': 'ready' if index < 2 else 'planned'}
            for index, identifier in enumerate(manifest.CHAIN)]
        selected = runner.select_promotion_prefix({'promotion_chain': rows}, manifest.CHAIN[1])
        self.assertEqual([row['id'] for row in selected], list(manifest.CHAIN[:2]))

    def test_prefix_cannot_skip_a_planned_dependency(self):
        rows = [{'id': identifier, 'state': 'planned' if index == 1 else 'ready'}
            for index, identifier in enumerate(manifest.CHAIN)]
        with self.assertRaises(runner.QualificationRunError):
            runner.select_promotion_prefix({'promotion_chain': rows}, manifest.CHAIN[2])

    def test_prefix_execution_runs_predecessors_but_not_the_planned_suffix(self):
        report = manifest.load_contract()
        for gate in report['promotion_chain'][:2]:
            gate['state'] = 'ready'
        case = {'id': 'case'}
        with patch.object(manifest, 'load_contract', return_value=report), patch.object(
            manifest, 'write_or_check'
        ), patch.object(runner, 'load_case_manifest', return_value={'cases': [case]}), patch.object(
            runner, 'verify_case_runner'
        ), patch.object(runner, 'require_pinned_native_execution') as native, patch.object(
            runner, 'run_case'
        ) as execute, patch('builtins.print'):
            self.assertEqual(runner.main(['--through', manifest.CHAIN[1]]), 0)
        native.assert_called_once()
        self.assertEqual([call.args[0]['id'] for call in execute.call_args_list], list(manifest.CHAIN[:2]))

    def test_all_ready_declarations_still_do_not_open_full_qualification(self):
        report = manifest.load_contract()
        for gate in report['promotion_chain']:
            gate['state'] = 'ready'
        with patch.object(manifest, 'load_contract', return_value=report), patch.object(
            manifest, 'write_or_check'
        ), patch.object(runner, 'run_case') as execute, patch('builtins.print'):
            self.assertEqual(runner.main([]), 1)
        execute.assert_not_called()

    def test_private_admission_is_a_receipted_non_promoting_prefix(self):
        report = manifest.load_contract()
        selected = runner.select_private_admission(report)
        self.assertEqual(selected["id"], "posix-abi-admission")
        self.assertTrue(selected["non_promoting"])
        self.assertNotIn(selected["id"], manifest.CHAIN)

        parser = runner.argument_parser()
        parsed = parser.parse_args(["--private-admission"])
        self.assertTrue(parsed.private_admission)
        self.assertIsNone(parsed.through)

    def test_private_admission_rejects_dirty_source_before_starting_a_child(self):
        report = manifest.load_contract()
        with patch.object(runner, "require_pinned_native_execution"), patch.object(
            runner, "source_identity", side_effect=runner.QualificationRunError("clean committed source")
        ), patch.object(runner.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(runner.QualificationRunError, "clean committed source"):
                runner.run_private_admission(report)
        popen.assert_not_called()

    def test_private_admission_runner_loads_without_an_ambient_import_path(self):
        loaded = runner.private_admission_runner_module()
        self.assertEqual(loaded.EXPECTED_ID, "qualification-posix-abi-admission")

    def test_stdout_only_claim_is_not_a_private_admission_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "receipt.json"
            receipt.write_text(json.dumps({
                "schema": manifest.RECEIPT_SCHEMA,
                "outcome": "passed-non-promoting",
                "stdout": "PASS",
            }))
            with patch.object(runner, "evidence_path", side_effect=lambda path: path):
                with self.assertRaisesRegex(runner.QualificationRunError, "fields drifted"):
                    runner.validate_private_admission_receipt(receipt)

if __name__ == '__main__':
    unittest.main()
