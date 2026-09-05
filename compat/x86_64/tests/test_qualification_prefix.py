#!/usr/bin/env python3
"""Execution, dependency and receipt boundaries for qualification prefixes."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import sys
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
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

    def test_timeout_cleanup_kills_a_leaf_that_started_its_own_session(self):
        scratch = ROOT / ".work/x86_64/tmp/qualification-timeout-supervisor-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            cases_root = Path(directory) / "cases"
            cases_root.mkdir()
            leaf = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                start_new_session=True,
            )
            record = cases_root / ".active-child-pgid"
            record.write_text(f"{leaf.pid}\n", encoding="ascii")

            class PrivateRunner:
                @staticmethod
                def active_child_record(root):
                    return root / ".active-child-pgid"

            try:
                runner.terminate_active_private_case(PrivateRunner, cases_root)
                self.assertEqual(leaf.wait(timeout=3), -9)
            finally:
                if leaf.poll() is None:
                    leaf.kill()
                    leaf.wait()

    def test_private_subreaper_scope_restores_the_callers_prior_state(self):
        before = runner.child_subreaper_enabled()
        with runner.private_admission_subreaper():
            self.assertTrue(runner.child_subreaper_enabled())
        self.assertEqual(runner.child_subreaper_enabled(), before)

    def test_private_subreaper_scope_restores_state_when_child_accounting_fails(self):
        before = runner.child_subreaper_enabled()
        with patch.object(
            runner,
            "direct_child_processes",
            side_effect=runner.QualificationRunError("synthetic /proc failure"),
        ):
            with self.assertRaisesRegex(runner.QualificationRunError, "synthetic /proc failure"):
                with runner.private_admission_subreaper():
                    self.fail("unreachable")
        self.assertEqual(runner.child_subreaper_enabled(), before)

    def test_timeout_waits_for_runner_death_before_draining_late_child_publication(self):
        with patch.object(runner, "direct_child_processes", return_value=set()):
            boundary = runner.PrivateAdmissionDescendantBoundary()
        process = unittest.mock.Mock(pid=731)
        boundary.register_private_runner(process)
        published = []

        def publish_after_runner_death(*, timeout):
            self.assertEqual(timeout, 3)
            published.append("late-session-leaf")

        def drain_published_child():
            self.assertEqual(published, ["late-session-leaf"])

        process.wait.side_effect = publish_after_runner_death
        with patch.object(runner.os, "killpg"), patch.object(
            boundary, "kill_process"
        ), patch.object(
            boundary, "reap_adopted_descendants", side_effect=drain_published_child
        ) as drain:
            boundary.terminate_and_reap(process)
        process.wait.assert_called_once_with(timeout=3)
        drain.assert_called_once_with()

    def test_final_pipe_timeout_drains_again_while_the_subreaper_is_scoped(self):
        with tempfile.TemporaryDirectory() as directory:
            receipts = Path(directory) / "qualification-receipts"
            transaction = receipts / "transaction"
            transaction.mkdir(parents=True)
            report = copy.deepcopy(manifest.load_contract())

            class PrivateRunner:
                @staticmethod
                def load_contract():
                    return (SimpleNamespace(timeout_seconds=1),)

                @staticmethod
                def active_child_record(cases_root):
                    return cases_root / ".active-child-pgid"

            process = unittest.mock.Mock(pid=732, returncode=-9)
            process.communicate.side_effect = (
                subprocess.TimeoutExpired(["fixture"], 1, output=b"first", stderr=b"first"),
                subprocess.TimeoutExpired(["fixture"], 10, output=b"late", stderr=b"late"),
            )
            boundary = unittest.mock.MagicMock()
            scope = unittest.mock.MagicMock()
            scope.__enter__.return_value = boundary
            scope.__exit__.return_value = False
            inputs = {"fixture": "inputs"}
            source = {"revision": "a" * 40, "content_sha256": "b" * 64}
            with patch.object(runner, "verify_private_admission_runner"), patch.object(
                runner, "require_pinned_native_execution"
            ), patch.object(runner, "source_identity", return_value=source), patch.object(
                runner, "execution_inputs", return_value=inputs
            ), patch.object(runner, "transaction_directory", return_value=transaction), patch.object(
                runner, "private_admission_runner_module", return_value=PrivateRunner), patch.object(
                runner, "ensure_physical_receipt_directory", return_value=receipts
            ), patch.object(runner, "private_admission_subreaper", return_value=scope), patch.object(
                runner, "terminate_private_admission_process"
            ), patch.object(runner.subprocess, "Popen", return_value=process):
                with self.assertRaisesRegex(runner.QualificationRunError, "prefix timed out"):
                    runner.run_private_admission(report)
            boundary.reap_adopted_descendants.assert_called_once_with()
            receipt = json.loads((transaction / "receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["outcome"], "failed")

    def test_receipt_log_cannot_be_transplanted_from_a_sibling_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            receipts = Path(directory) / "qualification-receipts"
            first = receipts / "first"
            sibling = receipts / "sibling"
            first.mkdir(parents=True)
            sibling.mkdir()
            sibling_log = sibling / "stdout.log"
            sibling_log.write_bytes(b"matching log\n")
            with patch.object(runner, "ensure_physical_receipt_directory", return_value=receipts):
                with self.assertRaisesRegex(runner.QualificationRunError, "transaction"):
                    runner.evidence_path(sibling_log, first)

    def test_receipt_final_symlink_is_rejected_before_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            receipts = Path(directory) / "qualification-receipts"
            transaction = receipts / "transaction"
            transaction.mkdir(parents=True)
            target = transaction / "target.log"
            target.write_bytes(b"log\n")
            link = transaction / "stdout.log"
            link.symlink_to(target.name)
            with patch.object(runner, "ensure_physical_receipt_directory", return_value=receipts):
                with self.assertRaisesRegex(runner.QualificationRunError, "symlink"):
                    runner.evidence_path(link, transaction)

    def test_mutable_cargo_configuration_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            cargo_home = Path(directory)
            (cargo_home / "config.toml").write_text("[build]\nrustflags = ['--cfg=poison']\n")
            with self.assertRaisesRegex(runner.QualificationRunError, "mutable Cargo home"):
                runner.require_unconfigured_cargo_home(cargo_home)

    def test_execution_input_snapshot_rechecks_cargo_configuration(self):
        with patch.object(runner, "require_unconfigured_cargo_home") as cargo_home, patch.object(
            runner, "tool_identity", return_value={"tool": "identity"}
        ), patch.object(runner, "trusted_tool_directories", return_value=[]), patch.object(
            runner, "pinned_rust_toolchain_identity", return_value={}
        ), patch.object(runner, "gcc_builtin_include_identity", return_value={}), patch.object(
            runner, "physical_file_identity", return_value={"file": "identity"}
        ), patch.object(runner, "physical_directory_identity", return_value={"directory": "identity"}):
            runner.execution_inputs()
        cargo_home.assert_called_once_with(Path(manifest.EXECUTION_CONTRACT["cargo_home"]))

    def test_prefix_timeout_reaps_unrecorded_session_escaping_descendants_and_seals_failure(self):
        scratch = ROOT / ".work/x86_64/tmp/qualification-timeout-descendant-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            receipts = root / "qualification-receipts"
            transaction = receipts / "transaction"
            transaction.mkdir(parents=True)
            fixture = root / "launch_escaping_descendants.py"
            fixture.write_text(
                """import os
import subprocess
import sys
import time
from pathlib import Path

cases = Path(os.environ[\"CRABC_QUALIFICATION_RECEIPT_ROOT\"])
leaf_pid = cases / \"unrecorded-leaf.pid\"
grandchild_pid = cases / \"escaping-grandchild.pid\"
grandchild = subprocess.Popen(
    [sys.executable, \"-c\", \"import time; time.sleep(60)\"],
    start_new_session=True,
)
grandchild_pid.write_text(f\"{grandchild.pid}\\n\", encoding=\"ascii\")
time.sleep(60)
""",
                encoding="utf-8",
            )
            supervisor = root / "launch_unrecorded_leaf.py"
            supervisor.write_text(
                """import os
import subprocess
import sys
import time
from pathlib import Path

cases = Path(os.environ[\"CRABC_QUALIFICATION_RECEIPT_ROOT\"])
fixture = Path(os.environ[\"QUALIFICATION_TIMEOUT_FIXTURE\"])
leaf = subprocess.Popen([sys.executable, str(fixture)], start_new_session=True)
(cases / \"unrecorded-leaf.pid\").write_text(f\"{leaf.pid}\\n\", encoding=\"ascii\")
while not (cases / \"escaping-grandchild.pid\").is_file():
    time.sleep(0.01)
time.sleep(60)
""",
                encoding="utf-8",
            )
            report = copy.deepcopy(manifest.load_contract())
            admission = report["private_admission"][0]
            admission["command"] = [sys.executable, str(supervisor)]
            admission["runner_sha256"] = "test-fixture"

            class PrivateRunner:
                @staticmethod
                def load_contract():
                    return (SimpleNamespace(timeout_seconds=1),)

                @staticmethod
                def active_child_record(cases_root):
                    return cases_root / ".active-child-pgid"

            inputs = {"fixture": "inputs"}
            source = {"revision": "a" * 40, "content_sha256": "b" * 64}
            environment = {"CRABC_QUALIFICATION_RECEIPT_ROOT": "ignored"}
            environment["QUALIFICATION_TIMEOUT_FIXTURE"] = str(fixture)
            started = time.monotonic()
            with patch.object(runner, "verify_private_admission_runner"), patch.object(
                runner, "require_pinned_native_execution"
            ), patch.object(runner, "source_identity", return_value=source), patch.object(
                runner, "execution_inputs", return_value=inputs
            ), patch.object(runner, "transaction_directory", return_value=transaction), patch.object(
                runner, "private_admission_runner_module", return_value=PrivateRunner), patch.object(
                runner, "ensure_physical_receipt_directory", return_value=receipts
            ), patch.object(runner, "controlled_environment", return_value=environment):
                with self.assertRaisesRegex(runner.QualificationRunError, "prefix timed out"):
                    runner.run_private_admission(report)
            self.assertLess(time.monotonic() - started, 5)

            for name in ("unrecorded-leaf.pid", "escaping-grandchild.pid"):
                process_id = int((transaction / "cases" / name).read_text(encoding="ascii"))
                deadline = time.monotonic() + 2
                while True:
                    try:
                        os.kill(process_id, 0)
                    except ProcessLookupError:
                        break
                    if time.monotonic() >= deadline:
                        self.fail(f"timeout left {name} running")
                    time.sleep(0.01)

            receipt = json.loads((transaction / "receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["outcome"], "failed")
            self.assertIn("prefix timed out", receipt["error"])

    def test_builtin_header_tree_identity_changes_with_header_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            headers = Path(directory) / "include"
            headers.mkdir()
            header = headers / "stdint.h"
            header.write_text("#define WIDTH 32\n")
            before = runner.physical_directory_identity(str(headers), "test headers")
            header.write_text("#define WIDTH 64\n")
            after = runner.physical_directory_identity(str(headers), "test headers")
            self.assertNotEqual(before["sha256"], after["sha256"])

    def test_stdout_only_claim_is_not_a_private_admission_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "receipt.json"
            receipt.write_text(json.dumps({
                "schema": manifest.RECEIPT_SCHEMA,
                "outcome": "passed-non-promoting",
                "stdout": "PASS",
            }))
            with patch.object(runner, "evidence_path", side_effect=lambda path, *unused: path):
                with self.assertRaisesRegex(runner.QualificationRunError, "fields drifted"):
                    runner.validate_private_admission_receipt(receipt)

if __name__ == '__main__':
    unittest.main()
