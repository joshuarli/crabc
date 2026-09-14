#!/usr/bin/env python3
"""Process-free controls for retained locale/time alias receipts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import locale_alias_contract_receipt as receipt


class LocaleAliasContractReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / ".work/x86_64/locale-alias-contract-receipt-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="receipt-", dir=scratch))
        self.addCleanup(shutil.rmtree, self.root)

    @staticmethod
    def digest(value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()

    def write(self, relative: str, value: bytes) -> dict[str, object]:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        return {
            "path": relative,
            "bytes": len(value),
            "sha256": self.digest(value),
            "mode": 0o644,
        }

    def fixed_command(self) -> dict[str, object]:
        return {
            "schema": receipt.COMMAND_SCHEMA,
            "role": "compile",
            "cwd": "/workspace",
            "argv": ["/workspace/inputs/dynamic/bin/crabc-cc-dynamic", "--dynamic-pie", "-c"],
            "status": 0,
            "environment": {"LC_ALL": "C", "PATH": receipt.COMMAND_PATH},
            "stdin": "/dev/null",
            "launcher": ["/usr/bin/env", "-i", "LC_ALL=C", f"PATH={receipt.COMMAND_PATH}", "/usr/bin/timeout", "20"],
            "stdout": self.write("raw/compile.stdout", b""),
            "stderr": self.write("raw/compile.stderr", b""),
            "status_stream": self.write("raw/compile.status", b"0\n"),
            "cwd_stream": self.write("raw/compile.cwd", b"/workspace\n"),
            "environment_stream": self.write("raw/compile.environment.json", b'{"LC_ALL":"C","PATH":"/opt/cargo/bin:/opt/musl-1.2.6/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}\n'),
            "stdin_stream": self.write("raw/compile.stdin", b"/dev/null\n"),
            "launcher_stream": self.write("raw/compile.launcher.json", b'["/usr/bin/env","-i","LC_ALL=C","PATH=/opt/cargo/bin:/opt/musl-1.2.6/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","/usr/bin/timeout","20"]\n'),
        }

    def test_retained_command_requires_exact_argv_and_all_raw_streams(self) -> None:
        record = self.fixed_command()
        receipt.validate_command_record(
            self.root,
            record,
            role="compile",
            cwd="/workspace",
            argv=["/workspace/inputs/dynamic/bin/crabc-cc-dynamic", "--dynamic-pie", "-c"],
            environment=receipt.COMMAND_ENVIRONMENT,
            launcher=receipt.RUNNER_LAUNCHER,
        )

        (self.root / "raw/compile.stdout").unlink()
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "stdout"):
            receipt.validate_command_record(
                self.root,
                record,
                role="compile",
                cwd="/workspace",
                argv=["/workspace/inputs/dynamic/bin/crabc-cc-dynamic", "--dynamic-pie", "-c"],
                environment=receipt.COMMAND_ENVIRONMENT,
                launcher=receipt.RUNNER_LAUNCHER,
            )

        self.write("raw/compile.stdout", b"")
        forged = json.loads(json.dumps(record))
        forged["argv"][-1] = "--forged"
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "argv"):
            receipt.validate_command_record(
                self.root,
                forged,
                role="compile",
                cwd="/workspace",
                argv=["/workspace/inputs/dynamic/bin/crabc-cc-dynamic", "--dynamic-pie", "-c"],
                environment=receipt.COMMAND_ENVIRONMENT,
                launcher=receipt.RUNNER_LAUNCHER,
            )

        forged = json.loads(json.dumps(record))
        forged["environment"]["PATH"] = "/forged"
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "environment"):
            receipt.validate_command_record(
                self.root,
                forged,
                role="compile",
                cwd="/workspace",
                argv=["/workspace/inputs/dynamic/bin/crabc-cc-dynamic", "--dynamic-pie", "-c"],
                environment=receipt.COMMAND_ENVIRONMENT,
                launcher=receipt.RUNNER_LAUNCHER,
            )

    def test_source_records_bind_current_bytes_not_only_claimed_hashes(self) -> None:
        source = self.root / "source/owned_calendar.rs"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"#[export_name = \"__asctime_r\"]\n")
        records = receipt.source_records(self.root, ("source/owned_calendar.rs",))
        receipt.validate_source_records(self.root, records)

        source.write_bytes(b"#[export_name = \"__forged___\"]\n")
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "source bytes"):
            receipt.validate_source_records(self.root, records)

    def test_source_contract_keeps_the_full_roster_and_hidden_time_boundary(self) -> None:
        for relative in (receipt.CONTRACT_PATH, "docker/x86_64-musl-oracle-gcc", *receipt.IMPLEMENTATION_SOURCES):
            source = ROOT / relative
            copied = self.root / relative
            copied.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, copied)
        observed = receipt.validate_source_contract(self.root)
        self.assertEqual((observed["visible_pairs"], observed["hidden_pairs"]), (43, 4))
        self.assertFalse(observed["wcsftime_l_in_contract"])

        timezone = self.root / "libc/src/c_abi/x86_64/owned_timezone.rs"
        timezone.write_text(timezone.read_text(encoding="utf-8").replace('fn refresh_tzset()', 'fn forged_refresh()'), encoding="utf-8")
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "tzset boundary"):
            receipt.validate_source_contract(self.root)

    def test_runner_plan_is_the_closed_35_command_normal_consumer_matrix(self) -> None:
        plan = receipt._runner_plan(".work/x86_64/locale-alias-contract-receipt")
        self.assertEqual([role for role, _argv in plan], list(receipt.RUNNER_STEMS))
        self.assertEqual(len(plan), 35)
        self.assertEqual(plan[0][1][-2:], ["-o", "/workspace/.work/x86_64/locale-alias-contract-receipt/tmp/runner/probe.o"])
        self.assertNotIn("wcsftime_l", "\n".join(argument for _role, argv in plan for argument in argv))

    def test_trusted_image_manifest_requires_the_pinned_oracle_and_actual_launch_tools(self) -> None:
        manifest = json.loads((ROOT / receipt.IMAGE_MANIFEST_PATH).read_text(encoding="utf-8"))
        self.assertIn("/opt/musl-1.2.6/lib/libc.a", manifest["files"])
        self.assertIn("/usr/bin/timeout", manifest["files"])

        forged_root = self.root / "forged-root"
        manifest_path = forged_root / receipt.IMAGE_MANIFEST_PATH
        manifest_path.parent.mkdir(parents=True)
        manifest["files"].pop("/usr/bin/timeout")
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with mock.patch.object(receipt, "ROOT", forged_root):
            with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "unexpected oracle or tool roster"):
                receipt._trusted_image_manifest()
        manifest = json.loads((ROOT / receipt.IMAGE_MANIFEST_PATH).read_text(encoding="utf-8"))
        manifest["files"]["/forged-tool"] = manifest["files"]["/usr/bin/timeout"]
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with mock.patch.object(receipt, "ROOT", forged_root):
            with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "unexpected oracle or tool roster"):
                receipt._trusted_image_manifest()

    def test_product_tree_retains_directory_file_and_symlink_modes(self) -> None:
        product = self.root / "products/static"
        nested = product / "bin"
        nested.mkdir(parents=True)
        nested.chmod(0o751)
        tool = nested / "crabc-cc"
        tool.write_bytes(b"driver\n")
        tool.chmod(0o755)
        (product / "driver-link").symlink_to("bin/crabc-cc")
        records = receipt._tree_records(self.root, "products/static")
        self.assertIn({"path": "products/static/bin", "kind": "directory", "mode": 0o751}, records)
        self.assertIn({"path": "products/static/bin/crabc-cc", "kind": "file", "bytes": 7,
                       "sha256": self.digest(b"driver\n"), "mode": 0o755}, records)
        self.assertIn({"path": "products/static/driver-link", "kind": "symlink", "target": "bin/crabc-cc", "mode": 0o777}, records)

    def test_retained_image_input_binds_manifest_bytes_and_mode(self) -> None:
        tool_bytes = b"pinned tool\n"
        image_entry = {"path": "/tool", "sha256": self.digest(tool_bytes), "size": len(tool_bytes), "mode": 0o644}
        trusted = {"schema": "test", "image": "test", "path": "test", "files": {"/tool": image_entry}}
        manifest_record = self.write(f"inputs/source/{receipt.IMAGE_MANIFEST_PATH}", json.dumps(trusted).encode() + b"\n")
        tool_record = self.write("inputs/image/tool", tool_bytes)
        report = {"id": receipt.PINNED_IMAGE, "manifest": manifest_record,
                  "files": {"/tool": {"image": image_entry, "retained": tool_record}}}
        with mock.patch.object(receipt, "_trusted_image_manifest", return_value=trusted):
            self.assertEqual(receipt._validate_image_inputs(self.root, report), report)
            (self.root / "inputs/image/tool").write_bytes(b"forged tool\n")
            with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "bytes changed"):
                receipt._validate_image_inputs(self.root, report)

    def test_final_transaction_recheck_rejects_a_post_report_source_change(self) -> None:
        source = {"revision": "a" * 40, "tree": "b" * 40, "content_sha256": "c" * 64, "clean": True,
                  "paths": []}
        with mock.patch.object(receipt, "_live_source_state", return_value={**source, "content_sha256": "d" * 64}), \
             mock.patch.object(receipt, "_validate_image_inputs"), \
             mock.patch.object(receipt, "_validate_products"), \
             mock.patch.object(receipt, "_raw_collector_commands"), \
             mock.patch.object(receipt, "_raw_runner_records"):
            with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "source changed after"):
                receipt._final_transaction_recheck(self.root, self.root, source, {}, {}, [], [], ".work/x86_64/test")

    def test_final_transaction_recheck_rejects_a_changed_raw_command_stream(self) -> None:
        source = {"revision": "a" * 40, "tree": "b" * 40, "content_sha256": "c" * 64, "clean": True,
                  "paths": []}
        with mock.patch.object(receipt, "_live_source_state", return_value=receipt._source_state(source)), \
             mock.patch.object(receipt, "_validate_image_inputs", return_value={}), \
             mock.patch.object(receipt, "_validate_products", return_value={}), \
             mock.patch.object(receipt, "_raw_collector_commands", return_value=[{"changed": True}]), \
             mock.patch.object(receipt, "_raw_runner_records", return_value=[]):
            with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "collector raw streams changed"):
                receipt._final_transaction_recheck(self.root, self.root, source, {}, {}, [], [], ".work/x86_64/test")

    def test_live_source_state_rejects_an_untracked_input(self) -> None:
        source = self.root / "clean-source"
        source.mkdir()
        (source / "tracked.txt").write_text("tracked\n", encoding="utf-8")
        for command in (("git", "init", "-q"), ("git", "add", "tracked.txt"),
                        ("git", "-c", "user.email=receipt@example.invalid", "-c", "user.name=Receipt", "commit", "-qm", "source")):
            subprocess.run(command, cwd=source, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        state = receipt._live_source_state(source)
        self.assertTrue(state["clean"])
        (source / "untracked.txt").write_text("untracked\n", encoding="utf-8")
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "clean Git source state"):
            receipt._live_source_state(source)

    def test_validate_report_public_entry_runs_real_source_authority_before_admission(self) -> None:
        report_root = Path(tempfile.mkdtemp(prefix="real-entry-", dir=ROOT / ".work/x86_64"))
        self.addCleanup(shutil.rmtree, report_root)
        report = {
            "schema": receipt.SCHEMA,
            "status": receipt.STATUS,
            "mode_policy": receipt.MODE_POLICY,
            "image_inputs": {"id": receipt.PINNED_IMAGE, "manifest": {}, "files": {}},
            "source_before": {"revision": "0" * 40, "tree": "0" * 40, "content_sha256": "0" * 64,
                              "clean": True, "paths": []},
            "source_after": {"revision": "0" * 40, "tree": "0" * 40, "content_sha256": "0" * 64,
                             "clean": True, "paths": []},
            "source_contract": {}, "products": {}, "collector_commands": [], "runner_commands": [],
            "snapshots": {}, "artifacts": {}, "runtime": {}, "symbols": {}, "nonclaims": list(receipt.NONCLAIMS),
        }
        report_path = report_root / "report.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "complete Git source authority"):
            receipt.validate_report(ROOT, report_path)

    def test_validate_report_entry_uses_real_source_and_contract_validators(self) -> None:
        """The public entry reaches source admission without mocking it away."""

        trusted = self.root / "trusted"
        for relative in receipt.SELECTED_SOURCES:
            source = ROOT / relative
            destination = trusted / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        for command in (("git", "init", "-q"), ("git", "add", "."),
                        ("git", "-c", "user.email=receipt@example.invalid", "-c", "user.name=Receipt", "commit", "-qm", "receipt")):
            subprocess.run(command, cwd=trusted, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        revision = subprocess.check_output(("git", "rev-parse", "HEAD"), cwd=trusted, text=True).strip()
        tree = subprocess.check_output(("git", "rev-parse", "HEAD^{tree}"), cwd=trusted, text=True).strip()
        report_root = trusted / ".work/x86_64/entry-report"
        report_root.mkdir(parents=True)
        sys.path.insert(0, str(ROOT / "compat/x86_64"))
        import owned_syscall_alias_authority as authority

        authority.capture_git_objects(trusted, report_root, [revision])
        authenticated, _files = authority.source_tree(report_root, revision)
        for directory in ("inputs/source", "source-after/inputs/source"):
            for relative in receipt.SELECTED_SOURCES:
                destination = report_root / directory / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(trusted / relative, destination)
        source = {"revision": revision, "tree": tree, "content_sha256": authenticated["content_sha256"],
                  "clean": True, "paths": receipt.source_records(report_root / "inputs/source", receipt.SELECTED_SOURCES)}
        source_contract = receipt.validate_source_contract(report_root / "inputs/source")
        report = {
            "schema": receipt.SCHEMA, "status": receipt.STATUS, "mode_policy": receipt.MODE_POLICY,
            "image_inputs": {"image": "deferred"}, "source_before": source, "source_after": source,
            "source_contract": source_contract, "products": {"products": "deferred"},
            "collector_commands": [{"collector": "deferred"}], "runner_commands": [{"runner": "deferred"}],
            "snapshots": {"before": {"records": ["same"]}, "after": {"records": ["same"]}},
            "artifacts": {"artifacts": "deferred"}, "runtime": {"runtime": "deferred"},
            "symbols": {"symbols": "deferred"}, "nonclaims": list(receipt.NONCLAIMS),
        }
        report_path = report_root / "report.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with mock.patch.object(receipt, "ROOT", trusted), \
             mock.patch("subprocess.Popen", side_effect=AssertionError("validate-report started a process")), \
             mock.patch.object(receipt, "_validate_image_inputs", return_value={"image": "deferred"}), \
             mock.patch.object(receipt, "_validate_products", return_value={"products": "deferred"}), \
             mock.patch.object(receipt, "_validate_collector_commands", return_value=[{"collector": "deferred"}]), \
             mock.patch.object(receipt, "_runner_records", return_value=[{"runner": "deferred"}]), \
             mock.patch.object(receipt, "_validate_execution_tools"), \
             mock.patch.object(receipt, "_validate_artifacts", return_value={"artifacts": "deferred"}), \
             mock.patch.object(receipt, "_validate_snapshot", side_effect=lambda _root, value, _name: value), \
             mock.patch.object(receipt, "_validate_runtime_and_headers", return_value={"runtime": "deferred"}), \
             mock.patch.object(receipt, "_validate_symbol_observation", return_value={"symbols": "deferred"}):
            admitted = receipt.validate_report(trusted, report_path)
        self.assertEqual(admitted["source"], source)

    def test_validate_report_entry_joins_every_required_retained_relation(self) -> None:
        report_root = Path(tempfile.mkdtemp(prefix="report-", dir=ROOT / ".work/x86_64"))
        self.addCleanup(shutil.rmtree, report_root)
        report = {
            "schema": receipt.SCHEMA,
            "status": receipt.STATUS,
            "mode_policy": receipt.MODE_POLICY,
            "image_inputs": {"image": "ok"},
            "source_before": {"source": "same"},
            "source_after": {"source": "same"},
            "source_contract": {"contract": "ok"},
            "products": {"products": "ok"},
            "collector_commands": [{"collector": "ok"}],
            "runner_commands": [{"runner": "ok"}],
            "snapshots": {"before": {"records": ["same"]}, "after": {"records": ["same"]}},
            "artifacts": {"object": "ok"},
            "runtime": {"runtime": "ok"},
            "symbols": {"symbols": "ok"},
            "nonclaims": list(receipt.NONCLAIMS),
        }
        report_path = report_root / "report.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        source_value = {"source": "same", "paths": []}
        with mock.patch.object(receipt, "_validate_source_seal", return_value=source_value) as source_seal, \
             mock.patch.object(receipt, "validate_source_contract", return_value={"contract": "ok"}) as source_contract, \
             mock.patch.object(receipt, "_validate_image_inputs", return_value={"image": "ok"}) as image, \
             mock.patch.object(receipt, "_validate_products", return_value={"products": "ok"}) as products, \
             mock.patch.object(receipt, "_validate_collector_commands", return_value=[{"collector": "ok"}]) as collector, \
             mock.patch.object(receipt, "_runner_records", return_value=[{"runner": "ok"}]) as runner, \
             mock.patch.object(receipt, "_validate_execution_tools") as tools, \
             mock.patch.object(receipt, "_validate_artifacts", return_value={"object": "ok"}) as artifacts, \
             mock.patch.object(receipt, "_validate_snapshot", side_effect=lambda _root, value, _name: value) as snapshots, \
             mock.patch.object(receipt, "_validate_runtime_and_headers", return_value={"runtime": "ok"}) as runtime, \
             mock.patch.object(receipt, "_validate_symbol_observation", return_value={"symbols": "ok"}) as symbols:
            admitted = receipt.validate_report(ROOT, report_path)

        self.assertEqual(admitted["status"], receipt.STATUS)
        for boundary in (source_seal, source_contract, image, products, collector, runner, tools, artifacts, snapshots, runtime, symbols):
            self.assertGreaterEqual(boundary.call_count, 1)

        malformed = dict(report)
        malformed.pop("artifacts")
        report_path.write_text(json.dumps(malformed), encoding="utf-8")
        with self.assertRaisesRegex(receipt.LocaleAliasReceiptError, "fields changed"):
            receipt.validate_report(ROOT, report_path)


class LocaleAliasRunnerRetentionTests(unittest.TestCase):
    def test_runner_accepts_a_fresh_explicit_receipt_directory_and_records_cwd(self) -> None:
        runner = (ROOT / "compat/x86_64/run_locale_alias_contract.sh").read_text(encoding="utf-8")
        self.assertIn("--receipt-dir", runner)
        self.assertIn('"$work/$stem.cwd"', runner)
        self.assertIn('"$work/$stem.environment.json"', runner)
        self.assertIn('"$work/$stem.launcher.json"', runner)
        self.assertIn('< /dev/null', runner)
        self.assertIn('umask 022', runner)
        self.assertIn("receipt directory must be below checkout-local TMPDIR", runner)


if __name__ == "__main__":
    unittest.main()
