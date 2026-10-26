#!/usr/bin/env python3
"""Contract tests for the native owned-product signal/process aggregate."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
from unittest.mock import patch
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_signal_process.sh"
EVIDENCE = ROOT / "compat/x86_64/owned_signal_process_evidence.py"
SOURCE = ROOT / "compat/signal-process/tests/signal_process.c"
SUBCASES = (
    "siginfo", "nodefer", "mask-pending", "sa-restart", "altstack",
    "thread-mask", "sigwait", "timer", "wait-signal", "wait-nohang",
    "atfork", "fork-worker-exec",
)


def load_evidence():
    spec = importlib.util.spec_from_file_location("owned_signal_process_evidence", EVIDENCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class OwnedSignalProcessTests(unittest.TestCase):
    def test_frozen_workload_is_architecture_neutral_and_has_the_full_roster(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertNotIn("aarch", source.lower())
        self.assertNotIn("x86", source.lower())
        for subcase in SUBCASES:
            self.assertIn(f'"{subcase}"', source)
        self.assertIn('strcmp(argv[1], "exec-check")', source)

    def test_runner_requires_a_supplied_dynamic_product_and_never_builds_one(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("usage: %s [--static-sysroot STATIC_SYSROOT] DYNAMIC_SYSROOT", source)
        compile = source.index('"$dynamic_sysroot/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin')
        snapshot = source.index("snapshot-compile-inputs")
        self.assertLess(snapshot, compile)
        self.assertNotIn("build_x86_64_owned_dynamic_sysroot.py", source)
        self.assertNotIn("build_x86_64_owned_sysroot.py", source)
        self.assertNotIn("-D", source)
        for subcase in SUBCASES:
            self.assertIn(subcase, source)

    def test_runner_records_raw_process_group_observations_for_every_entry(self) -> None:
        source = RUNNER.read_text(encoding="utf-8") + EVIDENCE.read_text(encoding="utf-8")
        for required in (
            "record-compile", "validate-compile", "validate_link", "start_new_session=True",
            "os.killpg", "TIMEOUT", ".stdout", ".stderr", ".status",
            "pie-kernel", "pie-direct", "non-pie-kernel", "non-pie-direct",
            "record-execution-payload", "execution-pre.json", "execution-post.json",
        ):
            self.assertIn(required, source)
        copied = source.index('cp -a "$dynamic_sysroot" "$execution_root"')
        recorded = source.index("record-execution-payload")
        first_dynamic_launch = source.index('capture_case "$mode-kernel-$subcase"')
        self.assertLess(copied, recorded)
        self.assertLess(recorded, first_dynamic_launch)

    def test_evidence_contract_binds_the_one_installed_driver_object(self) -> None:
        evidence = load_evidence()
        self.assertEqual(evidence.SIGNAL_PROCESS_SUBCASES, SUBCASES)
        self.assertEqual(
            evidence.COMPILE_SCHEMA,
            "crabc.x86_64-owned-signal-process-compile/v1",
        )
        self.assertEqual(
            evidence.OBSERVATION_SCHEMA,
            "crabc.x86_64-owned-signal-process-observations/v1",
        )
        self.assertTrue(callable(evidence.record_compile))
        self.assertTrue(callable(evidence.validate_compile))
        self.assertTrue(callable(evidence.record_observations))
        self.assertTrue(callable(evidence.validate_observations))
        self.assertTrue(callable(evidence.run_in_process_group))

    def test_cli_rejects_missing_or_ambiguous_products_before_evidence(self) -> None:
        scratch_root = ROOT / ".work/x86_64/tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        for arguments in (
            (),
            ("--static-sysroot",),
            ("--static-sysroot", ""),
            ("--static-sysroot", "one"),
            ("dynamic", "second"),
            ("--unexpected",),
        ):
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
                result = subprocess.run(
                    ["bash", str(RUNNER), *arguments],
                    env={"PATH": "/usr/bin:/bin", "TMPDIR": temporary},
                    text=True,
                    capture_output=True,
                    check=False,
                )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertEqual(
                result.stderr,
                f"usage: {RUNNER} [--static-sysroot STATIC_SYSROOT] DYNAMIC_SYSROOT\n",
            )

    def test_matching_nonzero_raw_statuses_are_rejected(self) -> None:
        evidence = load_evidence()
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            for label in ("oracle", "candidate"):
                (work / f"{label}.status").write_bytes(b"7\n")
                (work / f"{label}.stdout").write_bytes(b"same\n")
                (work / f"{label}.stderr").write_bytes(b"")
            with self.assertRaisesRegex(evidence.SignalProcessEvidenceError, "must succeed"):
                evidence.matched_observation(work / "oracle", work / "candidate", work, "matching failure")

    def test_compile_input_snapshot_rejects_source_and_header_tampering_before_object_seal(self) -> None:
        evidence = load_evidence()
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            product = work / "product"
            source = work / "signal_process.c"
            object_path = work / "workload.o"
            manifest = product / "share/crabc/manifest.json"
            driver = product / "bin/crabc-cc-dynamic"
            helper = product / "share/crabc/crabc_cc_static.py"
            compiler = work / "compiler"
            header = product / "usr/include/signal.h"
            for path, contents in (
                (manifest, b"{}\n"), (driver, b"driver\n"), (helper, b"HOSTED_TRANSLATION_FLAGS = ('-fstack-protector-strong',)\n"),
                (compiler, b"compiler\n"), (header, b"header\n"), (source, b"source\n"),
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(contents)
            dependencies = work / "compile-inputs.dependencies"
            trace = work / "compile-inputs.headers"
            status = work / "compile-inputs.header-status"
            dependencies.write_text(f"out.o: {source} {header}\n", encoding="utf-8")
            trace.write_bytes(b"")
            status.write_bytes(b"0\n")
            environment = {"PATH": "/usr/bin:/bin"}
            class Policy:
                @staticmethod
                def clean_environment():
                    return environment
            command = evidence.dependency_command(compiler, product, source)
            record = {
                "schema": evidence.COMPILE_INPUT_SCHEMA,
                "product_manifest": evidence.file_record(manifest),
                "source": evidence.file_record(source),
                "planned_object": str(object_path),
                "driver": evidence.file_record(driver),
                "compiler_helper": evidence.file_record(helper),
                "compiler": evidence.file_record(compiler),
                "driver_compile_command": evidence.driver_compile_command(driver, source, object_path),
                "dependency_audit_command": command,
                "clean_environment": environment,
                "dependency_file": evidence.file_record(dependencies),
                "header_trace": evidence.file_record(trace),
                "header_status": evidence.file_record(status),
                "headers": evidence.dependency_headers(dependencies, product, source),
            }
            snapshot = work / "compile-inputs.json"
            snapshot.write_text(json.dumps(record), encoding="utf-8")
            with patch.object(evidence, "dynamic_product", return_value=(product, manifest, driver)), \
                 patch.object(evidence, "installed_policy", return_value=(Policy(), helper, compiler)), \
                 patch.object(evidence, "SOURCE", source):
                evidence.validate_compile_inputs(product, source, object_path, snapshot)
                source.write_bytes(b"tampered source\n")
                with self.assertRaisesRegex(evidence.SignalProcessEvidenceError, "snapshot source identity drifted"):
                    evidence.validate_compile_inputs(product, source, object_path, snapshot)
                source.write_bytes(b"source\n")
                header.write_bytes(b"tampered header\n")
                with self.assertRaisesRegex(evidence.SignalProcessEvidenceError, "snapshot header identities drifted"):
                    evidence.validate_compile_inputs(product, source, object_path, snapshot)


class OwnedSignalProcessReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.evidence = load_evidence()
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.work = self.base / "work"
        self.work.mkdir()
        self.dynamic_product = self.base / "products/dynamic"
        self.static_product = self.base / "products/static"
        self._product(self.dynamic_product)
        self._product(self.static_product)
        self.object_path = self.work / "signal_process.o"
        self.object_path.write_bytes(b"fixture object\n")
        self.source = SOURCE
        self.compile_audit = self.work / "compile.json"
        self.oracle_cc = self.work / "oracle-cc"
        self.oracle_cc.write_bytes(b"fixture oracle compiler\n")
        self.oracle_binary = self.work / "oracle-binary"
        self.oracle_binary.write_bytes(b"fixture oracle binary\n")
        self.oracle_record = self.work / "oracle.json"
        self.oracle_record.write_text("{}\n", encoding="utf-8")
        self._patches = []
        for target, replacement in (
            (self.evidence, "_validate_dynamic_product"),
            (self.evidence, "_validate_static_product"),
        ):
            value = patch.object(target, replacement, side_effect=self._validate_product)
            value.start()
            self._patches.append(value)
        value = patch.object(
            self.evidence,
            "installed_policy",
            return_value=(self._Policy(), self.dynamic_product / "share/crabc/crabc_cc_static.py", self.compiler),
        )
        value.start()
        self._patches.append(value)
        value = patch.object(self.evidence, "dependency_command", return_value=["compiler", "-M", str(SOURCE)])
        value.start()
        self._patches.append(value)
        value = patch.object(self.evidence, "validate_oracle", side_effect=self._oracle_identity)
        value.start()
        self._patches.append(value)
        value = patch.object(self.evidence, "validate_link", side_effect=self._link_identity)
        self.link_validation = value.start()
        self._patches.append(value)
        self.addCleanup(self._stop_patches)
        self._compile_audit()
        self._link_records()
        self._execution_payload()
        self._raw_observations()

    def _stop_patches(self) -> None:
        for value in reversed(self._patches):
            value.stop()

    @staticmethod
    def _write(path: Path, content: bytes, mode: int = 0o644) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(mode)

    def _product(self, root: Path) -> None:
        self._write(root / "share/crabc/manifest.json", b"{}\n")
        self._write(root / "bin/crabc-cc-dynamic", b"fixture driver\n", 0o755)
        self._write(root / "share/crabc/crabc_cc_static.py", b"fixture helper\n")
        self._write(root / "usr/include/signal.h", b"fixture header\n")

    def _validate_product(self, product: Path):
        return product / "share/crabc/manifest.json", {}

    class _Policy:
        @staticmethod
        def clean_environment():
            return {"PATH": "/usr/bin:/bin"}

    @property
    def compiler(self) -> Path:
        path = self.work / "compiler"
        if not path.exists():
            path.write_bytes(b"fixture compiler\n")
        return path

    def _compile_audit(self) -> None:
        evidence = self.evidence
        product = self.dynamic_product
        manifest = product / "share/crabc/manifest.json"
        driver = product / "bin/crabc-cc-dynamic"
        helper = product / "share/crabc/crabc_cc_static.py"
        compiler = self.compiler
        dependency_file = self.work / "compile-inputs.dependencies"
        header = product / "usr/include/signal.h"
        dependency_file.write_text(f"out.o: {SOURCE} {header}\n", encoding="utf-8")
        trace = self.work / "compile-inputs.headers"
        trace.write_bytes(b"fixture include trace\n")
        status = self.work / "compile-inputs.header-status"
        status.write_bytes(b"0\n")
        snapshot = self.work / "compile-inputs.json"
        evidence.write_new_json(snapshot, {
            "schema": evidence.COMPILE_INPUT_SCHEMA,
            "product_manifest": evidence.file_record(manifest),
            "source": evidence.file_record(SOURCE),
            "planned_object": str(self.object_path),
            "driver": evidence.file_record(driver),
            "compiler_helper": evidence.file_record(helper),
            "compiler": evidence.file_record(compiler),
            "driver_compile_command": evidence.driver_compile_command(driver, SOURCE, self.object_path),
            "dependency_audit_command": evidence.dependency_command(compiler, product, SOURCE),
            "clean_environment": {"PATH": "/usr/bin:/bin"},
            "dependency_file": evidence.file_record(dependency_file),
            "header_trace": evidence.file_record(trace),
            "header_status": evidence.file_record(status),
            "headers": evidence.dependency_headers(dependency_file, product, SOURCE),
        })
        evidence.write_new_json(self.compile_audit, {
            "schema": evidence.COMPILE_SCHEMA,
            "input_snapshot": evidence.file_record(snapshot),
            "object": evidence.file_record(self.object_path),
            "driver_compile_command": evidence.driver_compile_command(driver, SOURCE, self.object_path),
        })

    def _execution_payload(self) -> None:
        evidence = self.evidence
        root = self.work / "execution-root"
        self._write(root / "share/crabc/manifest.json", (self.dynamic_product / "share/crabc/manifest.json").read_bytes())
        consumers = []
        for mode in ("pie", "non-pie"):
            source = self.work / f"dynamic-{mode}"
            execution = root / f"consumer-{mode}"
            self._write(source, f"{mode} consumer\n".encode())
            self._write(execution, source.read_bytes())
            consumers.append({
                "mode": mode,
                **evidence.copied_payload_record(source, execution, f"{mode} execution consumer"),
            })
        evidence.write_new_json(self.work / "execution-payload.json", {
            "schema": evidence.EXECUTION_PAYLOAD_SCHEMA,
            "product_manifest": evidence.file_record(self.dynamic_product / "share/crabc/manifest.json"),
            "execution_root": str(root),
            "product_payload": {
                "share/crabc/manifest.json": evidence.copied_payload_record(
                    self.dynamic_product / "share/crabc/manifest.json",
                    root / "share/crabc/manifest.json",
                    "execution manifest",
                ),
            },
            "consumers": consumers,
        })
        execution = evidence.audit_execution_payload(self.work, self.dynamic_product)
        evidence.write_new_json(self.work / "execution-pre.json", execution)
        evidence.write_new_json(self.work / "execution-post.json", execution)

    def _raw_observations(self) -> None:
        modes = ("static", "static-pie", "pie-kernel", "pie-direct", "non-pie-kernel", "non-pie-direct")
        for subcase in SUBCASES:
            for mode in ("oracle", *modes):
                base = self.work / f"{mode}-{subcase}"
                self._write(base.with_suffix(".status"), b"0\n")
                self._write(base.with_suffix(".stdout"), f"{subcase} output\n".encode())
                self._write(base.with_suffix(".stderr"), b"")

    def _oracle_identity(self, oracle_cc, object_path, binary, _record):
        return {
            "schema": self.evidence.ORACLE_SCHEMA,
            "compiler": self.evidence.file_record(oracle_cc),
            "musl_libc_archive": {"path": "/opt/musl-1.2.6/lib/libc.a", "sha256": "0" * 64},
            "object": self.evidence.file_record(object_path),
            "binary": self.evidence.file_record(binary),
            "link_command": [
                str(oracle_cc), "-static", "-fno-pie", "-no-pie", "-pthread", str(object_path),
                "-o", str(binary),
            ],
        }

    def _link_identity(self, product, object_path, executable, _receipt, linkage):
        return {
            "linkage": linkage,
            "product": str(product),
            "product_format": "fixture/v1",
            "product_manifest_sha256": self.evidence.sha256(product / "share/crabc/manifest.json"),
            "workload_sha256": self.evidence.sha256(object_path),
            "executable_sha256": "a" * 64,
            "receipt_sha256": "b" * 64,
        }

    def _link_records(self) -> None:
        modes = (
            (self.static_product, self.work / "static", "static", self.work / "static.link.json"),
            (self.static_product, self.work / "static-pie", "static-pie", self.work / "static-pie.link.json"),
            (self.dynamic_product, self.work / "dynamic-pie", "pie", self.work / "dynamic-pie.link.json"),
            (self.dynamic_product, self.work / "dynamic-non-pie", "non-pie", self.work / "dynamic-non-pie.link.json"),
        )
        for product, executable, linkage, record in modes:
            receipt = executable.with_suffix(
                ".crabc-link.json" if linkage in {"pie", "non-pie"} else ".receipt.json"
            )
            self.evidence.write_new_json(record, self._link_identity(
                product, self.object_path, executable, receipt, linkage,
            ))

    def _arguments(self, *, static_product=None, report_path=None, source=None, object_path=None,
                   dynamic_product_path=None):
        return {
            "work": self.work,
            "report_path": report_path or self.work / "signal-process-observations.json",
            "static_product": static_product,
            "dynamic_product_path": dynamic_product_path or self.dynamic_product,
            "source": source or self.source,
            "object_path": object_path or self.object_path,
            "compile_audit": self.compile_audit,
            "oracle_cc": self.oracle_cc,
            "oracle_binary": self.oracle_binary,
            "oracle_record": self.oracle_record,
        }

    def _seal(self, static_product):
        return self.evidence.record_observations(
            self.work, static_product, self.dynamic_product, self.source, self.object_path,
            self.compile_audit, self.oracle_cc, self.oracle_binary, self.oracle_record,
        )

    def test_replays_six_mode_and_existing_four_mode_records_without_execution(self) -> None:
        six = self._seal(self.static_product)
        six_report = self.work / "signal-process-observations.json"
        self.assertEqual(json.loads(six_report.read_text(encoding="utf-8")), six)
        self.assertEqual(
            six_report.read_bytes(),
            (json.dumps(six, sort_keys=True, separators=(",", ":")) + "\n").encode(),
        )
        four_path = self.work / "four-mode-observations.json"
        four = self.evidence._observation_record(
            self.work, None, self.dynamic_product, self.source, self.object_path,
            self.compile_audit, self.oracle_cc, self.oracle_binary, self.oracle_record,
        )
        self.evidence.write_new_json(four_path, four)
        self.link_validation.reset_mock()
        with patch.object(self.evidence, "run_in_process_group", side_effect=AssertionError("target execution")), \
             patch.object(self.evidence, "write_new_json", side_effect=AssertionError("report rewrite")):
            self.assertEqual(
                self.evidence.validate_observations(**self._arguments(static_product=self.static_product)), six,
            )
            self.assertEqual(
                self.evidence.validate_observations(**self._arguments(report_path=four_path)), four,
            )
        self.assertEqual(
            [call.args[4] for call in self.link_validation.call_args_list],
            ["static", "static-pie", "pie", "non-pie", "pie", "non-pie"],
        )

    def test_replay_rejects_static_link_mode_and_json_value_mutations(self) -> None:
        self._seal(self.static_product)
        report = self.work / "signal-process-observations.json"
        original = report.read_bytes()
        value = json.loads(original)
        for changed in (
            {**value, "links": value["links"][2:]},
            {**value, "observations": value["observations"][24:]},
            {**value, "unrecognized": True},
            {**value, "process_group_isolation": 1},
        ):
            with self.subTest(changed=changed.keys()):
                report.write_text(json.dumps(changed), encoding="utf-8")
                with self.assertRaises(self.evidence.SignalProcessEvidenceError):
                    self.evidence.validate_observations(**self._arguments(static_product=self.static_product))
        report.write_bytes(original)

    def test_replay_rejects_raw_status_and_stream_mutation(self) -> None:
        self._seal(self.static_product)
        status = self.work / "pie-kernel-siginfo.status"
        stdout = self.work / "pie-kernel-siginfo.stdout"
        status.write_bytes(b"7\n")
        with self.assertRaisesRegex(self.evidence.SignalProcessEvidenceError, "must succeed"):
            self.evidence.validate_observations(**self._arguments(static_product=self.static_product))
        status.write_bytes(b"0\n")
        stdout.write_bytes(b"changed output\n")
        with self.assertRaisesRegex(self.evidence.SignalProcessEvidenceError, "differs"):
            self.evidence.validate_observations(**self._arguments(static_product=self.static_product))

    def test_replay_rejects_missing_or_foreign_source_object_product_and_payload(self) -> None:
        self._seal(self.static_product)
        foreign_source = self.work / "foreign-signal_process.c"
        shutil.copyfile(SOURCE, foreign_source)
        with self.assertRaisesRegex(self.evidence.SignalProcessEvidenceError, "frozen workload"):
            self.evidence.validate_observations(**self._arguments(static_product=self.static_product, source=foreign_source))
        with self.assertRaises(self.evidence.SignalProcessEvidenceError):
            self.evidence.validate_observations(**self._arguments(
                static_product=self.static_product, source=self.work / "missing-source.c",
            ))
        foreign_object = self.work / "foreign-signal_process.o"
        foreign_object.write_bytes(self.object_path.read_bytes())
        with self.assertRaisesRegex(self.evidence.SignalProcessEvidenceError, "planned object path drifted"):
            self.evidence.validate_observations(**self._arguments(
                static_product=self.static_product, object_path=foreign_object,
            ))
        self.object_path.unlink()
        with self.assertRaises(self.evidence.SignalProcessEvidenceError):
            self.evidence.validate_observations(**self._arguments(static_product=self.static_product))
        self.object_path.write_bytes(b"fixture object\n")
        missing_product = self.base / "products/missing"
        with self.assertRaises(self.evidence.SignalProcessEvidenceError):
            self.evidence.validate_observations(**self._arguments(
                static_product=self.static_product, dynamic_product_path=missing_product,
            ))
        with self.assertRaisesRegex(self.evidence.SignalProcessEvidenceError, "must be a physical checkout .work"):
            self.evidence.validate_observations(**self._arguments(
                static_product=self.static_product, dynamic_product_path=Path("/usr/bin"),
            ))
        copied_manifest = self.work / "execution-root/share/crabc/manifest.json"
        copied_manifest.unlink()
        with self.assertRaises(self.evidence.SignalProcessEvidenceError):
            self.evidence.validate_observations(**self._arguments(static_product=self.static_product))
        copied_manifest.write_bytes(b"foreign payload\n")
        with self.assertRaises(self.evidence.SignalProcessEvidenceError):
            self.evidence.validate_observations(**self._arguments(static_product=self.static_product))

    def test_report_mutation_during_replay_is_detected_and_not_repaired(self) -> None:
        self._seal(self.static_product)
        report = self.work / "signal-process-observations.json"
        original_bytes = report.read_bytes()
        original = self.evidence._observation_record

        def mutate_during_replay(*args):
            result = original(*args)
            report.write_bytes(report.read_bytes() + b" ")
            return result

        with patch.object(self.evidence, "_observation_record", side_effect=mutate_during_replay), \
             patch.object(self.evidence, "write_new_json", side_effect=AssertionError("report rewrite")):
            with self.assertRaisesRegex(self.evidence.SignalProcessEvidenceError, "changed during replay"):
                self.evidence.validate_observations(**self._arguments(static_product=self.static_product))
        self.assertTrue(report.read_bytes().endswith(b" "))

        report.write_bytes(original_bytes)
        identity_before = self.evidence._observation_report_identity(report)

        def replace_during_replay(*args):
            result = original(*args)
            replacement = self.work / "replacement-report.json"
            replacement.write_bytes(original_bytes)
            os.replace(replacement, report)
            return result

        with patch.object(self.evidence, "_observation_record", side_effect=replace_during_replay), \
             patch.object(self.evidence, "write_new_json", side_effect=AssertionError("report rewrite")):
            with self.assertRaisesRegex(self.evidence.SignalProcessEvidenceError, "changed during replay"):
                self.evidence.validate_observations(**self._arguments(static_product=self.static_product))
        self.assertEqual(report.read_bytes(), original_bytes)
        self.assertNotEqual(identity_before, self.evidence._observation_report_identity(report))

    def test_execution_copy_record_rejects_consumer_tampering(self) -> None:
        evidence = load_evidence()
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            product = work / "product"
            manifest = product / "share/crabc/manifest.json"
            driver = product / "bin/crabc-cc-dynamic"
            payload = product / "usr/lib/libc.so"
            execution_root = work / "execution-root"
            for path, contents in (
                (manifest, b"{}\n"), (driver, b"driver\n"), (payload, b"payload\n"),
                (execution_root / "share/crabc/manifest.json", b"{}\n"),
                (execution_root / "usr/lib/libc.so", b"payload\n"),
                (work / "dynamic-pie", b"pie\n"), (execution_root / "consumer-pie", b"pie\n"),
                (work / "dynamic-non-pie", b"nonpie\n"), (execution_root / "consumer-non-pie", b"nonpie\n"),
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(contents)
            files = {"usr/lib/libc.so": evidence.sha256(payload)}
            with patch.object(evidence, "dynamic_product", return_value=(product, manifest, driver)), \
                 patch.object(evidence, "_validate_dynamic_product", return_value=(manifest, files)):
                evidence.record_execution_payload(work, product)
                evidence.audit_execution_payload(work, product)
                (execution_root / "consumer-pie").write_bytes(b"tampered\n")
                with self.assertRaisesRegex(evidence.SignalProcessEvidenceError, "execution consumer drifted"):
                    evidence.audit_execution_payload(work, product)


if __name__ == "__main__":
    unittest.main()
