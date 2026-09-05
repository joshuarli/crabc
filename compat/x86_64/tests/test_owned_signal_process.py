#!/usr/bin/env python3
"""Contract tests for the native owned-product signal/process aggregate."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
from unittest.mock import patch
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_signal_process.sh"
EVIDENCE = ROOT / "compat/x86_64/owned_signal_process_evidence.py"
DOCUMENT = ROOT / "compat/x86_64/owned-signal-process.md"
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
                (manifest, b"{}\n"), (driver, b"driver\n"), (helper, b"helper\n"),
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

    def test_document_names_the_frozen_source_and_non_promotion_boundary(self) -> None:
        document = DOCUMENT.read_text(encoding="utf-8")
        self.assertIn("`compat/signal-process/tests/signal_process.c`", document)
        self.assertIn("fresh process group", document)
        self.assertIn("does not promote", document)
        for subcase in SUBCASES:
            self.assertIn(f"`{subcase}`", document)


if __name__ == "__main__":
    unittest.main()
