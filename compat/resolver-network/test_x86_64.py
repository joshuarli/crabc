#!/usr/bin/env python3
"""Contract tests for the native resolver-network runner's local boundaries."""

from __future__ import annotations

import contextlib
import io
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent


def load_runner():
    spec = importlib.util.spec_from_file_location("resolver_network_x86_runner", HERE / "run_x86_64.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load native resolver-network runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load_runner()


class NativeResolverNetworkRunnerTests(unittest.TestCase):
    def test_private_work_root_rejects_a_path_outside_checkout_work(self) -> None:
        with self.assertRaisesRegex(runner.RunnerError, "must stay below"):
            runner.private_work_root(Path("/var/tmp/resolver-network"))

    def test_runner_requires_explicit_prepared_sysroots(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            runner.parse_args([])
        arguments = runner.parse_args([
            "--static-sysroot", "/prepared/static", "--dynamic-sysroot", "/prepared/dynamic",
            "--extracted-static-sysroot", "/prepared/extracted-static",
            "--extracted-dynamic-sysroot", "/prepared/extracted-dynamic",
        ])
        self.assertEqual(arguments.static_sysroot, Path("/prepared/static"))
        self.assertEqual(arguments.dynamic_sysroot, Path("/prepared/dynamic"))

    def test_missing_extracted_product_rejects_before_translation(self) -> None:
        with tempfile.TemporaryDirectory(dir=runner.ROOT / ".work") as directory:
            root = Path(directory)
            installed_static = root / "installed-static"
            installed_dynamic = root / "installed-dynamic"
            extracted_dynamic = root / "extracted-dynamic"
            for path in (installed_static, installed_dynamic, extracted_dynamic):
                path.mkdir()
            arguments = runner.parse_args([
                "--static-sysroot", str(installed_static), "--dynamic-sysroot", str(installed_dynamic),
                "--extracted-static-sysroot", str(root / "missing-static"),
                "--extracted-dynamic-sysroot", str(extracted_dynamic),
            ])
            with self.assertRaisesRegex(runner.RunnerError, "prepared extracted static sysroot"):
                runner.prepared_product_arms(arguments)

    def test_chroot_fixture_writes_only_its_private_conventional_files(self) -> None:
        with tempfile.TemporaryDirectory(dir=runner.ROOT / ".work") as directory:
            root = Path(directory) / "root"
            record = runner.write_fixture_files(root)
            self.assertEqual((root / "etc/hosts").read_text(encoding="ascii"), runner.HOSTS_CONFIG)
            self.assertEqual((root / "etc/resolv.conf").read_text(encoding="ascii"), runner.RESOLVER_CONFIG)
            self.assertEqual(set(record), {"hosts", "resolv_conf"})

    def test_event_contract_requires_every_resolver_transition(self) -> None:
        events = [{"name": name, "action": "answer", "role": "valid"} for name in runner.REQUIRED_SERVER_NAMES]
        events.extend(
            [
                {"name": "malformed.example.test.", "action": "malformed-sequence"},
                {"name": "fallback.example.test.", "role": "valid", "action": "drop"},
                {"name": "fallback.example.test.", "role": "valid", "action": "drop"},
                {"role": "drop", "action": "drop"},
                {"role": "drop", "action": "drop"},
                {"name": "fallback.example.test.", "role": "fallback", "action": "answer"},
                {"name": "fallback.example.test.", "role": "fallback", "action": "answer"},
                {"name": "alias.example.test.", "action": "cname"},
                {"name": "tc.example.test.", "transport": "udp", "action": "tc-sequence"},
            ]
        )
        self.assertFalse(runner.event_contract(events)["passed"])
        events.append({"name": "tc.example.test.", "transport": "tcp", "action": "answer"})
        self.assertTrue(runner.event_contract(events)["passed"])
        self.assertFalse(runner.event_contract(events, executions=2)["passed"])
        self.assertTrue(runner.event_contract(events * 2, executions=2)["passed"])

    def test_comparison_keeps_stream_records_raw(self) -> None:
        reference = runner.outcome(0, b"unchanged\n", b"")
        candidate = runner.outcome(0, b"changed\n", b"")
        self.assertEqual(
            runner.compare(reference, candidate),
            {"exit_status_match": True, "stdout_match": False, "stderr_match": True},
        )

    def test_incomplete_run_never_publishes_the_latest_report(self) -> None:
        with mock.patch.object(runner, "publish_report") as publish:
            self.assertIsNone(runner.publish_complete_report({"passed": False}, Path("private.json"), Path("latest.json")))
        publish.assert_not_called()

    def test_static_pie_elf_audit_accepts_the_et_dyn_header(self) -> None:
        with tempfile.TemporaryDirectory(dir=runner.ROOT / ".work") as directory:
            artifact = Path(directory) / "workload"
            artifact.write_bytes(b"candidate")
            records = iter(
                [
                    {"stdout": {"text": "Machine: Advanced Micro Devices X86-64\nType: DYN (Shared object file)\n"}},
                    {"stdout": {"text": "Program Headers:\n"}},
                    {"stdout": {"text": "   0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND \n"}},
                ]
            )
            with mock.patch.object(runner, "run_checked", side_effect=lambda *args, **kwargs: next(records)), mock.patch.object(
                runner, "command_record", return_value={"stdout": {"text": ""}}
            ):
                runner.elf_audit(artifact, mode="static-pie", dynamic=False)

    def test_unresolved_symbol_rows_exclude_only_the_mandated_null_entry(self) -> None:
        symbols = (
            "   0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND \n"
            "   1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND resolver_dependency\n"
        )
        self.assertEqual(runner.unresolved_symbol_rows(symbols), [
            "   1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND resolver_dependency"
        ])

    def test_dynamic_elf_audit_allows_owned_libc_imports(self) -> None:
        with tempfile.TemporaryDirectory(dir=runner.ROOT / ".work") as directory:
            artifact = Path(directory) / "workload"
            artifact.write_bytes(b"candidate")
            records = iter(
                [
                    {"stdout": {"text": "Machine: Advanced Micro Devices X86-64\nType: DYN (Shared object file)\n"}},
                    {"stdout": {"text": f"INTERP {runner.DYNAMIC_INTERPRETER}\n"}},
                    {"stdout": {"text": "   1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND res_query\n"}},
                ]
            )
            dynamic = {"stdout": {"text": "Shared library: [libc.so]\nLibrary runpath: [/usr/lib]\n"}}
            with mock.patch.object(runner, "run_checked", side_effect=lambda *args, **kwargs: next(records)), mock.patch.object(
                runner, "command_record", return_value=dynamic
            ):
                runner.elf_audit(artifact, mode="dynamic-pie", dynamic=True)

    def test_link_artifacts_creates_its_private_parent(self) -> None:
        with tempfile.TemporaryDirectory(dir=runner.ROOT / ".work") as directory:
            root = Path(directory)
            static_root = root / "static"
            dynamic_root = root / "dynamic"
            for path in (static_root / "bin/crabc-cc", dynamic_root / "bin/crabc-cc-dynamic"):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("#!/bin/sh\n", encoding="ascii")
                path.chmod(0o755)
            object_file = root / "workload.o"
            object_file.write_bytes(b"object")
            with mock.patch.object(runner, "command_record", return_value={"status": 0, "stderr": {"text": ""}}) as command, mock.patch.object(
                runner, "static_receipt_audit", return_value={}
            ), mock.patch.object(runner, "dynamic_receipt_audit", return_value={}), mock.patch.object(
                runner, "elf_audit", return_value={}
            ):
                runner.link_artifacts(static_root, dynamic_root, object_file, root / "artifacts", 1)
            self.assertTrue((root / "artifacts/static-et-exec").is_dir())
            self.assertTrue((root / "artifacts/dynamic-non-pie").is_dir())
            self.assertEqual(command.call_args_list[0].args[0][3], "link.receipt.json")


prepare_spec = importlib.util.spec_from_file_location("resolver_network_x86_prepare", HERE / "prepare_x86_64.py")
if prepare_spec is None or prepare_spec.loader is None:
    raise RuntimeError("cannot load native resolver-network preparation")
prepare = importlib.util.module_from_spec(prepare_spec)
prepare_spec.loader.exec_module(prepare)


class NativeResolverNetworkPreparationTests(unittest.TestCase):
    def test_preparation_root_rejects_an_outside_path(self) -> None:
        with self.assertRaisesRegex(prepare.PreparationError, "must stay below"):
            prepare.prepare_root(Path("/var/tmp/resolver-network"))

    def test_preparation_records_both_fixed_product_builds(self) -> None:
        with tempfile.TemporaryDirectory(dir=prepare.WORK_BOUNDARY) as directory:
            output = Path(directory) / "prepared"

            def produce(arguments, *, timeout):
                destination = Path(arguments[-1])
                if destination.suffix:
                    destination.write_bytes(b"package")
                else:
                    destination.mkdir()
                    if destination.name == "static-extraction":
                        (destination / "crabc-x86_64-owned-static-sysroot").mkdir()
                return {"argv": list(arguments), "status": 0, "stdout": {}, "stderr": {}}

            with mock.patch.object(prepare, "command_record", side_effect=produce) as command:
                report, report_path = prepare.run(prepare.parse_args(["--output", str(output), "--timeout", "1"]))
            self.assertEqual(report["result"], "pass")
            self.assertTrue(report_path.is_file())
            self.assertEqual([Path(call.args[0][-1]).name for call in command.call_args_list], [
                "static-sysroot", "dynamic-sysroot", "static-one.tar.xz", "static-two.tar.xz",
                "dynamic-one.tar", "dynamic-two.tar", "static-extraction", "dynamic-extraction",
            ])
            self.assertTrue(report["packages"]["static"]["byte_identical"])
            self.assertTrue(report["packages"]["dynamic"]["byte_identical"])


if __name__ == "__main__":
    unittest.main()
