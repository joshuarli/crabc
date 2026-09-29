#!/usr/bin/env python3
"""Contract tests for the native resolver-network runner's local boundaries."""

from __future__ import annotations

import contextlib
import io
import importlib.util
import json
import struct
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


def tc_failover_events() -> list[dict[str, object]]:
    name = "tc-failover.example.test."
    question = (b"\x0btc-failover\x07example\x04test\0\0\1\0\1")
    request = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + question
    truncated = struct.pack("!HHHHHH", 0x1234, 0x8380, 1, 0, 0, 0) + question
    complete = (struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + question +
                b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes((198, 51, 100, 55)))
    routes = (("valid", "udp", "drop", None), ("drop", "udp", "drop", None),
              ("fallback", "udp", "tc-sequence", truncated),
              ("fallback", "tcp", "answer", complete))
    return [dict(name=name, role=role, transport=transport, action=action,
                 qtype=1, qclass=1, identifier=0x1234 if transport == "udp" else None,
                 request_hex=request.hex(), response_hex=response.hex() if response else None)
            for role, transport, action, response in routes]


class NativeResolverNetworkRunnerTests(unittest.TestCase):
    def test_shared_dns_startup_keeps_classic_netdb_call_and_explicit_raw_readiness(self) -> None:
        ready = {
            "protocol": "resolver-network-dns-v1",
            "endpoints": {
                role: {"ipv4": address, "port": runner.DNS_PORT,
                       "udp4_port": runner.DNS_PORT, "tcp4_port": runner.DNS_PORT}
                for role, address in runner.ROLE_ADDRESSES.items()
            },
        }
        raw = json.dumps(ready).encode("utf-8") + b"\n"
        with tempfile.TemporaryDirectory(dir=runner.ROOT / ".work") as directory:
            root = Path(directory)
            for retain in (False, True):
                with self.subTest(retain=retain):
                    process = mock.Mock(stdout=io.BytesIO(raw))
                    selector = mock.Mock()
                    selector.select.return_value = [(object(), 1)]
                    with mock.patch.object(runner.subprocess, "Popen", return_value=process), \
                            mock.patch.object(runner.selectors, "DefaultSelector", return_value=selector):
                        arguments = [root / "dns-events.json"]
                        if retain:
                            arguments.append(root / "receipt/dns-ready.json")
                        observed_process, observed_ready = runner.start_server(*arguments)
                    self.assertIs(observed_process, process)
                    self.assertEqual(observed_ready, ready)
                    self.assertEqual((root / "receipt/dns-ready.json").exists(), retain)
                    if retain:
                        self.assertEqual((root / "receipt/dns-ready.json").read_bytes(), raw)
                    selector.close.assert_called_once()

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

    def test_product_arms_require_four_distinct_physical_roots(self) -> None:
        with tempfile.TemporaryDirectory(dir=runner.ROOT / ".work") as directory:
            root = Path(directory)
            for name in ("static", "dynamic", "extracted-dynamic"):
                (root / name).mkdir()
            arguments = runner.parse_args([
                "--static-sysroot", str(root / "static"), "--dynamic-sysroot", str(root / "dynamic"),
                "--extracted-static-sysroot", str(root / "static"),
                "--extracted-dynamic-sysroot", str(root / "extracted-dynamic"),
            ])
            with self.assertRaisesRegex(runner.RunnerError, "four distinct physical roots"):
                runner.prepared_product_arms(arguments)

    def test_chroot_fixture_writes_only_its_private_conventional_files(self) -> None:
        with tempfile.TemporaryDirectory(dir=runner.ROOT / ".work") as directory:
            root = Path(directory) / "root"
            record = runner.write_fixture_files(root)
            self.assertEqual((root / "etc/hosts").read_text(encoding="ascii"), runner.HOSTS_CONFIG)
            self.assertEqual((root / "etc/resolv.conf").read_text(encoding="ascii"), runner.RESOLVER_CONFIG)
            self.assertEqual(set(record), {"hosts", "resolv_conf"})

    def test_event_contract_requires_every_resolver_transition(self) -> None:
        events = [{"name": name, "action": "answer", "role": "valid"}
                  for name in runner.REQUIRED_SERVER_NAMES
                  if name not in {"source-spoof.example.test.", "tc-failover.example.test."}]
        events.extend(
            [
                {"name": "malformed.example.test.", "action": "malformed-sequence"},
                {"name": "fallback.example.test.", "role": "valid", "action": "drop"},
                {"name": "fallback.example.test.", "role": "valid", "action": "drop"},
                {"role": "drop", "action": "drop"},
                {"role": "drop", "action": "drop"},
                {"name": "fallback.example.test.", "role": "fallback", "transport": "udp", "action": "answer"},
                {"name": "fallback.example.test.", "role": "fallback", "transport": "udp", "action": "answer"},
                {"name": "alias.example.test.", "action": "cname"},
                {"name": "chain.example.test.", "role": "valid", "transport": "udp", "action": "cname-chain"},
                {"name": "tc.example.test.", "transport": "udp", "action": "tc-sequence"},
                {"name": "source-spoof.example.test.", "role": "valid", "transport": "udp",
                 "action": "source-spoof-sequence", "forged_source": "127.0.0.4",
                 "valid_source": "127.0.0.1"},
            ]
        )
        events.extend(tc_failover_events())
        self.assertFalse(runner.event_contract(events)["passed"])
        events.append({"name": "tc.example.test.", "transport": "tcp", "action": "answer"})
        self.assertTrue(runner.event_contract(events)["passed"])
        wrong_chain = [
            {**event, "action": "answer"} if event.get("name") == "chain.example.test." else event
            for event in events
        ]
        self.assertFalse(runner.event_contract(wrong_chain)["passed"])
        without_fallback_answer = [
            {**event, "action": "drop"} if event.get("role") == "fallback" else event
            for event in events
        ]
        self.assertFalse(runner.event_contract(without_fallback_answer)["passed"])
        self.assertFalse(runner.event_contract(events, executions=2)["passed"])
        self.assertTrue(runner.event_contract(events * 2, executions=2)["passed"])
        swapped = {"reference": events * 2, "installed-static-et-exec": []}
        self.assertFalse(runner.event_contract(events * 2, executions=2, by_execution=swapped)["passed"])

    def test_event_contract_requires_a_spoofed_source_before_the_valid_answer(self) -> None:
        events = [{"name": name, "action": "answer", "role": "valid"}
                  for name in runner.REQUIRED_SERVER_NAMES
                  if name not in {"source-spoof.example.test.", "tc-failover.example.test."}]
        events.extend([
            {"name": "malformed.example.test.", "action": "malformed-sequence"},
            {"name": "fallback.example.test.", "role": "valid", "action": "drop"},
            {"role": "drop", "action": "drop"},
            {"name": "fallback.example.test.", "role": "fallback", "transport": "udp", "action": "answer"},
            {"name": "alias.example.test.", "action": "cname"},
            {"name": "chain.example.test.", "role": "valid", "transport": "udp", "action": "cname-chain"},
            {"name": "tc.example.test.", "transport": "udp", "action": "tc-sequence"},
            {"name": "tc.example.test.", "transport": "tcp", "action": "answer"},
        ])
        events.extend(tc_failover_events())
        self.assertFalse(runner.event_contract(events)["passed"])
        events.append({"name": "source-spoof.example.test.", "role": "valid", "transport": "udp",
                       "action": "source-spoof-sequence", "forged_source": "127.0.0.4",
                       "valid_source": "127.0.0.1"})
        self.assertTrue(runner.event_contract(events)["passed"])
        events.append({"name": "source-spoof.example.test.", "role": "fallback", "transport": "udp",
                       "action": "answer"})
        self.assertFalse(runner.event_contract(events)["passed"])

    def test_truncated_failover_requires_exact_wire_provenance(self) -> None:
        events = tc_failover_events()
        self.assertTrue(runner.tc_failover_provenance(events))
        ad_bit = [{**event, "request_hex": event["request_hex"][:4] + "0120" + event["request_hex"][8:]}
                  for event in events]
        self.assertTrue(runner.tc_failover_provenance(ad_bit))
        changed = [dict(event) for event in events]
        changed[-1]["response_hex"] = changed[-1]["response_hex"][:-2] + "56"
        self.assertFalse(runner.tc_failover_provenance(changed))
        self.assertFalse(runner.tc_failover_provenance(events[:-1]))
        self.assertFalse(runner.tc_failover_provenance(events[:2] + events[3:] + events[2:3]))

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

    def test_receipt_retention_error_clears_a_previously_passing_summary_before_publication(self) -> None:
        report = {"passed": True, "result": "pass"}
        runner.record_run_error(report, runner.RunnerError("cannot retain physical receipt"))
        self.assertEqual(report, {
            "passed": False,
            "result": "fail",
            "error": "cannot retain physical receipt",
        })
        with mock.patch.object(runner, "publish_report") as publish:
            self.assertIsNone(runner.publish_complete_report(report, Path("private.json"), Path("latest.json")))
        publish.assert_not_called()

    def test_rejected_execution_receipt_preserves_non_utf8_raw_bytes(self) -> None:
        with tempfile.TemporaryDirectory(dir=runner.ROOT / ".work") as directory:
            state = Path(directory) / "state"
            execution_root = Path(directory) / "execution-root"
            state.mkdir()
            execution_root.mkdir()
            record = runner.retain_execution_record(
                state,
                "rejected-candidate",
                ["/workload"],
                (17, b"\xff raw stdout\n", b"\x80 raw stderr\n"),
                execution_root,
            )
            self.assertEqual(
                (state / "receipt/executions/rejected-candidate.stdout").read_bytes(),
                b"\xff raw stdout\n",
            )
            self.assertEqual(
                (state / "receipt/executions/rejected-candidate.stderr").read_bytes(),
                b"\x80 raw stderr\n",
            )
            self.assertEqual(
                (state / "receipt/executions/rejected-candidate.status.json").read_bytes(), b"17\n",
            )
            self.assertEqual(record["root"]["path"], str(execution_root))

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

    @contextlib.contextmanager
    def static_link_fixture(self, *, pie=False, extract_builtins=False):
        with tempfile.TemporaryDirectory(dir=runner.ROOT / ".work") as directory:
            root = Path(directory)
            product = root / "static"
            library = product / "usr/lib"
            library.mkdir(parents=True)
            entry = "rcrt1.o" if pie else "crt1.o"
            roles = ("crt-entry", "crt-prologue", "libc", "builtins", "crt-epilogue")
            runtime = [library / name for name in
                       (entry, "crti.o", "libc.a", "libcrabc-builtins.a", "crtn.o")]
            for path in runtime:
                path.write_bytes(path.name.encode())
            application = root / "workload.o"
            application.write_bytes(b"application")
            output = root / "workload"
            output.write_bytes(b"linked output")
            receipt = root / "link.receipt.json"
            receipt.with_suffix(".map").write_bytes(b"owned map")
            lines = [str(runtime[0]), str(runtime[1]), str(application),
                     f"{runtime[2]}(resolver.o)"]
            if extract_builtins:
                lines.append(f"{runtime[3]}(helper.o)")
            lines.append(str(runtime[4]))
            trace = receipt.with_suffix(".trace")
            trace.write_text("\n".join(lines) + "\n", encoding="ascii")
            record = {
                "schema": 1, "format": runner.STATIC_FORMAT,
                "mode": {"id": "static-pie" if pie else "static-et-exec",
                         "crt_object": entry, "elf_type": "ET_DYN" if pie else "ET_EXEC",
                         "interpreter": "absent"},
                "input_receipts": [
                    {"role": role, "path": path.relative_to(product).as_posix(),
                     "sha256": runner.sha256_file(path)}
                    for role, path in zip(roles, runtime)
                ] + [{"role": "application", "path": str(application),
                      "sha256": runner.sha256_file(application)}],
                "output": {"path": str(output), "sha256": runner.sha256_file(output)},
                "owned_link_contract": [
                    "ld.lld", "-static", *(["-pie"] if pie else []),
                    "--no-dynamic-linker", "--no-undefined", "--eh-frame-hdr", "--gc-sections",
                    "-z", "relro", "-z", "now", "-e", "_start",
                    str(runtime[0]), str(runtime[1]), "<application-objects>",
                    str(runtime[2]), str(runtime[3]), str(runtime[4]), "-o", "<output>",
                ],
            }

            def audit():
                for field in ("map", "trace"):
                    path = receipt.with_suffix("." + field)
                    record[field] = {"path": path.name, "sha256": runner.sha256_file(path)}
                receipt.write_text(json.dumps(record), encoding="ascii")
                return runner.static_receipt_audit(
                    product, "--static-pie" if pie else "--static-et-exec",
                    application, output, receipt,
                )

            yield record, trace, audit

    def test_static_receipt_authenticates_a_builtins_archive_without_extracted_members(self) -> None:
        for pie in (False, True):
            for extracted in (False, True):
                with self.subTest(pie=pie, extracted=extracted), self.static_link_fixture(
                        pie=pie, extract_builtins=extracted) as (_, _, audit):
                    self.assertIn("receipt", audit())

    def test_static_receipt_rejects_an_unbound_unused_archive(self) -> None:
        for remove_from in ("input_receipts", "owned_link_contract"):
            with self.subTest(remove_from=remove_from), self.static_link_fixture() as (record, _, audit):
                if remove_from == "input_receipts":
                    record[remove_from] = [item for item in record[remove_from] if item["role"] != "builtins"]
                else:
                    record[remove_from] = [item for item in record[remove_from] if not item.endswith("libcrabc-builtins.a")]
                with self.assertRaisesRegex(runner.RunnerError, "runtime|contract"):
                    audit()

    def test_static_receipt_still_rejects_unowned_or_missing_direct_trace_inputs(self) -> None:
        for missing_direct in (False, True):
            with self.subTest(missing_direct=missing_direct), self.static_link_fixture() as (_, trace, audit):
                lines = trace.read_text().splitlines()
                if missing_direct:
                    lines.pop(0)
                else:
                    lines.append("/ambient/libgcc.a(helper.o)")
                trace.write_text("\n".join(lines) + "\n", encoding="ascii")
                with self.assertRaisesRegex(runner.RunnerError, "unowned|boundary"):
                    audit()

    def test_dynamic_receipt_audit_accepts_closed_schema_one_and_schema_two(self) -> None:
        with tempfile.TemporaryDirectory(dir=runner.ROOT / ".work") as directory:
            root = Path(directory)
            product = root / "dynamic"
            library = product / "usr/lib"
            library.mkdir(parents=True)
            runtime = []
            for name in ("crti.o", "libc.so", "crtn.o", "Scrt1.o", "crabc-dynamic-attach.o", "libcrabc-builtins.a"):
                path = library / name
                path.write_bytes((name + "\n").encode())
                runtime.append(path)
            manifest = product / "share/crabc/manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_bytes(b"owned manifest\n")
            object_file = root / "workload.o"
            object_file.write_bytes(b"workload\n")
            output = root / "consumer"
            output.write_bytes(b"consumer\n")
            selected = runtime[:5]
            archive = runtime[-1]
            base = {
                "format": runner.DYNAMIC_FORMAT,
                "mode": "pie",
                "binding": "now",
                "runtime_imports": [],
                "application_runpath": "/usr/lib",
                "output_path": str(output.resolve()),
                "output_sha256": runner.sha256_file(output),
                "manifest_sha256": runner.sha256_file(manifest),
                "application_dsos": {},
                "owned_runtime_inputs": sorted(path.relative_to(product).as_posix() for path in [*selected, archive]),
                "input_receipts": [
                    {"path": str(path), "sha256": runner.sha256_file(path)}
                    for path in [*selected, object_file.resolve(), archive]
                ],
                "resolved_linker": {"path": "/owned/ld.lld", "sha256": "0" * 64},
                "link_command": ["/owned/ld.lld"],
                "link_trace": [*(str(path) for path in selected), str(object_file.resolve())],
                "campaign_complete": False,
            }

            def audit(record):
                receipt = root / "consumer.crabc-link.json"
                receipt.write_text(json.dumps(record), encoding="utf-8")
                return runner.dynamic_receipt_audit(product, "--dynamic-pie", object_file, output, receipt)

            for schema in (1, 2):
                with self.subTest(schema=schema):
                    record = {**base, "schema": schema}
                    if schema == 2:
                        record.update({
                            "application_search_kind": "runpath",
                            "application_rpath": None,
                            "application_hash_style": "sysv",
                        })
                    self.assertEqual(audit(record)["input_count"], 7)

            valid = {
                **base, "schema": 2, "application_search_kind": "runpath",
                "application_rpath": None, "application_hash_style": "sysv",
            }
            for changed in (
                {key: value for key, value in valid.items() if key != "schema"},
                {**base, "schema": 1, "application_search_kind": "runpath"},
                {**valid, "application_hash_style": "gnu"},
                {**valid, "application_search_kind": "rpath", "application_runpath": None,
                 "application_rpath": "/usr/lib"},
            ):
                with self.subTest(changed=changed):
                    with self.assertRaisesRegex(runner.RunnerError, "schema|fields|search-path"):
                        audit(changed)


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
