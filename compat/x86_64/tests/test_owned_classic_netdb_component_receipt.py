#!/usr/bin/env python3
"""Focused contract tests for the bounded classic-netdb receipt reader."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import tempfile
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "compat/x86_64/owned_classic_netdb_component_receipt.py"


def load_module():
    spec = importlib.util.spec_from_file_location("owned_classic_netdb_receipt_test", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


class OwnedClassicNetdbComponentReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.receipt = load_module()

    def test_component_contract_closes_only_the_named_resolver_slice(self) -> None:
        self.assertEqual(len(self.receipt.CASES), 23)
        report = {
            "component": "classic-netdb",
            "scope": ["libc.resolver"],
            "cases": list(self.receipt.CASES),
            "behavior_roster": self.receipt.BEHAVIOR_ROSTER,
            "family_completion": False,
            "promotion_ready": False,
            "public_support": False,
        }
        self.receipt.validate_component_contract(report)
        report["scope"] = ["network.resolver-transport"]
        with self.assertRaisesRegex(self.receipt.ReceiptError, "scope"):
            self.receipt.validate_component_contract(report)

    def test_development_dynamic_mode_cannot_supply_the_six_cell_requirement(self) -> None:
        self.assertEqual(self.receipt.cells(self.receipt.DYNAMIC_MODE), self.receipt.DYNAMIC_CELLS)
        self.assertEqual(self.receipt.cells(self.receipt.FULL_MODE), self.receipt.FULL_CELLS)
        with self.assertRaisesRegex(self.receipt.ReceiptError, "requires static/static-pie"):
            self.receipt.require_static_mode(self.receipt.DYNAMIC_MODE, True)

    def test_command_plan_keeps_the_one_object_and_installed_header_boundary(self) -> None:
        root = Path("/workspace")
        work = root / ".work/receipt"
        dynamic = root / ".work/dynamic"
        static = root / ".work/static"
        tools = {name: {"path": path} for name, path in {
            "oracle": "/usr/local/bin/crabc-x86_64-musl-gcc", "readelf": "/usr/bin/readelf",
            "compiler": "/usr/bin/gcc",
            "dynamic_driver": "/workspace/.work/dynamic/bin/crabc-cc-dynamic",
            "static_driver": "/workspace/.work/static/bin/crabc-cc",
        }.items()}
        plan = self.receipt.command_plan(root, work, static, dynamic, tools, self.receipt.FULL_MODE)
        self.assertEqual(plan["compile"].count("/workspace/.work/receipt/workload.o"), 1)
        self.assertIn("/workspace/.work/static/usr/include", plan["header-trace"])
        self.assertEqual(plan["static-link"][-2:], ["-o", "/workspace/.work/receipt/static"])

    def test_source_product_paths_accept_path_instances_from_argparse(self) -> None:
        self.assertEqual(
            self.receipt.mounted_relative(Path("/workspace/.work/frozen-26df/product"), "dynamic product"),
            ".work/frozen-26df/product",
        )

    def test_dns_event_document_keeps_the_fixture_schema_wrapper(self) -> None:
        self.assertEqual(
            self.receipt.dns_events({"schema_version": 1, "events": [{"name": "a.example.test."}]}),
            [{"name": "a.example.test."}],
        )

    def test_runner_keeps_the_single_dynamic_argument_branch(self) -> None:
        runner = (ROOT / "compat/x86_64/run_owned_classic_netdb.sh").read_text(encoding="utf-8")
        self.assertIn('if ! { [ "$#" -eq 1 ] || { [ "$#" -eq 3 ] && [ "$1" = --static-sysroot ]; }; }; then', runner)

    def test_link_replay_uses_the_fixed_pinned_lld_identity(self) -> None:
        self.assertEqual(self.receipt.LINKER_PATH.name, "ld.lld")
        self.assertIn(self.receipt.TOOLCHAIN, str(self.receipt.LINKER_PATH))

    def test_current_image_manifest_binds_the_selected_toolchain_and_exact_files(self) -> None:
        manifest = self.receipt.trusted_image_manifest(ROOT)
        self.assertEqual(
            manifest["image"],
            "sha256:307d75f06680c631437f9faa5f7c726613fcea6f1875dda8cf368ad4b6da1b3d",
        )
        files = manifest["files"]
        self.assertEqual(
            files[str(self.receipt.TOOLCHAIN_ROOT / "bin/rustc")]["sha256"],
            "228e24592d38da145ce4064b14e4bcfdd13cd3e2623bdbdcec45f37d16ef7b3b",
        )
        self.assertEqual(
            files[str(self.receipt.LINKER_PATH)]["sha256"],
            "dc40fa1b087ed4538d410a08e7314bcc1614dc7ff728b5bbf624a1daa97730bc",
        )

    def test_symbol_claims_replay_the_elf_not_retained_symbol_text(self) -> None:
        output = b"""Symbol table '.dynsym' contains 2 entries:\n   Num:    Value          Size Type    Bind   Vis      Ndx Name\n     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND gethostbyname\n     2: 0000000000001000    10 FUNC    GLOBAL DEFAULT   12 gethostbyname\n"""
        with mock.patch.object(self.receipt, "replay_readelf", return_value=output) as replay:
            self.receipt.validate_provider_symbols(Path("/readonly/libc.so"), "dynamic provider", ("gethostbyname",))
        replay.assert_called_once_with(Path("/readonly/libc.so"), dynamic=True)

    def test_symbol_replay_rejects_an_undefined_only_provider(self) -> None:
        output = b"""Symbol table '.dynsym' contains 1 entry:\n   Num:    Value          Size Type    Bind   Vis      Ndx Name\n     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND gethostbyname\n"""
        with mock.patch.object(self.receipt, "replay_readelf", return_value=output):
            with self.assertRaisesRegex(self.receipt.ReceiptError, "gethostbyname"):
                self.receipt.validate_provider_symbols(Path("/readonly/libc.so"), "dynamic provider", ("gethostbyname",))

    def test_only_the_named_exact_question_transcript_difference_is_admitted(self) -> None:
        value = {
            "case": "dns-batch",
            "entry": "dynamic-pie-kernel",
            "musl_stdout": "wrong-association=203.0.113.50\nclassic netdb scenario passed\n",
            "owned_stdout": "wrong-association=198.51.100.50\nclassic netdb scenario passed\n",
            "stderr": "",
        }
        self.receipt.validate_association_difference(value)
        value["entry"] = "oracle"
        with self.assertRaisesRegex(self.receipt.ReceiptError, "association"):
            self.receipt.validate_association_difference(value)

    def test_execution_evidence_binds_argv_and_file_positions(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp/classic-netdb-reader-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            work = root / "receipt"
            work.mkdir()
            label = "dynamic-pie-direct-host-numeric"
            data = {
                "argv": b'["/lib/ld-crabc-x86_64.so.1","/consumer","host-numeric"]\n',
                "stdout": b"classic netdb scenario passed\n",
                "stderr": b"",
                "status": b"0\n",
            }
            record = {}
            for field, value in data.items():
                suffix = "argv.json" if field == "argv" else field
                path = work / f"{label}.{suffix}"
                path.write_bytes(value)
                record[field] = self.receipt.identity(root, path)

            self.assertEqual(
                self.receipt.execution_artifacts(root, work, "dynamic-pie-direct", "host-numeric", record),
                (data["stdout"], data["stderr"]),
            )
            argv_path = work / f"{label}.argv.json"
            argv_path.write_bytes(b'["/other","host-numeric"]\n')
            record["argv"] = self.receipt.identity(root, argv_path)
            with self.assertRaisesRegex(self.receipt.ReceiptError, "execution argv"):
                self.receipt.execution_artifacts(root, work, "dynamic-pie-direct", "host-numeric", record)

            argv_path.write_bytes(data["argv"])
            record["argv"] = self.receipt.identity(root, argv_path)
            sibling = root / "sibling.stdout"
            sibling.write_bytes(data["stdout"])
            record["stdout"] = self.receipt.identity(root, sibling)
            with self.assertRaisesRegex(self.receipt.ReceiptError, "path differs"):
                self.receipt.execution_artifacts(root, work, "dynamic-pie-direct", "host-numeric", record)

    @unittest.skipUnless(os.getuid() == 0 and Path("/usr/local/bin/crabc-x86_64-musl-gcc").is_file(),
                         "requires the pinned compiler and an isolated unprivileged child")
    def test_source_recompile_uses_private_scratch_with_read_only_artifacts(self) -> None:
        temporary = ROOT / ".work/x86_64/tmp"
        temporary.mkdir(parents=True, exist_ok=True)
        original_mode = stat.S_IMODE(temporary.stat().st_mode)
        with tempfile.TemporaryDirectory(dir=temporary) as directory:
            work = Path(directory)
            workload = work / "workload.o"
            compiler = "/usr/local/bin/crabc-x86_64-musl-gcc"
            source = work / "probe.c"
            source.write_text("int retained_probe(void) { return 73; }\n", encoding="utf-8")
            argv = [compiler, "-std=c11", "-fno-builtin", "-c", str(source), "-o", str(workload)]
            subprocess.run(argv, check=True, capture_output=True)
            script = ("from pathlib import Path; import sys,json; "
                      "sys.path.insert(0, 'compat/x86_64'); "
                      "import owned_classic_netdb_component_receipt as r; "
                      "r.validate_source_object(Path('/workspace'), Path(sys.argv[1]), "
                      "Path(sys.argv[2]), json.loads(sys.argv[3]))")
            command = [sys.executable, "-B", "-c", script, str(work), str(workload), json.dumps(argv)]
            rejection = b"classic-netdb workload differs from source compile"
            before = {item.name: item.read_bytes() for item in work.iterdir()}
            try:
                temporary.chmod(0o1777)
                work.chmod(0o555)
                result = subprocess.run(command, cwd=ROOT, capture_output=True, user=65534, group=65534)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual({item.name: item.read_bytes() for item in work.iterdir()}, before)
                workload.write_bytes(b"substituted object")
                result = subprocess.run(command, cwd=ROOT, capture_output=True, user=65534, group=65534)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(rejection, result.stderr)
            finally:
                work.chmod(0o755)
                temporary.chmod(original_mode)

    def test_self_consistent_workload_identity_requires_source_recompile(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp/classic-netdb-reader-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            work = root / ".work/receipt"
            work.mkdir(parents=True)
            static = root / ".work/static"
            dynamic = root / ".work/dynamic"
            static.mkdir()
            dynamic.mkdir()
            source = root / self.receipt.SOURCE_PATHS["probe"]
            source.parent.mkdir(parents=True)
            source.write_text("int probe(void) { return 1; }\n", encoding="utf-8")
            compiler = work / "compiler"
            compiler.write_text(
                '#!/bin/sh\nwhile [ "$1" != -o ]; do shift; done\n'
                'shift\nprintf "\\177ELF\\002\\001\\001\\000\\000\\000\\000\\000\\000\\000\\000\\000\\001\\000>\\000source" > "$1"\n',
                encoding="utf-8",
            )
            compiler.chmod(0o755)
            workload = work / "workload.o"
            workload.write_bytes(b"\x7fELF\x02\x01\x01" + b"\0" * 9 + b"\x01\0>\0transplanted")
            manifest = root / ".work/image.json"
            manifest.write_text("{}\n", encoding="utf-8")
            seal = {"sources": {"probe": "selected"}}
            tools = {"static_driver": {"path": str(compiler)}}
            seals = {}
            for name, value in (("source-product-before", seal), ("source-product-after", seal),
                                ("tools-before", tools), ("tools-after", tools)):
                path = work / f"{name}.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                seals[name] = self.receipt.identity(root, path)
            plan = {
                "compile": [str(compiler), "-c", str(source), "-o", str(workload)],
                "header-trace": [str(compiler), "-H", str(source)],
            }
            commands = {}
            for label, argv in plan.items():
                commands[label] = {}
                for field, data in (("argv", json.dumps(argv).encode()), ("stdout", b""),
                                    ("stderr", (str(static / "usr/include/netdb.h") + "\n").encode()
                                     if label == "header-trace" else b""), ("status", b"0\n")):
                    path = work / f"{label}.{'argv.json' if field == 'argv' else field}"
                    path.write_bytes(data)
                    commands[label][field] = self.receipt.identity(root, path)
            report = {
                "schema": self.receipt.SCHEMA, "component": self.receipt.COMPONENT,
                "source_mount": str(root), "execution_mode": self.receipt.FULL_MODE,
                "scope": list(self.receipt.SCOPE), "cases": list(self.receipt.CASES),
                "behavior_roster": self.receipt.BEHAVIOR_ROSTER, "sources": seal["sources"],
                "products": {"static": static.relative_to(root).as_posix(),
                             "dynamic": dynamic.relative_to(root).as_posix()},
                "seals": seals, "image": {"id": self.receipt.PINNED_IMAGE,
                                          "manifest": self.receipt.identity(root, manifest)},
                "workload": self.receipt.identity(root, workload), "commands": commands,
                "links": {}, "payloads": {}, "executions": [], "network": {}, "dns": {}, "audits": {},
                "association_differences": [], "family_completion": False,
                "promotion_ready": False, "public_support": False,
            }
            report_path = work / "classic-netdb-products.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            with mock.patch.object(self.receipt, "SOURCE_MOUNT", str(root)), \
                    mock.patch.object(self.receipt, "IMAGE_MANIFEST", ".work/image.json"), \
                    mock.patch.object(self.receipt, "source_product_seal", return_value=seal), \
                    mock.patch.object(self.receipt, "trusted_image_manifest", return_value={}), \
                    mock.patch.object(self.receipt, "tool_roster", return_value=tools), \
                    mock.patch.object(self.receipt, "command_plan", return_value=plan), \
                    mock.patch.object(self.receipt, "validate_provider_symbols", side_effect=AssertionError("substituted object accepted")):
                with self.assertRaisesRegex(self.receipt.ReceiptError, "workload differs from source compile"):
                    self.receipt.validate_report(root, report_path, require_static=True)


if __name__ == "__main__":
    unittest.main()
