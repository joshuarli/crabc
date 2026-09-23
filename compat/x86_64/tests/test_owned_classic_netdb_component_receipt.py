#!/usr/bin/env python3
"""Focused contract tests for the bounded classic-netdb receipt reader."""

from __future__ import annotations

import importlib.util
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


if __name__ == "__main__":
    unittest.main()
