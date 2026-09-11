#!/usr/bin/env python3
"""Observable boundaries for the retained native loader inventory."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_loader_inventory as inventory


class OwnedLoaderInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / ".work" / "x86_64" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.product = self.root / "product"
        for relative in (inventory.LOADER_PATH, inventory.LIBC_PATH):
            path = self.product / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"candidate ELF\n")
        self.oracle = self.root / "oracle"
        self.oracle.mkdir()
        self.fake_mode = self.root / "readelf-mode"
        self.fake_mode.write_text("valid\n", encoding="utf-8")
        self.readelf = self.root / "readelf"
        self.readelf.write_text(
            "#!" + sys.executable + "\n"
            "from pathlib import Path\n"
            "import sys\n"
            "mode = Path(__file__).with_name('readelf-mode').read_text().strip()\n"
            "argument = sys.argv[1]\n"
            "if mode == 'empty': raise SystemExit(0)\n"
            "if argument == '-hW':\n"
            "  machine = 'AArch64' if mode == 'wrong-architecture' else 'Advanced Micro Devices X86-64'\n"
            "  print('ELF Header:')\n"
            "  print('  Class:                             ELF64')\n"
            "  print(\"  Data:                              2\\'s complement, little endian\")\n"
            "  print('  Version:                           1 (current)')\n"
            "  print('  OS/ABI:                            UNIX - System V')\n"
            "  print('  Type:                              DYN (Shared object file)')\n"
            "  print('  Machine:                           ' + machine)\n"
            "  print('  Entry point address:               0x1000')\n"
            "  print('  Start of program headers:          64 (bytes into file)')\n"
            "  print('  Size of program headers:           56 (bytes)')\n"
            "  print('  Number of program headers:         2')\n"
            "  print('  Number of section headers:         4')\n"
            "elif argument == '-lW':\n"
            "  print('Elf file type is DYN (Shared object file)')\n"
            "  print('Entry point 0x1000')\n"
            "  print('There are 2 program headers, starting at offset 64')\n"
            "  print('Program Headers:')\n"
            "  print('  Type           Offset             VirtAddr           PhysAddr           FileSiz            MemSiz              Flg       Align')\n"
            "  print('  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000 0x0000000000000200 0x0000000000000200 R E 0x1000')\n"
            "  print('  GNU_PROPERTY   0x0000000000000200 0x0000000000000200 0x0000000000000200 0x0000000000000020 0x0000000000000020 R 0x8')\n"
            "  print(' Section to Segment mapping:')\n"
            "elif argument == '-dW':\n"
            "  print('Dynamic section at offset 0x200 contains 1 entry:')\n"
            "  print('  Tag        Type                         Name/Value')\n"
            "  print(' 0x0000000000000005 (STRTAB)             0x200')\n"
            "elif argument == '-rW':\n"
            "  print('There are no relocations in this file.')\n"
            "elif argument == '--dyn-syms':\n"
            "  print(\"Symbol table '.dynsym' contains 1 entry:\")\n"
            "  print('   Num:    Value          Size Type    Bind   Vis      Ndx Name')\n"
            "  print('     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND ')\n"
            "else: raise SystemExit(2)\n",
            encoding="utf-8",
        )
        self.readelf.chmod(0o755)
        self.product_snapshot = {
            "root": self.product.relative_to(ROOT).as_posix(),
            "manifest_sha256": "a" * 64,
            "state": {"path": "share/crabc/dynamic-product-state.json", "sha256": "b" * 64, "mode": 0o644},
            "loader": {"path": inventory.LOADER_PATH, "sha256": "c" * 64, "mode": 0o755},
            "loader_alias": {"path": inventory.LOADER_ALIAS_PATH, "target": "ld-crabc-x86_64.so.1"},
            "libc": {"path": inventory.LIBC_PATH, "sha256": "d" * 64, "mode": 0o644},
            "loader_provenance": {"path": inventory.LOADER_PROVENANCE_PATH, "sha256": "e" * 64, "mode": 0o644},
        }
        self.source_snapshot = {
            "source_sha256": "f" * 64,
            "loader_provenance_sha256": "e" * 64,
            "compiler_dependencies": [],
            "configuration": [],
        }
        self.rows = [{
            "name": "compiler_selected_loader_closure", "description": "test source closure",
            "selected_sources": [], "targets": [], "runtime_test_executed": False, "verified": False,
        }]
        self.capture = mock.patch.object(
            inventory,
            "capture_bindings",
            return_value=(self.product_snapshot, self.source_snapshot, {}),
        )
        self.oracle_capture = mock.patch.object(inventory, "oracle_capture", side_effect=self.capture_oracle)
        self.oracle_loader_alias = mock.patch.object(
            inventory,
            "oracle_loader_alias",
            return_value={
                "path": inventory.MUSL_LOADER_PATH,
                "target": "/opt/musl-1.2.6/lib/libc.so",
                "sha256": "3" * 64,
                "mode": 0o755,
            },
        )
        self.readelf_capture = mock.patch.object(inventory, "readelf_capture", side_effect=self.capture_readelf)
        self.features = mock.patch.object(inventory, "feature_rows", return_value=self.rows)
        self.live_oracle = mock.patch.object(inventory.qualification, "require_live_oracle", return_value=None)
        self.validate_oracle = mock.patch.object(inventory.qualification, "validate_oracle", return_value={})
        self.capture_mock = self.capture.start()
        self.oracle_capture.start()
        self.oracle_loader_alias.start()
        self.readelf_capture.start()
        self.features.start()
        self.live_oracle.start()
        self.validate_oracle.start()
        self.addCleanup(self.capture.stop)
        self.addCleanup(self.oracle_capture.stop)
        self.addCleanup(self.oracle_loader_alias.stop)
        self.addCleanup(self.readelf_capture.stop)
        self.addCleanup(self.features.stop)
        self.addCleanup(self.live_oracle.stop)
        self.addCleanup(self.validate_oracle.stop)

    def receipt_path(self, name: str = "inventory.json") -> Path:
        return self.root / name

    def collect(self, name: str = "inventory.json") -> tuple[Path, dict]:
        path = self.receipt_path(name)
        receipt = inventory.collect(self.product, self.oracle, path, self.readelf)
        return path, receipt

    def capture_oracle(self, root: Path, requested: Path) -> dict:
        self.assertEqual(requested, self.oracle)
        identity = {
            "schema": "crabc.x86_64-owned-loader-inventory-oracle-capture/v1",
            "oracle": {"runtime_sha256": "3" * 64},
            "loader_alias": {
                "path": inventory.MUSL_LOADER_PATH,
                "target": "/opt/musl-1.2.6/lib/libc.so",
                "sha256": "3" * 64,
                "mode": 0o755,
            },
        }
        path = root / "oracle-capture.json"
        path.write_text(json.dumps(identity), encoding="utf-8")
        path.chmod(0o444)
        return {
            "path": path.relative_to(ROOT).as_posix(), "sha256": inventory.digest(path), "identity": identity,
        }

    def capture_readelf(self, root: Path, readelf: Path) -> dict:
        identity = {
            "schema": "crabc.x86_64-owned-loader-inventory-readelf-capture/v1",
            "readelf": inventory.tool_identity(readelf),
        }
        path = root / "readelf-capture.json"
        path.write_text(json.dumps(identity), encoding="utf-8")
        path.chmod(0o444)
        return {
            "path": path.relative_to(ROOT).as_posix(), "sha256": inventory.digest(path), "identity": identity,
        }

    @staticmethod
    def rewrite(path: Path, transform) -> None:
        path.chmod(0o644)
        value = json.loads(path.read_text(encoding="utf-8"))
        transform(value)
        path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")

    def test_collects_raw_shapes_and_host_replay_does_not_execute_readelf(self) -> None:
        path, receipt = self.collect()
        self.assertTrue(receipt["inventory_complete"])
        self.assertFalse(receipt["runtime_test_executed"])
        self.assertFalse(receipt["runtime_verified"])
        self.assertEqual(len(receipt["raw_readelf"]), 15)
        self.assertEqual((path.parent / (path.name + ".inputs")).stat().st_mode & 0o555, 0o555)
        with mock.patch.object(inventory.subprocess, "run", side_effect=AssertionError("reader executed readelf")), \
             mock.patch.object(inventory, "tool_identity", side_effect=AssertionError("reader opened host readelf")), \
             mock.patch.object(inventory.qualification, "require_live_oracle", side_effect=AssertionError("reader read native oracle")):
            self.assertEqual(
                inventory.validate_receipt(path, self.product, path.parent / (path.name + ".inputs/oracle-capture.json"),
                                           path.parent / (path.name + ".inputs/readelf-capture.json")),
                receipt,
            )

    def test_collect_rejects_empty_and_wrong_architecture_readelf_streams(self) -> None:
        for mode in ("empty", "wrong-architecture"):
            with self.subTest(mode=mode):
                self.fake_mode.write_text(mode + "\n", encoding="utf-8")
                with self.assertRaises(inventory.InventoryError):
                    self.collect("bad-" + mode + ".json")
        self.assertFalse(self.receipt_path("bad-empty.json").exists())
        self.assertFalse(self.receipt_path("bad-wrong-architecture.json").exists())

    @staticmethod
    def program_header_stream(types: list[str]) -> str:
        rows = [
            "  " + kind + "  0x000000 0x0000000000000000 0x0000000000000000 "
            "0x000020 0x000020 R 0x8"
            for kind in types
        ]
        return "\n".join([
            "Elf file type is DYN (Shared object file)",
            "Entry point 0x1000",
            f"There are {len(types)} program headers, starting at offset 64",
            "",
            "Program Headers:",
            "  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align",
            *rows,
            "",
            " Section to Segment mapping:",
        ]) + "\n"

    def test_program_header_parser_retains_actual_gnu_property_and_closes_counts(self) -> None:
        actual_musl_types = [
            "LOAD", "LOAD", "LOAD", "LOAD", "DYNAMIC", "NOTE", "NOTE", "GNU_PROPERTY",
            "GNU_EH_FRAME", "GNU_STACK", "GNU_RELRO",
        ]
        parsed = inventory.parse_program_headers(self.program_header_stream(actual_musl_types))
        self.assertEqual(parsed["declared_entries"], 11)
        self.assertEqual(parsed["observed_entries"], 11)
        self.assertEqual(parsed["entries"][7]["type"], "GNU_PROPERTY")
        self.assertEqual(
            inventory.parse_program_headers(self.program_header_stream(["LOOS+0x1234"]))["entries"][0]["type"],
            "LOOS+0x1234",
        )
        with self.assertRaisesRegex(inventory.InventoryError, "truncated"):
            inventory.parse_program_headers(self.program_header_stream(actual_musl_types[:-1]).replace(
                "There are 10 program headers", "There are 11 program headers"
            ))
        with self.assertRaisesRegex(inventory.InventoryError, "malformed"):
            inventory.parse_program_headers(self.program_header_stream(["LOAD"]).replace(
                "  LOAD  0x000000", "  LOAD  not-an-offset"
            ))

    def test_shape_rejects_program_header_count_mismatch_and_dynamic_truncation(self) -> None:
        streams = {
            "header": "\n".join([
                "  Class: ELF64", "  Data: 2's complement, little endian", "  Version: 1 (current)",
                "  OS/ABI: UNIX - System V", "  Type: DYN", "  Machine: Advanced Micro Devices X86-64",
                "  Entry point address: 0x1000", "  Start of program headers: 64", "  Size of program headers: 56",
                "  Number of program headers: 10", "  Number of section headers: 4",
            ]),
            "program_headers": self.program_header_stream(["LOAD"]),
            "dynamic": "\n".join([
                "Dynamic section at offset 0x200 contains 1 entry:", "  Tag        Type                         Name/Value",
                " 0x0000000000000005 (STRTAB)             0x200",
            ]),
            "relocations": "There are no relocations in this file.\n",
            "dynamic_symbols": "\n".join([
                "Symbol table '.dynsym' contains 1 entry:", "   Num:    Value          Size Type    Bind   Vis      Ndx Name",
                "     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND ",
            ]),
        }
        with self.assertRaisesRegex(inventory.InventoryError, "program-header counts"):
            inventory.shape(streams)
        with self.assertRaisesRegex(inventory.InventoryError, "truncated"):
            inventory.parse_dynamic("\n".join([
                "Dynamic section at offset 0x200 contains 2 entries:", "  Tag        Type                         Name/Value",
                " 0x0000000000000005 (STRTAB)             0x200",
            ]))
        with self.assertRaisesRegex(inventory.InventoryError, "malformed"):
            inventory.parse_dynamic("Dynamic section at offset 0x200 contains 0 entries:\nnot a tag\n")

    def test_relocation_and_symbol_parsers_reject_truncated_streams_but_admit_relr(self) -> None:
        self.assertEqual(
            inventory.parse_relocations("There are no relocations in this file.\n"),
            {"sections": [], "types": {}, "entries": 0},
        )
        with self.assertRaisesRegex(inventory.InventoryError, "relocation stream"):
            inventory.parse_relocations("unrelated readelf text\n")
        with self.assertRaisesRegex(inventory.InventoryError, "truncated"):
            inventory.parse_relocations(
                "Relocation section '.rela.dyn' at offset 0x10 contains 2 entries:\n"
                "0000000000001000  0000000000000008 R_X86_64_RELATIVE\n"
            )
        with self.assertRaisesRegex(inventory.InventoryError, "malformed"):
            inventory.parse_relocations(
                "Relocation section '.rela.dyn' at offset 0x10 contains 0 entries:\nnot a relocation\n"
            )
        self.assertEqual(
            inventory.parse_relocations(
                "Relocation section '.relr.dyn' at offset 0x10 contains 2 entries:\n"
                "  2 offsets\n0000000000001000\n0000000000002000\n"
            )["entries"],
            2,
        )
        with self.assertRaisesRegex(inventory.InventoryError, "truncated"):
            inventory.parse_dynamic_symbols(
                "Symbol table '.dynsym' contains 2 entries:\n"
                "   Num:    Value          Size Type    Bind   Vis      Ndx Name\n"
                "     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND \n"
            )
        with self.assertRaisesRegex(inventory.InventoryError, "malformed"):
            inventory.parse_dynamic_symbols("Symbol table '.dynsym' contains 0 entries:\nnot a symbol\n")

    def test_reader_rejects_changed_raw_stream_and_extra_or_missing_rows(self) -> None:
        for name, mutate in (
            ("changed-raw", self._change_raw),
            ("missing-raw-row", lambda value: value["raw_readelf"].pop()),
            ("extra-raw-row", lambda value: value["raw_readelf"].append(value["raw_readelf"][0])),
            ("missing-feature-row", lambda value: value["candidate_features"].pop()),
            ("extra-feature-row", lambda value: value["candidate_features"].append(value["candidate_features"][0])),
        ):
            with self.subTest(name=name):
                path, _ = self.collect(name + ".json")
                self.rewrite(path, mutate)
                with self.assertRaises(inventory.InventoryError):
                    inventory.validate_receipt(path, self.product, path.parent / (path.name + ".inputs/oracle-capture.json"),
                                               path.parent / (path.name + ".inputs/readelf-capture.json"))

    def _change_raw(self, value: dict) -> None:
        raw = ROOT / value["raw_readelf"][0]["path"]
        raw.chmod(0o644)
        raw.write_text("changed readelf stream\n", encoding="utf-8")

    def test_reader_rejects_fake_runtime_verification_and_changed_product_binding(self) -> None:
        for name, mutate in (
            ("runtime-verified", lambda value: value.__setitem__("runtime_verified", True)),
            ("feature-verified", lambda value: value["candidate_features"][0].__setitem__("verified", True)),
        ):
            with self.subTest(name=name):
                path, _ = self.collect(name + ".json")
                self.rewrite(path, mutate)
                with self.assertRaises(inventory.InventoryError):
                    inventory.validate_receipt(path, self.product, path.parent / (path.name + ".inputs/oracle-capture.json"),
                                               path.parent / (path.name + ".inputs/readelf-capture.json"))
        path, _ = self.collect("swapped-product.json")
        other = self.root / "other-product"
        other.mkdir()
        with self.assertRaisesRegex(inventory.InventoryError, "different supplied product"):
            inventory.validate_receipt(path, other, path.parent / (path.name + ".inputs/oracle-capture.json"),
                                       path.parent / (path.name + ".inputs/readelf-capture.json"))
        oracle_capture = path.parent / (path.name + ".inputs/oracle-capture.json")
        self.rewrite(oracle_capture, lambda value: value["oracle"].__setitem__("runtime_sha256", "0" * 64))
        with self.assertRaisesRegex(inventory.InventoryError, "pinned musl"):
            inventory.validate_receipt(path, self.product, path.parent / (path.name + ".inputs/oracle-capture.json"),
                                       path.parent / (path.name + ".inputs/readelf-capture.json"))
        path, _ = self.collect("malformed-readelf-capture.json")
        readelf_capture = path.parent / (path.name + ".inputs/readelf-capture.json")
        self.rewrite(readelf_capture, lambda value: value["readelf"].__setitem__("path", "../readelf"))
        with self.assertRaisesRegex(inventory.InventoryError, "readelf"):
            inventory.validate_receipt(path, self.product, path.parent / (path.name + ".inputs/oracle-capture.json"),
                                       readelf_capture)

    def test_missing_supplied_product_is_rejected_before_any_inventory_claim(self) -> None:
        self.capture.stop()
        self.addCleanup(self.capture.start)
        missing = self.root / "missing-product"
        with self.assertRaises(inventory.InventoryError):
            inventory.capture_bindings(missing)


if __name__ == "__main__":
    unittest.main()
