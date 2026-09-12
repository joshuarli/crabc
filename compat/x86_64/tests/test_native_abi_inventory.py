#!/usr/bin/env python3
"""Focused retained-fact tests for the native x86 ABI inventory."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "compat" / "x86_64" / "native_abi_inventory.py"
SPEC = importlib.util.spec_from_file_location("native_abi_inventory_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
inventory = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = inventory
SPEC.loader.exec_module(inventory)


class NativeAbiInventoryParserTests(unittest.TestCase):
    def test_dynamic_records_preserve_version_defaultness_and_measurements(self) -> None:
        raw = """\
Symbol table '.dynsym' contains 5 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000010    12 FUNC    GLOBAL DEFAULT   12 exported@@V2
     2: 0000000000000020     8 FUNC    WEAK   PROTECTED  12 old_name@V1
     3: 0000000000000030     4 OBJECT  GLOBAL HIDDEN    12 private
     4: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND missing
"""
        records = inventory.parse_dynamic_symbols(raw)
        self.assertEqual(
            records,
            [
                {
                    "name": "exported", "type": "FUNC", "binding": "GLOBAL",
                    "visibility": "DEFAULT", "version": "V2", "version_default": True,
                    "size": "12", "value": "0000000000000010", "section_index": "12",
                },
                {
                    "name": "old_name", "type": "FUNC", "binding": "WEAK",
                    "visibility": "PROTECTED", "version": "V1", "version_default": False,
                    "size": "8", "value": "0000000000000020", "section_index": "12",
                },
            ],
        )

    def test_dynamic_unique_binding_is_retained(self) -> None:
        raw = """\
Symbol table '.dynsym' contains 2 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000010     8 OBJECT  UNIQUE DEFAULT   12 singleton
"""
        self.assertEqual(
            inventory.parse_dynamic_symbols(raw),
            [{
                "name": "singleton", "type": "OBJECT", "binding": "UNIQUE",
                "visibility": "DEFAULT", "version": None, "version_default": False,
                "size": "8", "value": "0000000000000010", "section_index": "12",
            }],
        )

    def test_dynamic_version_index_decoration_preserves_version_semantics(self) -> None:
        raw = """\
Symbol table '.dynsym' contains 2 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000010    12 FUNC    GLOBAL DEFAULT   12 exported@VER_1 (2)
"""
        self.assertEqual(
            inventory.parse_dynamic_symbols(raw),
            [{
                "name": "exported", "type": "FUNC", "binding": "GLOBAL",
                "visibility": "DEFAULT", "version": "VER_1", "version_default": False,
                "size": "12", "value": "0000000000000010", "section_index": "12",
            }],
        )

    def test_dynamic_tag_count_rejects_a_truncated_table(self) -> None:
        raw = """\
Dynamic section at offset 0x1234 contains 2 entries:
  Tag        Type                         Name/Value
 0x0000000000000001 (NEEDED)             Shared library: [libc.so]
"""
        with self.assertRaisesRegex(inventory.InventoryError, "dynamic-tag rows are missing"):
            inventory._readelf_dynamic(raw)

    def test_pinned_specs_manifest_accepts_the_standard_sha256sum_record(self) -> None:
        digest = "a" * 64
        raw = f"{digest}  /opt/musl-1.2.6/lib/musl-gcc.specs\n"
        self.assertEqual(
            inventory._parse_specs_manifest(raw, digest),
            {"sha256": digest, "path": "/opt/musl-1.2.6/lib/musl-gcc.specs"},
        )

    def test_dynamic_truncated_row_is_rejected_instead_of_dropped(self) -> None:
        raw = """\
Symbol table '.dynsym' contains 3 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000010    12 FUNC    GLOBAL DEFAULT   12 exported@@V2
"""
        with self.assertRaisesRegex(inventory.InventoryError, "missing, duplicated, reordered, or truncated"):
            inventory.parse_dynamic_symbols(raw)

    def test_dynamic_malformed_row_is_rejected_instead_of_dropped(self) -> None:
        raw = """\
Symbol table '.dynsym' contains 2 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000020
"""
        with self.assertRaisesRegex(inventory.InventoryError, "dynamic symbol row"):
            inventory.parse_dynamic_symbols(raw)

    def test_index_zero_only_dynsym_is_a_complete_empty_generic_inventory(self) -> None:
        raw = """\
Symbol table '.dynsym' contains 1 entry:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
"""
        self.assertEqual(inventory.parse_dynamic_symbols(raw), [])

    def test_static_rows_and_repeated_member_names_are_not_deduplicated(self) -> None:
        raw = """\
/inputs/static/usr/lib/libc.a[first.o]: duplicate T 0 10
/inputs/static/usr/lib/libc.a[first.o]: duplicate T 0 10
/inputs/static/usr/lib/libc.a[first.o]: weak_alias W 10 4
"""
        records = inventory.parse_static_symbols(raw)
        self.assertEqual(len(records), 3)
        self.assertEqual([record["archive_member"] for record in records], ["first.o", "first.o", "first.o"])
        self.assertEqual([record["name"] for record in records], ["duplicate", "duplicate", "weak_alias"])
        self.assertEqual([record["nm_type"] for record in records], ["T", "T", "W"])
        self.assertEqual([record["binding"] for record in records], ["GLOBAL", "GLOBAL", "WEAK"])
        inventory.require_static_members_present(records, ["first.o", "first.o"])

    def test_nm_diagnostic_is_not_a_successful_smaller_inventory(self) -> None:
        with self.assertRaisesRegex(inventory.InventoryError, "diagnostic"):
            inventory.require_empty_diagnostics("nm", "nm: archive truncated\\n")

    def test_nm_no_symbol_diagnostic_must_name_an_archive_member(self) -> None:
        with self.assertRaisesRegex(inventory.InventoryError, "missing from ar roster"):
            inventory.parse_nm_no_global_symbols_diagnostics(
                "/usr/bin/nm: foreign.o: no symbols\n",
                ["member.o"],
            )

    def test_static_raw_prefix_must_match_selected_archive(self) -> None:
        nm = "/foreign/libc.a[member.o]: same T 0 1\n"
        with self.assertRaisesRegex(inventory.InventoryError, "different archive"):
            inventory.parse_static_symbols(nm, expected_archive="/inputs/static/usr/lib/libc.a")
        headers = """\\
File: /foreign/libc.a(member.o)
ELF Header:
  Class:                             ELF64
  Data:                              2's complement, little endian
  Type:                              REL (Relocatable file)
  Machine:                           Advanced Micro Devices X86-64
"""
        with self.assertRaisesRegex(inventory.InventoryError, "different archive"):
            inventory.parse_archive_member_headers(
                headers,
                ["member.o"],
                expected_archive="/inputs/static/usr/lib/libc.a",
            )

    def test_archive_member_observation_retains_an_unsupported_member(self) -> None:
        raw = """\
File: /inputs/static/usr/lib/libc.a[native.o]
ELF Header:
  Class:                             ELF64
  Data:                              2's complement, little endian
  Type:                              REL (Relocatable file)
  Machine:                           Advanced Micro Devices X86-64

"""
        observations = inventory.parse_archive_member_headers(raw, ["native.o", "opaque.bc"])
        self.assertEqual(observations[0]["outcome"], "x86_64-elf")
        self.assertEqual(observations[0]["member"], "native.o")
        self.assertEqual(observations[1], {"member": "opaque.bc", "outcome": "unobserved", "detail": "readelf emitted no member block"})

    def test_size_delta_remains_measurement_not_compatibility_mismatch(self) -> None:
        reference = [{
            "name": "same", "type": "FUNC", "binding": "GLOBAL", "visibility": "DEFAULT",
            "version": None, "version_default": False, "size": "1", "value": "10", "section_index": "12",
        }]
        candidate = [{
            "name": "same", "type": "FUNC", "binding": "GLOBAL", "visibility": "DEFAULT",
            "version": None, "version_default": False, "size": "99", "value": "ff", "section_index": "12",
        }]
        triage = inventory.compare_dynamic_symbols(reference, candidate)
        self.assertEqual(triage["compatibility_differences"], [])
        self.assertEqual(triage["measurement_differences"], [{
            "key": {"name": "same", "version": None, "version_default": False},
            "reference": {"size": "1", "value": "10", "section_index": "12"},
            "candidate": {"size": "99", "value": "ff", "section_index": "12"},
        }])
        self.assertEqual(triage["data_size_differences"], [])

    def test_object_and_tls_size_deltas_are_explicit_data_layout_triage(self) -> None:
        reference = [
            {
                "name": "object", "type": "OBJECT", "binding": "GLOBAL", "visibility": "DEFAULT",
                "version": None, "version_default": False, "size": "4", "value": "10", "section_index": "12",
            },
            {
                "name": "tls", "type": "TLS", "binding": "GLOBAL", "visibility": "DEFAULT",
                "version": None, "version_default": False, "size": "8", "value": "0", "section_index": "13",
            },
        ]
        candidate = [
            {**reference[0], "size": "16"},
            {**reference[1], "size": "32"},
        ]
        triage = inventory.compare_dynamic_symbols(reference, candidate)
        self.assertEqual(triage["measurement_differences"], [])
        self.assertEqual(
            triage["data_size_differences"],
            [
                {
                    "key": {"name": "object", "version": None, "version_default": False},
                    "type": "OBJECT", "reference_size": "4", "candidate_size": "16",
                },
                {
                    "key": {"name": "tls", "version": None, "version_default": False},
                    "type": "TLS", "reference_size": "8", "candidate_size": "32",
                },
            ],
        )

    def test_unversioned_symbols_on_only_one_side_are_not_version_differences(self) -> None:
        reference = [{
            "name": "reference_only", "type": "FUNC", "binding": "GLOBAL", "visibility": "DEFAULT",
            "version": None, "version_default": False, "size": "1", "value": "10", "section_index": "12",
        }]
        candidate = [{
            "name": "candidate_only", "type": "FUNC", "binding": "GLOBAL", "visibility": "DEFAULT",
            "version": None, "version_default": False, "size": "1", "value": "10", "section_index": "12",
        }]
        triage = inventory.compare_dynamic_symbols(reference, candidate)
        self.assertEqual([record["name"] for record in triage["missing"]], ["reference_only"])
        self.assertEqual([record["name"] for record in triage["extra"]], ["candidate_only"])
        self.assertEqual(triage["version_differences"], [])


class NativeAbiInventoryRetainedInputTests(unittest.TestCase):
    def setUp(self) -> None:
        work = ROOT / ".work/x86_64/native-abi-inventory-tests"
        work.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=work)
        self.addCleanup(self.temporary.cleanup)
        self.output_root = Path(self.temporary.name) / "report"
        self.output_root.mkdir()

    def snapshot(self, relative: str, original: str, data: bytes) -> dict[str, object]:
        retained = self.output_root / relative
        retained.parent.mkdir(parents=True, exist_ok=True)
        retained.write_bytes(data)
        retained.chmod(0o600)
        retained_record = inventory.file_record(retained, logical_path=relative)
        return {
            "original": {**retained_record, "path": original},
            "retained": retained_record,
        }

    def pinned_musl_fixture(self) -> dict[str, object]:
        regular_files = {
            relative: self.snapshot(
                f"{inventory.MUSL_COPY_ROOT}/{relative}",
                str(inventory.MUSL_ROOT / relative),
                relative.encode("utf-8"),
            )
            for relative in inventory.MUSL_REGULAR_FILES
        }
        source_header_root = self.output_root / "live-source-headers" / "include"
        source_header_root.mkdir(parents=True)
        headers = []
        for name, data in (("first.h", b"first\n"), ("second.h", b"second\n")):
            relative = f"include/{name}"
            source = source_header_root / name
            source.write_bytes(data)
            source.chmod(0o644)
            snapshot = self.snapshot(
                f"{inventory.MUSL_COPY_ROOT}/{relative}",
                str(inventory.MUSL_ROOT / relative),
                data,
            )
            snapshot["original"]["mode"] = 0o644
            headers.append({
                "relative_path": relative,
                "snapshot": snapshot,
            })
        compiler = self.snapshot(
            "inputs/toolchain/crabc-x86_64-musl-gcc",
            str(inventory.MUSL_COMPILER),
            b"wrapper\n",
        )
        header_root = self.output_root / inventory.MUSL_COPY_ROOT / "include"
        return {
            "fixed_root": str(inventory.MUSL_ROOT),
            "retained_root": inventory.MUSL_COPY_ROOT,
            "regular_files": regular_files,
            "headers": headers,
            "header_tree": inventory._header_tree_record(
                inventory._header_tree_identity(source_header_root),
                inventory._header_tree_identity(header_root),
            ),
            "loader": {
                "path": str(inventory.MUSL_ROOT / inventory.MUSL_LOADER),
                "target": str(inventory.MUSL_ROOT / "lib/libc.so"),
                "resolves_to": str(inventory.MUSL_ROOT / "lib/libc.so"),
            },
            "compiler_wrapper": compiler,
            "repository_pin": {},
            "oracle_manifest": {},
            "specs_manifest": {},
            "compiler_wrapper_matches_repository_source": True,
        }

    def test_source_header_modes_and_private_retained_modes_are_bound_separately(self) -> None:
        pinned = self.pinned_musl_fixture()
        source_tree, retained_tree = inventory._validate_header_tree_record(self.output_root, pinned["header_tree"])
        self.assertEqual([item["mode"] for item in source_tree["files"]], [0o644, 0o644])
        self.assertEqual([item["mode"] for item in retained_tree["files"]], [0o600, 0o600])
        with mock.patch.object(inventory, "_validate_oracle_manifests_retained"):
            inventory._validate_musl_inputs(self.output_root, pinned, {})
        pinned["headers"] = [pinned["headers"][0]]
        with mock.patch.object(inventory, "_validate_oracle_manifests_retained"):
            with self.assertRaisesRegex(inventory.InventoryError, "snapshot roster is incomplete"):
                inventory._validate_musl_inputs(self.output_root, pinned, {})

    def test_complete_retained_header_tree_rejects_deletion_addition_and_symlink(self) -> None:
        pinned = self.pinned_musl_fixture()
        header_tree = pinned["header_tree"]
        inventory._validate_header_tree_record(self.output_root, header_tree)
        header_root = self.output_root / inventory.MUSL_COPY_ROOT / "include"

        (header_root / "second.h").unlink()
        with self.assertRaisesRegex(inventory.InventoryError, "header-tree roster or content changed"):
            inventory._validate_header_tree_record(self.output_root, header_tree)
        (header_root / "second.h").write_text("second\n", encoding="utf-8")
        (header_root / "extra.h").write_text("extra\n", encoding="utf-8")
        with self.assertRaisesRegex(inventory.InventoryError, "header-tree roster or content changed"):
            inventory._validate_header_tree_record(self.output_root, header_tree)
        (header_root / "extra.h").unlink()
        (header_root / "link.h").symlink_to("first.h")
        with self.assertRaisesRegex(inventory.InventoryError, "non-regular entry"):
            inventory._validate_header_tree_record(self.output_root, header_tree)

    def test_public_replay_rejects_deleted_header_and_omitted_snapshot_row(self) -> None:
        pinned = self.pinned_musl_fixture()
        header_root = self.output_root / inventory.MUSL_COPY_ROOT / "include"
        (header_root / "second.h").unlink()
        pinned["headers"] = [pinned["headers"][0]]

        source_records = {
            "compat/x86_64/headers_layouts_aggregate.py": {},
            "compat/x86_64/generated/headers_layouts_aggregate/report.json": {},
        }
        report = {
            "schema": inventory.SCHEMA,
            "status": {
                "classification": "measurement-only-not-compatibility-or-promotion",
                "family_completion": False,
                "promotion_ready": False,
                "public_support": False,
            },
            "target": inventory.TARGET,
            "image": "crabc-core-evidence@sha256:" + "a" * 64,
            "collector_execution_source": {},
            "collector_sources": source_records,
            "header_closure": {
                "owner_source": "compat/x86_64/headers_layouts_aggregate.py",
                "owner_report": "compat/x86_64/generated/headers_layouts_aggregate/report.json",
                "source_identity": {},
                "report_identity": {},
                "meaning": (
                    "routes the existing native header-closure source/report identity; "
                    "this inventory does not claim header declaration evidence"
                ),
            },
            "product_provenance": {},
            "inputs": {"pinned_musl": pinned, "static_product": {}, "dynamic_product": {}},
            "tools": {},
            "commands": {},
            "inventories": {},
            "triage": {},
        }
        report_path = self.output_root / inventory.REPORT_NAME
        report_path.write_text(json.dumps(report), encoding="utf-8")
        report_path.chmod(0o600)
        with (
            mock.patch.object(inventory, "_validate_collector_source_seal"),
            mock.patch.object(inventory, "_validate_current_source_inputs"),
            mock.patch.object(inventory, "_validate_tools", return_value={}),
            mock.patch.object(inventory, "_validate_oracle_manifests_retained"),
        ):
            with self.assertRaisesRegex(inventory.InventoryError, "header-tree roster or content changed"):
                inventory.validate_report(
                    report_path,
                    static_product=self.output_root,
                    dynamic_product=self.output_root,
                    static_preparation=report_path,
                )

    def test_product_provenance_rejects_nonprepared_static_receipt_status(self) -> None:
        source = "a" * 64
        static_manifest = "b" * 64
        dynamic_manifest = "c" * 64
        state_payload = "d" * 64
        state = {
            "schema": "crabc.x86_64-owned-dynamic-materialization/v1",
            "status": "materialized-unqualified",
            "source_sha256": source,
            "contracts": {name: "e" * 64 for name in inventory.dynamic_materialization.CONTRACTS},
            "payload_files": {"usr/lib/libc.so": "f" * 64},
            "runtime_v1_published": False,
            "campaign_complete": False,
            "public_support": False,
            "modes": ["dynamic-pie", "dynamic-non-pie", "dynamic-shared-object"],
            "runtime_profile": inventory.dynamic_materialization.MATERIALIZATION_PROFILE,
            "qualification": inventory.dynamic_materialization.MATERIALIZATION_QUALIFICATION,
        }
        dynamic_product = {
            "manifest": {"sha256": dynamic_manifest},
            "payload_files": {inventory.DYNAMIC_STATE_RELATIVE: state_payload},
            "materialization_state": {
                "logical_path": inventory.DYNAMIC_STATE_LOGICAL_PATH,
                "identity": {"path": inventory.DYNAMIC_STATE_LOGICAL_PATH, "sha256": state_payload, "size": 1, "mode": 0o600},
                "manifest_sha256": dynamic_manifest,
                "state": state,
            },
        }
        receipt = self.output_root / "preparation.json"
        preparation = {
            "schema": "crabc.x86_64-owned-posix-static-preparation/v1",
            "status": "prepared-unqualified",
            "source": {"content_sha256": source, "revision": "1" * 40},
            "products": {"primary": {"manifest": {"sha256": static_manifest}}},
        }
        receipt.write_text(json.dumps(preparation), encoding="utf-8")
        inventory._bind_product_provenance(
            static_receipt=receipt,
            dynamic_product_root=self.output_root,
            static_product={"manifest": {"sha256": static_manifest}},
            dynamic_product=dynamic_product,
        )
        preparation["status"] = "failed"
        receipt.write_text(json.dumps(preparation), encoding="utf-8")
        with self.assertRaisesRegex(inventory.InventoryError, "not prepared-unqualified"):
            inventory._bind_product_provenance(
                static_receipt=receipt,
                dynamic_product_root=self.output_root,
                static_product={"manifest": {"sha256": static_manifest}},
                dynamic_product=dynamic_product,
            )

    def test_archive_inventory_retains_known_no_global_symbol_members(self) -> None:
        artifact = self.output_root / "libc.a"
        artifact.write_bytes(b"archive fixture\n")
        archive = str(artifact)
        outputs = {
            "reference-static-ar": ("member.o\nempty.o\n", ""),
            "reference-static-nm": (
                f"{archive}[member.o]: exported T 0 1\n",
                "/usr/bin/nm: empty.o: no symbols\n",
            ),
            "reference-static-headers": (
                f"""\\
File: {archive}[member.o]
ELF Header:
  Class:                             ELF64
  Data:                              2's complement, little endian
  Type:                              REL (Relocatable file)
  Machine:                           Advanced Micro Devices X86-64

File: {archive}[empty.o]
ELF Header:
  Class:                             ELF64
  Data:                              2's complement, little endian
  Type:                              REL (Relocatable file)
  Machine:                           Advanced Micro Devices X86-64
""",
                "",
            ),
        }

        def run_tool(
            output_root: Path,
            *,
            key: str,
            allow_diagnostics: bool = False,
            **_kwargs: object,
        ) -> dict[str, object]:
            stdout, stderr = outputs[key]
            if key == "reference-static-nm" and stderr and not allow_diagnostics:
                raise inventory.InventoryError("nm emitted a diagnostic and cannot describe a complete inventory")
            return {
                "returncode": 0,
                "stdout": inventory._write_raw(output_root, f"{key}.stdout", stdout),
                "stderr": inventory._write_raw(output_root, f"{key}.stderr", stderr),
            }

        with mock.patch.object(inventory, "_run_tool", side_effect=run_tool):
            observed = inventory._inspect_archive(
                self.output_root,
                name="reference-static",
                artifact_path=artifact,
                logical_artifact="/opt/musl-1.2.6/lib/libc.a",
                tool_records={"ar": {}, "nm": {}, "readelf": {}},
                commands={},
            )
        self.assertEqual(
            observed["member_nm_observations"],
            {
                "complete": True,
                "diagnostics_retained": True,
                "no_global_defined_symbols": [
                    {"member": "empty.o", "outcome": "no-global-defined-symbols"},
                ],
            },
        )


SYMBOL_HEADER = "   Num:    Value          Size Type    Bind   Vis      Ndx Name\n"
DYNAMIC = "Symbol table '.dynsym' contains 7 entries:\n" + SYMBOL_HEADER + """\
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000008     8 OBJECT  GLOBAL HIDDEN     1 hidden
     2: 0000000000000000     4 TLS     LOCAL  DEFAULT    2 local_tls
     3: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND imported@V1 (2)
     4: 0000000000000010     0 IFUNC   GLOBAL PROTECTED 1 dispatch@@V2
     5: 0000000000000020     1 <OS specific>: 12 GLOBAL DEFAULT ABS odd
     6: 0000000000000040     4 OBJECT  <processor specific>: 13 INTERNAL COM common
"""
HEADER = """\
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 03 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - GNU
  ABI Version:                       0
  Type:                              REL (Relocatable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          0 (bytes into file)
  Start of section headers:          256 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           0 (bytes)
  Number of program headers:         0
  Size of section headers:           64 (bytes)
  Number of section headers:         5
  Section header string table index: 4
"""
SECTIONS = """\
There are 5 section headers, starting at offset 0x100:

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .data             PROGBITS        0000000000000000 000040 000008 00  WA  0   0 32
  [ 2] .tdata            PROGBITS        0000000000000000 000048 000004 00 WAT  0   0 16
  [ 3] .symtab           SYMTAB          0000000000000000 000050 0000a8 18      4   3  8
  [ 4] .strtab           STRTAB          0000000000000000 0000f8 000008 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)
"""
STATIC = DYNAMIC.replace("'.dynsym'", "'.symtab'")


def archive_blocks(texts: list[str], names: list[str] | None = None) -> str:
    if names is None:
        names = ["same.o"] * len(texts)
    return "".join(f"\nFile: /facts/lib.a({name})\n{text}" for name, text in zip(names, texts))


class NativeAbiCompleteSymbolFactsTests(unittest.TestCase):
    def test_all_rows_keep_local_hidden_undefined_versions_and_unknown_kinds(self) -> None:
        rows = inventory.parse_dynamic_symbol_rows(DYNAMIC)
        self.assertEqual([row["row_index"] for row in rows], list(range(7)))
        self.assertIsNone(rows[0]["name"])
        self.assertEqual(rows[1]["visibility"], "HIDDEN")
        self.assertEqual(rows[2]["binding"], "LOCAL")
        self.assertEqual(rows[3]["section_index"], "UND")
        self.assertEqual(rows[3]["version_index"], 2)
        self.assertEqual(rows[3]["raw_name"], "imported@V1")
        self.assertEqual((rows[3]["version"], rows[3]["version_default"]), ("V1", False))
        self.assertEqual((rows[4]["version"], rows[4]["version_default"]), ("V2", True))
        self.assertEqual(rows[5]["type"], "<OS specific>: 12")
        self.assertEqual(rows[6]["binding"], "<processor specific>: 13")
        self.assertEqual(rows[6]["common_alignment"], 64)
        self.assertEqual([row["raw"] for row in rows], DYNAMIC.splitlines()[2:])

    def test_archive_duplicate_member_occurrences_and_section_placement_are_exact(self) -> None:
        facts = inventory.parse_archive_elf_facts(
            archive_blocks([HEADER, HEADER]), archive_blocks([SECTIONS, SECTIONS]),
            archive_blocks([STATIC, STATIC.replace("hidden", "other")]),
            ["same.o", "same.o"], expected_archive="/facts/lib.a",
        )
        self.assertEqual([(f["member_index"], f["member_occurrence"]) for f in facts], [(0, 0), (1, 1)])
        table = facts[0]["symbol_tables"][0]
        self.assertEqual(table["section_index"], 3)
        self.assertEqual(table["rows"][1]["section_index"], "1")
        self.assertEqual(facts[0]["sections"][1]["alignment"], 32)
        self.assertEqual(facts[0]["sections"][2]["flags"], "WAT")
        self.assertEqual(facts[1]["symbol_tables"][0]["rows"][1]["name"], "other")
        self.assertEqual(facts[0]["sections"][0]["name"], "")

    def test_truncated_reordered_duplicate_and_malformed_rows_fail_closed(self) -> None:
        for raw in (
            DYNAMIC.rsplit("\n", 2)[0] + "\n",
            DYNAMIC.replace("     3:", "     2:"),
            DYNAMIC.replace("0000000000000008", "bad-value"),
            DYNAMIC.replace("imported@V1 (2)", "imported@@@V1 (2)"),
            DYNAMIC.replace("imported@V1 (2)", "imported@V1@@V2 (2)"),
            DYNAMIC.replace("   Num:", "   Wrong:"),
        ):
            with self.subTest(raw=raw), self.assertRaises(inventory.InventoryError):
                inventory.parse_dynamic_symbol_rows(raw)

    def test_archive_roster_or_section_symbol_mismatch_fails_closed(self) -> None:
        cases = [
            (archive_blocks([HEADER]), archive_blocks([SECTIONS]), archive_blocks([STATIC]), ["same.o", "same.o"]),
            (archive_blocks([HEADER], ["wrong.o"]), archive_blocks([SECTIONS]), archive_blocks([STATIC]), ["same.o"]),
            (archive_blocks([HEADER]), archive_blocks([SECTIONS.replace("0000a8", "000090")]), archive_blocks([STATIC]), ["same.o"]),
            (archive_blocks([HEADER]), archive_blocks([SECTIONS]), archive_blocks([STATIC.replace("     1 hidden", "    99 hidden")]), ["same.o"]),
        ]
        for args in cases:
            with self.subTest(args=args), self.assertRaises(inventory.InventoryError):
                inventory.parse_archive_elf_facts(*args, expected_archive="/facts/lib.a")

    def test_pinned_unknown_type_binding_and_other_bits_remain_distinct_fields(self) -> None:
        # Exact GNU readelf row shape from the pinned ELF fixture with only its
        # st_info/st_other bytes changed; no unknown value is mapped to DEFAULT.
        raw = "Symbol table '.symtab' contains 1 entry:\n" + SYMBOL_HEADER + (
            "     0: 0000000000000000     4 <processor specific>: 13 "
            "<OS specific>: 12 HIDDEN  [<other>: 80]     5 local_tls\n"
        )
        row = inventory.parse_elf_symbol_tables(raw)[0]["rows"][0]
        self.assertEqual(row["type"], "<processor specific>: 13")
        self.assertEqual(row["binding"], "<OS specific>: 12")
        self.assertEqual(row["visibility"], "HIDDEN")
        self.assertEqual(row["other"], "[<other>: 80]")

    def test_all_symbol_tables_and_repeated_identities_are_retained_in_order(self) -> None:
        tables = inventory.parse_elf_symbol_tables(STATIC + STATIC)
        self.assertEqual([table["table_index"] for table in tables], [0, 1])
        self.assertEqual(tables[0]["rows"], tables[1]["rows"])
        with self.assertRaisesRegex(inventory.InventoryError, "exactly one"):
            inventory.parse_dynamic_symbol_rows(DYNAMIC + DYNAMIC)
        raw = STATIC.replace("local_tls", "hidden")
        self.assertEqual([r["name"] for r in inventory.parse_elf_symbol_tables(raw)[0]["rows"]].count("hidden"), 2)

    def test_display_names_with_spaces_and_hex_sizes_are_not_silently_split(self) -> None:
        raw = STATIC.replace("local_tls", "source file.c (2)").replace("     4 TLS", "   0x4 TLS")
        row = inventory.parse_elf_symbol_tables(raw)[0]["rows"][2]
        self.assertEqual(row["name"], "source file.c (2)")
        self.assertIsNone(row["version_index"])
        self.assertEqual((row["size"], row["size_bytes"]), ("0x4", 4))

    def test_unknown_section_types_flags_and_duplicate_names_keep_section_indexes(self) -> None:
        raw = SECTIONS.replace(".tdata", ".data").replace("WAT", "WAx").replace("PROGBITS", "LOOS+0x42", 1)
        sections = inventory.parse_elf_sections(raw)["sections"]
        self.assertEqual([r["index"] for r in sections if r["name"] == ".data"], [1, 2])
        self.assertEqual(sections[1]["type"], "LOOS+0x42")
        self.assertEqual(sections[2]["flags"], "WAx")

    def test_missing_repeated_reordered_or_appended_section_rows_fail_closed(self) -> None:
        lines = SECTIONS.splitlines(keepends=True)
        row_index = next(i for i, line in enumerate(lines) if "[ 2]" in line)
        for raw in (
            "".join(lines[:row_index] + lines[row_index + 1:]),
            SECTIONS.replace("[ 2]", "[ 1]"),
            "".join(lines[:row_index - 1] + [lines[row_index], lines[row_index - 1]] + lines[row_index + 1:]),
            SECTIONS + lines[row_index],
            SECTIONS.replace("32\n", "bad\n"),
        ):
            with self.subTest(raw=raw), self.assertRaises(inventory.InventoryError):
                inventory.parse_elf_sections(raw)

    def test_archive_no_symbol_table_requires_independent_complete_section_facts(self) -> None:
        sections = SECTIONS.replace("5 section headers", "4 section headers")
        sections = "\n".join(line for line in sections.splitlines() if ".symtab" not in line)
        sections = sections.replace("[ 4]", "[ 3]")
        header = HEADER.replace("Number of section headers:         5", "Number of section headers:         4")
        header = header.replace("Section header string table index: 4", "Section header string table index: 3")
        facts = inventory.parse_archive_elf_facts(
            archive_blocks([header]), archive_blocks([sections]), archive_blocks([""]),
            ["same.o"], expected_archive="/facts/lib.a",
        )
        self.assertEqual(facts[0]["symbol_tables"], [])
        with self.assertRaisesRegex(inventory.InventoryError, "counts differ"):
            inventory.parse_archive_elf_facts(
                archive_blocks([HEADER]), archive_blocks([SECTIONS]), archive_blocks([""]),
                ["same.o"], expected_archive="/facts/lib.a",
            )

    def test_archive_headers_diagnostics_foreign_target_and_reordered_members_fail_closed(self) -> None:
        for header in (
            HEADER + "readelf: Error: truncated\n", HEADER.replace("X86-64", "AArch64"),
            HEADER + "  Class: ELF64\n", HEADER + "  Number of section headers: 9\n",
        ):
            with self.subTest(header=header), self.assertRaises(inventory.InventoryError):
                inventory.parse_archive_elf_facts(
                    archive_blocks([header]), archive_blocks([SECTIONS]), archive_blocks([STATIC]),
                    ["same.o"], expected_archive="/facts/lib.a",
                )
        with self.assertRaisesRegex(inventory.InventoryError, "order/count"):
            inventory.parse_archive_elf_facts(
                archive_blocks([HEADER, HEADER], ["b.o", "a.o"]),
                archive_blocks([SECTIONS, SECTIONS], ["a.o", "b.o"]),
                archive_blocks([STATIC, STATIC], ["a.o", "b.o"]),
                ["a.o", "b.o"], expected_archive="/facts/lib.a",
            )

    def test_native_header_retains_both_readelf_version_fields_in_order(self) -> None:
        facts = inventory.parse_archive_elf_facts(
            archive_blocks([HEADER]), archive_blocks([SECTIONS]), archive_blocks([STATIC]),
            ["same.o"], expected_archive="/facts/lib.a",
        )
        self.assertEqual(
            [row["value"] for row in facts[0]["header"]["fields"] if row["name"] == "Version"],
            ["1 (current)", "0x1"],
        )

    def test_pinned_flag_legend_truncated_after_first_line_is_rejected(self) -> None:
        lines = SECTIONS.splitlines()
        title = lines.index("Key to Flags:")
        truncated = "\n".join(lines[:title + 2]) + "\n"
        with self.assertRaises(inventory.InventoryError):
            inventory.parse_elf_sections(truncated)

    def test_first_archive_header_truncated_after_machine_is_rejected(self) -> None:
        lines = HEADER.splitlines()
        machine = next(i for i, line in enumerate(lines) if line.strip().startswith("Machine:"))
        truncated = "\n".join(lines[:machine + 1]) + "\n"
        with self.assertRaises(inventory.InventoryError):
            inventory.parse_archive_elf_facts(
                archive_blocks([truncated, HEADER]), archive_blocks([SECTIONS, SECTIONS]),
                archive_blocks([STATIC, STATIC]), ["same.o", "same.o"], expected_archive="/facts/lib.a",
            )

    def test_every_pinned_header_field_occurrence_is_mandatory(self) -> None:
        lines = HEADER.splitlines(keepends=True)
        for index in range(1, len(lines)):
            with self.subTest(omitted=lines[index]), self.assertRaises(inventory.InventoryError):
                inventory.parse_archive_elf_facts(
                    archive_blocks(["".join(lines[:index] + lines[index + 1:])]),
                    archive_blocks([SECTIONS]), archive_blocks([STATIC]),
                    ["same.o"], expected_archive="/facts/lib.a",
                )
        for header in (
            HEADER.replace("Number of section headers:         5", "Number of section headers:         6"),
            HEADER.replace("Number of section headers:         5", "Number of section headers:         five"),
            HEADER.replace("  Version:                           0x1\n", "") + "  Version:                           0x1\n",
        ):
            with self.subTest(header=header), self.assertRaises(inventory.InventoryError):
                inventory.parse_archive_elf_facts(
                    archive_blocks([header]), archive_blocks([SECTIONS]), archive_blocks([STATIC]),
                    ["same.o"], expected_archive="/facts/lib.a",
                )

    def test_pinned_flag_legend_requires_every_ordered_line_and_termination(self) -> None:
        lines = SECTIONS.splitlines(keepends=True)
        title = lines.index("Key to Flags:\n")
        prefix, legend = lines[:title + 1], lines[title + 1:]
        for modified in (
            legend[:2], legend[:3], legend[1:], legend + legend[-1:],
            [legend[1], legend[0], *legend[2:]],
            [*legend[:-1], legend[-1].replace("specific)", "specific),")],
        ):
            with self.subTest(legend=modified), self.assertRaises(inventory.InventoryError):
                inventory.parse_elf_sections("".join(prefix + modified))

    def test_both_observed_pinned_flag_legend_endings_preserve_raw_lines(self) -> None:
        # The pinned native archive displays R (retain) for its GNU ABI members,
        # and omits that entry for the symbol-free member. Both are complete.
        for ending in (
            "  D (mbind), l (large), p (processor specific)",
            "  R (retain), D (mbind), l (large), p (processor specific)",
        ):
            raw = SECTIONS.replace("  D (mbind), l (large), p (processor specific)", ending)
            with self.subTest(ending=ending):
                self.assertEqual(inventory.parse_elf_sections(raw)["flag_legend"][-1], ending)


if __name__ == "__main__":
    unittest.main()
