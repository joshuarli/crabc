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


if __name__ == "__main__":
    unittest.main()
