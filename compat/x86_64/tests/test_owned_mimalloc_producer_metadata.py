#!/usr/bin/env python3
"""Focused fixed-C mimalloc producer-metadata contract regressions."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "compat/x86_64/owned_mimalloc_producer_metadata.py"
SPEC = importlib.util.spec_from_file_location("owned_mimalloc_producer_metadata_test", MODULE)
assert SPEC is not None and SPEC.loader is not None
producer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = producer
SPEC.loader.exec_module(producer)


def symbol(
    name: str,
    *,
    kind: str = "FUNC",
    binding: str = "GLOBAL",
    visibility: str = "DEFAULT",
    section: str = "1",
    size: int = 17,
) -> dict[str, object]:
    return {
        "name": name,
        "raw_name": name,
        "version": None,
        "version_default": False,
        "binding": binding,
        "visibility": visibility,
        "section_index": section,
        "type": kind,
        "value": "0000000000000000",
        "size": str(size),
        "size_bytes": size,
        "row_index": 1,
        "raw": f"fixture {name}",
        "other": None,
        "version_index": None,
        "common_alignment": None,
    }


class FixedCMimallocProducerMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = producer.load_contract()
        cls.members = producer.contract_members(cls.contract)

    def fixture(self) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
        contract = self.contract
        metadata = contract["metadata"]
        data_layouts = {item["name"]: item for item in metadata["data_objects"]}
        tls_layout = metadata["tls_object"]
        weak = metadata["weak_null_fallback"]
        excluded = set(metadata["strong_functions"]["excluded_names"])
        c_rows: list[dict[str, object]] = []
        shared_rows: list[dict[str, object]] = []
        static_sections: list[dict[str, object]] = []
        shared_sections: list[dict[str, object]] = []
        section_indices = {
            "_mi_cpu_has_popcnt": (101, 201),
            "_mi_heap_default_key": (102, 202),
            "_mi_stats_main": (103, 203),
            "mi_thread_locals": (104, 204),
        }
        for name in self.members:
            if name in data_layouts:
                layout = data_layouts[name]
                static_index, shared_index = section_indices[name]
                static = symbol(
                    name,
                    kind="OBJECT",
                    section=str(static_index),
                    size=layout["size_bytes"],
                )
                shared = symbol(
                    name,
                    kind="OBJECT",
                    binding="LOCAL",
                    section=str(shared_index),
                    size=layout["size_bytes"],
                )
                static_sections.append(
                    {
                        "index": static_index,
                        "alignment": layout["producer"]["static_section_alignment"],
                        "name": ".fixture.static",
                    }
                )
                shared_sections.append(
                    {
                        "index": shared_index,
                        "alignment": layout["source"]["source_required_alignment"],
                        "name": ".fixture.shared",
                    }
                )
            elif name == tls_layout["name"]:
                static_index, shared_index = section_indices[name]
                static = symbol(
                    name,
                    kind="TLS",
                    section=str(static_index),
                    size=tls_layout["size_bytes"],
                )
                shared = symbol(
                    name,
                    kind="TLS",
                    binding="LOCAL",
                    section=str(shared_index),
                    size=tls_layout["size_bytes"],
                )
                static_sections.append(
                    {
                        "index": static_index,
                        "alignment": tls_layout["producer"]["static_section_alignment"],
                        "name": ".fixture.tdata",
                    }
                )
                shared_sections.append(
                    {
                        "index": shared_index,
                        "alignment": tls_layout["source"]["source_required_alignment"],
                        "name": ".fixture.tdata",
                    }
                )
            elif name == weak["name"]:
                static = symbol(name, binding="WEAK", section="41", size=3)
                shared = symbol(name, binding="LOCAL", section="9", size=3)
            else:
                self.assertNotIn(name, excluded)
                static = symbol(name, section="10")
                shared = symbol(name, binding="LOCAL", section="9")
            c_rows.append(static)
            shared_rows.append(shared)

        imports = contract["rust_root_imports"]["names"]
        rust_rows = [
            symbol(name, kind="NOTYPE", section="UND", size=0)
            for name in imports
        ]
        c_member = "b85de32113adef8e-static.o"
        rust_member = "fixture-rust.rcgu.o"
        shared_rust_member = "fixture-dynamic.rcgu.o"
        c_sha = "c" * 64
        static_sha = "a" * 64
        shared_sha = "b" * 64
        source_map = dict(contract["source_provenance"]["upstream_sources"])
        source_map.update(contract["source_provenance"]["project_header_sources"])
        source_map["include/fixture.h"] = "f" * 64
        crate_pin = {
            "name": contract["backend"]["crate"],
            "version": contract["backend"]["version"],
            "checksum": contract["backend"]["checksum"],
        }
        static_provenance: dict[str, object] = {
            "archive": {"name": "libc.a", "sha256": static_sha},
            "selected_members": [
                {"name": rust_member, "sha256": "d" * 64},
                {"name": c_member, "sha256": c_sha},
            ],
            "allocator_backend": {
                "archive_sha256": "e" * 64,
                "crate": crate_pin,
                "implementation": "accepted C backend; native Rust promotion remains separate",
                "member": c_member,
                "member_sha256": c_sha,
                "source_and_header_sha256": source_map,
                "target_flags": list(contract["build"]["static_target_flags"]),
                "lifecycle_profile": dict(contract["build"]["lifecycle_profile"]),
            },
        }
        shared_provenance: dict[str, object] = {
            "accepted_allocator": crate_pin,
            "allocator_headers": source_map,
            "allocator_flags": list(contract["build"]["shared_allocator_flags"]),
            "selected_members": {
                c_member: c_sha,
                shared_rust_member: "d" * 64,
            },
            "shared_mimalloc_hidden_exports": {
                "source": {
                    "path": contract["source_provenance"]["members_file"],
                    "sha256": contract["source_provenance"]["members_sha256"],
                    "mode": 0o644,
                },
                "member_count": len(self.members),
                "members": list(self.members),
                "linker_script_sha256": contract["shared_localization"]["linker_script_sha256"],
                "linker_policy": "exact-local-symbols",
            },
            "libc_shared_link_command": [
                "/fixture/ld.lld",
                "-shared",
                "--version-script=$BUILD/libc-mimalloc-hidden.exports",
                f"$BUILD/objects/{shared_rust_member}",
                f"$BUILD/objects/{c_member}",
                "-o",
                "$BUILD/installed/usr/lib/libc.so",
            ],
        }
        facts: dict[str, object] = {
            "schema": producer.ELF_FACTS_SCHEMA,
            "target": producer.TARGET,
            "status": dict(producer.ELF_FACTS_STATUS),
            "collector_execution_source": {
                "revision": "1" * 40,
                "content_sha256": "2" * 64,
                "clean": True,
            },
            "artifacts": {
                "candidate-static": {"identity": {"sha256": static_sha}},
                "candidate-shared": {
                    "identity": {
                        "path": "/fixture/usr/lib/libc.so",
                        "sha256": shared_sha,
                        "size": 4096,
                        "mode": 0o755,
                    },
                },
            },
            "facts": {
                "candidate-static": [
                    {
                        "member": rust_member,
                        "member_occurrence": 0,
                        "symbol_tables": [{"name": ".symtab", "rows": rust_rows}],
                        "sections": [],
                    },
                    {
                        "member": c_member,
                        "member_occurrence": 0,
                        "symbol_tables": [{"name": ".symtab", "rows": c_rows}],
                        "sections": static_sections,
                    },
                ],
                "candidate-shared": {
                    "symbol_tables": [
                        {"name": ".dynsym", "rows": []},
                        {"name": ".symtab", "rows": shared_rows},
                    ],
                    "sections": shared_sections,
                },
            },
        }
        shared_manifest: dict[str, object] = {
            "schema": producer.DYNAMIC_PRODUCT_MANIFEST_SCHEMA,
            "format": producer.DYNAMIC_PRODUCT_MANIFEST_FORMAT,
            "target": producer.TARGET,
            "files": {producer.DYNAMIC_PRODUCT_LIBC_PATH: shared_sha},
            "symlinks": {"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"},
        }
        return facts, static_provenance, shared_provenance, shared_manifest

    def account(self) -> dict[str, object]:
        facts, static_provenance, shared_provenance, shared_manifest = self.fixture()
        return producer.account_producer_metadata(facts, static_provenance, shared_provenance, shared_manifest)

    def test_accounts_exact_four_metadata_buckets_and_seven_rust_root_joins(self) -> None:
        account = self.account()
        self.assertEqual(account["status"], "component-pass-not-qualification")
        self.assertEqual(account["scope"]["member_count"], 424)
        self.assertEqual(account["scope"]["metadata_buckets"], {
            "strong-functions": 419,
            "weak-null-fallback": 1,
            "data-objects": 3,
            "initial-exec-tls": 1,
        })
        self.assertEqual(account["scope"]["rust_root_c_imports"], 7)
        self.assertEqual(account["archive_map"]["raw_cargo_allocator_archive_sha256"], "e" * 64)
        self.assertEqual(account["archive_map"]["reconstructed_static_libc_archive_sha256"], "a" * 64)
        self.assertEqual(
            [item["name"] for item in account["rust_root_c_import_joins"]],
            self.contract["rust_root_imports"]["names"],
        )
        weak = account["metadata_buckets"]["weak-null-fallback"]["members"][0]
        self.assertEqual(weak["static"]["binding"], "WEAK")
        self.assertEqual(weak["static"]["definition"], "defined")
        self.assertEqual(weak["source_semantics"], "defined-null-fallback")
        self.assertEqual(weak["shared"]["binding"], "LOCAL")
        self.assertFalse(account["status_flags"]["family_completion"])
        self.assertFalse(account["status_flags"]["promotion_ready"])
        self.assertFalse(account["status_flags"]["public_support"])

        layouts = {
            record["name"]: record["layout"]
            for record in account["metadata_buckets"]["data-objects"]["members"]
        }
        layouts[producer.EXPECTED_TLS_OBJECT] = account["metadata_buckets"]["initial-exec-tls"]["members"][0]["layout"]
        self.assertEqual(
            {
                name: (
                    layout["size_bytes"],
                    layout["source"]["source_required_alignment"],
                    layout["producer"]["static_section_alignment"],
                )
                for name, layout in layouts.items()
            },
            {
                "_mi_cpu_has_popcnt": (1, 64, 64),
                "_mi_heap_default_key": (4, 4, 4),
                "_mi_stats_main": (4368, 8, 32),
                "mi_thread_locals": (8, 8, 8),
            },
        )
        self.assertEqual(layouts["mi_thread_locals"]["shared_symbol_value"]["integer"], 0)
        self.assertEqual(layouts["mi_thread_locals"]["shared_symbol_value"]["modulo_source_required_alignment"], 0)

    def test_selected_metadata_projects_exact_private_roster_without_observed_values(self) -> None:
        projection = producer.selected_metadata()
        self.assertEqual(list(projection), self.members)
        self.assertEqual(projection["_mi_cpu_has_popcnt"], {
            "static": {
                "type": "OBJECT", "binding": "GLOBAL", "visibility": "DEFAULT",
                "size_bytes": 1, "alignment_bytes": 64,
            },
            "shared": {
                "type": "OBJECT", "binding": "LOCAL", "visibility": "DEFAULT",
                "size_bytes": 1, "alignment_bytes": 64,
            },
        })
        self.assertEqual(projection["_ZSt15get_new_handlerv"]["static"]["binding"], "WEAK")
        self.assertEqual(projection["_mi_stats_main"], {
            "static": {
                "type": "OBJECT", "binding": "GLOBAL", "visibility": "DEFAULT",
                "size_bytes": 4368, "alignment_bytes": 8,
            },
            "shared": {
                "type": "OBJECT", "binding": "LOCAL", "visibility": "DEFAULT",
                "size_bytes": 4368, "alignment_bytes": 8,
            },
        })
        self.assertEqual(set(projection["mi_thread_locals"]), {"static", "shared"})

    def test_static_stats_value_uses_source_alignment_not_section_overalignment(self) -> None:
        """A source-valid symbol offset must not inherit static section 32-byte placement."""
        facts, static_provenance, shared_provenance, shared_manifest = self.fixture()
        static_rows = facts["facts"]["candidate-static"][1]["symbol_tables"][0]["rows"]
        stats = next(row for row in static_rows if row["name"] == "_mi_stats_main")
        stats["value"] = "0000000000000008"
        account = producer.account_producer_metadata(facts, static_provenance, shared_provenance, shared_manifest)
        layout = next(
            record["layout"]
            for record in account["metadata_buckets"]["data-objects"]["members"]
            if record["name"] == "_mi_stats_main"
        )
        self.assertEqual(layout["producer"]["static_section_alignment"], 32)
        self.assertEqual(layout["static_symbol_value"]["source_required_alignment"], 8)
        self.assertEqual(layout["static_symbol_value"]["integer"], 8)
        self.assertEqual(producer.selected_metadata()["_mi_stats_main"]["static"]["alignment_bytes"], 8)

    def test_rejects_omitted_or_extra_identity_from_exact_roster(self) -> None:
        facts, static_provenance, shared_provenance, shared_manifest = self.fixture()
        c_member = facts["facts"]["candidate-static"][1]
        c_member["symbol_tables"][0]["rows"].pop()
        with self.assertRaisesRegex(producer.ProducerMetadataError, "static provider roster differs"):
            producer.account_producer_metadata(facts, static_provenance, shared_provenance, shared_manifest)

        work = ROOT / ".work/x86_64/owned-mimalloc-producer-metadata-tests"
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            altered = Path(temporary) / "owned_mimalloc_hidden.list"
            altered.write_text("\n".join(self.members + ["unexpected_backend_identity"]) + "\n", encoding="utf-8")
            with mock.patch.object(producer, "HIDDEN_LIST", altered):
                with self.assertRaisesRegex(producer.ProducerMetadataError, "member count/digest"):
                    producer.contract_members(self.contract)

    def test_rejects_metadata_layout_or_dynsym_exposure_drift(self) -> None:
        facts, static_provenance, shared_provenance, shared_manifest = self.fixture()
        shared_rows = facts["facts"]["candidate-shared"]["symbol_tables"][1]["rows"]
        stats = next(row for row in shared_rows if row["name"] == "_mi_stats_main")
        stats["size_bytes"] = 4367
        stats["size"] = "4367"
        with self.assertRaisesRegex(producer.ProducerMetadataError, "data layout"):
            producer.account_producer_metadata(facts, static_provenance, shared_provenance, shared_manifest)

        facts, static_provenance, shared_provenance, shared_manifest = self.fixture()
        dynsym = facts["facts"]["candidate-shared"]["symbol_tables"][0]["rows"]
        dynsym.append(symbol("mi_malloc_aligned"))
        with self.assertRaisesRegex(producer.ProducerMetadataError, "shared dynsym exposes"):
            producer.account_producer_metadata(facts, static_provenance, shared_provenance, shared_manifest)

    def test_rejects_unaligned_symbol_values_and_unbound_shared_artifact_identity(self) -> None:
        """ELF section alignment cannot stand in for each selected symbol's value."""
        for placement in ("candidate-static", "candidate-shared"):
            for name in (*producer.EXPECTED_DATA_OBJECTS, producer.EXPECTED_TLS_OBJECT):
                with self.subTest(placement=placement, name=name):
                    facts, static_provenance, shared_provenance, shared_manifest = self.fixture()
                    member = (
                        facts["facts"][placement][1]
                        if placement == "candidate-static"
                        else facts["facts"][placement]
                    )
                    rows = next(table["rows"] for table in member["symbol_tables"] if table["name"] == ".symtab")
                    row = next(item for item in rows if item["name"] == name)
                    row["value"] = f"{int(row['value'], 16) + 1:016x}"
                    with self.assertRaisesRegex(producer.ProducerMetadataError, "symbol value alignment"):
                        producer.account_producer_metadata(facts, static_provenance, shared_provenance, shared_manifest)

        facts, static_provenance, shared_provenance, shared_manifest = self.fixture()
        facts["artifacts"]["candidate-shared"]["identity"]["sha256"] = "f" * 64
        with self.assertRaisesRegex(producer.ProducerMetadataError, "shared artifact identity"):
            producer.account_producer_metadata(facts, static_provenance, shared_provenance, shared_manifest)

        facts, static_provenance, shared_provenance, shared_manifest = self.fixture()
        shared_manifest["files"][producer.DYNAMIC_PRODUCT_LIBC_PATH] = "f" * 64
        with self.assertRaisesRegex(producer.ProducerMetadataError, "shared artifact identity"):
            producer.account_producer_metadata(facts, static_provenance, shared_provenance, shared_manifest)

    def test_rejects_crate_or_pinned_c_source_drift_and_optional_undefined_handler_substitution(self) -> None:
        facts, static_provenance, shared_provenance, shared_manifest = self.fixture()
        static_provenance["allocator_backend"]["crate"]["version"] = "0.1.50"
        with self.assertRaisesRegex(producer.ProducerMetadataError, "allocator crate pin"):
            producer.account_producer_metadata(facts, static_provenance, shared_provenance, shared_manifest)

        facts, static_provenance, shared_provenance, shared_manifest = self.fixture()
        static_provenance["allocator_backend"]["source_and_header_sha256"][
            "libmimalloc-sys/c_src/mimalloc/v3/src/alloc.c"
        ] = "0" * 64
        with self.assertRaisesRegex(producer.ProducerMetadataError, "pinned v3 source map"):
            producer.account_producer_metadata(facts, static_provenance, shared_provenance, shared_manifest)

        facts, static_provenance, shared_provenance, shared_manifest = self.fixture()
        static_provenance["allocator_backend"]["source_and_header_sha256"].pop("include/bits/alltypes.h")
        with self.assertRaisesRegex(producer.ProducerMetadataError, "installed header source map"):
            producer.account_producer_metadata(facts, static_provenance, shared_provenance, shared_manifest)

        facts, static_provenance, shared_provenance, shared_manifest = self.fixture()
        c_rows = facts["facts"]["candidate-static"][1]["symbol_tables"][0]["rows"]
        handler = next(row for row in c_rows if row["name"] == "_ZSt15get_new_handlerv")
        handler.update(binding="GLOBAL", section_index="UND", size="0", size_bytes=0)
        with self.assertRaisesRegex(producer.ProducerMetadataError, "weak null fallback"):
            producer.account_producer_metadata(facts, static_provenance, shared_provenance, shared_manifest)

    def test_rejects_missing_rust_import_provider_or_final_shared_provider_join(self) -> None:
        facts, static_provenance, shared_provenance, shared_manifest = self.fixture()
        rust_rows = facts["facts"]["candidate-static"][0]["symbol_tables"][0]["rows"]
        rust_rows.pop()
        with self.assertRaisesRegex(producer.ProducerMetadataError, "Rust-root import roster"):
            producer.account_producer_metadata(facts, static_provenance, shared_provenance, shared_manifest)

        facts, static_provenance, shared_provenance, shared_manifest = self.fixture()
        rust_rows = facts["facts"]["candidate-static"][0]["symbol_tables"][0]["rows"]
        rust_rows.append(symbol("_mi_os_alloc", kind="NOTYPE", section="UND", size=0))
        with self.assertRaisesRegex(producer.ProducerMetadataError, "Rust-root import roster"):
            producer.account_producer_metadata(facts, static_provenance, shared_provenance, shared_manifest)

        facts, static_provenance, shared_provenance, shared_manifest = self.fixture()
        shared_provenance["selected_members"].pop("b85de32113adef8e-static.o")
        with self.assertRaisesRegex(producer.ProducerMetadataError, "shared allocator selected"):
            producer.account_producer_metadata(facts, static_provenance, shared_provenance, shared_manifest)

    def test_current_product_receipt_adapter_binds_input_bytes(self) -> None:
        facts, static_provenance, shared_provenance, shared_manifest = self.fixture()
        work = ROOT / ".work/x86_64/owned-mimalloc-producer-metadata-tests"
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            root = Path(temporary)
            fact_path = root / "facts.json"
            static_path = root / "static.json"
            shared_path = root / "shared.json"
            manifest_path = root / "manifest.json"
            output = root / "receipt.json"
            for path, value in (
                (fact_path, facts),
                (static_path, static_provenance),
                (shared_path, shared_provenance),
                (manifest_path, shared_manifest),
            ):
                path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
            receipt = producer.write_current_product_receipt(
                fact_path, static_path, shared_path, manifest_path, output
            )
            self.assertTrue(output.is_file())
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), receipt)
            self.assertEqual(receipt["inputs"]["before"], receipt["inputs"]["after"])
            self.assertEqual(receipt["inputs"]["before"]["elf_facts"]["sha256"], producer.sha256_file(fact_path))
            self.assertEqual(receipt["inputs"]["before"]["shared_manifest"]["sha256"], producer.sha256_file(manifest_path))
            self.assertEqual(receipt["account"]["scope"]["member_count"], 424)

    def test_current_product_receipt_rejects_manifest_change_during_accounting(self) -> None:
        facts, static_provenance, shared_provenance, shared_manifest = self.fixture()
        work = ROOT / ".work/x86_64/owned-mimalloc-producer-metadata-tests"
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            root = Path(temporary)
            fact_path = root / "facts.json"
            static_path = root / "static.json"
            shared_path = root / "shared.json"
            manifest_path = root / "manifest.json"
            output = root / "receipt.json"
            for path, value in (
                (fact_path, facts),
                (static_path, static_provenance),
                (shared_path, shared_provenance),
                (manifest_path, shared_manifest),
            ):
                path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")

            def mutate_manifest(*_arguments: object) -> dict[str, object]:
                manifest_path.write_text("{}\n", encoding="utf-8")
                return {"fixture": "account"}

            with mock.patch.object(producer, "account_producer_metadata", side_effect=mutate_manifest):
                with self.assertRaisesRegex(producer.ProducerMetadataError, "inputs changed during accounting"):
                    producer.write_current_product_receipt(
                        fact_path, static_path, shared_path, manifest_path, output
                    )
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
