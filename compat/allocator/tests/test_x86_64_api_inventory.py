#!/usr/bin/env python3
"""Tests for the bounded x86-64 source C-header API inventory."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
INVENTORY_PATH = ROOT / "compat/allocator/x86_64-api-v3.5.0.json"
SCRIPT_PATH = ROOT / "compat/allocator/x86_64_api_inventory.py"
SPEC = importlib.util.spec_from_file_location("crabc_x86_64_api_inventory", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
INVENTORY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = INVENTORY
SPEC.loader.exec_module(INVENTORY)


class X86_64ApiInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))

    def test_parser_records_only_uncommented_exported_function_declarations(self) -> None:
        header = """\
#define mi_decl_export __attribute__((visibility("default")))
// mi_decl_export void mi_comment_only(void);
mi_decl_export mi_decl_restrict void* mi_first(size_t size);
/* mi_decl_export void mi_block_comment(void); */
mi_decl_export void
mi_second(void);
mi_decl_export void* mi_third(void) mi_attr_alloc_size(1);
"""
        self.assertEqual(
            INVENTORY.source_declarations(header),
            [
                INVENTORY.Declaration("mi_first", 3),
                INVENTORY.Declaration("mi_second", 6),
                INVENTORY.Declaration("mi_third", 7),
            ],
        )

    def test_contract_is_a_target_local_source_declaration_inventory(self) -> None:
        self.assertEqual(
            set(self.contract),
            {
                "classification",
                "declaration_count",
                "declaration_names_sha256",
                "declarations",
                "format",
                "integration_boundary",
                "kind",
                "maturity",
                "profile",
                "scope",
                "source",
                "target_context",
                "upstream",
            },
        )
        self.assertEqual(self.contract["format"], 1)
        self.assertEqual(self.contract["kind"], "mimalloc-x86_64-source-c-api-inventory")
        self.assertEqual(
            self.contract["maturity"], "bounded-source-inventory-foundation"
        )
        self.assertEqual(self.contract["profile"], "linux-x86_64-mimalloc-source-c-api")
        self.assertEqual(
            self.contract["target_context"],
            {
                "architecture": "x86_64",
                "endianness": "little",
                "rust_target": "x86_64-unknown-linux-musl",
                "system": "linux",
            },
        )
        self.assertEqual(
            self.contract["classification"]["name"], "source-declared-c-function"
        )
        self.assertIn(
            "not a claim",
            self.contract["classification"]["meaning"],
        )

    def test_entries_are_source_anchors_not_implementation_statuses(self) -> None:
        declarations = self.contract["declarations"]
        self.assertEqual(self.contract["declaration_count"], len(declarations))
        self.assertEqual(len(declarations), 180)
        self.assertEqual(
            [entry["name"] for entry in declarations[:8]],
            [
                "mi_malloc",
                "mi_calloc",
                "mi_realloc",
                "mi_expand",
                "mi_free",
                "mi_strdup",
                "mi_strndup",
                "mi_realpath",
            ],
        )
        names = {entry["name"] for entry in declarations}
        self.assertTrue(
            {
                "mi_manage_memory",
                "mi_collect_reduce",
                "mi_option_set_default",
                "mi_new",
                "mi_heap_alloc_new_n",
            }
            <= names
        )
        self.assertEqual(len(names), len(declarations))
        self.assertTrue(
            all(set(entry) == {"name", "source_line"} for entry in declarations)
        )
        self.assertTrue(all(entry["source_line"] > 0 for entry in declarations))
        declaration_records = [
            INVENTORY.Declaration(entry["name"], entry["source_line"])
            for entry in declarations
        ]
        self.assertEqual(
            self.contract["declaration_names_sha256"],
            INVENTORY.declaration_names_hash(declaration_records),
        )
        serialized = json.dumps(self.contract, sort_keys=True)
        self.assertNotIn("aarch64", serialized.lower())
        self.assertNotIn('"implemented"', serialized)
        self.assertNotIn('"differential_verified"', serialized)

    def test_integration_and_verification_remain_explicitly_unassessed(self) -> None:
        boundary = self.contract["integration_boundary"]
        self.assertEqual(
            {
                key: value
                for key, value in boundary.items()
                if key != "verification"
            },
            {
                "crabc_libc_exports": "not-assessed",
                "crabc_mimalloc_implementation": "not-assessed",
                "native_object_export_inventory": "not-assessed",
                "public_c_api_adapter": "not-assessed",
            },
        )
        self.assertIn("does not establish", boundary["verification"])
        self.assertIn(
            "include/mimalloc-override.h", self.contract["scope"]["excluded_headers"]
        )

    def test_checked_in_pin_fields_agree_with_upstreams_toml(self) -> None:
        pin = INVENTORY.load_mimalloc_pin()
        self.assertEqual(
            self.contract["upstream"],
            {
                "archive_root": pin["archive_root"],
                "revision": pin["revision"],
                "version": pin["version"],
            },
        )
        self.assertEqual(
            self.contract["source"]["archive_sha256"],
            pin["sha256"],
        )
        self.assertEqual(self.contract["source"]["member"], "include/mimalloc.h")
        self.assertEqual(len(self.contract["source"]["header_sha256"]), 64)

    @unittest.skipUnless(
        INVENTORY.DEFAULT_ARCHIVE_PATH.is_file(),
        "native allocator oracle has not populated the pinned source archive cache",
    )
    def test_checked_in_contract_matches_the_pinned_source_archive(self) -> None:
        INVENTORY.check_contract(INVENTORY.DEFAULT_ARCHIVE_PATH)


if __name__ == "__main__":
    unittest.main()
