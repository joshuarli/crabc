#!/usr/bin/env python3
"""Tests for the source-only x86-64 public API coverage ledger."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
LEDGER_PATH = ROOT / "compat/allocator/x86_64-api-coverage-v3.5.0.json"
SCRIPT_PATH = ROOT / "compat/allocator/x86_64_api_coverage.py"
SPEC = importlib.util.spec_from_file_location("crabc_x86_64_api_coverage", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
COVERAGE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = COVERAGE
SPEC.loader.exec_module(COVERAGE)


class X86_64ApiCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        cls.headers = {
            header["member"]: header for header in cls.contract["header_surfaces"]
        }

    def test_contract_is_an_explicitly_incomplete_target_local_source_ledger(self) -> None:
        self.assertEqual(
            set(self.contract),
            {
                "base_c_function_inventory",
                "build_mode_declarations",
                "coverage",
                "format",
                "header_surfaces",
                "integration_boundary",
                "kind",
                "maturity",
                "profile",
                "scope",
                "source",
                "symbol_dispositions",
                "target_context",
                "test_source_inventory",
                "upstream",
            },
        )
        self.assertEqual(self.contract["format"], 1)
        self.assertEqual(
            self.contract["kind"],
            "mimalloc-x86_64-public-api-mode-test-symbol-coverage-ledger",
        )
        self.assertEqual(self.contract["maturity"], "source-surface-coverage-foundation")
        self.assertEqual(
            self.contract["profile"], "linux-x86_64-mimalloc-source-public-surface"
        )
        self.assertEqual(self.contract["target_context"], COVERAGE.TARGET_CONTEXT)
        self.assertEqual(self.contract["coverage"]["overall_status"], "incomplete")
        self.assertEqual(
            self.contract["coverage"]["native-x86_64-object-symbol-inventory"],
            "not-assessed",
        )
        self.assertEqual(
            self.contract["coverage"]["target-preprocessor-selection"], "not-assessed"
        )

    def test_root_cmake_public_header_boundary_and_source_hash_coverage_are_complete(self) -> None:
        self.assertEqual(
            set(self.headers),
            {
                "include/mimalloc.h",
                "include/mimalloc-new-delete.h",
                "include/mimalloc-override.h",
                "include/mimalloc-stats.h",
            },
        )
        self.assertEqual(
            [record["member"] for record in self.contract["source"]["all_include_headers"]],
            [
                "include/mimalloc-new-delete.h",
                "include/mimalloc-override.h",
                "include/mimalloc-stats.h",
                "include/mimalloc.h",
                "include/mimalloc/atomic.h",
                "include/mimalloc/bits.h",
                "include/mimalloc/internal.h",
                "include/mimalloc/prim-tls.h",
                "include/mimalloc/prim.h",
                "include/mimalloc/track.h",
                "include/mimalloc/types.h",
            ],
        )
        self.assertEqual(
            [record["member"] for record in self.contract["source"]["noninstalled_include_headers"]],
            [
                "include/mimalloc/atomic.h",
                "include/mimalloc/bits.h",
                "include/mimalloc/internal.h",
                "include/mimalloc/prim-tls.h",
                "include/mimalloc/prim.h",
                "include/mimalloc/track.h",
                "include/mimalloc/types.h",
            ],
        )
        records = (
            self.contract["source"]["all_include_headers"]
            + self.contract["source"]["test_members"]
            + [self.contract["source"]["root_cmake"]]
        )
        self.assertTrue(all(record["bytes"] > 0 for record in records))
        self.assertTrue(all(len(record["sha256"]) == 64 for record in records))
        self.assertEqual(len(self.contract["source"]["test_members"]), 18)
        self.assertEqual(len(self.contract["source"]["archive_sha256"]), 64)

    def test_base_and_statistics_c_function_surfaces_remain_source_only(self) -> None:
        base = self.contract["base_c_function_inventory"]
        self.assertEqual(base["source_declared_function_count"], 180)
        self.assertEqual(len(base["source_declared_function_names_sha256"]), 64)
        self.assertEqual(
            base["checked_in_inventory"]["path"],
            "compat/allocator/x86_64-api-v3.5.0.json",
        )
        self.assertEqual(len(base["checked_in_inventory"]["sha256"]), 64)

        base_surface = self.headers["include/mimalloc.h"]["c_external_function_surface"]
        self.assertEqual(base_surface["source_declared_function_count"], 180)
        self.assertEqual(base_surface["symbol_disposition"], "native-object-export-unassessed")
        self.assertNotIn("declarations", base_surface)

        stats_surface = self.headers["include/mimalloc-stats.h"]["c_external_function_surface"]
        self.assertEqual(stats_surface["source_declared_function_count"], 15)
        self.assertEqual(
            [entry["name"] for entry in stats_surface["declarations"]],
            [
                "mi_heap_stats_get",
                "mi_heap_stats_get_json",
                "mi_heap_stats_print_out",
                "mi_theap_stats_get",
                "mi_subproc_stats_get",
                "mi_subproc_stats_get_json",
                "mi_subproc_stats_print_out",
                "mi_subproc_heap_stats_print_out",
                "mi_stats_get",
                "mi_stats_get_json",
                "mi_stats_print_out",
                "mi_heap_stats_merge_to_subproc",
                "mi_subproc_stats_get_exclusive",
                "mi_stats_as_json",
                "mi_stats_get_bin_size",
            ],
        )
        self.assertEqual(stats_surface["symbol_disposition"], "native-object-export-unassessed")

    def test_types_options_macros_and_cxx_source_forms_are_inventoried_without_mode_claims(self) -> None:
        base = self.headers["include/mimalloc.h"]
        self.assertEqual(
            [entry["name"] for entry in base["c_type_aliases"]],
            [
                "mi_deferred_free_fun",
                "mi_output_fun",
                "mi_error_fun",
                "mi_heap_t",
                "mi_heap_area_t",
                "mi_block_visit_fun",
                "mi_arena_id_t",
                "mi_subproc_id_t",
                "mi_heap_visit_fun",
                "mi_theap_t",
                "mi_commit_fun_t",
                "mi_option_t",
            ],
        )
        self.assertEqual(
            [entry["name"] for entry in base["c_type_tags"]],
            ["mi_heap_s", "mi_heap_area_s", "mi_theap_s", "mi_option_e"],
        )
        options = base["runtime_option_enumerators"]
        self.assertEqual(len(options), 53)
        self.assertEqual(options[0]["name"], "mi_option_show_errors")
        self.assertEqual(options[-1], {
            "kind": "legacy-alias",
            "name": "mi_option_limit_os_alloc",
            "source_line": 519,
            "value_source": "mi_option_disallow_os_alloc",
        })
        self.assertIn(
            {"kind": "internal-sentinel", "name": "_mi_option_last", "source_line": 513},
            options,
        )
        self.assertEqual(
            [entry["name"] for entry in base["cxx_template_structures"]],
            [
                "mi_stl_allocator",
                "mi_heap_stl_allocator",
                "mi_heap_destroy_stl_allocator",
            ],
        )
        self.assertEqual(len(base["c_static_inline_functions"]), 5)
        self.assertEqual(base["mode"]["x86_64_preprocessor_selection"], "not-assessed")
        self.assertIn(
            "mi_malloc_tp", [entry["name"] for entry in base["macro_definitions"]]
        )

        new_delete = self.headers["include/mimalloc-new-delete.h"]
        self.assertEqual(len(new_delete["cxx_operator_source_definitions"]), 20)
        self.assertEqual(new_delete["mode"]["x86_64_preprocessor_selection"], "not-assessed")
        override = self.headers["include/mimalloc-override.h"]
        override_macros = [entry["name"] for entry in override["macro_definitions"]]
        self.assertIn("malloc", override_macros)
        self.assertIn("_aligned_offset_recalloc", override_macros)
        self.assertEqual(override["mode"]["x86_64_preprocessor_selection"], "not-assessed")

    def test_build_and_test_source_modes_are_not_native_execution_results(self) -> None:
        modes = self.contract["build_mode_declarations"]
        self.assertEqual(modes["resolution_status"], "not-assessed")
        declarations = modes["declarations"]
        self.assertEqual(len(declarations), 52)
        self.assertEqual(declarations[0]["name"], "MI_SECURE")
        self.assertIn(
            {
                "declaration_kind": "cmake-cache-string",
                "default_source_token": '"DEFAULT"',
                "name": "MI_TLS_MODEL",
                "source_line": 62,
            },
            declarations,
        )
        tests = self.contract["test_source_inventory"]
        self.assertEqual(tests["native_x86_64_execution_status"], "not-assessed")
        self.assertEqual(
            [target["name"] for target in tests["root_cmake_test_targets"]],
            ["api", "api-fill", "stress-heaps", "stress-subprocs", "stress", "stress-static", "stress-dynamic"],
        )
        self.assertEqual(
            [target["name"] for target in tests["standalone_consumer_test_targets"]],
            [
                "dynamic-override",
                "dynamic-override-cxx",
                "static-override-obj",
                "static-override-static",
                "static-override",
                "static-override-cxx",
                "test-wrong",
            ],
        )
        self.assertIn("not a compilation", tests["scope"])

    def test_symbol_dispositions_and_integration_boundary_do_not_claim_parity(self) -> None:
        symbols = self.contract["symbol_dispositions"]
        self.assertEqual(
            [entry["surface"] for entry in symbols],
            [
                "base-c-functions",
                "statistics-extension-functions",
                "base-header-inline-helpers",
                "statistics-header-inline-helpers",
                "base-header-cxx-templates",
                "new-delete-header-cxx-operators",
                "override-header-rewrite-macros",
                "type-option-and-macro-source-forms",
            ],
        )
        self.assertTrue(
            all(
                entry["native_x86_64_object_symbol_status"]
                in {"not-assessed", "not-an-object-symbol-inventory"}
                for entry in symbols
            )
        )
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
                "public_x86_64_runtime_support": "not-claimed",
            },
        )
        self.assertIn("does not establish", boundary["verification"])

    def test_source_parsers_ignore_comments_and_preserve_source_categories(self) -> None:
        header = """\
// mi_decl_export void mi_comment_only(void);
#define mi_rewrite(value) mi_real(value)
typedef struct mi_state_s mi_state_t;
typedef enum mi_mode_e { MI_MODE_ZERO } mi_mode_t;
typedef void (mi_cdecl mi_callback_fun)(void);
mi_decl_export void mi_real(void);
static inline void mi_inline(void) { }
template<class T> struct mi_template { };
/* #define mi_blocked value */
"""
        self.assertEqual(
            COVERAGE.source_external_functions(header, member="example.h"),
            [{"name": "mi_real", "source_line": 6}],
        )
        self.assertEqual(
            COVERAGE.source_static_inline_functions(header, member="example.h"),
            [{"name": "mi_inline", "source_line": 7}],
        )
        self.assertEqual(
            COVERAGE.source_cxx_template_structures(header, member="example.h"),
            [{"name": "mi_template", "source_line": 8}],
        )
        self.assertEqual(
            COVERAGE.source_type_aliases(header, member="example.h"),
            [
                {"name": "mi_state_t", "source_line": 3},
                {"name": "mi_mode_t", "source_line": 4},
                {"name": "mi_callback_fun", "source_line": 5},
            ],
        )
        self.assertEqual(
            COVERAGE.source_type_tags(header, member="example.h"),
            [
                {"name": "mi_state_s", "source_lines": [3]},
                {"name": "mi_mode_e", "source_lines": [4]},
            ],
        )
        self.assertEqual(
            COVERAGE.source_macro_definitions(header),
            [{"name": "mi_rewrite", "source_lines": [2]}],
        )

    @unittest.skipUnless(
        COVERAGE.DEFAULT_ARCHIVE_PATH.is_file(),
        "native allocator oracle has not populated the pinned source archive cache",
    )
    def test_callable_validator_returns_a_scoped_source_only_result(self) -> None:
        result = COVERAGE.checked_contract_result(COVERAGE.DEFAULT_ARCHIVE_PATH)
        self.assertEqual(
            set(result),
            {
                "build_mode_declaration_count",
                "contract",
                "header_surface_count",
                "overall_status",
                "profile",
                "scope",
                "source_declared_function_count",
                "source_member_count",
                "status",
                "symbol_disposition_count",
                "target",
                "test_member_count",
            },
        )
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["overall_status"], "incomplete")
        self.assertEqual(result["target"], COVERAGE.TARGET_CONTEXT)
        self.assertEqual(
            result["profile"], "linux-x86_64-mimalloc-source-public-surface"
        )
        self.assertEqual(result["header_surface_count"], 4)
        self.assertEqual(result["build_mode_declaration_count"], 52)
        self.assertEqual(result["test_member_count"], 18)
        self.assertEqual(result["source_member_count"], 30)
        self.assertEqual(result["source_declared_function_count"], 195)
        self.assertEqual(result["symbol_disposition_count"], 8)
        self.assertEqual(
            result["contract"]["path"],
            "compat/allocator/x86_64-api-coverage-v3.5.0.json",
        )
        self.assertIn("does not establish", result["scope"])
        self.assertIn("native execution", result["scope"])

    @unittest.skipUnless(
        COVERAGE.DEFAULT_ARCHIVE_PATH.is_file(),
        "native allocator oracle has not populated the pinned source archive cache",
    )
    def test_checked_in_ledger_matches_the_pinned_source_archive(self) -> None:
        COVERAGE.check_contract(COVERAGE.DEFAULT_ARCHIVE_PATH)


if __name__ == "__main__":
    unittest.main()
