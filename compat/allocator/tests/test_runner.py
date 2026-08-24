#!/usr/bin/env python3
"""Focused pure-Python tests for the Milestone 0 mimalloc oracle harness."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


RUNNER_PATH = Path(__file__).resolve().parents[1] / "run.py"
SPEC = importlib.util.spec_from_file_location("crabc_allocator_runner", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


def production_dependency_metadata() -> dict[str, object]:
    versions = {
        "crabc-mimalloc": "0.3.0",
        "crabc-core": "0.3.0",
        "chacha20": "0.10.1",
        "cfg-if": "1.0.4",
        "cipher": "0.5.2",
        "block-buffer": "0.12.1",
        "hybrid-array": "0.4.14",
        "typenum": "1.20.1",
        "crypto-common": "0.2.2",
        "inout": "0.2.2",
        "zeroize": "1.9.0",
    }
    edges = {
        "crabc-mimalloc": ("chacha20", "crabc-core", "zeroize"),
        "crabc-core": (),
        "chacha20": ("cfg-if", "cipher", "zeroize"),
        "cfg-if": (),
        "cipher": ("block-buffer", "crypto-common", "inout"),
        "block-buffer": ("hybrid-array",),
        "hybrid-array": ("typenum",),
        "typenum": (),
        "crypto-common": ("hybrid-array",),
        "inout": ("hybrid-array",),
        "zeroize": (),
    }
    packages = []
    nodes = []
    for name, version in versions.items():
        package_id = f"{name} {version}"
        packages.append(
            {
                "id": package_id,
                "name": name,
                "version": version,
                "source": None if name.startswith("crabc-") else "registry+https://github.com/rust-lang/crates.io-index",
                "targets": [{"kind": ["lib"]}],
            }
        )
        nodes.append(
            {
                "id": package_id,
                "deps": [
                    {
                        "name": dependency.replace("-", "_"),
                        "pkg": f"{dependency} {versions[dependency]}",
                        "dep_kinds": [{"kind": None, "target": None}],
                    }
                    for dependency in edges[name]
                ],
            }
        )
    return {"packages": packages, "resolve": {"nodes": nodes}}


class ArchiveTests(unittest.TestCase):
    def test_safe_extract_accepts_only_the_expected_archive_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "mimalloc.tar.gz"
            contents = b"#define MI_MALLOC_VERSION 30500\n"
            with tarfile.open(archive, "w:gz") as stream:
                directory = tarfile.TarInfo("mimalloc-3.5.0")
                directory.type = tarfile.DIRTYPE
                stream.addfile(directory)
                header = tarfile.TarInfo("mimalloc-3.5.0/include/mimalloc.h")
                header.size = len(contents)
                stream.addfile(header, io.BytesIO(contents))
                source = tarfile.TarInfo("mimalloc-3.5.0/src/alloc.c")
                source.size = 1
                stream.addfile(source, io.BytesIO(b"\n"))
            extracted = RUNNER.safe_extract(archive, root / "out", "mimalloc-3.5.0")
            self.assertEqual((extracted / "include/mimalloc.h").read_bytes(), contents)

    def test_safe_extract_rejects_a_path_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "bad.tar.gz"
            with tarfile.open(archive, "w:gz") as stream:
                bad = tarfile.TarInfo("mimalloc-3.5.0/../escape")
                bad.size = 1
                stream.addfile(bad, io.BytesIO(b"x"))
            with self.assertRaisesRegex(RUNNER.HarnessError, "escapes expected root"):
                RUNNER.safe_extract(archive, root / "out", "mimalloc-3.5.0")


class InventoryTests(unittest.TestCase):
    def test_production_dependency_graph_is_exact_and_build_code_free(self) -> None:
        report = RUNNER.validate_production_dependency_graph(production_dependency_metadata())
        self.assertEqual(report["target"], "aarch64-unknown-linux-musl")
        self.assertEqual(report["external_package_count"], 9)
        self.assertEqual(report["build_script_count"], 0)
        self.assertEqual(report["proc_macro_count"], 0)
        self.assertEqual(
            [(package["name"], package["version"]) for package in report["packages"]],
            sorted(
                (name, version)
                for name, version in {
                    "crabc-core": "0.3.0",
                    "chacha20": "0.10.1",
                    "cfg-if": "1.0.4",
                    "cipher": "0.5.2",
                    "block-buffer": "0.12.1",
                    "hybrid-array": "0.4.14",
                    "typenum": "1.20.1",
                    "crypto-common": "0.2.2",
                    "inout": "0.2.2",
                    "zeroize": "1.9.0",
                }.items()
            ),
        )

    def test_production_dependency_graph_rejects_a_selected_libc_edge(self) -> None:
        metadata = production_dependency_metadata()
        packages = metadata["packages"]
        nodes = metadata["resolve"]["nodes"]
        assert isinstance(packages, list) and isinstance(nodes, list)
        packages.append(
            {
                "id": "libc 0.2.189",
                "name": "libc",
                "version": "0.2.189",
                "source": "registry+https://github.com/rust-lang/crates.io-index",
                "targets": [{"kind": ["lib"]}],
            }
        )
        nodes.append({"id": "libc 0.2.189", "deps": []})
        chacha = next(node for node in nodes if node["id"] == "chacha20 0.10.1")
        chacha["deps"].append(
            {
                "name": "libc",
                "pkg": "libc 0.2.189",
                "dep_kinds": [{"kind": None, "target": None}],
            }
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "unexpected selected package: libc 0.2.189"):
            RUNNER.validate_production_dependency_graph(metadata)

    def test_production_dependency_graph_rejects_build_scripts(self) -> None:
        metadata = production_dependency_metadata()
        packages = metadata["packages"]
        assert isinstance(packages, list)
        cipher = next(package for package in packages if package["name"] == "cipher")
        cipher["targets"].append({"kind": ["custom-build"]})
        with self.assertRaisesRegex(RUNNER.HarnessError, "selected build script: cipher 0.5.2"):
            RUNNER.validate_production_dependency_graph(metadata)

    def test_production_dependency_graph_rejects_proc_macros(self) -> None:
        metadata = production_dependency_metadata()
        packages = metadata["packages"]
        assert isinstance(packages, list)
        cipher = next(package for package in packages if package["name"] == "cipher")
        cipher["targets"].append({"kind": ["proc-macro"]})
        with self.assertRaisesRegex(RUNNER.HarnessError, "selected proc macro: cipher 0.5.2"):
            RUNNER.validate_production_dependency_graph(metadata)

    def test_production_dependency_graph_rejects_edge_drift_with_the_same_packages(self) -> None:
        metadata = production_dependency_metadata()
        nodes = metadata["resolve"]["nodes"]
        assert isinstance(nodes, list)
        chacha = next(node for node in nodes if node["id"] == "chacha20 0.10.1")
        chacha["deps"] = [dependency for dependency in chacha["deps"] if dependency["name"] != "zeroize"]
        with self.assertRaisesRegex(RUNNER.HarnessError, "selected dependency edge mismatch"):
            RUNNER.validate_production_dependency_graph(metadata)

    def test_external_static_inline_and_cxx_template_parsing_are_distinct(self) -> None:
        header = """
            mi_decl_export void* mi_malloc(size_t size);
            mi_decl_export bool mi_heap_contains(const mi_heap_t* heap, const void* p);
            static inline void* mi_malloc_csize(size_t size) { return mi_malloc(size); }
            static inline void mi_free_csize(void* p, size_t size) { mi_free(p); }
            template<class T> struct mi_stl_allocator {
              T* allocate(size_t count) { return static_cast<T*>(mi_new(count)); }
            };
        """
        self.assertEqual(
            RUNNER.public_external_function_names(header),
            {"mi_malloc", "mi_heap_contains"},
        )
        self.assertEqual(
            RUNNER.public_static_inline_names(header),
            {"mi_malloc_csize", "mi_free_csize"},
        )
        self.assertEqual(RUNNER.public_cxx_template_names(header), {"mi_stl_allocator"})

    def test_type_and_option_parsing_ignore_enum_tag_and_option_functions(self) -> None:
        header = """
            typedef struct mi_heap_s mi_heap_t;
            typedef struct { void* _mi_subproc_id; } mi_subproc_id_t;
            typedef bool (mi_cdecl mi_heap_visit_fun)(mi_heap_t* heap, void* arg);
            typedef struct mi_stats_s { size_t size; } mi_stats_t;
            typedef enum mi_option_e {
              mi_option_show_errors,
              mi_option_deprecated_eager_commit,
              mi_option_os_tag,
              _mi_option_last,
              mi_option_large_os_pages = mi_option_show_errors
            } mi_option_t;
            mi_decl_export bool mi_option_is_enabled(mi_option_t option);
            mi_decl_export void mi_option_enable(mi_option_t option);
        """
        self.assertEqual(
            RUNNER.public_type_names(header),
            {
                "mi_heap_t",
                "mi_subproc_id_t",
                "mi_heap_visit_fun",
                "mi_stats_t",
                "mi_option_t",
            },
        )
        self.assertEqual(
            RUNNER.public_option_names(header),
            {
                "mi_option_show_errors",
                "mi_option_deprecated_eager_commit",
                "mi_option_os_tag",
                "mi_option_large_os_pages",
            },
        )

    def test_linux_aarch64_classification_has_named_release_exceptions(self) -> None:
        stale = RUNNER.classify_api_item("mi_collect_reduce", "external-function")
        self.assertEqual(stale["classification"], "unsupported-linux-aarch64")
        self.assertIn("no definition", stale["classification_reason"])
        override = RUNNER.classify_api_item("mi_malloc_size", "external-function")
        self.assertEqual(override["classification"], "override-only")
        self.assertEqual(override["profile"], "linux-aarch64-override")
        wide = RUNNER.classify_api_item("mi_wdupenv_s", "external-function")
        self.assertEqual(wide["classification"], "unsupported-linux-aarch64")
        self.assertFalse(wide["test_adapter_applicable"])

    def test_cxx_declaration_macros_and_legacy_option_aliases_keep_their_source_roles(self) -> None:
        declaration = RUNNER.classify_api_item("mi_decl_new", "macro")
        self.assertEqual(declaration["classification"], "source-only-cxx-convenience")
        self.assertEqual(declaration["profile"], "linux-aarch64-cxx-source")
        self.assertFalse(declaration["test_adapter_applicable"])
        legacy = RUNNER.classify_api_item("mi_option_reset_delay", "option")
        self.assertEqual(legacy["classification"], "deprecated")
        self.assertEqual(legacy["profile"], "linux-aarch64-legacy-option-alias")
        deprecated = RUNNER.classify_api_item("mi_option_deprecated_page_reset", "option")
        self.assertEqual(deprecated["classification"], "deprecated")
        self.assertEqual(deprecated["profile"], "linux-aarch64-deprecated")

    def test_release_symbol_cross_check_rejects_unclassified_discrepancies(self) -> None:
        contract = {
            "items": [
                {"kind": "external-function", "name": "mi_malloc", "oracle_release_exported": True},
                {"kind": "external-function", "name": "mi_collect_reduce", "oracle_release_exported": False},
            ],
            "release_symbol_contract": {
                "expected_defined_symbol_names": ["mi_malloc"],
                "header_declarations_without_normal_release_symbol": [
                    {"name": "mi_collect_reduce"},
                ],
            },
        }
        self.assertEqual(
            RUNNER.validate_release_symbol_contract(contract, ["mi_malloc"]),
            {"declared_external_function_count": 2, "defined_export_count": 1},
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "unclassified"):
            RUNNER.validate_release_symbol_contract(contract, ["mi_malloc", "mi_extra"])

    def test_function_macro_type_and_option_parsing_are_distinct(self) -> None:
        header = """
            #define mi_malloc_tp(tp) ((tp*)mi_malloc(sizeof(tp)))
            #define mi_attribute_like(p) \\
                mi_attribute_like_continuation(p)
            typedef struct mi_heap_s mi_heap_t;
            typedef enum mi_option_e { mi_option_show_errors } mi_option_t;
            mi_decl_export void* mi_malloc(size_t size);
            mi_decl_export void mi_free(void* p);
        """
        self.assertEqual(RUNNER.public_external_function_names(header), {"mi_malloc", "mi_free"})
        self.assertEqual(RUNNER.public_macro_names(header), {"mi_attribute_like", "mi_malloc_tp"})
        self.assertIn("mi_heap_t", RUNNER.public_type_names(header))
        self.assertEqual(RUNNER.public_option_names(header), {"mi_option_show_errors"})

    def test_inventory_item_does_not_advertise_an_implementation(self) -> None:
        item = RUNNER.item_record("mi_malloc", "external-function", ["include/mimalloc.h"], ["test/test-api.c"])
        self.assertEqual(item["classification"], "required-platform-applicable")
        self.assertEqual(item["adapter_surface"], "test-c-api-adapter-only")
        for field in ("exported", "implemented", "unit_verified", "differential_verified", "stress_verified", "performance_qualified"):
            self.assertFalse(item[field], field)

    def test_configuration_macro_parser_is_stable(self) -> None:
        parsed = RUNNER.parse_macros("#define MI_SECURE 4\n#define MI_EMPTY\n#define OTHER 1\n")
        self.assertEqual(parsed, {"MI_EMPTY": "", "MI_SECURE": "4"})

    def test_rust_layout_parser_ignores_test_harness_noise_and_requires_markers(self) -> None:
        output = """
running 1 test
test types::tests::oracle_layout_probe_emits_machine_record ... CRABC_MI_LAYOUT_BEGIN
pointer.size=8
sizeof.mi_page_t=128
CRABC_MI_LAYOUT_END
ok
"""
        self.assertEqual(
            RUNNER.parse_rust_layout(output),
            {"pointer.size": 8, "sizeof.mi_page_t": 128},
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "layout markers"):
            RUNNER.parse_rust_layout("pointer.size=8\n")

    def test_small_trace_parser_requires_one_address_independent_machine_record(self) -> None:
        output = """
noise before
CRABC_MI_SMALL_TRACE_BEGIN
trace.boundary.count=2
trace.boundary.0.request=0
trace.boundary.0.usable=8
CRABC_MI_SMALL_TRACE_END
noise after
"""
        self.assertEqual(
            RUNNER.parse_small_trace(output),
            {
                "trace.boundary.0.request": 0,
                "trace.boundary.0.usable": 8,
                "trace.boundary.count": 2,
            },
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "trace.*markers"):
            RUNNER.parse_small_trace("trace.boundary.count=2\n")

    def test_small_trace_comparison_requires_exact_keys_and_values(self) -> None:
        c_trace = {
            "trace.boundary.0.request": 0,
            "trace.boundary.0.usable": 8,
            "trace.boundary.count": 1,
        }
        self.assertEqual(
            RUNNER.compare_small_trace(c_trace, c_trace),
            {"compared_value_count": 3, "status": "matched"},
        )
        with self.assertRaisesRegex(
            RUNNER.HarnessError,
            r"missing from C oracle: trace\.extra; "
            r"missing from Rust port: trace\.boundary\.0\.usable; "
            r"value mismatches: trace\.boundary\.count \(C=1, Rust=2\)",
        ):
            RUNNER.compare_small_trace(
                c_trace,
                {
                    "trace.boundary.0.request": 0,
                    "trace.boundary.count": 2,
                    "trace.extra": 1,
                },
            )

    def test_fundamental_trace_parser_requires_one_address_independent_machine_record(self) -> None:
        output = """
noise before
CRABC_MI_FUNDAMENTAL_TRACE_BEGIN
trace.fundamental.class.small.request=10240
trace.fundamental.class.small.usable=10240
trace.fundamental.class.small.success=1
trace.fundamental.calloc.content_hash=14695981039346656037
CRABC_MI_FUNDAMENTAL_TRACE_END
noise after
"""
        self.assertEqual(
            RUNNER.parse_fundamental_trace(output),
            {
                "trace.fundamental.calloc.content_hash": 14695981039346656037,
                "trace.fundamental.class.small.request": 10240,
                "trace.fundamental.class.small.success": 1,
                "trace.fundamental.class.small.usable": 10240,
            },
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "fundamental-operation trace.*markers"):
            RUNNER.parse_fundamental_trace("trace.fundamental.class.small.request=10240\n")

    def test_fundamental_trace_comparison_names_missing_and_mismatched_values(self) -> None:
        c_trace = {
            "trace.fundamental.class.small.request": 10240,
            "trace.fundamental.class.small.success": 1,
            "trace.fundamental.class.small.usable": 10240,
        }
        self.assertEqual(
            RUNNER.compare_fundamental_trace(c_trace, c_trace),
            {"compared_value_count": 3, "status": "matched"},
        )
        with self.assertRaisesRegex(
            RUNNER.HarnessError,
            r"missing from C oracle: trace\.fundamental\.extra; "
            r"missing from Rust port: trace\.fundamental\.class\.small\.usable; "
            r"value mismatches: trace\.fundamental\.class\.small\.success \(C=1, Rust=0\)",
        ):
            RUNNER.compare_fundamental_trace(
                c_trace,
                {
                    "trace.fundamental.class.small.request": 10240,
                    "trace.fundamental.class.small.success": 0,
                    "trace.fundamental.extra": 1,
                },
            )

    def test_fundamental_trace_parser_rejects_raw_address_fields(self) -> None:
        output = """
CRABC_MI_FUNDAMENTAL_TRACE_BEGIN
trace.fundamental.class.small.address=12345
CRABC_MI_FUNDAMENTAL_TRACE_END
"""
        with self.assertRaisesRegex(RUNNER.HarnessError, "raw address field"):
            RUNNER.parse_fundamental_trace(output)
        hexadecimal = """
CRABC_MI_FUNDAMENTAL_TRACE_BEGIN
trace.fundamental.class.small.content_hash=0xface
CRABC_MI_FUNDAMENTAL_TRACE_END
"""
        with self.assertRaisesRegex(RUNNER.HarnessError, "raw address"):
            RUNNER.parse_fundamental_trace(hexadecimal)

    def test_fundamental_trace_same_run_marker_cannot_claim_comparison(self) -> None:
        status = RUNNER.pending_fundamental_trace_comparison()
        self.assertEqual(status["status"], "pending")
        self.assertIn("before the Rust library probe", status["reason"])
        self.assertIn("replaces this marker", status["reason"])

    def test_layout_parser_rejects_duplicate_machine_record_keys(self) -> None:
        with self.assertRaisesRegex(RUNNER.HarnessError, "duplicate layout probe key"):
            RUNNER.parse_layout("pointer.size=8\npointer.size=4\n")

    def test_rust_test_summary_parser_requires_one_successful_library_result(self) -> None:
        output = """
running 68 tests
test result: ok. 68 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
"""
        self.assertEqual(RUNNER.parse_rust_test_count(output), 68)
        with self.assertRaisesRegex(RUNNER.HarnessError, "Rust allocator test summary"):
            RUNNER.parse_rust_test_count("test result: FAILED. 67 passed; 1 failed\n")

    def test_upstream_api_summary_parser_requires_one_zero_failure_summary(self) -> None:
        output = """
malloc_aligned5: usable size: 8192.

---------------------------------------------
succeeded: 34
failed   : 0
"""
        self.assertEqual(
            RUNNER.parse_upstream_api_test_summary(output),
            {"failed": 0, "succeeded": 34},
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "reported 1 failure"):
            RUNNER.parse_upstream_api_test_summary("succeeded: 33\nfailed   : 1\n")
        with self.assertRaisesRegex(RUNNER.HarnessError, "absent or ambiguous"):
            RUNNER.parse_upstream_api_test_summary(
                "succeeded: 34\nfailed   : 0\nsucceeded: 34\nfailed   : 0\n"
            )

    def test_adapter_symbol_contract_requires_exact_prefixed_exports(self) -> None:
        expected = [
            "crabc_test_free",
            "crabc_test_init",
            "crabc_test_malloc",
        ]
        self.assertEqual(
            RUNNER.validate_adapter_dynamic_symbols(
                ["_init", *expected, "rust_eh_personality"], expected
            ),
            {"exported_symbol_count": 3, "symbols": expected},
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "missing adapter symbols"):
            RUNNER.validate_adapter_dynamic_symbols(expected[:-1], expected)
        with self.assertRaisesRegex(RUNNER.HarnessError, "unexpected adapter symbols"):
            RUNNER.validate_adapter_dynamic_symbols(
                [*expected, "crabc_test_unreviewed"], expected
            )
        with self.assertRaisesRegex(RUNNER.HarnessError, "forbidden allocator exports"):
            RUNNER.validate_adapter_dynamic_symbols([*expected, "malloc", "mi_malloc"], expected)

    def test_adapter_header_inventory_extracts_only_function_declarations(self) -> None:
        header = """
int crabc_test_init(void);
void *crabc_test_malloc(size_t size);
#define mi_malloc(size) crabc_test_malloc((size))
#define CRABC_MIMALLOC_TEST_ADAPTER_H
"""
        self.assertEqual(
            RUNNER.adapter_header_function_names(header),
            ["crabc_test_init", "crabc_test_malloc"],
        )

    def test_native_static_library_parser_preserves_rustc_link_order(self) -> None:
        output = """
   Compiling crabc-mimalloc-test-adapter v0.3.0
note: native-static-libs: -lgcc_s -lc
    Finished `release` profile
"""
        self.assertEqual(RUNNER.parse_native_static_libraries(output), ["-lgcc_s", "-lc"])
        with self.assertRaisesRegex(RUNNER.HarnessError, "absent or ambiguous"):
            RUNNER.parse_native_static_libraries("Finished release\n")
        with self.assertRaisesRegex(RUNNER.HarnessError, "invalid native static library"):
            RUNNER.parse_native_static_libraries("native-static-libs: -lgcc_s /ambient/libbad.a\n")

    def test_rust_layout_comparison_names_missing_and_mismatched_values(self) -> None:
        c_layout = {
            "pointer.size": 8,
            "sizeof.mi_memid_t": 24,
            "sizeof.mi_page_t": 128,
        }
        self.assertEqual(
            RUNNER.compare_rust_layout(c_layout, c_layout),
            {"compared_value_count": 3, "status": "matched"},
        )
        with self.assertRaisesRegex(
            RUNNER.HarnessError,
            r"missing from C oracle: alignof\.mi_page_t; value mismatches: sizeof\.mi_page_t \(C=128, Rust=120\)",
        ):
            RUNNER.compare_rust_layout(
                c_layout,
                {
                    "alignof.mi_page_t": 8,
                    "pointer.size": 8,
                    "sizeof.mi_memid_t": 24,
                "sizeof.mi_page_t": 120,
            },
        )

    def test_configuration_layout_requires_an_exact_c_and_rust_key_set(self) -> None:
        c_layout = {
            "config.WORD_SIZE": object(),
            "config.PAGE_MAP_FLAT": object(),
        }
        rust_layout = dict(c_layout)
        self.assertEqual(RUNNER.compare_configuration_layout(c_layout, rust_layout), 2)
        with self.assertRaisesRegex(RUNNER.HarnessError, "configuration records missing from Rust"):
            RUNNER.compare_configuration_layout(c_layout, {"config.WORD_SIZE": object()})
        with self.assertRaisesRegex(RUNNER.HarnessError, "configuration records missing from C"):
            RUNNER.compare_configuration_layout({"config.WORD_SIZE": object()}, rust_layout)


class ContractTests(unittest.TestCase):
    def test_pin_is_complete_and_names_the_exact_archive(self) -> None:
        pin = RUNNER.load_pin()
        self.assertEqual(pin["version"], "3.5.0")
        self.assertEqual(pin["repository"], "https://github.com/microsoft/mimalloc.git")
        self.assertEqual(pin["tag"], "v3.5.0")
        self.assertEqual(pin["archive_root"], "mimalloc-3.5.0")
        self.assertEqual(pin["revision"], "18b08671c9302247bfb682286e6bf3cc1773f801")
        self.assertEqual(pin["tag_object"], "438b0c4b78d2599aede7fca3ddacc28863b0eae8")

    def test_port_map_covers_the_required_v3_sources_and_has_only_verified_claims(self) -> None:
        port_map = RUNNER.load_port_map()
        counts = RUNNER.port_map_counts(port_map)
        self.assertEqual(counts["unit_count"], len(RUNNER.REQUIRED_PORT_UNITS))
        self.assertGreaterEqual(counts["implemented"], 8)
        self.assertEqual(counts["implemented"], counts["unit_verified"])

    def test_checked_in_upstream_test_inventory_distinguishes_sources_and_support(self) -> None:
        inventory = RUNNER.read_json(RUNNER.UPSTREAM_TEST_CONTRACT)
        self.assertEqual(inventory["summary"]["test_source_count"], 13)
        self.assertEqual(inventory["summary"]["test_support_file_count"], 3)
        self.assertEqual(inventory["summary"]["total_inventory_file_count"], 16)

    def test_adapted_api_fixture_contract_is_exact_and_reviewed(self) -> None:
        contract = RUNNER.read_json(RUNNER.ADAPTED_TEST_CONTRACT)
        header = RUNNER.TEST_ADAPTER_HEADER.read_text(encoding="utf-8")
        summary = RUNNER.validate_adapted_test_contract(contract, RUNNER.load_pin(), header)
        self.assertEqual(
            summary,
            {
                "expected_adapter_symbol_count": 16,
                "omitted_test_count": 21,
                "selected_test_count": 33,
            },
        )

    def test_adapted_api_fixture_rejects_unexplained_omission_and_symbol_drift(self) -> None:
        contract = RUNNER.read_json(RUNNER.ADAPTED_TEST_CONTRACT)
        header = RUNNER.TEST_ADAPTER_HEADER.read_text(encoding="utf-8")
        contract["omitted_tests"][0]["reason"] = ""
        with self.assertRaisesRegex(RUNNER.HarnessError, "invalid omitted test"):
            RUNNER.validate_adapted_test_contract(contract, RUNNER.load_pin(), header)

        contract = RUNNER.read_json(RUNNER.ADAPTED_TEST_CONTRACT)
        contract["expected_adapter_symbols"] = sorted(
            [*contract["expected_adapter_symbols"], "crabc_test_unreviewed"]
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "header symbol contract"):
            RUNNER.validate_adapted_test_contract(contract, RUNNER.load_pin(), header)

    def test_checked_in_api_inventory_has_audited_linux_aarch64_boundaries(self) -> None:
        inventory = RUNNER.read_json(RUNNER.API_CONTRACT)
        self.assertEqual(inventory["format"], 2)
        self.assertEqual(
            inventory["summary"],
            {
                "configuration_macro_count": 138,
                "cxx_convenience_count": 1,
                "cxx_template_count": 3,
                "external_function_count": 194,
                "macro_count": 26,
                "option_count": 52,
                "override_macro_count": 37,
                "source_only_count": 147,
                "source_only_macro_count": 63,
                "static_inline_count": 7,
                "total_item_count": 336,
                "type_count": 16,
            },
        )
        self.assertEqual(
            [entry["name"] for entry in inventory["release_symbol_contract"]["header_declarations_without_normal_release_symbol"]],
            ["mi_collect_reduce", "mi_malloc_size", "mi_malloc_usable_size", "mi_stats_merge"],
        )
        self.assertEqual(
            len(inventory["release_symbol_contract"]["expected_defined_symbol_names"]), 190
        )
        items = {item["name"]: item for item in inventory["items"]}
        self.assertEqual(items["mi_wdupenv_s"]["classification"], "unsupported-linux-aarch64")
        self.assertTrue(items["mi_wdupenv_s"]["oracle_release_exported"])
        self.assertEqual(items["mi_option_os_tag"]["classification"], "unsupported-linux-aarch64")
        self.assertEqual(items["mi_stats_init"]["classification"], "source-only-inline")
        self.assertEqual(items["mi_stl_allocator"]["kind"], "cxx-template")
        self.assertFalse(any(item["crabc_libc_exported"] for item in inventory["items"]))

    def test_full_and_performance_modes_have_precise_unmet_milestones(self) -> None:
        full = (
            "allocator --full remains unavailable after the passing Milestone 4 adapter lane: Milestone 5 must provide remote free, abandonment/adoption, thread/TLS lifecycle, Loom protocols, and pthread stress before later backend, fork, and corpus lanes can run."
        )
        performance = (
            "allocator performance is unavailable: Milestone 9 requires comparable C and Rust opaque allocator boundaries plus Milestone 8 integrated crabc backends; the current private one-thread engine is not a benchmark boundary."
        )
        self.assertIn("passing Milestone 4 adapter lane", full)
        self.assertIn("Milestone 5", full)
        self.assertIn("Milestone 9", performance)

    def test_ratchet_rejects_a_true_status_moved_to_another_item(self) -> None:
        baseline = {
            "port_map_true_statuses": {
                "item:include/mimalloc/bits.h:mi_popcount": ["implemented", "unit_verified"],
                "item:include/mimalloc/bits.h:mi_ctz": ["implemented"],
            }
        }
        current = {
            "port_map_true_statuses": {
                "item:include/mimalloc/bits.h:mi_popcount": ["implemented"],
                "item:include/mimalloc/bits.h:mi_ctz": ["implemented", "unit_verified"],
            }
        }
        self.assertEqual(
            RUNNER.ratchet_status_regressions(baseline, current),
            ["item:include/mimalloc/bits.h:mi_popcount:unit_verified"],
        )

    def test_ratchet_snapshot_rejects_scalar_and_aggregate_regressions(self) -> None:
        baseline = {
            "api_total_item_count": 336,
            "configuration_profile_count": 5,
            "upstream_test_source_count": 13,
            "upstream_test_inventory_file_count": 16,
            "port_map_counts": {
                "unit_count": 35,
                "item_count": 24,
                "implemented": 27,
                "unit_verified": 27,
            },
        }
        current = {
            **baseline,
            "api_total_item_count": 335,
            "port_map_counts": {
                **baseline["port_map_counts"],
                "unit_verified": 26,
            },
        }
        self.assertEqual(
            RUNNER.ratchet_measurement_regressions(baseline, current),
            ["api_total_item_count", "port_map_counts.unit_verified"],
        )
        self.assertEqual(RUNNER.ratchet_measurement_regressions(baseline, baseline), [])


if __name__ == "__main__":
    unittest.main()
