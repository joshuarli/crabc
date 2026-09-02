#!/usr/bin/env python3
"""Focused pure-Python tests for the Milestone 0 mimalloc oracle harness."""

from __future__ import annotations

import importlib.util
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
from unittest import mock
from pathlib import Path


RUNNER_PATH = Path(__file__).resolve().parents[1] / "run.py"
SPEC = importlib.util.spec_from_file_location("crabc_allocator_runner", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


# The finite M1 random image combines the C ABI fields with the deliberately
# address-independent C/Rust state record. Keep this exact source order in the
# harness test so a manifest edit cannot silently drop a covered branch.
M1_RANDOM_IMAGE_KEYS = (
    "sizeof.mi_random_ctx_t",
    "alignof.mi_random_ctx_t",
    "offsetof.mi_random_ctx_t.input",
    "offsetof.mi_random_ctx_t.output",
    "offsetof.mi_random_ctx_t.output_available",
    "offsetof.mi_random_ctx_t.weak",
    "m1.random.split.parent.output_available",
    "m1.random.split.parent.consumed_words_cleared",
    "m1.random.split.parent.counter_low",
    "m1.random.split.parent.counter_high",
    "m1.random.split.child.output_available",
    "m1.random.split.child.counter_low",
    "m1.random.split.child.counter_high",
    "m1.random.split.child.weak",
    "m1.random.split.child.nonce_xor_destination",
    "m1.random.next.zero_retry.result",
    "m1.random.next.zero_retry.output_available",
    "m1.random.next.zero_retry.consumed_words_cleared",
    "m1.random.forced_weak.initialized",
    "m1.random.forced_weak.weak",
    "m1.random.forced_weak.output_available",
    "m1.random.forced_weak.counter_low",
    "m1.random.forced_weak.counter_high",
    "m1.random.forced_weak.nonce_xor_destination",
    "m1.random.reinit.strong.attempted",
    "m1.random.reinit.strong.state_preserved",
    "m1.random.reinit.strong.fingerprint",
)


# M1's representation boundary is deliberately finite: the default-release
# `types.h:288-541` scalar/metadata records and `internal.h:1316-1369`
# memory-ID constructors. Keep every C/Rust witness in source order here so a
# future manifest edit cannot shrink the evidence back to selected endpoint
# offsets while still claiming the represented-layout component is complete.
M1_REPRESENTED_LAYOUT_KEYS = (
    "sizeof.mi_memkind_t",
    "alignof.mi_memkind_t",
    "value.MI_MEM_NONE",
    "value.MI_MEM_EXTERNAL",
    "value.MI_MEM_STATIC",
    "value.MI_MEM_OS",
    "value.MI_MEM_OS_HUGE",
    "value.MI_MEM_OS_REMAP",
    "value.MI_MEM_ARENA",
    "value.MI_MEM_MALLOC",
    "sizeof.mi_memid_t.mem",
    "alignof.mi_memid_t.mem",
    "sizeof.mi_memid_os_info_t",
    "alignof.mi_memid_os_info_t",
    "offsetof.mi_memid_os_info_t.base",
    "offsetof.mi_memid_os_info_t.size",
    "sizeof.mi_memid_arena_info_t",
    "alignof.mi_memid_arena_info_t",
    "offsetof.mi_memid_arena_info_t.arena",
    "offsetof.mi_memid_arena_info_t.slice_index",
    "offsetof.mi_memid_arena_info_t.slice_count",
    "sizeof.mi_memid_malloc_info_t",
    "alignof.mi_memid_malloc_info_t",
    "offsetof.mi_memid_malloc_info_t.base",
    "offsetof.mi_memid_malloc_info_t.size",
    "sizeof.mi_memid_t",
    "alignof.mi_memid_t",
    "offsetof.mi_memid_t.mem",
    "offsetof.mi_memid_t.mem.os.base",
    "offsetof.mi_memid_t.mem.os.size",
    "offsetof.mi_memid_t.mem.arena.arena",
    "offsetof.mi_memid_t.mem.arena.slice_index",
    "offsetof.mi_memid_t.mem.arena.slice_count",
    "offsetof.mi_memid_t.mem.malloc.base",
    "offsetof.mi_memid_t.mem.malloc.size",
    "offsetof.mi_memid_t.memkind",
    "offsetof.mi_memid_t.is_pinned",
    "offsetof.mi_memid_t.initially_committed",
    "offsetof.mi_memid_t.initially_zero",
    "m1.provenance.memkind.is_os.mask",
    "m1.provenance.memkind.needs_no_free.mask",
    "m1.provenance.create.none.kind",
    "m1.provenance.create.none.pinned",
    "m1.provenance.create.none.committed",
    "m1.provenance.create.none.zero",
    "m1.provenance.create.none.memid_size",
    "m1.provenance.create.static.kind",
    "m1.provenance.create.static.pinned",
    "m1.provenance.create.static.committed",
    "m1.provenance.create.static.zero",
    "m1.provenance.create.static.base_is_null",
    "m1.provenance.create.static.stored_size",
    "m1.provenance.create.static.memid_size",
    "m1.provenance.create.static_allocation.kind",
    "m1.provenance.create.static_allocation.pinned",
    "m1.provenance.create.static_allocation.committed",
    "m1.provenance.create.static_allocation.zero",
    "m1.provenance.create.static_allocation.base_is_input",
    "m1.provenance.create.static_allocation.stored_size",
    "m1.provenance.create.static_allocation.memid_size",
    "m1.provenance.create.malloc.kind",
    "m1.provenance.create.malloc.pinned",
    "m1.provenance.create.malloc.committed",
    "m1.provenance.create.malloc.zero",
    "m1.provenance.create.malloc.base_is_input",
    "m1.provenance.create.malloc.stored_size",
    "m1.provenance.create.malloc.memid_size",
    "m1.provenance.create.os.kind",
    "m1.provenance.create.os.pinned",
    "m1.provenance.create.os.committed",
    "m1.provenance.create.os.zero",
    "m1.provenance.create.os.base_is_input",
    "m1.provenance.create.os.stored_size",
    "m1.provenance.create.os.memid_size",
    "sizeof.mi_encoded_t",
    "alignof.mi_encoded_t",
    "sizeof.mi_threadid_t",
    "alignof.mi_threadid_t",
    "sizeof.mi_thread_free_t",
    "alignof.mi_thread_free_t",
    "sizeof.mi_used_t",
    "alignof.mi_used_t",
    "sizeof.mi_page_flags_t",
    "alignof.mi_page_flags_t",
    "value.MI_PAGE_IN_FULL_QUEUE",
    "value.MI_PAGE_HAS_INTERIOR_POINTERS",
    "value.MI_PAGE_FLAG_MASK",
    "value.MI_PAGE_FLAG_BITS",
    "value.MI_THREADID_ABANDONED",
    "value.MI_THREADID_ABANDONED_MAPPED",
    "value.MI_THREADID_DETACHED",
    "sizeof.mi_block_t",
    "alignof.mi_block_t",
    "offsetof.mi_block_t.next",
    "sizeof.mi_page_t",
    "alignof.mi_page_t",
    "offsetof.mi_page_t.self",
    "offsetof.mi_page_t.xthread_id",
    "offsetof.mi_page_t.free",
    "offsetof.mi_page_t.used",
    "offsetof.mi_page_t.local_free",
    "offsetof.mi_page_t.block_size",
    "offsetof.mi_page_t.page_offset",
    "offsetof.mi_page_t.capacity",
    "offsetof.mi_page_t.reserved",
    "offsetof.mi_page_t.slice_pcommitted",
    "offsetof.mi_page_t.retire_expire",
    "offsetof.mi_page_t.free_is_zero",
    "offsetof.mi_page_t.xthread_free",
    "offsetof.mi_page_t.theap",
    "offsetof.mi_page_t.heap",
    "offsetof.mi_page_t.next",
    "offsetof.mi_page_t.prev",
    "offsetof.mi_page_t.memid",
    "sizeof.mi_page_kind_t",
    "alignof.mi_page_kind_t",
    "value.MI_PAGE_SMALL",
    "value.MI_PAGE_MEDIUM",
    "value.MI_PAGE_LARGE",
    "value.MI_PAGE_SINGLETON",
    "sizeof.mi_page_queue_t",
    "alignof.mi_page_queue_t",
    "offsetof.mi_page_queue_t.first",
    "offsetof.mi_page_queue_t.last",
    "offsetof.mi_page_queue_t.count",
    "offsetof.mi_page_queue_t.block_size",
)

# A complete representation vector must retain the paired exclusions. These
# source shapes have fields adjacent to the selected records, but need a live
# arena or a nondefault configuration image and therefore cannot be smuggled
# into a default-release M1 layout claim.
M1_REPRESENTATION_EXCLUSION_IDS = {
    "arena-and-external-memory-id-lifecycle",
    "heap-theap-subprocess-and-tld-layout-lifecycles",
    "nondefault-page-layout-modes",
    "statistics-representations-and-operations",
    "whole-types-and-internal-units",
}


class WorkRootTests(unittest.TestCase):
    def test_work_root_routes_all_runner_owned_outputs(self) -> None:
        work_root = RUNNER.default_work_root()
        self.assertEqual(RUNNER.WORK_ROOT, work_root)
        self.assertEqual(RUNNER.CACHE, work_root / "allocator-cache")
        self.assertEqual(RUNNER.REPORT_ROOT, work_root / "reports/allocator")
        self.assertEqual(
            RUNNER.ARTIFACT_ROOT,
            work_root / "target/compat/allocator",
        )
        self.assertEqual(RUNNER.TEMP_ROOT, work_root / "tmp/allocator")
        self.assertEqual(
            RUNNER.TLS_CODEGEN_REPORT,
            work_root / "reports/allocator/tls-codegen.json",
        )
        self.assertEqual(
            RUNNER.X86_64_TLS_CODEGEN_REPORT,
            work_root / "reports/allocator/tls-codegen-x86_64.json",
        )
        self.assertEqual(
            RUNNER.X86_64_ORACLE_REPORT_ROOT,
            work_root / "reports/allocator/x86_64",
        )
        self.assertEqual(
            RUNNER.X86_64_ORACLE_ARTIFACT_ROOT,
            work_root / "target/compat/allocator/x86_64",
        )
        self.assertEqual(
            RUNNER.RUNTIME_TICKET_ZERO_SOAK_REPORT,
            work_root / "reports/allocator/runtime-ticket-zero-soak-1024.json",
        )

    def test_default_work_root_honors_crabc_work_dir(self) -> None:
        with mock.patch.dict(RUNNER.os.environ, {}, clear=True):
            self.assertEqual(RUNNER.default_work_root(), RUNNER.ROOT / ".work")
        with mock.patch.dict(
            RUNNER.os.environ, {"CRABC_WORK_DIR": "isolated-work"}, clear=True
        ):
            self.assertEqual(
                RUNNER.default_work_root(),
                RUNNER.ROOT / "isolated-work",
            )
        custom = RUNNER.ROOT / ".work/custom-root"
        with mock.patch.dict(
            RUNNER.os.environ, {"CRABC_WORK_DIR": str(custom)}, clear=True
        ):
            self.assertEqual(RUNNER.default_work_root(), custom)

    def test_runner_temporary_directory_stays_below_the_work_root(self) -> None:
        with RUNNER.temporary_directory("crabc-allocator-work-root-") as temporary:
            path = Path(temporary).resolve()
            self.assertEqual(path.parent, RUNNER.TEMP_ROOT.resolve())


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


def x86_64_engine_dependency_metadata() -> dict[str, object]:
    """Return the selected x86 normal graph, including its CPUID helper."""

    metadata = production_dependency_metadata()
    packages = metadata["packages"]
    nodes = metadata["resolve"]["nodes"]
    assert isinstance(packages, list) and isinstance(nodes, list)
    packages.append(
        {
            "id": "cpufeatures 0.3.0",
            "name": "cpufeatures",
            "version": "0.3.0",
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "targets": [{"kind": ["lib"]}],
        }
    )
    nodes.append({"id": "cpufeatures 0.3.0", "deps": []})
    chacha = next(node for node in nodes if node["id"] == "chacha20 0.10.1")
    chacha["deps"].append(
        {
            "name": "cpufeatures",
            "pkg": "cpufeatures 0.3.0",
            "dep_kinds": [{"kind": None, "target": None}],
        }
    )
    return metadata


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
    def test_native_x86_64_profile_records_its_musl_target_boundary(self) -> None:
        self.assertEqual(RUNNER.X86_64_RUST_TARGET, "x86_64-unknown-linux-musl")
        self.assertEqual(RUNNER.X86_64_INTERPRETER, "ld-musl-x86_64.so.1")
        self.assertEqual(
            RUNNER.X86_64_TARGET_METADATA,
            {
                "architecture": "x86_64",
                "target": "x86_64-unknown-linux-musl",
                "interpreter": "ld-musl-x86_64.so.1",
            },
        )
        self.assertEqual(
            RUNNER.X86_64_ORACLE_REPORT_ROOT,
            RUNNER.REPORT_ROOT / "x86_64",
        )

    def test_parser_selects_x86_64_without_changing_the_default(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CRABC_ALLOCATOR_EVIDENCE_ARCH", None)
            with mock.patch.object(sys, "argv", ["run.py", "--quick"]):
                self.assertEqual(RUNNER.parse_arguments().architecture, "aarch64")
        with mock.patch.dict(
            os.environ, {"CRABC_ALLOCATOR_EVIDENCE_ARCH": "x86_64"}, clear=False
        ):
            with mock.patch.object(sys, "argv", ["run.py", "--quick"]):
                self.assertEqual(RUNNER.parse_arguments().architecture, "x86_64")
        with mock.patch.dict(
            os.environ, {"CRABC_ALLOCATOR_EVIDENCE_ARCH": ""}, clear=False
        ):
            with mock.patch.object(sys, "argv", ["run.py", "--quick", "--arch", "x86_64"]):
                self.assertEqual(RUNNER.parse_arguments().architecture, "x86_64")
            with mock.patch.object(sys, "argv", ["run.py", "--quick", "--x86-64"]):
                self.assertEqual(RUNNER.parse_arguments().architecture, "x86_64")
        with mock.patch.object(sys, "argv", ["run.py", "--m1"]):
            arguments = RUNNER.parse_arguments()
            self.assertTrue(arguments.m1)
            self.assertEqual(arguments.architecture, "aarch64")

    def test_parser_does_not_allow_x86_64_to_claim_later_production_lanes(self) -> None:
        for mode in ("--m1", "--full", "--perf-smoke", "--perf-full", "--generate-contracts", "--snapshot-ratchet"):
            with self.subTest(mode=mode), mock.patch.object(
                sys, "argv", ["run.py", mode, "--architecture", "x86_64"]
            ):
                with self.assertRaises(SystemExit):
                    RUNNER.parse_arguments()

    def test_native_architecture_gate_rejects_non_native_x86_64(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"CRABC_EXECUTION_MODE": "native", "CRABC_HOST_ARCH": "x86_64"},
            clear=False,
        ), mock.patch.object(RUNNER.platform, "system", return_value="Linux"), mock.patch.object(
            RUNNER.platform, "machine", return_value="aarch64"
        ):
            with self.assertRaisesRegex(RUNNER.HarnessError, "native Linux/x86-64"):
                RUNNER.require_native_x86_64()

    def test_native_architecture_gate_rejects_missing_or_emulated_x86_provenance(self) -> None:
        with mock.patch.object(RUNNER.platform, "system", return_value="Linux"), mock.patch.object(
            RUNNER.platform, "machine", return_value="x86_64"
        ):
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(RUNNER.HarnessError, "canonical native provenance"):
                    RUNNER.require_native_x86_64()
            with mock.patch.dict(
                os.environ,
                {"CRABC_EXECUTION_MODE": "emulated", "CRABC_HOST_ARCH": "x86_64"},
                clear=True,
            ):
                with self.assertRaisesRegex(RUNNER.HarnessError, "canonical native provenance"):
                    RUNNER.require_native_x86_64()
            with mock.patch.dict(
                os.environ,
                {"CRABC_EXECUTION_MODE": "native", "CRABC_HOST_ARCH": "amd64"},
                clear=True,
            ):
                self.assertEqual(
                    RUNNER.require_native_x86_64(),
                    {"execution_mode": "native", "host_architecture": "amd64"},
                )

    def test_x86_quick_rejects_emulated_provenance_before_oracle_work(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"CRABC_EXECUTION_MODE": "emulated", "CRABC_HOST_ARCH": "x86_64"},
            clear=True,
        ), mock.patch.object(RUNNER.platform, "system", return_value="Linux"), mock.patch.object(
            RUNNER.platform, "machine", return_value="x86_64"
        ), mock.patch.object(RUNNER, "load_pin") as load_pin:
            with self.assertRaisesRegex(RUNNER.HarnessError, "canonical native provenance"):
                RUNNER.run_milestone0(
                    offline=True,
                    generate_contracts=False,
                    check_only=False,
                    architecture="x86_64",
                )
        load_pin.assert_not_called()

    def test_x86_quick_uses_only_target_local_contract_inputs(self) -> None:
        source_api_inventory = {
            "contract": {"path": "compat/allocator/x86_64-api-v3.5.0.json"},
            "declaration_count": 180,
            "status": "passed",
        }
        source_api_coverage = {
            "build_mode_declaration_count": 52,
            "contract": {"path": "compat/allocator/x86_64-api-coverage-v3.5.0.json"},
            "header_surface_count": 4,
            "overall_status": "incomplete",
            "profile": "linux-x86_64-mimalloc-source-public-surface",
            "scope": (
                "pinned source inventory only; it does not establish native execution "
                "or public runtime integration"
            ),
            "source_declared_function_count": 195,
            "source_member_count": 30,
            "status": "passed",
            "symbol_disposition_count": 8,
            "target": {
                "architecture": "x86_64",
                "endianness": "little",
                "rust_target": "x86_64-unknown-linux-musl",
                "system": "linux",
            },
            "test_member_count": 18,
        }
        source_map = {
            "contract": {"path": "compat/allocator/x86_64-source-map-v3.5.0.json"},
            "overall_status": "incomplete",
            "profile": "linux-x86_64-mimalloc-engine-parity",
            "scope": "pinned source mapping only; it does not establish runtime integration",
            "source_member_count": 34,
            "status": "passed",
            "status_counts": {
                "implemented": 1,
                "inapplicable": 3,
                "not-started": 5,
                "partial": 25,
            },
            "target": {
                "architecture": "x86_64",
                "endianness": "little",
                "rust_target": "x86_64-unknown-linux-musl",
                "system": "linux",
            },
            "unit_count": 34,
            "unfinished_unit_count": 30,
        }
        expected = {"status": "x86-local"}
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            archive = temporary_root / "mimalloc.tar.gz"
            archive.write_bytes(b"pinned archive placeholder")
            source = temporary_root / "mimalloc-3.5.0"
            source.mkdir()
            with mock.patch.dict(
                os.environ,
                {"CRABC_EXECUTION_MODE": "native", "CRABC_HOST_ARCH": "x86_64"},
                clear=False,
            ), mock.patch.object(
                RUNNER.platform, "system", return_value="Linux"
            ), mock.patch.object(
                RUNNER.platform, "machine", return_value="x86_64"
            ), mock.patch.object(
                RUNNER, "fetch_archive", return_value=archive
            ), mock.patch.object(
                RUNNER, "safe_extract", return_value=source
            ), mock.patch.object(
                RUNNER,
                "x86_64_source_api_inventory",
                return_value=source_api_inventory,
            ) as inventory, mock.patch.object(
                RUNNER,
                "x86_64_source_map_contract",
                return_value=source_map,
            ) as source_map_validator, mock.patch.object(
                RUNNER,
                "x86_64_api_coverage_contract",
                return_value=source_api_coverage,
            ) as source_api_coverage_validator, mock.patch.object(
                RUNNER,
                "apply_and_verify_adapted_test_patch",
                return_value={"selected_test_count": 33},
            ), mock.patch.object(
                RUNNER, "require_tool", return_value="patch"
            ), mock.patch.object(
                RUNNER, "run_x86_64_oracle", return_value=expected
            ) as run_x86, mock.patch.object(
                RUNNER, "generated_contracts"
            ) as generated_contracts, mock.patch.object(
                RUNNER, "load_port_map"
            ) as load_port_map, mock.patch.object(
                RUNNER, "check_ratchet"
            ) as check_ratchet:
                self.assertEqual(
                    RUNNER.run_milestone0(
                        offline=True,
                        generate_contracts=False,
                        check_only=False,
                        architecture="x86_64",
                    ),
                    expected,
                )
                source_check = RUNNER.run_milestone0(
                    offline=True,
                    generate_contracts=False,
                    check_only=True,
                    architecture="x86_64",
                )
        self.assertEqual(source_check["architecture_profile"], "x86_64-source-contract-check")
        self.assertEqual(source_check["x86_64_source_api_inventory"], source_api_inventory)
        self.assertEqual(source_check["x86_64_api_coverage"], source_api_coverage)
        self.assertEqual(source_check["x86_64_source_map"], source_map)
        self.assertNotIn("native_execution_provenance", source_check)
        inventory.assert_has_calls([mock.call(archive), mock.call(archive)])
        self.assertEqual(inventory.call_count, 2)
        source_map_validator.assert_has_calls([mock.call(archive), mock.call(archive)])
        self.assertEqual(source_map_validator.call_count, 2)
        source_api_coverage_validator.assert_has_calls([mock.call(archive), mock.call(archive)])
        self.assertEqual(source_api_coverage_validator.call_count, 2)
        self.assertEqual(
            run_x86.call_args.kwargs["source_api_inventory"], source_api_inventory
        )
        self.assertEqual(
            run_x86.call_args.kwargs["source_api_coverage"], source_api_coverage
        )
        self.assertEqual(run_x86.call_args.kwargs["source_map"], source_map)
        generated_contracts.assert_not_called()
        load_port_map.assert_not_called()
        check_ratchet.assert_not_called()

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

    def test_x86_64_engine_dependency_graph_is_exact_and_excludes_libc(self) -> None:
        report = RUNNER.validate_x86_64_engine_dependency_graph(
            x86_64_engine_dependency_metadata()
        )
        self.assertEqual(report["target"], "x86_64-unknown-linux-musl")
        self.assertEqual(report["external_package_count"], 10)
        self.assertEqual(report["build_script_count"], 0)
        self.assertEqual(report["proc_macro_count"], 0)
        packages = {(package["name"], package["version"]) for package in report["packages"]}
        self.assertIn(("cpufeatures", "0.3.0"), packages)
        self.assertNotIn(("libc", "0.2.189"), packages)

    def test_x86_64_engine_dependency_graph_rejects_a_selected_libc_edge(self) -> None:
        metadata = x86_64_engine_dependency_metadata()
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
        cpufeatures = next(node for node in nodes if node["id"] == "cpufeatures 0.3.0")
        cpufeatures["deps"].append(
            {
                "name": "libc",
                "pkg": "libc 0.2.189",
                "dep_kinds": [{"kind": None, "target": None}],
            }
        )
        with self.assertRaisesRegex(
            RUNNER.HarnessError, "unexpected selected package: libc 0.2.189"
        ):
            RUNNER.validate_x86_64_engine_dependency_graph(metadata)

    def test_x86_64_engine_dependency_graph_command_is_pinned_and_unfeatured(self) -> None:
        metadata = x86_64_engine_dependency_metadata()
        with mock.patch.object(
            RUNNER,
            "command_record",
            return_value={"status": 0, "stderr": "", "stdout": json.dumps(metadata)},
        ) as command_record:
            report = RUNNER.x86_64_engine_dependency_graph()
        expected_command = [
            "cargo",
            "metadata",
            "--format-version",
            "1",
            "--filter-platform",
            "x86_64-unknown-linux-musl",
            "--no-default-features",
            "--locked",
        ]
        command_record.assert_called_once_with(expected_command, cwd=RUNNER.ROOT)
        self.assertEqual(report["command"], expected_command)
        self.assertEqual(report["resolution"], RUNNER.X86_64_LOCKFILE_RESOLUTION)
        self.assertNotIn("--offline", expected_command)

    def test_x86_64_normal_engine_rlib_parser_rejects_test_features(self) -> None:
        event = {
            "reason": "compiler-artifact",
            "target": {
                "crate_types": ["lib"],
                "kind": ["lib"],
                "name": "crabc_mimalloc",
            },
            "profile": {"test": False},
            "features": [],
            "filenames": ["/tmp/libcrabc_mimalloc.rlib"],
        }
        self.assertEqual(
            RUNNER.x86_64_normal_engine_rlib_from_cargo_output(json.dumps(event)),
            Path("/tmp/libcrabc_mimalloc.rlib"),
        )
        event["features"] = ["test-adapter"]
        with self.assertRaisesRegex(RUNNER.HarnessError, "unexpectedly selected crate features"):
            RUNNER.x86_64_normal_engine_rlib_from_cargo_output(json.dumps(event))

    def test_x86_64_normal_engine_artifact_command_is_locked_unfeatured_and_not_offline(self) -> None:
        command = RUNNER.x86_64_normal_engine_artifact_command("cargo")
        self.assertEqual(
            command,
            [
                "cargo",
                "rustc",
                "--locked",
                "--package",
                "crabc-mimalloc",
                "--lib",
                "--release",
                "--no-default-features",
                "--target",
                "x86_64-unknown-linux-musl",
                "--message-format=json",
            ],
        )
        self.assertNotIn("--offline", command)

    def test_x86_64_normal_engine_artifact_requires_the_normal_fat_lto_bitcode_member(self) -> None:
        self.assertEqual(
            RUNNER.x86_64_normal_engine_codegen_member_format(
                "<normal-engine-codegen-member>: LLVM IR bitcode"
            ),
            "llvm-ir-bitcode",
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "expected fat-LTO LLVM bitcode"):
            RUNNER.x86_64_normal_engine_codegen_member_format(
                "<normal-engine-codegen-member>: ELF 64-bit LSB relocatable, x86-64"
            )

    def test_x86_64_direct_engine_probe_is_pinned_unfeatured_and_isolated(self) -> None:
        c_layout = {"config.value": 1}
        c_small_trace = {"small.value": 2}
        c_fundamental_trace = {
            key: 3 for key in RUNNER.FUNDAMENTAL_TRACE_X86_64_EXPECTED_KEYS
        }
        with mock.patch.object(
            RUNNER,
            "command_record",
            return_value={"status": 0, "stderr": "", "stdout": "probe output"},
        ) as command_record, mock.patch.object(
            RUNNER, "parse_rust_layout", return_value=c_layout
        ), mock.patch.object(
            RUNNER, "parse_small_trace", return_value=c_small_trace
        ), mock.patch.object(
            RUNNER, "parse_fundamental_trace", return_value=c_fundamental_trace
        ), mock.patch.object(RUNNER, "parse_rust_test_count", return_value=1):
            report = RUNNER.rust_layout_probe(
                c_layout,
                c_small_trace,
                c_fundamental_trace,
                rust_target="x86_64-unknown-linux-musl",
            )
        command = command_record.call_args.args[0]
        environment = command_record.call_args.kwargs["env"]
        self.assertEqual(
            command,
            [
                "cargo",
                "test",
                "-p",
                "crabc-mimalloc",
                "--lib",
                "--locked",
                "--no-default-features",
                "--target",
                "x86_64-unknown-linux-musl",
                "--",
                "--nocapture",
            ],
        )
        self.assertEqual(environment["CARGO_INCREMENTAL"], "0")
        target_directory = Path(environment["CARGO_TARGET_DIR"])
        self.assertEqual(target_directory.name, "target")
        self.assertFalse(target_directory.exists())
        self.assertEqual(report["dependency_resolution"], RUNNER.X86_64_LOCKFILE_RESOLUTION)
        self.assertEqual(report["target_directory"], "fresh temporary CARGO_TARGET_DIR")

    def test_aarch64_direct_engine_probe_is_lockfile_pinned(self) -> None:
        c_layout = {"config.value": 1}
        c_small_trace = {"small.value": 2}
        c_fundamental_trace = {
            key: 3 for key in RUNNER.FUNDAMENTAL_TRACE_AARCH64_EXPECTED_KEYS
        }
        with mock.patch.object(
            RUNNER,
            "command_record",
            return_value={"status": 0, "stderr": "", "stdout": "probe output"},
        ) as command_record, mock.patch.object(
            RUNNER, "parse_rust_layout", return_value=c_layout
        ), mock.patch.object(
            RUNNER, "parse_small_trace", return_value=c_small_trace
        ), mock.patch.object(
            RUNNER, "parse_fundamental_trace", return_value=c_fundamental_trace
        ), mock.patch.object(RUNNER, "parse_rust_test_count", return_value=1):
            report = RUNNER.rust_layout_probe(
                c_layout,
                c_small_trace,
                c_fundamental_trace,
            )
        self.assertEqual(
            command_record.call_args.args[0],
            [
                "cargo",
                "test",
                "-p",
                "crabc-mimalloc",
                "--lib",
                "--locked",
                "--",
                "--nocapture",
            ],
        )
        self.assertEqual(
            command_record.call_args.kwargs["env"]["CARGO_TARGET_DIR"],
            str(RUNNER.RUST_LAYOUT_CARGO_TARGET),
        )
        self.assertEqual(report["comparison"], {"compared_value_count": 1, "status": "matched"})

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
        self.assertEqual(stale["classification"], "upstream-unavailable-declaration")
        self.assertIn("no definition", stale["classification_reason"])
        override = RUNNER.classify_api_item("mi_malloc_size", "external-function")
        self.assertEqual(override["classification"], "override-only")
        self.assertEqual(override["profile"], "linux-aarch64-override")
        wide = RUNNER.classify_api_item("mi_wdupenv_s", "external-function")
        self.assertEqual(wide["classification"], "linux-einval-operation")
        self.assertTrue(wide["test_adapter_applicable"])

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

    def test_native_x86_64_direct_engine_probe_selects_its_explicit_target(self) -> None:
        fundamental_trace = {
            key: 1 for key in RUNNER.FUNDAMENTAL_TRACE_X86_64_EXPECTED_KEYS
        }
        fundamental_output = "\n".join(
            f"{key}={value}" for key, value in sorted(fundamental_trace.items())
        )
        output = f"""
CRABC_MI_LAYOUT_BEGIN
config.MAX_VABITS=47
config.PAGE_MAP_SHIFT=18
CRABC_MI_LAYOUT_END
CRABC_MI_SMALL_TRACE_BEGIN
trace.boundary.count=1
CRABC_MI_SMALL_TRACE_END
CRABC_MI_FUNDAMENTAL_TRACE_BEGIN
{fundamental_output}
CRABC_MI_FUNDAMENTAL_TRACE_END
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
"""
        record = {"status": 0, "stdout": output, "stderr": ""}
        c_layout = {"config.MAX_VABITS": 47, "config.PAGE_MAP_SHIFT": 18}
        small_trace = {"trace.boundary.count": 1}
        with mock.patch.object(RUNNER, "command_record", return_value=record) as command_record:
            result = RUNNER.rust_layout_probe(
                c_layout,
                small_trace,
                fundamental_trace,
                rust_target=RUNNER.X86_64_RUST_TARGET,
            )
        self.assertEqual(
            command_record.call_args.args[0],
            [
                "cargo",
                "test",
                "-p",
                "crabc-mimalloc",
                "--lib",
                "--locked",
                "--no-default-features",
                "--target",
                "x86_64-unknown-linux-musl",
                "--",
                "--nocapture",
            ],
        )
        self.assertEqual(result["target"], RUNNER.X86_64_RUST_TARGET)
        self.assertEqual(result["comparison"], {"compared_value_count": 2, "status": "matched"})
        self.assertEqual(
            result["single_thread_small_trace"]["comparison"],
            {"compared_value_count": 1, "status": "matched"},
        )
        self.assertEqual(
            result["single_thread_fundamental_trace"]["comparison"],
            {"compared_value_count": 75, "status": "matched"},
        )

    def test_direct_engine_probe_rejects_a_target_without_a_trace_schema(self) -> None:
        with self.assertRaisesRegex(
            RUNNER.HarnessError,
            "direct Rust fundamental trace has no schema for target: riscv64gc-unknown-linux-musl",
        ):
            RUNNER.rust_layout_probe(
                {"config.value": 1},
                {"small.value": 1},
                {key: 1 for key in RUNNER.FUNDAMENTAL_TRACE_AARCH64_EXPECTED_KEYS},
                rust_target="riscv64gc-unknown-linux-musl",
            )

    def test_native_x86_64_adapter_contract_is_target_local_and_source_bound(self) -> None:
        source_contract = RUNNER.read_json(RUNNER.ADAPTED_TEST_CONTRACT)
        x86_contract = RUNNER.read_json(RUNNER.X86_64_TEST_ADAPTER_CONTRACT)
        summary = RUNNER.validate_x86_64_test_adapter_contract(
            x86_contract,
            source_contract,
            RUNNER.load_pin(),
            RUNNER.TEST_ADAPTER_HEADER.read_text(encoding="utf-8"),
        )
        self.assertEqual(
            summary,
            {
                "expected_adapter_symbol_count": 16,
                "profile": "linux-x86_64-private-test-adapter",
                "selected_test_count": 33,
                "target": "x86_64-unknown-linux-musl",
            },
        )
        compile_requirements = x86_contract["compile_requirements"]
        self.assertEqual(compile_requirements["native_library_search_paths"], [])
        self.assertEqual(compile_requirements["native_static_libs"], ["-lunwind", "-lc"])
        self.assertFalse(compile_requirements["rust_cdylib_supported"])
        self.assertEqual(
            compile_requirements["rust_target_self_contained_native_library"], "libunwind.a"
        )
        self.assertEqual(compile_requirements["expected_executable_dynamic_dependencies"], [])

    def test_x86_64_adapter_resolves_rusts_target_self_contained_unwinder(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = Path(temporary) / "rust"
            search_path = (
                sysroot
                / "lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained"
            )
            search_path.mkdir(parents=True)
            (search_path / "libunwind.a").touch()
            requirements = {
                "native_library_search_paths": [],
                "rust_target_self_contained_native_library": "libunwind.a",
            }
            with mock.patch.object(RUNNER, "require_tool", return_value="rustc"), mock.patch.object(
                RUNNER,
                "command_record",
                return_value={"status": 0, "stdout": f"{sysroot}\n", "stderr": ""},
            ):
                self.assertEqual(
                    RUNNER.native_static_library_search_paths(
                        requirements, rust_target="x86_64-unknown-linux-musl"
                    ),
                    [str(search_path)],
                )

    def test_native_x86_64_adapter_contract_rejects_the_legacy_gcc_s_link_tail(self) -> None:
        source_contract = RUNNER.read_json(RUNNER.ADAPTED_TEST_CONTRACT)
        x86_contract = RUNNER.read_json(RUNNER.X86_64_TEST_ADAPTER_CONTRACT)
        x86_contract["compile_requirements"]["native_static_libs"] = ["-lgcc_s", "-lc"]
        with self.assertRaisesRegex(RUNNER.HarnessError, "compile requirements"):
            RUNNER.validate_x86_64_test_adapter_contract(
                x86_contract,
                source_contract,
                RUNNER.load_pin(),
                RUNNER.TEST_ADAPTER_HEADER.read_text(encoding="utf-8"),
            )

    def test_native_x86_64_adapter_contract_rejects_source_selection_drift(self) -> None:
        source_contract = RUNNER.read_json(RUNNER.ADAPTED_TEST_CONTRACT)
        x86_contract = RUNNER.read_json(RUNNER.X86_64_TEST_ADAPTER_CONTRACT)
        x86_contract["source_selection"]["base_source_selection_sha256"] = "0" * 64
        with self.assertRaisesRegex(RUNNER.HarnessError, "source-selection digest"):
            RUNNER.validate_x86_64_test_adapter_contract(
                x86_contract,
                source_contract,
                RUNNER.load_pin(),
                RUNNER.TEST_ADAPTER_HEADER.read_text(encoding="utf-8"),
            )

    def test_x86_64_adapter_source_selection_does_not_inherit_aarch64_link_requirements(self) -> None:
        source_contract = RUNNER.read_json(RUNNER.ADAPTED_TEST_CONTRACT)
        x86_contract = RUNNER.read_json(RUNNER.X86_64_TEST_ADAPTER_CONTRACT)
        source_contract["compile_requirements"]["expected_dynamic_dependencies"] = [
            "libc.musl-x86_64.so.1",
            "libgcc_s.so.1",
        ]
        with self.assertRaisesRegex(RUNNER.HarnessError, "compile requirement changed"):
            RUNNER.validate_adapted_test_contract(
                source_contract,
                RUNNER.load_pin(),
                RUNNER.TEST_ADAPTER_HEADER.read_text(encoding="utf-8"),
            )
        self.assertEqual(
            RUNNER.adapted_test_source_selection_digest(source_contract),
            x86_contract["source_selection"]["base_source_selection_sha256"],
        )
        header_verification_drift = RUNNER.read_json(RUNNER.ADAPTED_TEST_CONTRACT)
        header_verification_drift["verification"]["header_compile_verified"] = False
        with self.assertRaisesRegex(RUNNER.HarnessError, "header_compile_verified"):
            RUNNER.validate_adapted_test_contract(
                header_verification_drift,
                RUNNER.load_pin(),
                RUNNER.TEST_ADAPTER_HEADER.read_text(encoding="utf-8"),
            )
        self.assertEqual(
            RUNNER.adapted_test_source_selection_digest(header_verification_drift),
            x86_contract["source_selection"]["base_source_selection_sha256"],
        )
        selected_check_drift = RUNNER.read_json(RUNNER.ADAPTED_TEST_CONTRACT)
        selected_check_drift["selected_tests"][0]["name"] = "selection-drift"
        self.assertNotEqual(
            RUNNER.adapted_test_source_selection_digest(selected_check_drift),
            x86_contract["source_selection"]["base_source_selection_sha256"],
        )
        self.assertEqual(
            RUNNER.validate_x86_64_test_adapter_contract(
                x86_contract,
                source_contract,
                RUNNER.load_pin(),
                RUNNER.TEST_ADAPTER_HEADER.read_text(encoding="utf-8"),
            )["target"],
            RUNNER.X86_64_RUST_TARGET,
        )
        self.assertEqual(
            RUNNER.validate_x86_64_test_adapter_contract(
                x86_contract,
                header_verification_drift,
                RUNNER.load_pin(),
                RUNNER.TEST_ADAPTER_HEADER.read_text(encoding="utf-8"),
            )["target"],
            RUNNER.X86_64_RUST_TARGET,
        )

    def test_native_x86_64_adapter_elf_identity_requires_the_native_machine(self) -> None:
        header = """
  Class:                             ELF64
  Data:                              2's complement, little endian
  Machine:                           Advanced Micro Devices X86-64
"""
        self.assertEqual(
            RUNNER.parse_elf_identity(header, "x86_64"),
            {
                "class": "ELF64",
                "endianness": "little",
                "machine": "Advanced Micro Devices X86-64",
            },
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "not little-endian x86_64"):
            RUNNER.parse_elf_identity(
                header.replace("Advanced Micro Devices X86-64", "AArch64"),
                "x86_64",
            )

    def test_native_x86_64_fixture_audit_requires_elf_interp_and_dependencies(self) -> None:
        header = """
  Class:                             ELF64
  Data:                              2's complement, little endian
  Machine:                           Advanced Micro Devices X86-64
"""
        dynamic = ""

        def records(interpreter: str) -> list[dict[str, object]]:
            return [
                {"status": 0, "stdout": header, "stderr": ""},
                {
                    "status": 0,
                    "stdout": f"[Requesting program interpreter: {interpreter}]\n",
                    "stderr": "",
                },
                {"status": 0, "stdout": dynamic, "stderr": ""},
            ]

        expected_elf = {
            "class": "ELF64",
            "endianness": "little",
            "machine": "Advanced Micro Devices X86-64",
        }
        with mock.patch.object(
            RUNNER,
            "command_record",
            side_effect=records("/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1"),
        ) as command_record:
            evidence = RUNNER.audit_native_executable(
                "readelf",
                Path("fixture"),
                architecture="x86_64",
                expected_elf=expected_elf,
                expected_interpreter="ld-musl-x86_64.so.1",
                expected_dynamic_dependencies=[],
            )
        self.assertEqual(
            evidence,
            {
                "dynamic_dependencies": [],
                "elf": expected_elf,
                "interpreter": "/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1",
            },
        )
        self.assertEqual(command_record.call_count, 3)
        with mock.patch.object(
            RUNNER,
            "command_record",
            side_effect=records("/lib64/ld-linux-x86-64.so.2"),
        ):
            with self.assertRaisesRegex(RUNNER.HarnessError, "PT_INTERP differs"):
                RUNNER.audit_native_executable(
                    "readelf",
                    Path("fixture"),
                    architecture="x86_64",
                    expected_elf=expected_elf,
                    expected_interpreter="ld-musl-x86_64.so.1",
                    expected_dynamic_dependencies=[],
                )

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

    def test_fundamental_trace_comparison_names_value_mismatch_after_schema_validation(self) -> None:
        c_trace = {key: 1 for key in RUNNER.FUNDAMENTAL_TRACE_X86_64_EXPECTED_KEYS}
        self.assertEqual(
            RUNNER.compare_fundamental_trace(c_trace, c_trace, architecture="x86_64"),
            {"compared_value_count": 75, "status": "matched"},
        )
        mismatched = dict(c_trace)
        mismatched["trace.fundamental.class.small.success"] = 0
        with self.assertRaisesRegex(
            RUNNER.HarnessError,
            r"value mismatches: trace\.fundamental\.class\.small\.success \(C=1, Rust=0\)",
        ):
            RUNNER.compare_fundamental_trace(c_trace, mismatched, architecture="x86_64")

    def test_fundamental_trace_comparison_rejects_a_synchronized_schema_regression(self) -> None:
        # Comparing only the two observed maps would let a matching deletion
        # silently reduce the pinned trace contract. The durable record has a
        # fixed 75-key schema, including the nonzero null-pointer expand case
        # and checked counted zeroed reallocation outcomes.
        self.assertEqual(RUNNER.FUNDAMENTAL_TRACE_X86_64_EXPECTED_COUNT, 75)
        self.assertEqual(len(RUNNER.FUNDAMENTAL_TRACE_X86_64_EXPECTED_KEYS), 75)
        self.assertIn(
            "trace.fundamental.expand.null_nonzero_returns_null",
            RUNNER.FUNDAMENTAL_TRACE_X86_64_EXPECTED_KEYS,
        )
        self.assertIn(
            "trace.fundamental.recalloc_overflow.preserved",
            RUNNER.FUNDAMENTAL_TRACE_X86_64_EXPECTED_KEYS,
        )
        self.assertIn("mi_recalloc", RUNNER.FUNDAMENTAL_TRACE_PROBE)
        self.assertIn("mi_expand(NULL, expand_request)", RUNNER.FUNDAMENTAL_TRACE_PROBE)
        self.assertIn("#if defined(__x86_64__)", RUNNER.FUNDAMENTAL_TRACE_PROBE)
        synchronized_but_incomplete = {
            "trace.fundamental.class.small.request": 10240,
            "trace.fundamental.class.small.success": 1,
            "trace.fundamental.class.small.usable": 10240,
        }
        with self.assertRaisesRegex(
            RUNNER.HarnessError,
            r"fixed 75-key schema.*trace\.fundamental\.expand\.null_nonzero_returns_null",
        ):
            RUNNER.compare_fundamental_trace(
                synchronized_but_incomplete,
                synchronized_but_incomplete,
                architecture="x86_64",
            )

    def test_fundamental_trace_schema_keeps_aarch64_baseline_separate_from_x86_extension(self) -> None:
        self.assertEqual(RUNNER.FUNDAMENTAL_TRACE_AARCH64_EXPECTED_COUNT, 51)
        self.assertEqual(len(RUNNER.FUNDAMENTAL_TRACE_AARCH64_EXPECTED_KEYS), 51)
        self.assertEqual(RUNNER.FUNDAMENTAL_TRACE_EXPECTED_COUNT, 51)
        self.assertNotIn(
            "trace.fundamental.expand.usable",
            RUNNER.FUNDAMENTAL_TRACE_AARCH64_EXPECTED_KEYS,
        )
        self.assertNotIn(
            "trace.fundamental.recalloc.valid",
            RUNNER.FUNDAMENTAL_TRACE_AARCH64_EXPECTED_KEYS,
        )
        self.assertEqual(
            len(RUNNER.FUNDAMENTAL_TRACE_X86_64_EXTENSION_KEYS),
            24,
        )
        aarch_trace = {key: 1 for key in RUNNER.FUNDAMENTAL_TRACE_AARCH64_EXPECTED_KEYS}
        self.assertEqual(
            RUNNER.compare_fundamental_trace(aarch_trace, aarch_trace),
            {"compared_value_count": 51, "status": "matched"},
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "fixed 51-key schema"):
            RUNNER.compare_fundamental_trace(aarch_trace, aarch_trace | {
                "trace.fundamental.expand.usable": 1,
            })

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

    def test_m1_raw_trace_allows_only_its_declared_address_like_scalar(self) -> None:
        scalar = """
CRABC_MI_M1_RAW_TRACE_BEGIN
m1.raw.config.virtual_address_bits=48
CRABC_MI_M1_RAW_TRACE_END
"""
        self.assertEqual(
            RUNNER.parse_m1_raw_primitive_trace(scalar),
            {"m1.raw.config.virtual_address_bits": 48},
        )
        address = """
CRABC_MI_M1_RAW_TRACE_BEGIN
m1.raw.map.address=12345
CRABC_MI_M1_RAW_TRACE_END
"""
        with self.assertRaisesRegex(RUNNER.HarnessError, "raw address field"):
            RUNNER.parse_m1_raw_primitive_trace(address)

    def test_m1_raw_trace_schema_requires_every_selected_source_fact(self) -> None:
        self.assertEqual(RUNNER.M1_RAW_PRIMITIVE_TRACE_EXPECTED_COUNT, 47)
        self.assertEqual(
            len(RUNNER.M1_RAW_PRIMITIVE_TRACE_EXPECTED_KEYS),
            RUNNER.M1_RAW_PRIMITIVE_TRACE_EXPECTED_COUNT,
        )
        trace = {key: 1 for key in RUNNER.M1_RAW_PRIMITIVE_TRACE_EXPECTED_KEYS}
        self.assertEqual(
            RUNNER.compare_m1_raw_primitive_trace(trace, trace),
            {"compared_value_count": 47, "status": "matched"},
        )
        trace.pop("m1.raw.threadpool.false")
        with self.assertRaisesRegex(
            RUNNER.HarnessError,
            r"fixed 47-key schema.*m1\.raw\.threadpool\.false",
        ):
            RUNNER.compare_m1_raw_primitive_trace(trace, trace)

    def test_m1_compiler_tls_trace_schema_requires_every_selected_source_fact(self) -> None:
        self.assertEqual(RUNNER.M1_COMPILER_TLS_TRACE_EXPECTED_COUNT, 32)
        self.assertEqual(
            len(RUNNER.M1_COMPILER_TLS_TRACE_EXPECTED_KEYS),
            RUNNER.M1_COMPILER_TLS_TRACE_EXPECTED_COUNT,
        )
        trace = {key: 1 for key in RUNNER.M1_COMPILER_TLS_TRACE_EXPECTED_KEYS}
        self.assertEqual(
            RUNNER.compare_m1_compiler_tls_trace(trace, trace),
            {"compared_value_count": 32, "status": "matched"},
        )
        trace.pop("m1.tls.cache.reset.dynamic_refcount")
        with self.assertRaisesRegex(
            RUNNER.HarnessError,
            r"fixed 32-key schema.*m1\.tls\.cache\.reset\.dynamic_refcount",
        ):
            RUNNER.compare_m1_compiler_tls_trace(trace, trace)

    def test_m1_compiler_tls_same_tld_trace_schema_is_fixed_and_source_shaped(self) -> None:
        expected = dict(RUNNER.M1_COMPILER_TLS_SAME_TLD_TRACE_EXPECTED_VALUES)
        self.assertEqual(RUNNER.M1_COMPILER_TLS_SAME_TLD_TRACE_EXPECTED_COUNT, 40)
        self.assertEqual(
            len(RUNNER.M1_COMPILER_TLS_SAME_TLD_TRACE_EXPECTED_KEYS),
            RUNNER.M1_COMPILER_TLS_SAME_TLD_TRACE_EXPECTED_COUNT,
        )
        RUNNER.validate_m1_compiler_tls_same_tld_trace(expected, source="test")
        self.assertEqual(
            RUNNER.compare_m1_compiler_tls_same_tld_trace(expected, expected),
            {"compared_value_count": 40, "status": "matched"},
        )
        output = "\n".join(
            (
                "CRABC_MI_M1_TLS_SAME_TLD_TRACE_BEGIN",
                *(f"{key}={value}" for key, value in expected.items()),
                "CRABC_MI_M1_TLS_SAME_TLD_TRACE_END",
            )
        )
        self.assertEqual(RUNNER.parse_m1_compiler_tls_same_tld_trace(output), expected)
        missing = dict(expected)
        missing.pop("m1.tls.same_tld.detach.aux_heap_list_empty")
        with self.assertRaisesRegex(
            RUNNER.HarnessError,
            r"fixed 40-key fixture schema.*m1\.tls\.same_tld\.detach\.aux_heap_list_empty",
        ):
            RUNNER.validate_m1_compiler_tls_same_tld_trace(missing, source="test")
        wrong_order = dict(expected)
        wrong_order["m1.tls.same_tld.final.dynamic_refcount"] = 2
        with self.assertRaisesRegex(
            RUNNER.HarnessError,
            r"value mismatches: m1\.tls\.same_tld\.final\.dynamic_refcount \(expected=1, observed=2\)",
        ):
            RUNNER.validate_m1_compiler_tls_same_tld_trace(wrong_order, source="test")

    def test_m1_compiler_tls_same_tld_trace_parser_rejects_raw_addresses(self) -> None:
        output = """
CRABC_MI_M1_TLS_SAME_TLD_TRACE_BEGIN
m1.tls.same_tld.entry.cached_address=12345
CRABC_MI_M1_TLS_SAME_TLD_TRACE_END
"""
        with self.assertRaisesRegex(RUNNER.HarnessError, "raw address field"):
            RUNNER.parse_m1_compiler_tls_same_tld_trace(output)

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

    def test_runtime_ticket_zero_adapter_symbol_contract_requires_exact_exports(self) -> None:
        expected = [
            "crabc_ticket_zero_test_free",
            "crabc_ticket_zero_test_init",
            "crabc_ticket_zero_test_malloc",
        ]
        self.assertEqual(
            RUNNER.validate_runtime_ticket_zero_adapter_symbols(
                ["_init", *expected, "rust_eh_personality"], expected
            ),
            {"exported_symbol_count": 3, "symbols": expected},
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "missing symbols"):
            RUNNER.validate_runtime_ticket_zero_adapter_symbols(expected[:-1], expected)
        with self.assertRaisesRegex(RUNNER.HarnessError, "unexpected symbols"):
            RUNNER.validate_runtime_ticket_zero_adapter_symbols(
                [*expected, "crabc_ticket_zero_test_unreviewed"], expected
            )
        with self.assertRaisesRegex(RUNNER.HarnessError, "forbidden allocator exports"):
            RUNNER.validate_runtime_ticket_zero_adapter_symbols(
                [*expected, "malloc", "mi_malloc"], expected
            )

    def test_runtime_ticket_zero_adapter_header_inventory_extracts_only_declarations(self) -> None:
        header = """
int crabc_ticket_zero_test_init(size_t page_size);
void *crabc_ticket_zero_test_malloc(size_t size);
#define hidden crabc_ticket_zero_test_malloc((size))
"""
        self.assertEqual(
            RUNNER.runtime_ticket_zero_adapter_header_function_names(header),
            ["crabc_ticket_zero_test_init", "crabc_ticket_zero_test_malloc"],
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

    def test_optional_native_static_library_parser_accepts_a_no_std_empty_tail(self) -> None:
        self.assertEqual(
            RUNNER.parse_optional_native_static_libraries("native-static-libs: \n"),
            [],
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "invalid native static library"):
            RUNNER.parse_optional_native_static_libraries(
                "native-static-libs: /ambient/libbad.a\n"
            )
    def test_native_x86_64_static_library_parser_preserves_the_unwind_tail(self) -> None:
        output = "note: native-static-libs: -lunwind -lc\n"
        self.assertEqual(RUNNER.parse_native_static_libraries(output), ["-lunwind", "-lc"])

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
    def test_loom_model_is_explicitly_feature_targeted_and_clears_production_rustflags(self) -> None:
        record = {
            "status": 0,
            "stderr": "",
            "stdout": "test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 579 filtered out; finished in 0.01s\n",
        }
        with mock.patch.object(RUNNER, "command_record", return_value=record) as command_record:
            report = RUNNER.loom_remote_free_model()

        self.assertEqual(
            command_record.call_args.args[0],
            [
                "cargo",
                "test",
                "-p",
                "crabc-mimalloc",
                "--lib",
                "--features",
                "loom",
                "--locked",
                "remote_free::loom_tests",
                "--",
                "--test-threads=1",
            ],
        )
        self.assertEqual(command_record.call_args.kwargs["env"]["CARGO_ENCODED_RUSTFLAGS"], "")
        self.assertEqual(
            command_record.call_args.kwargs["env"]["CARGO_TARGET_DIR"],
            str(RUNNER.LOOM_CARGO_TARGET),
        )
        self.assertEqual(report["cargo_encoded_rustflags"], [])

    def test_loom_dependency_and_model_sources_remain_feature_target_gated(self) -> None:
        manifest_path = RUNNER.ROOT / "crabc-mimalloc/Cargo.toml"
        with manifest_path.open("rb") as stream:
            manifest = tomllib.load(stream)

        dependencies = manifest["dependencies"]
        self.assertEqual(
            set(dependencies),
            {"chacha20", "crabc-core", "loom", "zeroize"},
        )
        self.assertEqual(
            dependencies["loom"],
            {
                "version": "=0.7.2",
                "default-features": False,
                "optional": True,
            },
        )
        self.assertFalse(manifest.get("dev-dependencies", {}))
        self.assertEqual(manifest["features"]["loom"], ["dep:loom"])

        remote_free = (RUNNER.ROOT / "crabc-mimalloc/src/remote_free.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "#[cfg(all(test, feature = \"loom\"))]\n"
            "#[path = \"remote_free_loom.rs\"]\n"
            "mod loom_tests;",
            remote_free,
        )
        self.assertIn(
            "#[cfg(all(test, feature = \"loom\"))]\n"
            "#[path = \"remote_free_owner_unown_loom.rs\"]\n"
            "mod owner_unown_loom_tests;",
            remote_free,
        )

    def test_pin_is_complete_and_names_the_exact_archive(self) -> None:
        pin = RUNNER.load_pin()
        self.assertEqual(pin["version"], "3.5.0")
        self.assertEqual(pin["repository"], "https://github.com/microsoft/mimalloc.git")
        self.assertEqual(pin["tag"], "v3.5.0")
        self.assertEqual(pin["archive_root"], "mimalloc-3.5.0")
        self.assertEqual(pin["revision"], "18b08671c9302247bfb682286e6bf3cc1773f801")
        self.assertEqual(pin["tag_object"], "438b0c4b78d2599aede7fca3ddacc28863b0eae8")

    def test_owner_exit_publication_contract_keeps_source_order_and_rejects_raw_reconstruction(self) -> None:
        contract = RUNNER.read_json(RUNNER.OWNER_EXIT_PUBLICATION_CONTRACT)
        pin = RUNNER.load_pin()
        source_text = {
            "src/init.c": """
                void mi_thread_theaps_done(void) {
                    mi_lock(&tld->theaps_lock) { }
                    _mi_theap_collect_abandon(theap);
                    mi_assert_internal(theap->page_count==0);
                }
            """,
            "src/theap.c": """
                void mi_theap_page_collect(void) {
                    _mi_page_free_collect(page, collect >= MI_FORCE);
                    if (mi_page_all_free(page)) { }
                    else if (collect == MI_ABANDON) { }
                    _mi_page_abandon(page, pq);
                }
            """,
            "src/page.c": """
                void _mi_page_abandon(void) {
                    _mi_page_free_collect(page, false);
                    if (mi_page_all_free(page)) { }
                    _mi_page_free(page, pq);
                    mi_page_queue_remove(pq, page);
                    mi_page_set_theap(page, NULL);
                    _mi_arenas_page_abandon(page, theap);
                }
            """,
            "include/mimalloc/internal.h": """
                void mi_page_set_theap(void) {
                    page->theap = theap;
                    theap == NULL ? MI_THREADID_ABANDONED : theap->tld->thread_id;
                    mi_atomic_cas_weak_release(&page->xthread_id, &xtid_old, xtid);
                }
            """,
            "src/arena.c": """
                void _mi_arenas_page_abandon(void) {
                    if (page->memid.memkind==MI_MEM_ARENA && !mi_page_is_full(page)) { }
                    mi_page_set_abandoned_mapped(page);
                    mi_bitmap_set(arena_pages->pages_abandoned[bin], slice_index);
                    mi_atomic_increment_relaxed(&heap->abandoned_count[bin]);
                    mi_abandoned_page_unown(page, current_theapx);
                    if (page->memid.memkind != MI_MEM_ARENA) { }
                    mi_lock(&heap->os_abandoned_pages_lock) { }
                    heap->os_abandoned_pages = page;
                    mi_theapx_stat_increase(heap, current_theapx, pages_abandoned, 1);
                    mi_abandoned_page_unown(page, current_theapx);
                }
            """,
            "src/free.c": """
                void mi_abandoned_page_try_free(void) {
                    if (!mi_page_all_free(page)) return false;
                    _mi_arenas_page_unabandon(page,NULL);
                    _mi_arenas_page_free(page,NULL);
                }
            """,
        }

        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            for path, text in source_text.items():
                target = source / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8")

            self.assertEqual(
                RUNNER.validate_owner_exit_publication_contract(contract, pin, source),
                {
                    "forbidden_reconstruction_input_count": 4,
                    "publication_route_count": 2,
                    "source_fact_count": 8,
                },
            )

            stale_claim = json.loads(json.dumps(contract))
            stale_claim["stale_w07_claim"]["claim_reconstruction"] = "allowed"
            with self.assertRaisesRegex(RUNNER.HarnessError, "stale W07 claim"):
                RUNNER.validate_owner_exit_publication_contract(stale_claim, pin, source)

            stale_empty_release = json.loads(json.dumps(contract))
            stale_empty_release["transition"]["empty_terminal_release"][
                "forbidden_transition_events"
            ] = []
            with self.assertRaisesRegex(RUNNER.HarnessError, "empty terminal release"):
                RUNNER.validate_owner_exit_publication_contract(
                    stale_empty_release,
                    pin,
                    source,
                )

            reordered = source / "src/page.c"
            reordered.write_text(
                source_text["src/page.c"].replace(
                    "mi_page_queue_remove(pq, page);\n                    mi_page_set_theap(page, NULL);",
                    "mi_page_set_theap(page, NULL);\n                    mi_page_queue_remove(pq, page);",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RUNNER.HarnessError, "queue-detach-before-abandoned-identity"):
                RUNNER.validate_owner_exit_publication_contract(contract, pin, source)

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

    def test_upstream_test_inventory_records_the_reviewed_adapter_selections(self) -> None:
        inventory = RUNNER.read_json(RUNNER.UPSTREAM_TEST_CONTRACT)
        states = {item["path"]: item["status"] for item in inventory["tests"]}

        self.assertEqual(inventory["format"], 3)
        self.assertEqual(states["test/test-api.c"], "adapted-milestone-4")
        self.assertEqual(states["test/testhelper.h"], "adapted-milestone-4")
        self.assertEqual(states["test/test-stress.c"], "adapted-milestone-5")
        self.assertEqual(states["test/main.c"], "blocked-milestone-5-plus")
        self.assertEqual(inventory["summary"]["adapted_milestone_4_file_count"], 2)
        self.assertEqual(inventory["summary"]["adapted_milestone_5_file_count"], 1)
        self.assertEqual(inventory["summary"]["blocked_milestone_5_plus_count"], 13)

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

    def test_adapted_stress_fixture_contract_is_exact_and_reviewed(self) -> None:
        contract = RUNNER.read_json(RUNNER.ADAPTED_STRESS_TEST_CONTRACT)
        header = RUNNER.TEST_ADAPTER_HEADER.read_text(encoding="utf-8")
        self.assertEqual(
            RUNNER.validate_adapted_stress_test_contract(
                contract, RUNNER.load_pin(), header
            ),
            {
                "excluded_upstream_mode_count": 6,
                "expected_adapter_symbol_count": 16,
                "required_prefixed_adapter_symbol_count": 3,
            },
        )

    def test_native_shadow_stress_contract_is_exact_and_reviewed(self) -> None:
        contract = RUNNER.read_json(RUNNER.NATIVE_SHADOW_STRESS_CONTRACT)
        self.assertEqual(
            RUNNER.validate_native_shadow_stress_contract(contract, RUNNER.load_pin()),
            {
                "excluded_upstream_mode_count": 5,
                "process_epochs": 128,
                "source_worker_count": 4,
            },
        )

    def test_runtime_ticket_zero_adapter_contract_is_exact_and_reviewed(self) -> None:
        contract = RUNNER.read_json(RUNNER.RUNTIME_TICKET_ZERO_ADAPTER_CONTRACT)
        header = RUNNER.RUNTIME_TICKET_ZERO_ADAPTER_HEADER.read_text(encoding="utf-8")
        self.assertEqual(
            RUNNER.validate_runtime_ticket_zero_adapter_contract(contract, header),
            {"expected_adapter_symbol_count": 9},
        )
        contract["lifecycle_audit"]["fixture_success_line"] = "stale success line"
        with self.assertRaisesRegex(RUNNER.HarnessError, "lifecycle audit contract"):
            RUNNER.validate_runtime_ticket_zero_adapter_contract(contract, header)

        contract = RUNNER.read_json(RUNNER.RUNTIME_TICKET_ZERO_ADAPTER_CONTRACT)
        contract["soak_report"]["evidence_scope"] = "stale scope"
        with self.assertRaisesRegex(RUNNER.HarnessError, "soak report contract"):
            RUNNER.validate_runtime_ticket_zero_adapter_contract(contract, header)

    def test_runtime_ticket_zero_lifecycle_audit_record_is_exact(self) -> None:
        stdout = (
            "runtime ticket-zero lifecycle audit worker_cycles=3 process_active=1 "
            "page_owner_ready=1 page_map_registered_entries=0 "
            "page_map_published_submaps=2 page_map_lazy_submap_allocations=1 "
            "arena_registry_entries=1 live_tlds=1 metadata_live_capabilities=0 "
            "metadata_high_water_capabilities=3 shared_later_theaps=0 "
            "abandoned_regular_pages=0 os_abandoned_pages_empty=1\n"
            "runtime ticket-zero allocator ok\n"
        )
        self.assertEqual(
            RUNNER.parse_runtime_ticket_zero_lifecycle_audit(stdout),
            {
                "worker_cycles": 3,
                "process_active": 1,
                "page_owner_ready": 1,
                "page_map_registered_entries": 0,
                "page_map_published_submaps": 2,
                "page_map_lazy_submap_allocations": 1,
                "arena_registry_entries": 1,
                "live_tlds": 1,
                "metadata_live_capabilities": 0,
                "metadata_high_water_capabilities": 3,
                "shared_later_theaps": 0,
                "abandoned_regular_pages": 0,
                "os_abandoned_pages_empty": 1,
            },
        )
        with self.assertRaisesRegex(RUNNER.HarnessError, "fields differ"):
            RUNNER.parse_runtime_ticket_zero_lifecycle_audit(
                stdout.replace("live_tlds=1 ", "unexpected=1 ")
            )

    def test_runtime_ticket_zero_lifecycle_commands_are_bounded_and_watchdog_ready(self) -> None:
        fixture = Path("/tmp/runtime-ticket-zero-fixture")
        self.assertEqual(
            RUNNER.runtime_ticket_zero_stress_schedule(
                worker_cycles=128,
                stress_seed=RUNNER.RUNTIME_TICKET_ZERO_CHURN_STRESS_SEED,
            ),
            {
                "seed": "0xd1b54a32d192ed03",
                "worker_route_invocation_count": 256,
                "worker_routes_per_cycle": 2,
            },
        )
        self.assertEqual(
            RUNNER.runtime_ticket_zero_fixture_command(fixture, worker_cycles=128),
            [
                str(fixture),
                "--worker-cycles",
                "128",
                "--stress-seed",
                "0x9e3779b97f4a7c15",
            ],
        )
        self.assertEqual(
            RUNNER.runtime_ticket_zero_fixture_command(
                fixture,
                worker_cycles=1024,
                stress_seed=RUNNER.RUNTIME_TICKET_ZERO_SOAK_STRESS_SEED,
            ),
            [
                str(fixture),
                "--worker-cycles",
                "1024",
                "--stress-seed",
                "0x94d049bb133111eb",
            ],
        )
        self.assertEqual(RUNNER.RUNTIME_TICKET_ZERO_CHURN_WORKER_CYCLES, 128)
        self.assertEqual(RUNNER.RUNTIME_TICKET_ZERO_CHURN_WATCHDOG_SECONDS, 30)
        self.assertEqual(
            RUNNER.RUNTIME_TICKET_ZERO_CHURN_STRESS_SEED,
            0xD1B54A32D192ED03,
        )
        self.assertEqual(RUNNER.RUNTIME_TICKET_ZERO_SOAK_WORKER_CYCLES, 1024)
        self.assertEqual(RUNNER.RUNTIME_TICKET_ZERO_SOAK_WATCHDOG_SECONDS, 180)
        with self.assertRaisesRegex(RUNNER.HarnessError, "worker cycles"):
            RUNNER.runtime_ticket_zero_fixture_command(fixture, worker_cycles=0)
        with self.assertRaisesRegex(RUNNER.HarnessError, "worker cycles"):
            RUNNER.runtime_ticket_zero_fixture_command(fixture, worker_cycles=1025)
        with self.assertRaisesRegex(RUNNER.HarnessError, "stress seed"):
            RUNNER.runtime_ticket_zero_fixture_command(fixture, worker_cycles=1, stress_seed=-1)
        with self.assertRaisesRegex(RUNNER.HarnessError, "stress seed"):
            RUNNER.runtime_ticket_zero_fixture_command(
                fixture,
                worker_cycles=1,
                stress_seed=1 << 64,
            )

    def test_m2_memory_substrate_contract_has_fixed_partial_eight_component_boundary(self) -> None:
        contract = RUNNER.read_json(RUNNER.M2_MEMORY_SUBSTRATE_CONTRACT)
        summary = RUNNER.validate_m2_memory_substrate_contract(contract, RUNNER.load_pin())

        self.assertEqual(
            [component["id"] for component in summary["components"]],
            list(RUNNER.M2_MEMORY_SUBSTRATE_COMPONENT_IDS),
        )
        self.assertEqual(summary["milestone"]["status"], "partial")
        self.assertEqual(
            [component["id"] for component in summary["components"] if component["checks"]],
            ["page-map"],
        )
        page_map = next(component for component in summary["components"] if component["id"] == "page-map")
        self.assertEqual(
            page_map["checks"][0]["kind"],
            "c-rust-page-map-success-differential",
        )
        self.assertEqual(page_map["checks"][0]["target"], "page_map::tests::emit_m2_page_map_init_c_rust_trace")
        self.assertEqual(
            page_map["checks"][1]["kind"],
            "c-rust-page-map-cold-init-differential",
        )
        self.assertEqual(
            page_map["checks"][1]["target"],
            "process_page_map::tests::emit_m2_page_map_cold_init_failure_rust_trace",
        )
        self.assertEqual(
            page_map["remaining_conditions"],
            [
                "cover lazy PageMap extension and destruction release failure-injection branches with "
                "ownership-preserving evidence",
                "resolve PageMap initialization cleanup when an initial commit failure is "
                "followed by failed unmap, retaining the exact mapping instead of dropping it",
                "resolve the directly witnessed C static-empty-root versus Rust "
                "poisoned cold-root safety divergence when a complete "
                "process-lifecycle owner can supply source-equivalent cold lookup "
                "or explicitly close the semantic gap",
            ],
        )
        self.assertTrue(summary["exclusions"])
        self.assertTrue(
            any(
                "cold-init differential records" in nonclaim
                for nonclaim in summary["milestone"]["nonclaims"]
            )
        )

    @staticmethod
    def _m2_page_map_trace(*, rust: bool) -> dict[str, int]:
        trace = {key: 1 for key in RUNNER.M2_PAGE_MAP_TRACE_KEYS}
        trace.update(
            {
                "m2.page_map.control.page_size": 4096,
                "m2.page_map.control.max_vabits": 48,
                "m2.page_map.layout.header_bytes": 56 if rust else 88,
                "m2.page_map.layout.lock_bytes": 4 if rust else 40,
                "m2.page_map.init.reserve_count": 524288,
                "m2.page_map.init.reserved_count": 524794 if rust else 524790,
                "m2.page_map.init.committed_count": 16890 if rust else 16886,
                "m2.page_map.extend.map_index": 16891 if rust else 16887,
                "m2.page_map.extend.start_sub_index": 8191,
                "m2.page_map.extend.slice_count": 2,
                "m2.page_map.extend.committed_before": 16890 if rust else 16886,
                "m2.page_map.extend.committed_after": 24570 if rust else 24566,
                "m2.page_map.destroy.root_unpublished_before": 1 if rust else 0,
            }
        )
        return trace

    def test_m2_page_map_trace_schema_accepts_the_controlled_selected_record(self) -> None:
        c_trace = self._m2_page_map_trace(rust=False)
        output = "CRABC_MI_M2_PAGE_MAP_TRACE_BEGIN\n"
        output += "\n".join(f"{key}={value}" for key, value in c_trace.items())
        output += "\nCRABC_MI_M2_PAGE_MAP_TRACE_END\n"
        parsed_c = RUNNER.parse_m2_page_map_trace(output, source="pinned C")
        RUNNER.validate_m2_page_map_trace(parsed_c, source="pinned C")
        rust_trace = self._m2_page_map_trace(rust=True)
        RUNNER.validate_m2_page_map_trace(rust_trace, source="Rust")
        comparison = RUNNER.compare_m2_page_map_trace(parsed_c, rust_trace)
        self.assertEqual(comparison["status"], "matched")
        self.assertEqual(
            comparison["compared_value_count"],
            len(RUNNER.M2_PAGE_MAP_TRACE_KEYS)
            - len(RUNNER.M2_PAGE_MAP_HEADER_DEPENDENT_KEYS)
            - 1,
        )
        self.assertEqual(comparison["root_ownership_difference"]["pinned_c"], 0)
        self.assertEqual(comparison["root_ownership_difference"]["rust"], 1)

    def test_m2_page_map_trace_comparison_rejects_an_unmet_selected_relation(self) -> None:
        c_trace = self._m2_page_map_trace(rust=False)
        rust_trace = self._m2_page_map_trace(rust=True)
        rust_trace["m2.page_map.register.first_lookup_matches"] = 0
        with self.assertRaisesRegex(RUNNER.HarnessError, "unmet relation"):
            RUNNER.compare_m2_page_map_trace(c_trace, rust_trace)

    @staticmethod
    def _m2_page_map_cold_init_trace(*, rust: bool) -> dict[str, int]:
        trace = {key: 0 for key in RUNNER.M2_PAGE_MAP_COLD_INIT_TRACE_KEYS}
        trace.update(
            {
                "m2.page_map.cold.first_init_failed": 1,
                "m2.page_map.cold.dynamic_root_unpublished": 1,
                "m2.page_map.cold.init_body_attempt_count": 1,
                "m2.page_map.cold.static_empty_root": 0 if rust else 1,
                "m2.page_map.cold.absent_root": 1 if rust else 0,
                "m2.page_map.cold.second_call_returns_success": 0 if rust else 1,
                "m2.page_map.cold.second_call_returns_poisoned": 1 if rust else 0,
                "m2.page_map.cold.null_lookup_returns_null": 0 if rust else 1,
                "m2.page_map.cold.cold_lookup_route_unavailable": 1 if rust else 0,
            }
        )
        return trace

    def test_m2_page_map_cold_init_trace_models_the_explicit_safety_divergence(self) -> None:
        c_trace = self._m2_page_map_cold_init_trace(rust=False)
        rust_trace = self._m2_page_map_cold_init_trace(rust=True)

        output = "CRABC_MI_M2_PAGE_MAP_COLD_INIT_TRACE_BEGIN\n"
        output += "\n".join(f"{key}={value}" for key, value in c_trace.items())
        output += "\nCRABC_MI_M2_PAGE_MAP_COLD_INIT_TRACE_END\n"
        parsed_c = RUNNER.parse_m2_page_map_cold_init_trace(output, source="pinned C")
        RUNNER.validate_m2_page_map_cold_init_trace(parsed_c, source="pinned C")
        RUNNER.validate_m2_page_map_cold_init_trace(rust_trace, source="Rust")
        comparison = RUNNER.compare_m2_page_map_cold_init_trace(parsed_c, rust_trace)

        self.assertEqual(comparison["status"], "modeled-safety-divergence")
        self.assertEqual(comparison["matched_value_count"], 3)
        self.assertEqual(comparison["safety_divergence"]["pinned_c"]["static_empty_root"], 1)
        self.assertEqual(comparison["safety_divergence"]["rust"]["absent_root"], 1)

    def test_m2_page_map_cold_init_trace_rejects_a_replayed_once_body(self) -> None:
        c_trace = self._m2_page_map_cold_init_trace(rust=False)
        rust_trace = self._m2_page_map_cold_init_trace(rust=True)
        rust_trace["m2.page_map.cold.init_body_attempt_count"] = 2
        with self.assertRaisesRegex(RUNNER.HarnessError, "replayed"):
            RUNNER.compare_m2_page_map_cold_init_trace(c_trace, rust_trace)

    def test_m2_parser_is_native_only_and_mutually_exclusive(self) -> None:
        with mock.patch.object(sys, "argv", ["run.py", "--m2"]):
            arguments = RUNNER.parse_arguments()
        self.assertTrue(arguments.m2)
        self.assertEqual(arguments.architecture, "aarch64")
        with mock.patch.object(
            sys, "argv", ["run.py", "--m2", "--architecture", "x86_64"]
        ):
            with self.assertRaises(SystemExit):
                RUNNER.parse_arguments()

    def test_m2_unmet_message_keeps_partial_status_explicit(self) -> None:
        message = RUNNER.m2_memory_substrate_unmet_message(
            {"milestone": {"unmet_component_ids": ["vm-primitives", "page-map"]}}
        )
        self.assertIn("M2 memory substrate remains partial", message)
        self.assertIn("m2-memory-substrate-latest.json", message)

    def test_m2_main_writes_report_then_returns_intentional_unmet_status(self) -> None:
        report = {
            "milestone": {
                "status": "partial",
                "unmet_component_ids": ["vm-primitives", "page-map"],
            }
        }
        with mock.patch.object(sys, "argv", ["run.py", "--m2"]), mock.patch.object(
            RUNNER, "run_m2_memory_substrate", return_value=report
        ):
            self.assertEqual(RUNNER.main(), 3)

    def test_m5_gate_contract_names_the_current_full_lane_and_open_gates(self) -> None:
        contract = RUNNER.read_json(RUNNER.M5_GATE_CONTRACT)
        summary = RUNNER.validate_m5_gate_contract(contract, RUNNER.load_pin())

        self.assertEqual(summary["gate_count"], 6)
        self.assertEqual(
            summary["full_lane"],
            {
                "routes_per_cycle": 2,
                "stress_seed": "0xd1b54a32d192ed03",
                "watchdog_seconds": 30,
                "worker_cycles": 128,
            },
        )
        self.assertEqual(
            summary["gate_ids"],
            ["m5.base", "m5.5a", "m5.5b", "m5.5c", "m5.5d", "m5.5e"],
        )
        m5_5d = next(gate for gate in contract["gates"] if gate["id"] == "m5.5d")
        self.assertEqual(m5_5d["evidence"], list(RUNNER.M5_5D_EVIDENCE))
        self.assertEqual(m5_5d["required"], True)
        self.assertEqual(len(m5_5d["blocked_by"]), 1)
        blocker = m5_5d["blocked_by"][0]
        self.assertIn("12-row shadow subset", blocker)
        self.assertIn("large_object_mode: source-cli-enabled", blocker)
        self.assertIn(
            "not proof that every probabilistic large allocation succeeded", blocker
        )
        self.assertIn("broader claimed M5 lifecycle surface", blocker)
        self.assertNotIn("large_object_mode: not-claimed", blocker)

    def test_m1_foundations_contract_keeps_a_finite_component_inventory(self) -> None:
        contract = RUNNER.read_json(RUNNER.M1_FOUNDATIONS_CONTRACT)
        summary = RUNNER.validate_m1_foundations_contract(
            contract,
            RUNNER.load_pin(),
            RUNNER.load_port_map(),
        )

        self.assertEqual(
            [component["id"] for component in summary["components"]],
            list(RUNNER.M1_FOUNDATIONS_COMPONENT_IDS),
        )
        self.assertEqual(summary["milestone"]["status"], "complete")
        self.assertEqual(summary["execution"], {
            "features": [],
            "package": "crabc-mimalloc",
            "test_threads": 1,
            "timeout_seconds": 300,
        })
        configuration_and_arithmetic = next(
            component
            for component in summary["components"]
            if component["id"] == "configuration-and-arithmetic"
        )
        self.assertEqual(configuration_and_arithmetic["completion_status"], "complete")
        self.assertEqual(configuration_and_arithmetic["remaining_conditions"], [])
        self.assertEqual(
            configuration_and_arithmetic["layout_keys"],
            list(RUNNER.M1_CONFIGURATION_AND_ARITHMETIC_LAYOUT_KEYS),
        )
        self.assertIn(
            "generic-alignment",
            [check["id"] for check in configuration_and_arithmetic["checks"]],
        )
        self.assertIn(
            "pointer-alignment-zero",
            [check["id"] for check in configuration_and_arithmetic["checks"]],
        )
        self.assertIn(
            {
                "kind": "item",
                "name": "alignment-division-and-slice-invariants",
                "required_statuses": [
                    "implemented",
                    "unit_verified",
                    "differential_verified",
                ],
                "upstream": "include/mimalloc/internal.h",
            },
            configuration_and_arithmetic["source_map_records"],
        )

        self.assertIn(
            {
                "kind": "item",
                "name": "pointer-alignment-predicate",
                "required_statuses": [
                    "implemented",
                    "unit_verified",
                    "differential_verified",
                ],
                "upstream": "include/mimalloc/internal.h",
            },
            configuration_and_arithmetic["source_map_records"],
        )
        represented_layouts = next(
            component
            for component in summary["components"]
            if component["id"] == "provenance-and-represented-layouts"
        )
        self.assertEqual(represented_layouts["completion_status"], "complete")
        self.assertEqual(represented_layouts["remaining_conditions"], [])
        self.assertEqual(
            represented_layouts["layout_keys"], list(M1_REPRESENTED_LAYOUT_KEYS)
        )
        self.assertIn(
            {
                "kind": "item",
                "name": "_mi_memid_create_os-and-_mi_memid_size",
                "required_statuses": [
                    "implemented",
                    "unit_verified",
                    "differential_verified",
                ],
                "upstream": "include/mimalloc/internal.h",
            },
            represented_layouts["source_map_records"],
        )
        self.assertIn(
            {
                "kind": "item",
                "name": "_mi_memid_create_static-and-malloc",
                "required_statuses": [
                    "implemented",
                    "unit_verified",
                    "differential_verified",
                ],
                "upstream": "include/mimalloc/internal.h",
            },
            represented_layouts["source_map_records"],
        )
        self.assertTrue(
            M1_REPRESENTATION_EXCLUSION_IDS
            <= {exclusion["id"] for exclusion in summary["exclusions"]}
        )
        # The C probe must query the anonymous union member and selected page
        # member directly. A type-arm proxy or a synthetic zero offset for an
        # absent nondefault field would falsely broaden the release claim.
        self.assertIn(
            '__alignof__(((mi_memid_t*)0)->mem)',
            RUNNER.LAYOUT_PROBE,
        )
        self.assertNotIn(
            'U("offsetof.mi_page_t.self", 0);',
            RUNNER.LAYOUT_PROBE,
        )
        random_image = next(
            component
            for component in summary["components"]
            if component["id"] == "random-image"
        )
        self.assertEqual(random_image["completion_status"], "complete")
        self.assertEqual(random_image["remaining_conditions"], [])
        self.assertEqual(random_image["layout_keys"], list(M1_RANDOM_IMAGE_KEYS))
        self.assertIn(
            {
                "kind": "item",
                "name": "original-chacha-context-state-and-output-contract",
                "required_statuses": [
                    "implemented",
                    "unit_verified",
                    "differential_verified",
                ],
                "upstream": "src/random.c",
            },
            random_image["source_map_records"],
        )
        bootstrap = next(
            component
            for component in summary["components"]
            if component["id"] == "atomics-locks-once-and-bootstrap"
        )
        self.assertEqual(
            bootstrap["layout_keys"],
            list(RUNNER.M1_BOOTSTRAP_STATIC_IMAGE_LAYOUT_KEYS),
        )
        self.assertIn(
            "static-bootstrap-memid-image",
            [check["id"] for check in bootstrap["checks"]],
        )
        self.assertIn(
            "static-bootstrap-relational-image",
            [check["id"] for check in bootstrap["checks"]],
        )
        self.assertEqual(
            bootstrap["once_call_site_dispositions"],
            list(RUNNER.M1_BOOTSTRAP_ATOMIC_ONCE_CALL_SITE_DISPOSITIONS),
        )
        self.assertEqual(
            RUNNER.M1_BOOTSTRAP_STATIC_IMAGE_PROBE_DEFINES,
            ("-DMI_PRIM_HAS_PROCESS_ATTACH=1",),
        )
        self.assertIn(
            'U("m1.bootstrap.detached_tld.numa_node", detached_tld->numa_node);',
            RUNNER.STATIC_IMAGE_PROBE,
        )
        self.assertNotIn(
            'U("m1.bootstrap.detached_tld.numa_node", detached_tld->numa_node);',
            RUNNER.LAYOUT_PROBE,
        )
        self.assertNotIn(
            "MI_PRIM_HAS_PROCESS_ATTACH",
            RUNNER.LAYOUT_PROBE,
        )
        self.assertTrue(
            all(
                f'"{key}"' not in RUNNER.LAYOUT_PROBE
                for key in RUNNER.M1_BOOTSTRAP_STATIC_IMAGE_READER_ONLY_LAYOUT_KEY_SET
            )
        )
        self.assertIn(
            {
                "kind": "item",
                "name": "MI_MEMID_STATIC-bootstrap-page-and-theap-images",
                "required_statuses": [
                    "implemented",
                    "unit_verified",
                    "differential_verified",
                ],
                "upstream": "src/init.c",
            },
            bootstrap["source_map_records"],
        )
        self.assertIn(
            {
                "kind": "item",
                "name": "immutable-static-bootstrap-image-relational-vector",
                "required_statuses": [
                    "implemented",
                    "unit_verified",
                    "differential_verified",
                ],
                "upstream": "src/init.c",
            },
            bootstrap["source_map_records"],
        )
        self.assertIn(
            {
                "kind": "item",
                "name": "mi_atomic_do_once-callsite-disposition-ledger",
                "required_statuses": ["implemented", "unit_verified"],
                "upstream": "include/mimalloc/atomic.h",
            },
            bootstrap["source_map_records"],
        )
        compiler_tls = next(
            component
            for component in summary["components"]
            if component["id"] == "compiler-tls-roots"
        )
        self.assertIn(
            "compiler-tls-count-zero-root-teardown",
            [check["id"] for check in compiler_tls["checks"]],
        )
        self.assertIn(
            "compiler-tls-c-rust-trace",
            [check["id"] for check in compiler_tls["checks"]],
        )
        self.assertIn(
            "compiler-tls-same-tld-terminal-c-rust-trace",
            [check["id"] for check in compiler_tls["checks"]],
        )
        self.assertIn(
            "compiler-tls-same-tld-page-free-queue-half-rejection",
            [check["id"] for check in compiler_tls["checks"]],
        )
        self.assertEqual(compiler_tls["completion_status"], "complete")
        self.assertEqual(compiler_tls["remaining_conditions"], [])
        self.assertIn(
            {
                "kind": "item",
                "name": "current-thread-allocator-owned-regular-tls-backing",
                "required_statuses": ["implemented", "unit_verified"],
                "upstream": "src/threadlocal.c",
            },
            compiler_tls["source_map_records"],
        )
        self.assertEqual(
            [
                record["name"]
                for record in compiler_tls["source_map_records"]
                if record["required_statuses"]
                == ["implemented", "unit_verified", "differential_verified"]
            ],
            [
                "linux-aarch64-private-compiler-tls-root-image-and-thread-identity",
                "count-zero-root-image-and-positive-regular-reset",
                "canonical-empty-cached-root-transition",
                "cached-theap-reference-pair",
                "page-free-same-tld-mi-thread-theaps-done-sequence",
            ],
        )
        raw_primitives = next(
            component
            for component in summary["components"]
            if component["id"] == "linux-raw-primitives"
        )
        self.assertEqual(
            [
                declaration["name"]
                for declaration in raw_primitives["prim_h_declaration_inventory"]
            ],
            list(RUNNER.M1_RAW_PRIMITIVE_DECLARATIONS),
        )

        self.assertEqual(
            [record["name"] for record in raw_primitives["source_map_records"]],
            [
                "mi_os_mem_config-and-good-allocation-size",
                "linux-regular-map-memory-transitions",
                "linux-direct-process-thread-and-entropy-observations",
                "linux-raw-numa-node-count-observation",
                "linux-false-threadpool-observation",
            ],
        )
        self.assertEqual(raw_primitives["completion_status"], "complete")
        self.assertEqual(raw_primitives["remaining_conditions"], [])
        self.assertIn(
            "raw-primitive-c-rust-trace",
            [check["id"] for check in raw_primitives["checks"]],
        )
        self.assertTrue(
            all(
                record["required_statuses"]
                == ["implemented", "unit_verified", "differential_verified"]
                for record in raw_primitives["source_map_records"]
            )
        )
        self.assertEqual(
            next(
                declaration["record_id"]
                for declaration in raw_primitives["prim_h_declaration_inventory"]
                if declaration["name"] == "_mi_prim_thread_is_in_threadpool"
            ),
            "linux-false-threadpool-observation",
        )
        self.assertEqual(contract["global_evidence"], list(RUNNER.M1_FOUNDATIONS_GLOBAL_EVIDENCE))
        self.assertIn(
            "random-reinit-process-hook",
            [exclusion["id"] for exclusion in summary["exclusions"]],
        )
        pinned_chacha_block = next(
            check
            for check in random_image["checks"]
            if check["id"] == "pinned-chacha-block"
        )
        self.assertEqual(
            {
                declaration["name"]: declaration["record_id"]
                for declaration in raw_primitives["prim_h_declaration_inventory"]
                if declaration["classification"] == "later-milestone-exclusion"
            },
            {
                "_mi_prim_reuse": "prim-h-reuse-and-huge-page-allocation",
                "_mi_prim_alloc_huge_os_pages": "prim-h-reuse-and-huge-page-allocation",
                "mi_process_info_t": "prim-h-process-statistics",
                "_mi_prim_process_info": "prim-h-process-statistics",
                "_mi_prim_out_stderr": "prim-h-options-environment-and-diagnostics",
                "_mi_prim_getenv": "prim-h-options-environment-and-diagnostics",
                "_mi_prim_thread_init_auto_done": "prim-h-automatic-thread-lifecycle",
                "_mi_prim_thread_done_auto_done": "prim-h-automatic-thread-lifecycle",
                "_mi_prim_thread_associate_default_theap": "prim-h-automatic-thread-lifecycle",
            },
        )
        exclusions_by_id = {
            exclusion["id"]: exclusion["disposition"]
            for exclusion in summary["exclusions"]
        }
        self.assertEqual(
            {
                exclusion_id: exclusions_by_id[exclusion_id]
                for exclusion_id in {
                    "prim-h-reuse-and-huge-page-allocation",
                    "prim-h-process-statistics",
                    "prim-h-options-environment-and-diagnostics",
                    "prim-h-automatic-thread-lifecycle",
                    "prim-c-automatic-process-lifecycle",
                    "prim-c-allocator-redirection-integration",
                    "prim-unix-nondefault-vm-routes",
                    "prim-unix-option-and-diagnostic-routes",
                    "prim-unix-portability-fallback-routes",
                }
            },
            {
                "prim-h-reuse-and-huge-page-allocation": "deferred-to-m2",
                "prim-h-process-statistics": "deferred-to-m7",
                "prim-h-options-environment-and-diagnostics": "deferred-to-m7",
                "prim-h-automatic-thread-lifecycle": "deferred-to-m5",
                "prim-c-automatic-process-lifecycle": "deferred-to-m5",
                "prim-c-allocator-redirection-integration": "deferred-to-m8",
                "prim-unix-nondefault-vm-routes": "deferred-to-m2",
                "prim-unix-option-and-diagnostic-routes": "deferred-to-m7",
                "prim-unix-portability-fallback-routes": "outside-m1",
            },
        )
        self.assertNotIn("whole-prim-h-memory-policy", exclusions_by_id)
        self.assertEqual(
            RUNNER.m1_foundations_check_command(
                summary["execution"], pinned_chacha_block
            ),
            [
                "cargo",
                "test",
                "-p",
                "crabc-mimalloc",
                "--locked",
                "--lib",
                "random::tests::pinned_c_block_vector_uses_the_original_chacha_word_layout",
                "--",
                "--test-threads=1",
            ],
        )

    def test_m1_bootstrap_contract_requires_static_image_and_once_callsite_inventory(self) -> None:
        contract = RUNNER.read_json(RUNNER.M1_FOUNDATIONS_CONTRACT)
        bootstrap = next(
            component
            for component in contract["components"]
            if component["id"] == "atomics-locks-once-and-bootstrap"
        )

        self.assertEqual(
            bootstrap["layout_keys"],
            list(RUNNER.M1_BOOTSTRAP_STATIC_IMAGE_LAYOUT_KEYS),
        )
        self.assertEqual(
            bootstrap["once_call_site_dispositions"],
            list(RUNNER.M1_BOOTSTRAP_ATOMIC_ONCE_CALL_SITE_DISPOSITIONS),
        )

    def test_layout_probe_reads_the_selected_source_shape_macros(self) -> None:
        # The M1 configuration boundary must observe the macros that actually
        # selected the normal-release geometry. Repeating their current
        # arithmetic in the probe would let a future source branch drift
        # without changing the C/Rust comparison.
        self.assertIn(
            'U("config.ARENA_SLICE_SHIFT", MI_ARENA_SLICE_SHIFT);',
            RUNNER.LAYOUT_PROBE,
        )
        self.assertIn(
            'U("config.BCHUNK_BITS_SHIFT", MI_BCHUNK_BITS_SHIFT);',
            RUNNER.LAYOUT_PROBE,
        )

    def test_m1_foundations_contract_rejects_a_noncurrent_source_map_claim(self) -> None:
        contract = RUNNER.read_json(RUNNER.M1_FOUNDATIONS_CONTRACT)
        malformed = json.loads(json.dumps(contract))
        malformed["components"][0]["source_map_records"][0]["required_statuses"].append(
            "stress_verified"
        )

        with self.assertRaisesRegex(RUNNER.HarnessError, "lacks required status"):
            RUNNER.validate_m1_foundations_contract(
                malformed,
                RUNNER.load_pin(),
                RUNNER.load_port_map(),
            )

    def test_m1_foundations_contract_rejects_an_unmapped_raw_prim_declaration(self) -> None:
        contract = RUNNER.read_json(RUNNER.M1_FOUNDATIONS_CONTRACT)
        malformed = json.loads(json.dumps(contract))
        raw_primitives = next(
            component
            for component in malformed["components"]
            if component["id"] == "linux-raw-primitives"
        )
        raw_primitives["prim_h_declaration_inventory"][0]["record_id"] = "unreviewed"

        with self.assertRaisesRegex(
            RUNNER.HarnessError, "lacks a current source-map witness"
        ):
            RUNNER.validate_m1_foundations_contract(
                malformed,
                RUNNER.load_pin(),
                RUNNER.load_port_map(),
            )

    def test_m1_foundations_layout_evidence_marks_only_missing_m1_keys_pending(self) -> None:
        contract = RUNNER.read_json(RUNNER.M1_FOUNDATIONS_CONTRACT)
        summary = RUNNER.validate_m1_foundations_contract(
            contract,
            RUNNER.load_pin(),
            RUNNER.load_port_map(),
        )
        keys = {
            key
            for component in summary["components"]
            for key in component["layout_keys"]
        }
        c_layout = {key: 1 for key in keys}
        rust_layout = dict(c_layout)
        rust_layout.pop("offsetof.mi_random_ctx_t.weak")

        evidence = RUNNER.m1_foundations_layout_evidence(
            summary["components"],
            c_layout,
            rust_layout,
            static_image_c_layout=c_layout,
        )

        self.assertEqual(
            evidence["random-image"],
            {
                "keys": list(M1_RANDOM_IMAGE_KEYS),
                "missing_from_rust": ["offsetof.mi_random_ctx_t.weak"],
                "mismatches": [],
                "status": "pending",
            },
        )
        self.assertEqual(
            evidence["configuration-and-arithmetic"]["status"], "matched"
        )
        self.assertEqual(
            evidence["atomics-locks-once-and-bootstrap"]["status"], "matched"
        )

    def test_m1_foundations_layout_evidence_keeps_bootstrap_image_mismatch_pending(self) -> None:
        contract = RUNNER.read_json(RUNNER.M1_FOUNDATIONS_CONTRACT)
        summary = RUNNER.validate_m1_foundations_contract(
            contract,
            RUNNER.load_pin(),
            RUNNER.load_port_map(),
        )
        keys = {
            key
            for component in summary["components"]
            for key in component["layout_keys"]
        }
        c_layout = {key: 1 for key in keys}
        rust_layout = dict(c_layout)
        rust_layout["m1.bootstrap.empty_page.memid.pinned"] = 0

        evidence = RUNNER.m1_foundations_layout_evidence(
            summary["components"],
            c_layout,
            rust_layout,
            static_image_c_layout=c_layout,
        )

        self.assertEqual(
            evidence["atomics-locks-once-and-bootstrap"],
            {
                "keys": list(RUNNER.M1_BOOTSTRAP_STATIC_IMAGE_LAYOUT_KEYS),
                "missing_from_rust": [],
                "mismatches": [
                    "m1.bootstrap.empty_page.memid.pinned (C=1, Rust=0)"
                ],
                "status": "pending",
            },
        )

    def test_m1_foundations_report_does_not_promote_a_synthetic_partial_contract(self) -> None:
        contract = RUNNER.read_json(RUNNER.M1_FOUNDATIONS_CONTRACT)
        pin = RUNNER.load_pin()
        partial_contract = json.loads(json.dumps(contract))
        partial_contract["milestone"]["status"] = "partial"
        partial_compiler_tls = next(
            component
            for component in partial_contract["components"]
            if component["id"] == "compiler-tls-roots"
        )
        partial_compiler_tls["completion_status"] = "partial"
        partial_compiler_tls["remaining_conditions"] = [
            "synthetic ratchet condition: do not promote a partial compiler-TLS component"
        ]
        summary = RUNNER.validate_m1_foundations_contract(
            partial_contract,
            pin,
            RUNNER.load_port_map(),
        )
        keys = {
            key
            for component in summary["components"]
            for key in component["layout_keys"]
        }
        focused_checks = [
            {
                "component": component["id"],
                "command": [],
                "evidence_scope": "focused-source-test",
                "id": check["id"],
                "passed_test_count": check["expected_passed_test_count"],
                "target": check["target"],
            }
            for component in summary["components"]
            for check in component["checks"]
        ]
        source_state = {
            "kind": "git",
            "revision": "a" * 40,
            "worktree_clean": True,
            "worktree_status": {
                "bytes": 0,
                "hex": "",
                "sha256": hashlib.sha256(b"").hexdigest(),
            },
        }
        report = RUNNER.m1_foundations_report(
            contract=partial_contract,
            pin=pin,
            summary=summary,
            source_attestation=RUNNER.m1_foundations_source_attestation(
                source_state, source_state
            ),
            shared_oracle={
                "c_oracle": {
                    "profiles": {
                        "release": {
                            "artifact": {
                                "bytes": 1,
                                "path": ".work/test/libmimalloc.so",
                            "sha256": "b" * 64,
                        },
                            "layout": {
                                key: 1
                                for key in keys
                                if key
                                not in RUNNER.M1_BOOTSTRAP_STATIC_IMAGE_READER_ONLY_LAYOUT_KEY_SET
                            },
                            "m1_static_image_probe": {
                                "defines": list(
                                    RUNNER.M1_BOOTSTRAP_STATIC_IMAGE_PROBE_DEFINES
                                ),
                                "layout": {
                                    key: 1
                                    for key in RUNNER.M1_BOOTSTRAP_STATIC_IMAGE_LAYOUT_KEYS
                                },
                            },
                        }
                    }
                },
                "compiler_tls_codegen": {"status": "passed"},
                "production_dependency_graph": {"target": "aarch64-unknown-linux-musl"},
                "rust_release_layout": {
                    "comparison": {"status": "matched"},
                    "layout": {key: 1 for key in keys},
                },
            },
            raw_primitive_differential={
                "c_oracle": {"source_files": []},
                "comparison": {"compared_value_count": 47, "status": "matched"},
                "rust": {"passed_test_count": 1},
                "scope": "selected raw M1 source paths",
                "status": "matched",
            },
            compiler_tls_differential={
                "c_oracle": {"source_files": []},
                "comparison": {"compared_value_count": 32, "status": "matched"},
                "rust": {"passed_test_count": 1},
                "scope": "selected compiler-TLS M1 source paths",
                "status": "matched",
            },
            compiler_tls_same_tld_differential={
                "c_oracle": {"source_files": []},
                "comparison": {"compared_value_count": 40, "status": "matched"},
                "rust": {"passed_test_count": 1},
                "scope": "selected compiler-TLS same-TLD M1 source paths",
                "status": "matched",
            },
            focused_checks=focused_checks,
        )

        self.assertEqual(report["milestone"]["status"], "partial")
        expected_unmet = [
            component["id"]
            for component in summary["components"]
            if component["completion_status"] != "complete"
        ]
        self.assertEqual(
            report["milestone"]["unmet_component_ids"],
            expected_unmet,
        )
        self.assertEqual(
            RUNNER.m1_foundations_unmet_message(report).split(";", 1)[0],
            "M1 foundations remain partial for "
            + ", ".join(expected_unmet),
        )
        raw_component = next(
            component
            for component in report["components"]
            if component["id"] == "linux-raw-primitives"
        )
        self.assertEqual(raw_component["status"], "complete")
        self.assertEqual(
            raw_component["c_rust_differential"],
            {"compared_value_count": 47, "status": "matched"},
        )
        compiler_tls_component = next(
            component
            for component in report["components"]
            if component["id"] == "compiler-tls-roots"
        )
        self.assertEqual(compiler_tls_component["status"], "partial")
        self.assertEqual(
            compiler_tls_component["c_rust_differential"],
            {"compared_value_count": 32, "status": "matched"},
        )
        self.assertEqual(
            compiler_tls_component["same_tld_terminal_c_rust_differential"],
            {"compared_value_count": 40, "status": "matched"},
        )

    def test_native_owner_exit_lifecycle_contract_covers_every_reviewed_condition(self) -> None:
        contract = RUNNER.read_json(RUNNER.NATIVE_OWNER_EXIT_LIFECYCLE_CONTRACT)
        summary = RUNNER.validate_native_owner_exit_lifecycle_contract(
            contract,
            RUNNER.load_pin(),
        )

        self.assertEqual(summary["check_count"], 15)
        self.assertEqual(
            summary["scenario_coverage"],
            sorted(RUNNER.NATIVE_OWNER_EXIT_REQUIRED_SCENARIOS),
        )
        self.assertEqual(
            RUNNER.native_owner_exit_lifecycle_command(
                summary["execution"],
                summary["checks"][0],
            ),
            [
                "cargo",
                "test",
                "-p",
                "crabc-mimalloc",
                "--features",
                "native-runtime-test-audit,native-runtime-test-fault",
                "--locked",
                "--test",
                "native_post_exit_lifecycle",
                "--",
                "--test-threads=1",
            ],
        )
        self.assertEqual(
            RUNNER.native_owner_exit_lifecycle_command(
                summary["execution"],
                summary["checks"][-1],
            ),
            [
                "cargo",
                "test",
                "-p",
                "crabc-mimalloc",
                "--features",
                "native-runtime-test-audit,native-runtime-test-fault",
                "--locked",
                "--lib",
                "main_heap_page::tests::later_thread_exit_mapped_medium_route_adopts_into_a_fresh_later_owner",
                "--",
                "--test-threads=1",
            ],
        )

    def test_native_owner_exit_lifecycle_contract_rejects_retired_integration_target(self) -> None:
        contract = RUNNER.read_json(RUNNER.NATIVE_OWNER_EXIT_LIFECYCLE_CONTRACT)
        contract["checks"][0]["target"] = "retired_owner_exit_session"

        with self.assertRaisesRegex(RUNNER.HarnessError, "current integration test target"):
            RUNNER.validate_native_owner_exit_lifecycle_contract(
                contract,
                RUNNER.load_pin(),
            )

    def test_native_owner_exit_lifecycle_contract_rejects_retired_source_filter(self) -> None:
        contract = RUNNER.read_json(RUNNER.NATIVE_OWNER_EXIT_LIFECYCLE_CONTRACT)
        contract["checks"][-1]["target"] = "main_heap_page::tests::retired_owner_exit_filter"

        with self.assertRaisesRegex(RUNNER.HarnessError, "current source test filter"):
            RUNNER.validate_native_owner_exit_lifecycle_contract(
                contract,
                RUNNER.load_pin(),
            )

    def test_native_owner_exit_lifecycle_runner_records_every_reviewed_check(self) -> None:
        contract = RUNNER.read_json(RUNNER.NATIVE_OWNER_EXIT_LIFECYCLE_CONTRACT)
        result = {
            "status": 0,
            "stderr": "",
            "stdout": (
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                "0 filtered out; finished in 0.00s\n"
            ),
        }
        with mock.patch.object(RUNNER, "command_record", return_value=result) as command_record:
            report = RUNNER.run_native_owner_exit_lifecycle(contract, RUNNER.load_pin())

        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["check_count"], 15)
        self.assertEqual(len(report["checks"]), 15)
        self.assertEqual(command_record.call_count, 15)
        self.assertTrue(
            all(call.kwargs["timeout_seconds"] == 300 for call in command_record.call_args_list)
        )
        self.assertTrue(
            all(
                call.kwargs["env"]["CARGO_TARGET_DIR"]
                == str(RUNNER.NATIVE_OWNER_EXIT_CARGO_TARGET)
                for call in command_record.call_args_list
            )
        )

    def test_m5_owner_exit_evidence_rejects_a_partial_execution_record(self) -> None:
        contract = RUNNER.read_json(RUNNER.NATIVE_OWNER_EXIT_LIFECYCLE_CONTRACT)
        summary = RUNNER.validate_native_owner_exit_lifecycle_contract(
            contract,
            RUNNER.load_pin(),
        )
        report = {
            "native_owner_exit_lifecycle": {
                "check_count": summary["check_count"],
                "checks": [
                    {
                        "id": check["id"],
                        "kind": check["kind"],
                        "passed_test_count": check["expected_passed_test_count"],
                        "target": check["target"],
                    }
                    for check in summary["checks"]
                ],
                "contract": RUNNER.native_owner_exit_lifecycle_contract_record(
                    contract,
                    RUNNER.load_pin(),
                ),
                "scenario_coverage": summary["scenario_coverage"],
                "status": "passed",
            }
        }

        self.assertTrue(RUNNER._m5_native_owner_exit_lifecycle_evidence_passed(report))
        report["native_owner_exit_lifecycle"]["checks"].pop()
        self.assertFalse(RUNNER._m5_native_owner_exit_lifecycle_evidence_passed(report))

    def test_m5_gate_report_keeps_m5d_and_m5e_blocked_with_verified_upstream_matrix(self) -> None:
        contract = RUNNER.read_json(RUNNER.M5_GATE_CONTRACT)
        report = {
            "compiler_tls_codegen": {"status": "passed"},
            "m4_test_adapter": {
                "fixtures": {"adapted_upstream_api": {"summary": {"failed": 0, "succeeded": 33}}}
            },
            "remote_free_loom_model": {"status": "passed"},
            "runtime_ticket_zero_test_adapter": {
                "fixture": {
                    "watchdog": {"seconds": 30, "status": "passed"},
                    "worker_cycles": 128,
                    "stress_schedule": {
                        "seed": "0xd1b54a32d192ed03",
                        "worker_route_invocation_count": 256,
                        "worker_routes_per_cycle": 2,
                    },
                    "lifecycle_stability": {
                        "audit_snapshot_count": 129,
                        "post_warm_cycle_count": 127,
                        "status": "passed",
                        "warm_baseline": {
                            "worker_cycles": 128,
                            "process_active": 1,
                            "page_owner_ready": 1,
                            "page_map_registered_entries": 0,
                            "arena_registry_entries": 1,
                            "live_tlds": 1,
                            "metadata_live_capabilities": 0,
                            "shared_later_theaps": 0,
                            "abandoned_regular_pages": 0,
                            "os_abandoned_pages_empty": 1,
                        },
                    },
                }
            },
            "m5_source_derived_stress_adapter": {
                "fixture": {
                    "arguments": ["1", "1", "2"],
                    "compile_defines": ["NTHREADS=1"],
                    "rejected_compile_modes": [
                        "ALLOW_LARGE",
                        "MI_HEAP_WALK",
                        "MI_USE_HEAPS",
                        "TEST_LEAK",
                        "TEST_STRESS_SUBPROCS",
                        "USE_STD_MALLOC",
                    ],
                    "stderr": "",
                    "stdout": (
                        "Using 1 threads with a 1% load-per-thread and 2 iterations\n"
                        "crabc adapted stress ok\n"
                    ),
                    "watchdog": {"seconds": 30, "status": "passed"},
                }
            },
            "canonical_upstream_stress": {
                "format": 1,
                "schema": "crabc-mimalloc-canonical-upstream-stress-consumer",
                "status": "verified",
                "evidence_scope": "shadow_subset",
                "large_object_mode": {
                    "status": "source-cli-enabled",
                    "source_enablement": {
                        "parameter": "SCALE",
                        "operator": ">",
                        "threshold": 100,
                        "expected_stdout_suffix": " (allow large objects)",
                    },
                    "matrix_case_ids": [
                        "workers-1-scale-101-iterations-1",
                        "workers-2-scale-101-iterations-1",
                        "workers-4-scale-101-iterations-1",
                        "workers-8-scale-101-iterations-1",
                    ],
                    "reason": (
                        "The unmodified pinned source sets allow_large_objects only after "
                        "source CLI parsing when SCALE > 100. Each listed case uses SCALE=101; "
                        "no compile-time large-mode define is accepted. A passing row records "
                        "source-mode activation and completed bounded workload execution, not that "
                        "every probabilistic large allocation succeeded."
                    ),
                },
                "matrix": {"case_count": 12, "worker_counts": [1, 2, 4, 8]},
                "current_head": {"record": {}, "source": {}},
            },
        }
        native_contract = RUNNER.read_json(RUNNER.NATIVE_OWNER_EXIT_LIFECYCLE_CONTRACT)
        native_summary = RUNNER.validate_native_owner_exit_lifecycle_contract(
            native_contract,
            RUNNER.load_pin(),
        )
        # The native owner-exit suite is deliberately distinct from the
        # ticket-zero churn witness: its successful direct routes are the
        # evidence that lets Gate 5C advance while the stress and shadow
        # gates remain open.
        report["native_owner_exit_lifecycle"] = {
            "check_count": native_summary["check_count"],
            "checks": [
                {
                    "id": check["id"],
                    "kind": check["kind"],
                    "passed_test_count": check["expected_passed_test_count"],
                    "target": check["target"],
                }
                for check in native_summary["checks"]
            ],
            "contract": RUNNER.native_owner_exit_lifecycle_contract_record(
                native_contract,
                RUNNER.load_pin(),
            ),
            "scenario_coverage": native_summary["scenario_coverage"],
            "status": "passed",
        }

        gate = RUNNER.m5_gate_report(contract, report)

        self.assertEqual(gate["overall_status"], "unmet")
        self.assertEqual(gate["unmet_required"], ["m5.5d", "m5.5e"])
        self.assertEqual(
            {entry["id"]: entry["status"] for entry in gate["gates"]},
            {
                "m5.base": "passed",
                "m5.5a": "passed",
                "m5.5b": "passed",
                "m5.5c": "passed",
                "m5.5d": "blocked",
                "m5.5e": "blocked",
            },
        )
        gate_by_id = {entry["id"]: entry for entry in gate["gates"]}
        self.assertEqual(
            gate_by_id["m5.5c"]["observed_evidence"],
            ["report:/native_owner_exit_lifecycle"],
        )
        self.assertEqual(
            gate_by_id["m5.5d"]["observed_evidence"],
            [
                "report:/m5_source_derived_stress_adapter/fixture",
                "report:/canonical_upstream_stress",
            ],
        )
        self.assertNotIn("observed_evidence", gate_by_id["m5.5e"])

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

    def test_adapted_stress_fixture_rejects_scope_drift(self) -> None:
        contract = RUNNER.read_json(RUNNER.ADAPTED_STRESS_TEST_CONTRACT)
        header = RUNNER.TEST_ADAPTER_HEADER.read_text(encoding="utf-8")
        contract["execution"]["arguments"] = ["1", "1", "1"]
        with self.assertRaisesRegex(RUNNER.HarnessError, "execution contract changed"):
            RUNNER.validate_adapted_stress_test_contract(
                contract, RUNNER.load_pin(), header
            )

    def test_native_shadow_stress_rejects_scope_drift(self) -> None:
        contract = RUNNER.read_json(RUNNER.NATIVE_SHADOW_STRESS_CONTRACT)
        contract["execution"]["process_epochs"] = 127
        with self.assertRaisesRegex(RUNNER.HarnessError, "execution contract changed"):
            RUNNER.validate_native_shadow_stress_contract(contract, RUNNER.load_pin())

    def test_checked_in_api_inventory_has_audited_linux_aarch64_boundaries(self) -> None:
        inventory = RUNNER.read_json(RUNNER.API_CONTRACT)
        self.assertEqual(inventory["format"], 3)
        RUNNER.validate_api_parity_inventory(inventory)
        self.assertEqual(
            inventory["summary"],
            {
                "applicable_item_count": 334,
                "blocked_applicable_item_count": 334,
                "blocked_required_mode_count": 52,
                "compile_time_mode_count": 52,
                "configuration_macro_count": 138,
                "cxx_convenience_count": 1,
                "cxx_template_count": 3,
                "external_function_count": 194,
                "inapplicable_item_count": 2,
                "inapplicable_mode_count": 0,
                "macro_count": 26,
                "option_count": 52,
                "override_macro_count": 37,
                "required_mode_count": 52,
                "source_only_count": 146,
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
        self.assertEqual(
            {
                item["name"]
                for item in inventory["items"]
                if item["target_applicability"] == "inapplicable"
            },
            {"mi_collect_reduce", "mi_stats_merge"},
        )
        self.assertEqual(items["mi_wdupenv_s"]["classification"], "linux-einval-operation")
        self.assertEqual(items["mi_wdupenv_s"]["target_applicability"], "applicable")
        self.assertEqual(items["mi_wdupenv_s"]["completion_status"], "blocked")
        self.assertTrue(items["mi_wdupenv_s"]["applicability_sources"])
        self.assertTrue(items["mi_wdupenv_s"]["oracle_release_exported"])
        self.assertEqual(items["mi_option_os_tag"]["classification"], "platform-specific-effect-option")
        self.assertEqual(items["mi_option_os_tag"]["target_applicability"], "applicable")
        self.assertEqual(items["mi_option_retry_on_oom"]["target_applicability"], "applicable")
        self.assertEqual(
            items["mi_collect_reduce"]["classification"],
            "upstream-unavailable-declaration",
        )
        self.assertEqual(items["mi_collect_reduce"]["target_applicability"], "inapplicable")
        self.assertEqual(items["mi_stats_init"]["classification"], "source-only-inline")
        self.assertEqual(items["mi_stl_allocator"]["kind"], "cxx-template")
        self.assertFalse(any(item["crabc_libc_exported"] for item in inventory["items"]))

        modes = {mode["name"]: mode for mode in inventory["compile_time_modes"]}
        self.assertTrue(
            all(
                mode["target_applicability"] == "applicable"
                and all(
                    value["target_applicability"] == "applicable"
                    for value in mode["source_values"]
                )
                for mode in modes.values()
            )
        )
        self.assertEqual(modes["MI_DEBUG"]["allowed_source_tokens"], ["OFF", "ON", "INTERNAL", "FULL", "DEFAULT"])
        self.assertEqual(modes["MI_DEBUG"]["target_applicability"], "applicable")
        self.assertEqual(modes["MI_DEBUG"]["completion_status"], "blocked")
        self.assertEqual(modes["MI_OSX_ZONE"]["target_applicability"], "applicable")
        self.assertEqual(modes["MI_OSX_ZONE"]["completion_status"], "blocked")
        self.assertTrue(modes["MI_OSX_ZONE"]["applicability_sources"])
        self.assertEqual(modes["MI_TLS_MODEL_FIXED"]["target_applicability"], "applicable")
        self.assertEqual(modes["MI_TLS_MODEL_FIXED"]["completion_status"], "blocked")
        tls_values = {
            value["token"]: value for value in modes["MI_TLS_MODEL"]["source_values"]
        }
        self.assertEqual(tls_values["LOCAL"]["target_applicability"], "applicable")
        self.assertEqual(tls_values["FIXED"]["target_applicability"], "applicable")
        self.assertEqual(tls_values["WIN32"]["target_applicability"], "applicable")
        track_values = {
            value["token"]: value for value in modes["MI_TRACK"]["source_values"]
        }
        self.assertEqual(track_values["ETW"]["target_applicability"], "applicable")
        self.assertEqual(
            inventory["completion_tracks"]["malloc_engine_readiness"]["inventory_driven"],
            False,
        )
        self.assertEqual(
            inventory["completion_tracks"]["full_linux_aarch64_v3_5_0_parity"]["inventory_driven"],
            True,
        )

    def test_api_parity_inventory_rejects_omissions_and_contradictions(self) -> None:
        inventory = RUNNER.read_json(RUNNER.API_CONTRACT)

        missing_item = json.loads(json.dumps(inventory))
        missing_item["items"].pop()
        with self.assertRaisesRegex(RUNNER.HarnessError, "API item count"):
            RUNNER.validate_api_parity_inventory(missing_item)

        missing_mode = json.loads(json.dumps(inventory))
        missing_mode["compile_time_modes"].pop()
        with self.assertRaisesRegex(RUNNER.HarnessError, "compile-time mode count"):
            RUNNER.validate_api_parity_inventory(missing_mode)

        contradictory = json.loads(json.dumps(inventory))
        item = next(
            item
            for item in contradictory["items"]
            if item["target_applicability"] == "applicable"
        )
        item["parity_requirement"] = "not-required"
        with self.assertRaisesRegex(RUNNER.HarnessError, "applicable API item"):
            RUNNER.validate_api_parity_inventory(contradictory)

        unsupported_without_source = json.loads(json.dumps(inventory))
        item = next(
            item
            for item in unsupported_without_source["items"]
            if item["target_applicability"] == "inapplicable"
        )
        item["classification_reason"] = ""
        item["applicability_sources"] = []
        with self.assertRaisesRegex(RUNNER.HarnessError, "source-backed rationale"):
            RUNNER.validate_api_parity_inventory(unsupported_without_source)

        unsupported_value_without_source = json.loads(json.dumps(inventory))
        mode = next(
            mode for mode in unsupported_value_without_source["compile_time_modes"]
            if mode["name"] == "MI_TLS_MODEL"
        )
        value = next(value for value in mode["source_values"] if value["token"] == "FIXED")
        value["target_applicability"] = "inapplicable"
        value["classification_reason"] = ""
        value["applicability_sources"] = []
        with self.assertRaisesRegex(RUNNER.HarnessError, "mode value.*source-backed rationale"):
            RUNNER.validate_api_parity_inventory(unsupported_value_without_source)

        observable_api = json.loads(json.dumps(inventory))
        item = next(
            item for item in observable_api["items"] if item["name"] == "mi_wdupenv_s"
        )
        item["target_applicability"] = "inapplicable"
        item["parity_requirement"] = "not-required"
        item["completion_status"] = "not-required"
        item["implementation_blocker"] = ""
        with self.assertRaisesRegex(RUNNER.HarnessError, "normal-release public API"):
            RUNNER.validate_api_parity_inventory(observable_api)

        observable_mode = json.loads(json.dumps(inventory))
        mode = next(
            mode for mode in observable_mode["compile_time_modes"]
            if mode["name"] == "MI_OSX_ZONE"
        )
        mode["target_applicability"] = "inapplicable"
        mode["parity_requirement"] = "not-required"
        mode["completion_status"] = "not-required"
        mode["implementation_blocker"] = ""
        for value in mode["source_values"]:
            value["target_applicability"] = "inapplicable"
            value["applicability_sources"] = list(mode["applicability_sources"])
            value["classification_reason"] = mode["classification_reason"]
        with self.assertRaisesRegex(RUNNER.HarnessError, "unconditional root-CMake mode"):
            RUNNER.validate_api_parity_inventory(observable_mode)

        observable_value = json.loads(json.dumps(inventory))
        mode = next(
            mode for mode in observable_value["compile_time_modes"]
            if mode["name"] == "MI_TLS_MODEL"
        )
        value = next(value for value in mode["source_values"] if value["token"] == "FIXED")
        value["target_applicability"] = "inapplicable"
        with self.assertRaisesRegex(RUNNER.HarnessError, "declared mode value"):
            RUNNER.validate_api_parity_inventory(observable_value)

    def test_api_parity_inventory_keeps_readiness_separate_from_full_parity(self) -> None:
        inventory = RUNNER.read_json(RUNNER.API_CONTRACT)

        readiness = json.loads(json.dumps(inventory))
        readiness["completion_tracks"]["malloc_engine_readiness"]["inventory_driven"] = True
        with self.assertRaisesRegex(RUNNER.HarnessError, "readiness.*separate"):
            RUNNER.validate_api_parity_inventory(readiness)

        false_parity = json.loads(json.dumps(inventory))
        false_parity["completion_tracks"]["full_linux_aarch64_v3_5_0_parity"]["status"] = "complete"
        with self.assertRaisesRegex(RUNNER.HarnessError, "full parity.*blocked"):
            RUNNER.validate_api_parity_inventory(false_parity)

    def test_full_and_performance_modes_have_precise_unmet_milestones(self) -> None:
        full = "allocator --full did not meet Milestone 5: m5.5c: general owner exit remains blocked"
        performance = (
            "allocator performance is unavailable: Milestone 9 requires comparable C and Rust opaque allocator boundaries plus Milestone 8 integrated crabc backends; the current private one-thread engine is not a benchmark boundary."
        )
        self.assertIn("m5.5c", full)
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

    def test_checked_in_ratchet_accepts_checked_in_adapted_contract_digest(self) -> None:
        """The reviewed snapshot must cover the runner's current contract path."""

        baseline = RUNNER.read_json(RUNNER.RATCHET)
        self.assertEqual(
            baseline["adapted_test_contract_sha256"],
            RUNNER.file_digest(RUNNER.ADAPTED_TEST_CONTRACT),
        )
        self.assertEqual(
            baseline["m2_memory_substrate_contract_sha256"],
            RUNNER.file_digest(RUNNER.M2_MEMORY_SUBSTRATE_CONTRACT),
        )
        RUNNER.check_ratchet(RUNNER.load_port_map())

    def test_ratchet_check_rejects_unreviewed_port_map_digest_drift(self) -> None:
        """A status-preserving port-map edit still requires a reviewed snapshot."""

        current = {
            "format": 1,
            "port_map_counts": {},
            "port_map_true_statuses": {},
            "adapted_test_contract_sha256": "adapted-tests",
            "adapted_stress_test_contract_sha256": "adapted-stress",
            "native_shadow_stress_contract_sha256": "native-shadow-stress",
            "m1_foundations_contract_sha256": "m1-foundations",
            "m2_memory_substrate_contract_sha256": "m2-memory-substrate",
            "owner_exit_publication_contract_sha256": "owner-exit-publication",
            "api_contract_sha256": "api",
            "port_map_sha256": "current-port-map",
            "upstream_test_contract_sha256": "upstream-tests",
        }
        baseline = {**current, "port_map_sha256": "reviewed-port-map"}

        with tempfile.TemporaryDirectory() as temporary:
            ratchet = Path(temporary) / "ratchet.json"
            RUNNER.write_json(ratchet, baseline)
            with mock.patch.object(RUNNER, "RATCHET", ratchet), mock.patch.object(
                RUNNER, "ratchet_payload", return_value=current
            ):
                with self.assertRaisesRegex(
                    RUNNER.HarnessError,
                    "allocator ratchet input changed: port_map_sha256",
                ):
                    RUNNER.check_ratchet({})


class RuntimeTicketZeroSoakReportTests(unittest.TestCase):
    """Exercise the durable opt-in soak publication without a native 180s run."""

    @staticmethod
    def clean_source_state(revision: str = "a" * 40) -> dict[str, object]:
        return {
            "kind": "git",
            "revision": revision,
            "worktree_clean": True,
            "worktree_status": {
                "bytes": 0,
                "hex": "",
                "sha256": hashlib.sha256(b"").hexdigest(),
            },
        }

    @staticmethod
    def lifecycle_audit(worker_cycles: int = 1024) -> dict[str, int]:
        return {
            "worker_cycles": worker_cycles,
            "process_active": 1,
            "page_owner_ready": 1,
            "page_map_registered_entries": 0,
            "page_map_published_submaps": 2,
            "page_map_lazy_submap_allocations": 1,
            "arena_registry_entries": 1,
            "live_tlds": 1,
            "metadata_live_capabilities": 0,
            "metadata_high_water_capabilities": 3,
            "shared_later_theaps": 0,
            "abandoned_regular_pages": 0,
            "os_abandoned_pages_empty": 1,
        }

    @classmethod
    def successful_milestone_report(
        cls, root: Path
    ) -> tuple[dict[str, object], dict[str, str], Path]:
        """Make live artifact records shaped like the completed native lane."""

        def write(path: Path, payload: bytes) -> Path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            return path

        archive = write(root / "allocator-cache/mimalloc-3.5.0.tar.gz", b"mimalloc")
        adapter_root = root / "target/compat/allocator/runtime-ticket-zero-adapter"
        release_root = (
            adapter_root
            / "cargo-target"
            / RUNNER.PRODUCTION_RUST_TARGET
            / "release"
        )
        adapter_archive = write(
            release_root / "libcrabc_mimalloc_runtime_ticket_zero_adapter.a",
            b"adapter archive",
        )
        adapter_shared = write(
            release_root / "libcrabc_mimalloc_runtime_ticket_zero_adapter.so",
            b"adapter shared",
        )
        fixture_binary = write(
            adapter_root / "runtime-ticket-zero-fixture", b"fixture"
        )
        pin = {
            **RUNNER.load_pin(),
            "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        }
        tag_attestation = {
            "format": 1,
            "repository": pin["repository"],
            "revision": pin["revision"],
            "tag": pin["tag"],
            "tag_object": pin["tag_object"],
        }
        write(
            root / "allocator-cache/mimalloc-3.5.0.tag.json",
            (json.dumps(tag_attestation, sort_keys=True) + "\n").encode(),
        )
        audit = cls.lifecycle_audit()
        stdout = (
            RUNNER.RUNTIME_TICKET_ZERO_LIFECYCLE_AUDIT_PREFIX
            + " ".join(f"{name}={audit[name]}" for name in audit)
            + "\n"
            + RUNNER.RUNTIME_TICKET_ZERO_LIFECYCLE_AUDIT_SUCCESS_LINE
            + "\n"
        )
        fixture = {
            "artifact": RUNNER.artifact_record(fixture_binary),
            "build_command": [
                "musl-gcc",
                "-std=c11",
                "-O2",
                "-fPIE",
                "-pie",
                "-ftls-model=initial-exec",
                "-pthread",
                "-I",
                str(RUNNER.RUNTIME_TICKET_ZERO_ADAPTER_ROOT),
                str(RUNNER.RUNTIME_TICKET_ZERO_ADAPTER_FIXTURE),
                str(adapter_archive),
                "-o",
                str(fixture_binary),
            ],
            "lifecycle_stability": {
                "audit_snapshot_count": 1025,
                "post_warm_cycle_count": 1023,
                "status": "passed",
                "warm_baseline": audit,
            },
            "run_command": RUNNER.runtime_ticket_zero_fixture_command(
                fixture_binary,
                worker_cycles=1024,
                stress_seed=RUNNER.RUNTIME_TICKET_ZERO_SOAK_STRESS_SEED,
            ),
            "stdout": stdout,
            "stress_schedule": RUNNER.runtime_ticket_zero_stress_schedule(
                worker_cycles=1024,
                stress_seed=RUNNER.RUNTIME_TICKET_ZERO_SOAK_STRESS_SEED,
            ),
            "watchdog": {"seconds": 180, "status": "passed"},
            "worker_cycles": 1024,
        }
        return (
            {
                "c_oracle": {
                    "build_strategy": "pinned C oracle",
                    "compiler": "musl-gcc (pinned container)",
                    "profiles": {},
                    "source_files": [],
                },
                "oracle": {
                    "archive": RUNNER.artifact_record(archive),
                    "archive_root": pin["archive_root"],
                    "revision": pin["revision"],
                    "sha256": pin["sha256"],
                    "source": pin["source"],
                    "tag_object": pin["tag_object"],
                    "tag_verified": tag_attestation,
                    "version": pin["version"],
                },
                "runtime_ticket_zero_test_adapter": {
                    "build": {
                        "archive": RUNNER.artifact_record(adapter_archive),
                        "archive_symbols": {"symbols": []},
                        "shared_library": RUNNER.artifact_record(adapter_shared),
                        "shared_symbols": {"symbols": []},
                    },
                    "fixture": fixture,
                },
                "target": {"architecture": "aarch64", "system": "Linux"},
            },
            pin,
            fixture_binary,
        )

    @staticmethod
    def patch_soak_artifact_roots(root: Path):
        """Make synthetic live paths match the producer's trusted locations."""

        return mock.patch.multiple(
            RUNNER,
            CACHE=root / "allocator-cache",
            ARTIFACT_ROOT=root / "target/compat/allocator",
        )

    def test_soak_publication_is_unique_attested_and_leaves_latest_untouched(self) -> None:
        with RUNNER.temporary_directory("runtime-ticket-zero-soak-report-") as temporary:
            root = Path(temporary)
            report_path = root / "reports/allocator/runtime-ticket-zero-soak-1024.json"
            latest_path = root / "reports/allocator/latest.json"
            report_path.parent.mkdir(parents=True)
            latest_path.write_text('{"shared":"keep"}\n', encoding="utf-8")
            legacy_temporary = report_path.with_name(f".{report_path.name}.tmp")
            legacy_temporary.write_text("occupied", encoding="utf-8")
            milestone, pin, _ = self.successful_milestone_report(root)
            source = self.clean_source_state()

            with self.patch_soak_artifact_roots(root), mock.patch.object(
                RUNNER, "RUNTIME_TICKET_ZERO_SOAK_REPORT", report_path
            ), mock.patch.object(
                RUNNER, "load_pin", return_value=pin
            ), mock.patch.object(
                RUNNER,
                "runtime_ticket_zero_soak_source_state",
                side_effect=[source, source],
            ), mock.patch.object(
                RUNNER, "run_milestone0", return_value=milestone
            ) as run_milestone:
                report = RUNNER.run_runtime_ticket_zero_soak(
                    offline=True, architecture="aarch64"
                )

            self.assertEqual(
                run_milestone.call_args.kwargs,
                {
                    "offline": True,
                    "generate_contracts": False,
                    "check_only": False,
                    "include_test_adapter": True,
                    "include_adapted_stress": False,
                    "include_native_owner_exit_lifecycle": False,
                    "runtime_ticket_zero_worker_cycles": 1024,
                    "runtime_ticket_zero_watchdog_seconds": 180,
                    "runtime_ticket_zero_stress_seed": RUNNER.RUNTIME_TICKET_ZERO_SOAK_STRESS_SEED,
                    "architecture": "aarch64",
                    "write_report": False,
                },
            )
            self.assertEqual(
                set(report),
                {
                    "format",
                    "schema",
                    "mode",
                    "status",
                    "evidence_scope",
                    "nonclaims",
                    "contract",
                    "source",
                    "pin",
                    "oracle",
                    "target",
                    "build_artifacts",
                    "fixture",
                    "schedule",
                    "audit",
                },
            )
            self.assertEqual(report["format"], 1)
            self.assertEqual(
                report["schema"], "crabc-mimalloc-runtime-ticket-zero-soak-report"
            )
            self.assertEqual(report["mode"], "soak")
            self.assertEqual(report["status"], "passed")
            self.assertEqual(
                report["evidence_scope"], "bounded-private-ticket-zero-soak"
            )
            self.assertEqual(
                report["schedule"],
                {
                    "stress_seed": "0x94d049bb133111eb",
                    "watchdog_seconds": 180,
                    "worker_cycles": 1024,
                    "worker_route_invocation_count": 2048,
                    "worker_routes_per_cycle": 2,
                },
            )
            self.assertEqual(
                set(report["audit"]["warm_baseline"]),
                set(RUNNER.RUNTIME_TICKET_ZERO_LIFECYCLE_AUDIT_FIELDS),
            )
            self.assertEqual(len(report["audit"]["warm_baseline"]), 13)
            self.assertEqual(report["source"]["before"], source)
            self.assertEqual(report["source"]["after"], source)
            self.assertTrue(report["source"]["unchanged_during_execution"])
            self.assertEqual(
                report["source"]["git_read_environment"], {"GIT_OPTIONAL_LOCKS": "0"}
            )
            self.assertEqual(report["contract"]["record"], RUNNER.artifact_record(
                RUNNER.RUNTIME_TICKET_ZERO_ADAPTER_CONTRACT
            ))
            self.assertEqual(
                report["pin"]["tag_verified"],
                {
                    "format": 1,
                    "repository": pin["repository"],
                    "revision": pin["revision"],
                    "tag": pin["tag"],
                    "tag_object": pin["tag_object"],
                },
            )
            self.assertEqual(
                report["fixture"]["artifact"],
                milestone["runtime_ticket_zero_test_adapter"]["fixture"]["artifact"],
            )
            self.assertEqual(
                report["build_artifacts"]["adapter_archive"],
                milestone["runtime_ticket_zero_test_adapter"]["build"]["archive"],
            )
            self.assertEqual(
                report["build_artifacts"]["adapter_shared_library"],
                milestone["runtime_ticket_zero_test_adapter"]["build"]["shared_library"],
            )
            self.assertEqual(json.loads(report_path.read_text(encoding="utf-8")), report)
            self.assertEqual(latest_path.read_text(encoding="utf-8"), '{"shared":"keep"}\n')
            self.assertEqual(legacy_temporary.read_text(encoding="utf-8"), "occupied")

    def test_soak_failure_preserves_a_prior_good_stable_record(self) -> None:
        with RUNNER.temporary_directory("runtime-ticket-zero-soak-preserve-") as temporary:
            root = Path(temporary)
            report_path = root / "reports/allocator/runtime-ticket-zero-soak-1024.json"
            report_path.parent.mkdir(parents=True)
            previous = '{"status":"passed","prior":true}\n'
            report_path.write_text(previous, encoding="utf-8")
            milestone, pin, _ = self.successful_milestone_report(root)
            before = self.clean_source_state()
            after = self.clean_source_state("b" * 40)

            with self.patch_soak_artifact_roots(root), mock.patch.object(
                RUNNER, "RUNTIME_TICKET_ZERO_SOAK_REPORT", report_path
            ), mock.patch.object(
                RUNNER, "load_pin", return_value=pin
            ), mock.patch.object(
                RUNNER,
                "runtime_ticket_zero_soak_source_state",
                side_effect=[before, after],
            ), mock.patch.object(RUNNER, "run_milestone0", return_value=milestone):
                with self.assertRaisesRegex(RUNNER.HarnessError, "source changed during execution"):
                    RUNNER.run_runtime_ticket_zero_soak(offline=True, architecture="aarch64")

            self.assertEqual(report_path.read_text(encoding="utf-8"), previous)

    def test_soak_rejects_a_source_transition_before_contract_read(self) -> None:
        """A contract digest must not describe a source state captured too late."""

        with RUNNER.temporary_directory("runtime-ticket-zero-soak-source-transition-") as temporary:
            root = Path(temporary)
            contract_path = root / "compat/allocator/runtime-ticket-zero-test-v3.5.0.json"
            contract_path.parent.mkdir(parents=True)
            original_text = RUNNER.RUNTIME_TICKET_ZERO_ADAPTER_CONTRACT.read_text(
                encoding="utf-8"
            )
            contract_path.write_text(original_text, encoding="utf-8")
            original_contract = json.loads(original_text)
            transitioned_contract = json.loads(original_text)
            transitioned_soak_report = dict(transitioned_contract["soak_report"])
            transitioned_soak_report["evidence_scope"] = "source-transitioned-contract"
            transitioned_contract["soak_report"] = transitioned_soak_report
            transitioned_text = json.dumps(transitioned_contract, indent=2) + "\n"
            self.assertNotEqual(
                original_contract["soak_report"], transitioned_contract["soak_report"]
            )
            self.assertNotEqual(
                hashlib.sha256(original_text.encode()).hexdigest(),
                hashlib.sha256(transitioned_text.encode()).hexdigest(),
            )

            report_path = root / "reports/allocator/runtime-ticket-zero-soak-1024.json"
            report_path.parent.mkdir(parents=True)
            previous = '{"status":"passed","prior":true}\n'
            report_path.write_text(previous, encoding="utf-8")
            milestone, pin, _ = self.successful_milestone_report(root)
            before = self.clean_source_state("a" * 40)
            after = self.clean_source_state("b" * 40)
            transition = {"occurred": False}
            pin_source_capture_counts: list[int] = []
            validate_contract = RUNNER.validate_runtime_ticket_zero_adapter_contract

            def source_state() -> dict[str, object]:
                return after if transition["occurred"] else before

            def validate_then_transition(contract: object, header: object) -> dict[str, object]:
                result = validate_contract(contract, header)
                contract_path.write_text(transitioned_text, encoding="utf-8")
                transition["occurred"] = True
                return result

            def load_pin_after_source_capture() -> dict[str, str]:
                pin_source_capture_counts.append(source_states.call_count)
                return pin

            with self.patch_soak_artifact_roots(root), mock.patch.object(
                RUNNER, "RUNTIME_TICKET_ZERO_ADAPTER_CONTRACT", contract_path
            ), mock.patch.object(
                RUNNER, "RUNTIME_TICKET_ZERO_SOAK_REPORT", report_path
            ), mock.patch.object(
                RUNNER, "load_pin", side_effect=load_pin_after_source_capture
            ), mock.patch.object(
                RUNNER,
                "runtime_ticket_zero_soak_source_state",
                side_effect=source_state,
            ) as source_states, mock.patch.object(
                RUNNER,
                "validate_runtime_ticket_zero_adapter_contract",
                side_effect=validate_then_transition,
            ), mock.patch.object(RUNNER, "run_milestone0", return_value=milestone):
                with self.assertRaisesRegex(RUNNER.HarnessError, "source changed during execution"):
                    RUNNER.run_runtime_ticket_zero_soak(offline=True, architecture="aarch64")

            self.assertTrue(transition["occurred"])
            self.assertEqual(source_states.call_count, 2)
            self.assertEqual(pin_source_capture_counts, [1, 1])
            self.assertEqual(report_path.read_text(encoding="utf-8"), previous)

    def test_soak_requires_live_fixture_artifact_before_replacing_the_stable_record(self) -> None:
        with RUNNER.temporary_directory("runtime-ticket-zero-soak-live-artifact-") as temporary:
            root = Path(temporary)
            report_path = root / "reports/allocator/runtime-ticket-zero-soak-1024.json"
            report_path.parent.mkdir(parents=True)
            previous = '{"status":"passed","prior":true}\n'
            report_path.write_text(previous, encoding="utf-8")
            milestone, pin, fixture_binary = self.successful_milestone_report(root)
            source = self.clean_source_state()

            def completed_run(**_: object) -> dict[str, object]:
                fixture_binary.write_bytes(b"fixture drift")
                return milestone

            with self.patch_soak_artifact_roots(root), mock.patch.object(
                RUNNER, "RUNTIME_TICKET_ZERO_SOAK_REPORT", report_path
            ), mock.patch.object(
                RUNNER, "load_pin", return_value=pin
            ), mock.patch.object(
                RUNNER, "runtime_ticket_zero_soak_source_state", side_effect=[source, source]
            ), mock.patch.object(RUNNER, "run_milestone0", side_effect=completed_run):
                with self.assertRaisesRegex(RUNNER.HarnessError, "fixture artifact"):
                    RUNNER.run_runtime_ticket_zero_soak(offline=True, architecture="aarch64")

            self.assertEqual(report_path.read_text(encoding="utf-8"), previous)

    def test_soak_rejects_a_fixture_command_for_an_unattested_live_binary(self) -> None:
        with RUNNER.temporary_directory("runtime-ticket-zero-soak-fixture-identity-") as temporary:
            root = Path(temporary)
            report_path = root / "reports/allocator/runtime-ticket-zero-soak-1024.json"
            report_path.parent.mkdir(parents=True)
            previous = '{"status":"passed","prior":true}\n'
            report_path.write_text(previous, encoding="utf-8")
            milestone, pin, fixture_binary = self.successful_milestone_report(root)
            alternate_binary = fixture_binary.with_name("runtime-ticket-zero-unattested")
            alternate_binary.write_bytes(b"a different live fixture")
            adapter = milestone["runtime_ticket_zero_test_adapter"]
            assert isinstance(adapter, dict)
            fixture = adapter["fixture"]
            assert isinstance(fixture, dict)
            fixture["run_command"] = RUNNER.runtime_ticket_zero_fixture_command(
                alternate_binary,
                worker_cycles=1024,
                stress_seed=RUNNER.RUNTIME_TICKET_ZERO_SOAK_STRESS_SEED,
            )
            source = self.clean_source_state()

            with self.patch_soak_artifact_roots(root), mock.patch.object(
                RUNNER, "RUNTIME_TICKET_ZERO_SOAK_REPORT", report_path
            ), mock.patch.object(
                RUNNER, "load_pin", return_value=pin
            ), mock.patch.object(
                RUNNER,
                "runtime_ticket_zero_soak_source_state",
                side_effect=[source, source],
            ), mock.patch.object(RUNNER, "run_milestone0", return_value=milestone):
                with self.assertRaisesRegex(RUNNER.HarnessError, "fixture executable"):
                    RUNNER.run_runtime_ticket_zero_soak(offline=True, architecture="aarch64")

            self.assertEqual(report_path.read_text(encoding="utf-8"), previous)

    def test_soak_rejects_fixture_build_records_unbound_to_its_artifacts(self) -> None:
        for case in ("output", "source", "adapter-archive"):
            with self.subTest(case=case), RUNNER.temporary_directory(
                "runtime-ticket-zero-soak-build-identity-"
            ) as temporary:
                root = Path(temporary)
                report_path = root / "reports/allocator/runtime-ticket-zero-soak-1024.json"
                report_path.parent.mkdir(parents=True)
                previous = '{"status":"passed","prior":true}\n'
                report_path.write_text(previous, encoding="utf-8")
                milestone, pin, fixture_binary = self.successful_milestone_report(root)
                adapter = milestone["runtime_ticket_zero_test_adapter"]
                assert isinstance(adapter, dict)
                build = adapter["build"]
                fixture = adapter["fixture"]
                assert isinstance(build, dict) and isinstance(fixture, dict)
                build_command = fixture["build_command"]
                assert isinstance(build_command, list)
                if case == "output":
                    alternate = fixture_binary.with_name("runtime-ticket-zero-other-output")
                    alternate.write_bytes(b"other fixture output")
                    build_command[build_command.index("-o") + 1] = str(alternate)
                elif case == "source":
                    alternate = root / "runtime-ticket-zero-other-fixture.c"
                    alternate.write_text("int main(void) { return 0; }\n", encoding="utf-8")
                    build_command[build_command.index(str(RUNNER.RUNTIME_TICKET_ZERO_ADAPTER_FIXTURE))] = str(
                        alternate
                    )
                else:
                    alternate = root / "libother-runtime-ticket-zero-adapter.a"
                    alternate.write_bytes(b"other adapter archive")
                    adapter_archive = (
                        root
                        / "target/compat/allocator/runtime-ticket-zero-adapter/cargo-target"
                        / RUNNER.PRODUCTION_RUST_TARGET
                        / "release/libcrabc_mimalloc_runtime_ticket_zero_adapter.a"
                    )
                    build_command[build_command.index(str(adapter_archive))] = str(alternate)
                source = self.clean_source_state()

                with self.patch_soak_artifact_roots(root), mock.patch.object(
                    RUNNER, "RUNTIME_TICKET_ZERO_SOAK_REPORT", report_path
                ), mock.patch.object(
                    RUNNER, "load_pin", return_value=pin
                ), mock.patch.object(
                    RUNNER,
                    "runtime_ticket_zero_soak_source_state",
                    side_effect=[source, source],
                ), mock.patch.object(RUNNER, "run_milestone0", return_value=milestone):
                    with self.assertRaisesRegex(RUNNER.HarnessError, "fixture build"):
                        RUNNER.run_runtime_ticket_zero_soak(offline=True, architecture="aarch64")

                self.assertEqual(report_path.read_text(encoding="utf-8"), previous)

    def test_soak_requires_a_live_pin_matched_tag_attestation(self) -> None:
        for case in (
            "missing-report-attestation",
            "missing-live-attestation",
            "mismatched-live-attestation",
        ):
            with self.subTest(case=case), RUNNER.temporary_directory(
                "runtime-ticket-zero-soak-tag-attestation-"
            ) as temporary:
                root = Path(temporary)
                report_path = root / "reports/allocator/runtime-ticket-zero-soak-1024.json"
                report_path.parent.mkdir(parents=True)
                previous = '{"status":"passed","prior":true}\n'
                report_path.write_text(previous, encoding="utf-8")
                milestone, pin, _ = self.successful_milestone_report(root)
                oracle = milestone["oracle"]
                assert isinstance(oracle, dict)
                if case == "missing-report-attestation":
                    oracle["tag_verified"] = None
                elif case == "missing-live-attestation":
                    (root / "allocator-cache/mimalloc-3.5.0.tag.json").unlink()
                else:
                    tag_path = root / "allocator-cache/mimalloc-3.5.0.tag.json"
                    tag_path.write_text(
                        json.dumps({"format": 1, "repository": "wrong"}) + "\n",
                        encoding="utf-8",
                    )
                source = self.clean_source_state()

                with self.patch_soak_artifact_roots(root), mock.patch.object(
                    RUNNER, "RUNTIME_TICKET_ZERO_SOAK_REPORT", report_path
                ), mock.patch.object(
                    RUNNER, "load_pin", return_value=pin
                ), mock.patch.object(
                    RUNNER,
                    "runtime_ticket_zero_soak_source_state",
                    side_effect=[source, source],
                ), mock.patch.object(RUNNER, "run_milestone0", return_value=milestone):
                    with self.assertRaisesRegex(RUNNER.HarnessError, "tag attestation"):
                        RUNNER.run_runtime_ticket_zero_soak(offline=True, architecture="aarch64")

                self.assertEqual(report_path.read_text(encoding="utf-8"), previous)

    def test_soak_expected_artifact_attestation_rejects_final_and_parent_symlinks(self) -> None:
        for kind in ("final", "parent"):
            with self.subTest(kind=kind), RUNNER.temporary_directory(
                "runtime-ticket-zero-soak-artifact-symlink-"
            ) as temporary:
                root = Path(temporary)
                expected = root / "artifacts/nested/live-artifact"
                expected.parent.mkdir(parents=True)
                expected.write_bytes(b"live artifact")
                if kind == "final":
                    target = expected.with_name("other-artifact")
                    expected.rename(target)
                    expected.symlink_to(target.name)
                else:
                    target_parent = expected.parent.with_name("other-artifacts")
                    expected.parent.rename(target_parent)
                    expected.parent.symlink_to(target_parent.name)

                record = RUNNER.artifact_record(expected)
                self.assertNotEqual(
                    record["path"], expected.relative_to(RUNNER.ROOT).as_posix()
                )

                with self.assertRaisesRegex(RUNNER.HarnessError, "not a regular file"):
                    RUNNER.attest_runtime_ticket_zero_soak_artifact(
                        record,
                        "fixture",
                        expected_path=expected,
                    )

    def test_soak_source_attestation_disables_git_optional_locks_and_rejects_dirty_state(self) -> None:
        revision = "a" * 40
        clean_records = [
            {"status": 0, "stdout": f"{revision}\n", "stderr": ""},
            {"status": 0, "stdout": "", "stderr": ""},
        ]
        with mock.patch.object(RUNNER.shutil, "which", return_value="/usr/bin/git"), mock.patch.object(
            RUNNER, "command_record", side_effect=clean_records
        ) as commands:
            self.assertEqual(RUNNER.runtime_ticket_zero_soak_source_state(), self.clean_source_state())
        self.assertEqual(commands.call_count, 2)
        self.assertTrue(
            all(
                call.kwargs["env"]["GIT_OPTIONAL_LOCKS"] == "0"
                for call in commands.call_args_list
            )
        )

        dirty_records = [
            {"status": 0, "stdout": f"{revision}\n", "stderr": ""},
            {"status": 0, "stdout": " M compat/allocator/run.py\0", "stderr": ""},
        ]
        with mock.patch.object(RUNNER.shutil, "which", return_value="/usr/bin/git"), mock.patch.object(
            RUNNER, "command_record", side_effect=dirty_records
        ):
            with self.assertRaisesRegex(RUNNER.HarnessError, "clean Git source"):
                RUNNER.runtime_ticket_zero_soak_source_state()

    def test_main_routes_soak_only_to_the_dedicated_stable_producer(self) -> None:
        with mock.patch.object(sys, "argv", ["run.py", "--soak"]), mock.patch.object(
            RUNNER, "run_runtime_ticket_zero_soak", return_value={}
        ) as soak, mock.patch.object(RUNNER, "run_milestone0") as milestone, mock.patch(
            "builtins.print"
        ) as output:
            self.assertEqual(RUNNER.main(), 0)

        soak.assert_called_once_with(offline=False, architecture="aarch64")
        milestone.assert_not_called()
        output.assert_called_once_with(RUNNER.RUNTIME_TICKET_ZERO_SOAK_REPORT)


class RuntimeTicketZeroSoakConsumerTests(unittest.TestCase):
    """Exercise the non-executing private-soak reader with hostile records."""

    @staticmethod
    def byte_record(payload: bytes) -> dict[str, object]:
        return {
            "bytes": len(payload),
            "hex": payload.hex(),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    @staticmethod
    def file_record(root: Path, path: Path) -> dict[str, object]:
        payload = path.read_bytes()
        return {
            "bytes": len(payload),
            "path": path.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    @classmethod
    def write_fixture(cls, root: Path) -> dict[str, object]:
        """Create a complete current private-soak record without running it."""

        def write(path: Path, payload: bytes) -> Path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            return path

        contract_path = root / "compat/allocator/runtime-ticket-zero-test-v3.5.0.json"
        header_path = root / (
            "compat/allocator/runtime-ticket-zero-adapter/"
            "crabc-mimalloc-runtime-ticket-zero-test.h"
        )
        fixture_source = root / (
            "compat/allocator/runtime-ticket-zero-adapter/"
            "runtime-ticket-zero-fixture.c"
        )
        write(
            contract_path,
            RUNNER.RUNTIME_TICKET_ZERO_ADAPTER_CONTRACT.read_bytes(),
        )
        write(
            header_path,
            RUNNER.RUNTIME_TICKET_ZERO_ADAPTER_HEADER.read_bytes(),
        )
        write(
            fixture_source,
            RUNNER.RUNTIME_TICKET_ZERO_ADAPTER_FIXTURE.read_bytes(),
        )
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        work_root = root / ".work"
        artifact_paths = RUNNER.runtime_ticket_zero_soak_consumer_artifact_paths(
            work_root
        )
        base_pin = RUNNER.load_pin()
        archive = artifact_paths["archive"]
        archive.parent.mkdir(parents=True, exist_ok=True)
        source_files: list[dict[str, object]] = []
        with tarfile.open(archive, mode="w:gz") as stream:
            for source_name in sorted(RUNNER.ORACLE_SOURCES):
                payload = f"synthetic {source_name}\n".encode()
                member = tarfile.TarInfo(f"{base_pin['archive_root']}/{source_name}")
                member.size = len(payload)
                stream.addfile(member, io.BytesIO(payload))
                source_files.append(
                    {
                        "bytes": len(payload),
                        "path": source_name,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                )
        adapter_archive = write(
            artifact_paths["adapter_archive"], b"synthetic adapter archive"
        )
        adapter_shared_library = write(
            artifact_paths["adapter_shared_library"], b"synthetic adapter shared"
        )
        fixture_binary = write(artifact_paths["fixture"], b"synthetic fixture")
        pin = {
            **base_pin,
            "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        }
        tag = {
            "format": 1,
            "repository": pin["repository"],
            "revision": pin["revision"],
            "tag": pin["tag"],
            "tag_object": pin["tag_object"],
        }
        write(
            artifact_paths["tag_attestation"],
            (json.dumps(tag, sort_keys=True) + "\n").encode(),
        )
        source = {
            "kind": "git",
            "revision": "a" * 40,
            "worktree_clean": True,
            "worktree_status": cls.byte_record(b""),
        }
        audit = RuntimeTicketZeroSoakReportTests.lifecycle_audit()
        stdout = (
            RUNNER.RUNTIME_TICKET_ZERO_LIFECYCLE_AUDIT_PREFIX
            + " ".join(f"{field}={audit[field]}" for field in audit)
            + "\n"
            + RUNNER.RUNTIME_TICKET_ZERO_LIFECYCLE_AUDIT_SUCCESS_LINE
            + "\n"
        )
        compiler = str(root / "pinned-container/bin/musl-gcc")
        fixture = {
            "artifact": cls.file_record(root, fixture_binary),
            "build_command": [
                compiler,
                "-std=c11",
                "-O2",
                "-fPIE",
                "-pie",
                "-ftls-model=initial-exec",
                "-pthread",
                "-I",
                str(header_path.parent),
                str(fixture_source),
                str(adapter_archive),
                "-o",
                str(fixture_binary),
            ],
            "run_command": RUNNER.runtime_ticket_zero_fixture_command(
                fixture_binary,
                worker_cycles=RUNNER.RUNTIME_TICKET_ZERO_SOAK_WORKER_CYCLES,
                stress_seed=RUNNER.RUNTIME_TICKET_ZERO_SOAK_STRESS_SEED,
            ),
            "stdout": stdout,
        }
        report = {
            "format": RUNNER.RUNTIME_TICKET_ZERO_SOAK_REPORT_FORMAT,
            "schema": RUNNER.RUNTIME_TICKET_ZERO_SOAK_REPORT_SCHEMA,
            "mode": "soak",
            "status": "passed",
            "evidence_scope": RUNNER.RUNTIME_TICKET_ZERO_SOAK_EVIDENCE_SCOPE,
            "nonclaims": list(RUNNER.RUNTIME_TICKET_ZERO_SOAK_NONCLAIMS),
            "contract": {
                "format": contract["format"],
                "record": cls.file_record(root, contract_path),
                "schema": contract["schema"],
                "soak_report": contract["soak_report"],
                "upstream": contract["upstream"],
            },
            "source": {
                "after": source,
                "before": source,
                "git_read_environment": {"GIT_OPTIONAL_LOCKS": "0"},
                "unchanged_during_execution": True,
            },
            "pin": {
                "archive": cls.file_record(root, archive),
                "archive_root": pin["archive_root"],
                "revision": pin["revision"],
                "sha256": pin["sha256"],
                "source": pin["source"],
                "tag_object": pin["tag_object"],
                "tag_verified": tag,
                "version": pin["version"],
            },
            "oracle": {
                "build_strategy": "pinned C oracle",
                "compiler": "musl-gcc (pinned container)",
                "source_files": source_files,
            },
            "target": {
                "architecture": "aarch64",
                "rust_target": RUNNER.PRODUCTION_RUST_TARGET,
                "system": "Linux",
            },
            "build_artifacts": {
                "adapter_archive": cls.file_record(root, adapter_archive),
                "adapter_shared_library": cls.file_record(root, adapter_shared_library),
            },
            "fixture": fixture,
            "schedule": {
                "stress_seed": f"0x{RUNNER.RUNTIME_TICKET_ZERO_SOAK_STRESS_SEED:016x}",
                "watchdog_seconds": RUNNER.RUNTIME_TICKET_ZERO_SOAK_WATCHDOG_SECONDS,
                "worker_cycles": RUNNER.RUNTIME_TICKET_ZERO_SOAK_WORKER_CYCLES,
                "worker_route_invocation_count": 2048,
                "worker_routes_per_cycle": 2,
            },
            "audit": {
                "audit_snapshot_count": 1025,
                "post_warm_cycle_count": 1023,
                "status": "passed",
                "warm_baseline": audit,
            },
        }
        report_path = work_root / "reports/allocator/runtime-ticket-zero-soak-1024.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")
        return {
            "artifact_paths": artifact_paths,
            "compiler": compiler,
            "contract_path": contract_path,
            "fixture_source": fixture_source,
            "header_path": header_path,
            "pin": pin,
            "report": report,
            "report_path": report_path,
            "root": root,
            "source": source,
            "work_root": work_root,
        }

    @classmethod
    def consume(cls, fixture: dict[str, object]) -> dict[str, object]:
        with mock.patch.object(
            RUNNER,
            "runtime_ticket_zero_soak_consumer_current_git_source_state",
            return_value=fixture["source"],
        ), mock.patch.object(RUNNER.shutil, "which", return_value=fixture["compiler"]):
            return RUNNER.consume_runtime_ticket_zero_soak_evidence(
                contract_path=fixture["contract_path"],
                report_path=fixture["report_path"],
                root=fixture["root"],
                work_root=fixture["work_root"],
                pin=fixture["pin"],
            )

    def test_consumer_accepts_one_current_fixed_private_report_without_execution(self) -> None:
        RUNNER.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            fixture = self.write_fixture(Path(temporary))
            with mock.patch.object(
                RUNNER,
                "run_runtime_ticket_zero_soak",
                side_effect=AssertionError("consumer must not execute soak"),
            ):
                evidence = self.consume(fixture)

        self.assertEqual(evidence["status"], "verified")
        self.assertEqual(evidence["report_path"], ".work/reports/allocator/runtime-ticket-zero-soak-1024.json")
        self.assertEqual(evidence["evidence_scope"], "bounded-private-ticket-zero-soak")
        self.assertEqual(evidence["nonclaims"], RUNNER.RUNTIME_TICKET_ZERO_SOAK_NONCLAIMS)
        self.assertEqual(evidence["schedule"]["worker_route_invocation_count"], 2048)
        self.assertEqual(evidence["source"]["after"], fixture["source"])

    def test_consumer_classifies_a_missing_fixed_report_and_rejects_redirects(self) -> None:
        RUNNER.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            root = Path(temporary)
            work_root = root / ".work"
            expected_contract = root / "compat/allocator/runtime-ticket-zero-test-v3.5.0.json"
            expected_report = work_root / "reports/allocator/runtime-ticket-zero-soak-1024.json"
            unavailable = RUNNER.consume_runtime_ticket_zero_soak_evidence(
                contract_path=expected_contract,
                report_path=expected_report,
                root=root,
                work_root=work_root,
                pin=RUNNER.load_pin(),
            )
            redirected = RUNNER.consume_runtime_ticket_zero_soak_evidence(
                contract_path=expected_contract,
                report_path=work_root / "reports/allocator/latest.json",
                root=root,
                work_root=work_root,
                pin=RUNNER.load_pin(),
            )

        self.assertEqual(unavailable["status"], "unavailable")
        self.assertEqual(redirected["status"], "rejected")
        self.assertIn("fixed raw", redirected["reason"])

    def test_consumer_rejects_mutated_contract_pin_command_schedule_audit_and_target(self) -> None:
        mutations = {
            "nonclaims": lambda report: report["nonclaims"].pop(),
            "contract-record": lambda report: report["contract"]["record"].update(
                {"path": "compat/allocator/other.json"}
            ),
            "pin-archive": lambda report: report["pin"]["archive"].update(
                {"path": ".work/allocator-cache/other.tar.gz"}
            ),
            "tag": lambda report: report["pin"]["tag_verified"].update(
                {"tag": "v0.0.0"}
            ),
            "oracle-source-member": lambda report: report["oracle"]["source_files"][0].update(
                {"path": "src/unreviewed.c"}
            ),
            "build-command": lambda report: report["fixture"]["build_command"].__setitem__(
                0, "/unreviewed/musl-gcc"
            ),
            "run-command": lambda report: report["fixture"]["run_command"].__setitem__(
                0, "/unreviewed/fixture"
            ),
            "schedule": lambda report: report["schedule"].update({"worker_cycles": 128}),
            "audit": lambda report: report["audit"]["warm_baseline"].update(
                {"live_tlds": 0}
            ),
            "target": lambda report: report["target"].update({"architecture": "x86_64"}),
            "source": lambda report: report["source"].update(
                {"after": {**report["source"]["after"], "revision": "b" * 40}}
            ),
        }
        RUNNER.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory(
                dir=RUNNER.TEMP_ROOT
            ) as temporary:
                fixture = self.write_fixture(Path(temporary))
                report = fixture["report"]
                assert isinstance(report, dict)
                mutate(report)
                Path(fixture["report_path"]).write_text(
                    json.dumps(report, sort_keys=True) + "\n", encoding="utf-8"
                )
                evidence = self.consume(fixture)

                self.assertEqual(evidence["status"], "rejected")
                self.assertIsInstance(evidence["reason"], str)

    def test_consumer_rejects_report_and_artifact_final_or_parent_symlinks(self) -> None:
        cases = (
            "report-final",
            "report-parent",
            "contract-final",
            "header-parent",
            "fixture-source-final",
            "tag-final",
            "artifact-final",
            "artifact-parent",
        )
        RUNNER.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory(
                dir=RUNNER.TEMP_ROOT
            ) as temporary:
                fixture = self.write_fixture(Path(temporary))
                report_path = Path(fixture["report_path"])
                artifact_paths = fixture["artifact_paths"]
                assert isinstance(artifact_paths, dict)
                if case == "report-final":
                    target = report_path.with_name("other-soak-report.json")
                    report_path.rename(target)
                    report_path.symlink_to(target.name)
                elif case == "report-parent":
                    parent = report_path.parent
                    target = parent.with_name("allocator-real")
                    parent.rename(target)
                    parent.symlink_to(target.name)
                elif case == "contract-final":
                    contract_path = Path(fixture["contract_path"])
                    target = contract_path.with_name("other-contract.json")
                    contract_path.rename(target)
                    contract_path.symlink_to(target.name)
                elif case == "header-parent":
                    header_path = Path(fixture["header_path"])
                    parent = header_path.parent
                    target = parent.with_name("runtime-ticket-zero-adapter-real")
                    parent.rename(target)
                    parent.symlink_to(target.name)
                elif case == "fixture-source-final":
                    fixture_source = Path(fixture["fixture_source"])
                    target = fixture_source.with_name("other-fixture.c")
                    fixture_source.rename(target)
                    fixture_source.symlink_to(target.name)
                elif case == "tag-final":
                    tag_path = artifact_paths["tag_attestation"]
                    assert isinstance(tag_path, Path)
                    target = tag_path.with_name("other-tag.json")
                    tag_path.rename(target)
                    tag_path.symlink_to(target.name)
                else:
                    archive = artifact_paths["adapter_archive"]
                    assert isinstance(archive, Path)
                    if case == "artifact-final":
                        target = archive.with_name("other-adapter.a")
                        archive.rename(target)
                        archive.symlink_to(target.name)
                    else:
                        parent = archive.parent
                        target = parent.with_name("release-real")
                        parent.rename(target)
                        parent.symlink_to(target.name)
                evidence = self.consume(fixture)

                self.assertEqual(evidence["status"], "rejected")
                self.assertIn("not a regular file", evidence["reason"])

    def test_main_full_renders_the_consumer_without_running_or_gating_the_soak(self) -> None:
        soak_evidence = {"status": "verified", "nonclaims": list(RUNNER.RUNTIME_TICKET_ZERO_SOAK_NONCLAIMS)}
        gate = {"overall_status": "passed", "unmet_required": []}
        with mock.patch.object(sys, "argv", ["run.py", "--full"]), mock.patch.object(
            RUNNER, "run_milestone0", return_value={}
        ), mock.patch.object(
            RUNNER, "consume_canonical_upstream_stress_evidence", return_value={"status": "unavailable"}
        ), mock.patch.object(
            RUNNER, "consume_runtime_ticket_zero_soak_evidence", return_value=soak_evidence
        ) as consumer, mock.patch.object(
            RUNNER, "run_runtime_ticket_zero_soak", side_effect=AssertionError("nested soak")
        ) as soak, mock.patch.object(
            RUNNER, "m5_gate_report", return_value=gate
        ) as m5_gate, mock.patch.object(RUNNER, "write_json") as write_report, mock.patch(
            "builtins.print"
        ):
            self.assertEqual(RUNNER.main(), 0)

        consumer.assert_called_once_with()
        soak.assert_not_called()
        self.assertIn("runtime_ticket_zero_soak", m5_gate.call_args.args[1])
        self.assertEqual(
            m5_gate.call_args.args[1]["runtime_ticket_zero_soak"], soak_evidence
        )
        write_report.assert_called_once()


class CanonicalUpstreamStressConsumerTests(unittest.TestCase):
    """Exercise the M5 consumer without compiling the canonical fixture."""

    @staticmethod
    def byte_record(payload: bytes) -> dict[str, object]:
        return {
            "bytes": len(payload),
            "hex": payload.hex(),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    @staticmethod
    def file_record(root: Path, path: Path) -> dict[str, object]:
        payload = path.read_bytes()
        return {
            "bytes": len(payload),
            "path": path.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    @classmethod
    def canonical_loader_record(cls, root: Path, path: Path) -> dict[str, object]:
        """Record the fixture stand-in as the literal external loader path."""

        return {
            **cls.file_record(root, path),
            "path": "/lib/ld-crabc-aarch64.so.1",
        }

    @staticmethod
    def write_synthetic_archive(
        path: Path, archive_root: str, member: str, payload: bytes
    ) -> Path:
        """Write a tiny archive for the archive/member binding boundary."""

        path.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(path, "w:gz") as stream:
            for directory in (archive_root, f"{archive_root}/test"):
                header = tarfile.TarInfo(directory)
                header.type = tarfile.DIRTYPE
                stream.addfile(header)
            header = tarfile.TarInfo(f"{archive_root}/{member}")
            header.size = len(payload)
            stream.addfile(header, io.BytesIO(payload))
        return path

    @classmethod
    def write_fixture(cls, root: Path) -> dict[str, object]:
        """Make one complete current-head report with live local artifacts."""

        work_root = root / ".work"
        contract_path = root / "compat/allocator/upstream-stress-v3.5.0.json"
        contract_path.parent.mkdir(parents=True)
        contract_path.write_bytes(
            (RUNNER.ALLOCATOR_ROOT / "upstream-stress-v3.5.0.json").read_bytes()
        )
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        staged_loader = root / "canonical-loader/ld-crabc-aarch64.so.1"
        pin = RUNNER.load_pin()
        backend = contract["backend_inventory"]["backends"][0]
        cargo_contract = backend["artifact_attestation"]["cargo_compiler_artifact"]
        artifact_ids = contract["report"]["artifact_ids"]

        def write(path: Path, payload: bytes) -> Path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            return path

        fixture_source = b"synthetic upstream test-stress source\n"
        archive = cls.write_synthetic_archive(
            work_root / "allocator-cache/mimalloc-3.5.0.tar.gz",
            str(pin["archive_root"]),
            str(contract["fixture"]["archive_member"]),
            fixture_source,
        )
        pin = {**pin, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
        fixture_contract = {
            **contract["fixture"],
            "sha256": hashlib.sha256(fixture_source).hexdigest(),
        }
        output = work_root / "target/compat/allocator/upstream-stress"
        binary = write(output / "canonical-upstream-test-stress", b"stress binary")
        target = root / "target/debug"
        selected_libc = write(target / "libc.so", b"selected shared libc")
        selected_static_libc = write(target / "libc.a", b"selected static libc")
        selected_loader = write(target / "libldso.so", b"selected loader")
        sysroot = root / "target/crabc-sysroot"
        manifest = write(sysroot / "share/crabc/manifest.json", b"{}\n")
        purity_payload = {
            "crt_sysroot_pure_rust": True,
            "full_runtime_pure_rust": False,
            "full_runtime_purity_status": "blocked_by_native_allocator",
        }
        purity = write(
            sysroot / "share/crabc/purity.json",
            (json.dumps(purity_payload, sort_keys=True) + "\n").encode(),
        )
        compiler = write(sysroot / "bin/crabc-cc", b"#!/bin/sh\n")
        staged_loader = write(staged_loader, b"selected loader")
        write(root / "libc/Cargo.toml", b"[package]\nname = \"crabc-libc\"\n")
        write(root / "libc/src/lib.rs", b"#![no_std]\n")

        shared_record = cls.file_record(root, selected_libc)
        static_record = cls.file_record(root, selected_static_libc)
        compiler_artifact = {
            "package_id": f"path+file://{root}/libc#crabc-libc@0.3.0",
            "target": cargo_contract["target"],
            "profile": cargo_contract["profile"],
            "features": cargo_contract["exact_features"],
            "filenames": [shared_record["path"], static_record["path"]],
            "fresh": False,
        }
        cargo_message_artifact = {
            "reason": "compiler-artifact",
            "package_id": compiler_artifact["package_id"],
            "manifest_path": str(root / "libc/Cargo.toml"),
            "target": {
                **cargo_contract["target"],
                "src_path": str(root / "libc/src/lib.rs"),
            },
            "profile": cargo_contract["profile"],
            "features": cargo_contract["exact_features"],
            "filenames": [str(selected_libc), str(selected_static_libc)],
            "executable": None,
            "fresh": False,
        }
        build_record_path = output / "selected-libc-build.json"
        write(
            build_record_path,
            (json.dumps(
                {
                    "format": cargo_contract["build_record_format"],
                    "schema": cargo_contract["build_record_schema"],
                    "cargo_command": cargo_contract["cargo_command"],
                    "semantic_profile": cargo_contract["semantic_profile"],
                    "compiler_artifact": cargo_message_artifact,
                    "artifacts": {
                        "selected_shared_libc": shared_record,
                        "selected_static_libc": static_record,
                    },
                },
                sort_keys=True,
            ) + "\n").encode(),
        )
        build_record = cls.file_record(root, build_record_path)
        source = {
            "kind": "git",
            "revision": "a" * 40,
            "worktree_clean": True,
            "worktree_status": cls.byte_record(b""),
        }
        companion_path = output / "selected-libc-build-current-head.json"
        write(
            companion_path,
            (json.dumps(
                {
                    "format": 1,
                    "schema": "crabc-selected-libc-current-head-build",
                    "source_before": source,
                    "source_after": source,
                    "source_unchanged_during_build": True,
                    "selected_libc_build_record": build_record,
                    "artifacts": {
                        "selected_shared_libc": shared_record,
                        "selected_static_libc": static_record,
                    },
                },
                sort_keys=True,
            ) + "\n").encode(),
        )
        companion = cls.file_record(root, companion_path)
        contract_record = cls.file_record(root, contract_path)
        source_member = {
            "bytes": len(fixture_source),
            "path": "mimalloc-3.5.0/test/test-stress.c",
            "sha256": fixture_contract["sha256"],
        }
        artifact_records = {
            "contract": contract_record,
            "upstream_archive": cls.file_record(root, archive),
            "source_member": source_member,
            "owned_sysroot_manifest": cls.file_record(root, manifest),
            "owned_sysroot_purity": cls.file_record(root, purity),
            "owned_compiler": cls.file_record(root, compiler),
            "selected_loader": cls.file_record(root, selected_loader),
            "staged_canonical_loader": cls.canonical_loader_record(root, staged_loader),
            "selected_libc": shared_record,
            "selected_static_libc": static_record,
            "selected_backend_build_record": build_record,
            "stress_binary": cls.file_record(root, binary),
        }
        assert set(artifact_records) == set(artifact_ids)

        matrix = contract["execution"]["matrix"]
        results = []
        for attempt, case in enumerate(matrix, start=1):
            stdout = str(case["expected_stdout"]).encode()
            stderr = str(case["expected_stderr"]).encode()
            results.append(
                {
                    "case": {
                        key: case[key]
                        for key in ("id", "workers", "scale", "iterations", "arguments")
                    },
                    "process_attempt": attempt,
                    "state": "passed",
                    "observation": {
                        "command": [str(binary), *case["arguments"]],
                        "kind": "process",
                        "status": case["expected_exit_status"],
                        "stdout": cls.byte_record(stdout),
                        "stderr": cls.byte_record(stderr),
                    },
                }
            )
        report = {
            "format": contract["report"]["format"],
            "schema": contract["report"]["schema"],
            "status": "passed",
            "contract": {**contract_record, "upstream": contract["upstream"]},
            "artifacts": artifact_records,
            "fixture": {
                "archive_member": fixture_contract["archive_member"],
                "expected_sha256": fixture_contract["sha256"],
                "source_adaptation": {
                    "compile_defines": contract["source_adaptation"]["compile_defines"],
                    "patches": contract["source_adaptation"]["patches"],
                },
                "observed_source": source_member,
            },
            "execution": {
                "attempted": True,
                "attempted_process_count": len(matrix),
                "case_count": len(matrix),
                "case_results": results,
                "process_attempts_per_case": 1,
                "source_randomness": contract["execution"]["source_randomness"],
                "watchdog": contract["execution"]["watchdog"],
            },
            "requested_runtime": {
                "allocator_feature": contract["compile_requirements"]["allocator_feature"],
                "backend": backend["id"],
                "target_dir": "target/debug",
                "output_dir": output.relative_to(root).as_posix(),
                "selected_libc_build_record": build_record_path.relative_to(root).as_posix(),
                "current_head_build_record": companion_path.relative_to(root).as_posix(),
            },
            "selection": {
                "target": contract["target_inventory"]["targets"][0],
                "backend": backend["id"],
            },
            "runtime": {
                "compiler": compiler.relative_to(root).as_posix(),
                "backend_attestation": {
                    "backend": backend["id"],
                    "status": "passed",
                    "semantic_profile": cargo_contract["semantic_profile"],
                    "cargo_features": cargo_contract["exact_features"],
                    "build_record": build_record,
                    "compiler_artifact": compiler_artifact,
                    "artifacts": {
                        "selected_shared_libc": shared_record,
                        "selected_static_libc": static_record,
                    },
                    "exported_free": {
                        "symbol": "free",
                        "required_callee_suffix": backend["artifact_attestation"]["exported_free_route"]["required_callee_suffix"],
                        "forbidden_callee_suffix": backend["artifact_attestation"]["exported_free_route"]["forbidden_callee_suffix"],
                        "disassembly_sha256": "2" * 64,
                    },
                },
                "environment": {},
                "sysroot": sysroot.relative_to(root).as_posix(),
                "sysroot_purity": {
                    "crt_sysroot_pure_rust": True,
                    "full_runtime_pure_rust": False,
                    "full_runtime_purity_status": "blocked_by_native_allocator",
                },
            },
            "fixture_elf": {
                "dynamic_dependencies": contract["compile_requirements"]["expected_dynamic_dependencies"],
                "elf_identity": contract["compile_requirements"]["expected_elf_identity"],
                "interpreter": contract["compile_requirements"]["expected_interpreter"],
            },
            "dynamic_dependencies": contract["compile_requirements"]["expected_dynamic_dependencies"],
            "capability": {
                "failure_closed": True,
                "fully_verified_worker_counts": contract["capability"]["required_worker_counts"],
                "id": contract["capability"]["id"],
                "native_execution_completed": True,
                "native_execution_started": True,
                "passed_case_count": len(matrix),
                "required_case_count": len(matrix),
                "required_worker_counts": contract["capability"]["required_worker_counts"],
                "status": "passed",
            },
            "current_head": {
                "status": "attested",
                "record": companion,
                "source": source,
            },
            "blocked": None,
            "first_fact": {
                "kind": "pass",
                "stage": "matrix",
                "completed_case_count": len(matrix),
            },
            "upstream_pin": {
                "archive_root": contract["upstream"]["archive_root"],
                "repository": contract["upstream"]["repository"],
                "revision": contract["upstream"]["revision"],
                "sha256": pin["sha256"],
                "source": pin["source"],
                "tag": pin["tag"],
                "tag_object": pin["tag_object"],
                "version": pin["version"],
            },
        }
        report_path = work_root / "reports/allocator/upstream-stress/latest.json"
        report_path.parent.mkdir(parents=True)
        report_path.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")
        summary = RUNNER.validate_canonical_upstream_stress_contract(
            contract, RUNNER.load_pin()
        )
        summary["fixture"] = fixture_contract
        return {
            "contract": contract,
            "contract_path": contract_path,
            "pin": pin,
            "report": report,
            "report_path": report_path,
            "root": root,
            "source": source,
            "work_root": work_root,
            "archive_record": artifact_records["upstream_archive"],
            "source_member": source_member,
            "staged_loader": staged_loader,
            "summary": summary,
            "contract_record": contract_record,
        }

    @classmethod
    def validate_fixture(
        cls, fixture: dict[str, object], *, source_state: object | None = None
    ) -> dict[str, object]:
        """Exercise report validation with a synthetic archive pin unmocked.

        The production consumer validates the checked-in literal contract and
        pin first. This isolated fixture instead passes a coherent synthetic
        archive/pin/fixture triple directly to the report validator, so its
        tar extraction and report binding remain real without pretending the
        synthetic tarball is the pinned upstream archive. Its staged loader
        record stays execution-scoped evidence: no later `/lib` file is
        fabricated or read by this test.
        """

        with mock.patch.object(
            RUNNER,
            "canonical_current_git_source_state",
            return_value=(fixture["source"] if source_state is None else source_state),
        ):
            try:
                verified = RUNNER.canonical_upstream_stress_validate_report(
                    fixture["report"],
                    root=fixture["root"],
                    work_root=fixture["work_root"],
                    contract=fixture["contract"],
                    contract_record=fixture["contract_record"],
                    summary=fixture["summary"],
                    pin=fixture["pin"],
                )
            except RUNNER.CanonicalUpstreamStressRejected as error:
                return {"status": "rejected", "reason": str(error)}
            return {"status": "verified", **verified}

    @classmethod
    def consume_unavailable(cls, fixture: dict[str, object]) -> dict[str, object]:
        return RUNNER.consume_canonical_upstream_stress_evidence(
            contract_path=fixture["contract_path"],
            report_path=fixture["report_path"],
            root=fixture["root"],
            work_root=fixture["work_root"],
            pin=RUNNER.load_pin(),
        )

    def test_report_validator_accepts_execution_scoped_staged_loader_record(self) -> None:
        RUNNER.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            fixture = self.write_fixture(Path(temporary))
            Path(fixture["staged_loader"]).unlink()
            observed_file_record = RUNNER.canonical_upstream_stress_observed_file_record
            with mock.patch.object(
                RUNNER,
                "canonical_upstream_stress_observed_file_record",
                wraps=observed_file_record,
            ) as live_reads:
                evidence = self.validate_fixture(fixture)

        self.assertEqual(evidence["status"], "verified")
        self.assertEqual(evidence["evidence_scope"], "shadow_subset")
        self.assertEqual(evidence["matrix"], {"case_count": 12, "worker_counts": [1, 2, 4, 8]})
        self.assertEqual(evidence["large_object_mode"]["status"], "source-cli-enabled")
        self.assertEqual(evidence["current_head"]["source"], fixture["source"])
        self.assertFalse(
            any(
                call.args[1] == Path("/lib/ld-crabc-aarch64.so.1")
                for call in live_reads.call_args_list
            )
        )

    def test_archive_member_binding_rejects_a_coherent_archive_substitution(self) -> None:
        RUNNER.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            root = Path(temporary)
            archive = self.write_synthetic_archive(
                root / ".work/allocator-cache/mimalloc-3.5.0.tar.gz",
                "mimalloc-test",
                "test/test-stress.c",
                b"pinned source member\n",
            )
            pin = {
                "archive_root": "mimalloc-test",
                "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            }
            fixture = {
                "archive_member": "test/test-stress.c",
                "sha256": hashlib.sha256(b"pinned source member\n").hexdigest(),
            }
            archive_record, source_record = RUNNER.canonical_upstream_stress_archive_source_member(
                root, archive, pin, fixture
            )

            self.assertEqual(archive_record, self.file_record(root, archive))
            self.assertEqual(source_record["bytes"], len(b"pinned source member\n"))

            # Simulate an attacker replacing both the live archive and its
            # report artifact record. The immutable pin still rejects it.
            self.write_synthetic_archive(
                archive,
                "mimalloc-test",
                "test/test-stress.c",
                b"substituted source member\n",
            )
            substituted_report_record = self.file_record(root, archive)
            RUNNER.canonical_upstream_stress_live_file_record(
                root,
                substituted_report_record,
                "upstream archive",
                expected_path=archive,
            )
            with self.assertRaisesRegex(
                RUNNER.CanonicalUpstreamStressRejected, "pinned digest"
            ):
                RUNNER.canonical_upstream_stress_archive_source_member(
                    root, archive, pin, fixture
                )

            # The checked-in pin also rejects a report/artifact substitution
            # that is internally coherent with this different archive.
            with self.assertRaisesRegex(
                RUNNER.CanonicalUpstreamStressRejected, "pinned digest"
            ):
                RUNNER.canonical_upstream_stress_archive_source_member(
                    root,
                    archive,
                    RUNNER.load_pin(),
                    RUNNER.read_json(RUNNER.CANONICAL_UPSTREAM_STRESS_CONTRACT)[
                        "fixture"
                    ],
                )

            substituted_pin = {**pin, "sha256": substituted_report_record["sha256"]}
            with self.assertRaisesRegex(
                RUNNER.CanonicalUpstreamStressRejected, "fixture digest"
            ):
                RUNNER.canonical_upstream_stress_archive_source_member(
                    root, archive, substituted_pin, fixture
                )

    def test_contract_rejects_redirected_loader_or_purity_policy(self) -> None:
        contract = RUNNER.read_json(RUNNER.CANONICAL_UPSTREAM_STRESS_CONTRACT)
        redirected = json.loads(json.dumps(contract))
        redirected["compile_requirements"]["canonical_loader"] = "/tmp/redirected-loader"
        with self.assertRaisesRegex(
            RUNNER.CanonicalUpstreamStressRejected, "canonical loader"
        ):
            RUNNER.validate_canonical_upstream_stress_contract(
                redirected, RUNNER.load_pin()
            )

        policy_drift = json.loads(json.dumps(contract))
        policy_drift["compile_requirements"]["sysroot_purity"][
            "allowed_full_runtime_purity"
        ].pop()
        with self.assertRaisesRegex(
            RUNNER.CanonicalUpstreamStressRejected, "sysroot purity"
        ):
            RUNNER.validate_canonical_upstream_stress_contract(
                policy_drift, RUNNER.load_pin()
            )

        broadened_scope = json.loads(json.dumps(contract))
        broadened_scope["report"]["execution_scoped_artifact_ids"].append(
            "selected_loader"
        )
        with self.assertRaisesRegex(
            RUNNER.CanonicalUpstreamStressRejected, "report policy"
        ):
            RUNNER.validate_canonical_upstream_stress_contract(
                broadened_scope, RUNNER.load_pin()
            )

    def test_contract_rejects_promotion_or_source_ownership_scope_drift(self) -> None:
        contract = RUNNER.read_json(RUNNER.CANONICAL_UPSTREAM_STRESS_CONTRACT)

        promotion_scope = json.loads(json.dumps(contract))
        promotion_scope["scope"]["not_a_promotion_gate"] = False
        with self.assertRaisesRegex(
            RUNNER.CanonicalUpstreamStressRejected, "scope or nonpromotion"
        ):
            RUNNER.validate_canonical_upstream_stress_contract(
                promotion_scope, RUNNER.load_pin()
            )

        compile_time_large_mode = json.loads(json.dumps(contract))
        compile_time_large_mode["source_adaptation"]["compile_defines"].append(
            "ALLOW_LARGE"
        )
        with self.assertRaisesRegex(
            RUNNER.CanonicalUpstreamStressRejected, "source adaptation"
        ):
            RUNNER.validate_canonical_upstream_stress_contract(
                compile_time_large_mode, RUNNER.load_pin()
            )

        threshold_100_or_lower = json.loads(json.dumps(contract))
        threshold_100_or_lower["execution"]["large_object_mode"][
            "source_enablement"
        ]["threshold"] = 99
        with self.assertRaisesRegex(
            RUNNER.CanonicalUpstreamStressRejected, "execution policy"
        ):
            RUNNER.validate_canonical_upstream_stress_contract(
                threshold_100_or_lower, RUNNER.load_pin()
            )

        moved_initial_thread_cleanup = json.loads(json.dumps(contract))
        moved_initial_thread_cleanup["execution"]["scheduler_and_ownership"].pop()
        with self.assertRaisesRegex(
            RUNNER.CanonicalUpstreamStressRejected, "execution policy"
        ):
            RUNNER.validate_canonical_upstream_stress_contract(
                moved_initial_thread_cleanup, RUNNER.load_pin()
            )

    def test_report_validator_rejects_relabelled_runtime_artifact_or_execution_scoped_loader_drift(self) -> None:
        RUNNER.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            fixture = self.write_fixture(Path(temporary))
            root = Path(fixture["root"])
            relabelled_manifest = root / "target/other/manifest.json"
            relabelled_manifest.parent.mkdir(parents=True)
            relabelled_manifest.write_bytes(b"{}\n")
            report = fixture["report"]
            assert isinstance(report, dict)
            report["artifacts"]["owned_sysroot_manifest"] = self.file_record(
                root, relabelled_manifest
            )
            relabelled_evidence = self.validate_fixture(fixture)

        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            fixture = self.write_fixture(Path(temporary))
            root = Path(fixture["root"])
            staged_loader = root / "canonical-loader/ld-crabc-aarch64.so.1"
            staged_loader.write_bytes(b"different staged loader")
            report = fixture["report"]
            assert isinstance(report, dict)
            report["artifacts"]["staged_canonical_loader"] = self.canonical_loader_record(
                root, staged_loader
            )
            mismatch_evidence = self.validate_fixture(fixture)

        scoped_path_evidence: list[dict[str, object]] = []
        for staged_path in (
            "canonical-loader/ld-crabc-aarch64.so.1",
            "/lib/not-the-crabc-loader.so",
        ):
            with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
                fixture = self.write_fixture(Path(temporary))
                report = fixture["report"]
                assert isinstance(report, dict)
                record = dict(report["artifacts"]["staged_canonical_loader"])
                record["path"] = staged_path
                report["artifacts"]["staged_canonical_loader"] = record
                scoped_path_evidence.append(self.validate_fixture(fixture))

        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            fixture = self.write_fixture(Path(temporary))
            report = fixture["report"]
            assert isinstance(report, dict)
            report["artifacts"]["staged_canonical_loader"] = {
                "bytes": 0,
                "path": "/lib/ld-crabc-aarch64.so.1",
                "sha256": hashlib.sha256(b"").hexdigest(),
            }
            empty_evidence = self.validate_fixture(fixture)

        self.assertEqual(relabelled_evidence["status"], "rejected")
        self.assertIn("owned sysroot manifest", relabelled_evidence["reason"])
        self.assertEqual(mismatch_evidence["status"], "rejected")
        self.assertIn("staged loader", mismatch_evidence["reason"])
        for evidence in scoped_path_evidence:
            self.assertEqual(evidence["status"], "rejected")
            self.assertIn("fixed execution path", evidence["reason"])
        self.assertEqual(empty_evidence["status"], "rejected")
        self.assertIn("fixed execution path", empty_evidence["reason"])

    def test_consumer_records_an_absent_fixed_report_as_unavailable(self) -> None:
        RUNNER.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            fixture = self.write_fixture(Path(temporary))
            Path(fixture["report_path"]).unlink()
            evidence = self.consume_unavailable(fixture)

        self.assertEqual(evidence["status"], "unavailable")
        self.assertIsNone(evidence["report"])
        self.assertIsNone(evidence["current_head"])

    def test_consumer_rejects_stale_or_dirty_current_git_source(self) -> None:
        RUNNER.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            fixture = self.write_fixture(Path(temporary))
            stale = json.loads(json.dumps(fixture["source"]))
            stale["revision"] = "b" * 40
            stale_evidence = self.validate_fixture(fixture, source_state=stale)
            dirty = json.loads(json.dumps(fixture["source"]))
            dirty["worktree_clean"] = False
            dirty["worktree_status"] = self.byte_record(b" M compat/allocator/run.py\0")
            dirty_evidence = self.validate_fixture(fixture, source_state=dirty)

        self.assertEqual(stale_evidence["status"], "rejected")
        self.assertIn("source", stale_evidence["reason"])
        self.assertEqual(dirty_evidence["status"], "rejected")
        self.assertIn("clean Git", dirty_evidence["reason"])

    def test_consumer_rejects_tampered_live_artifact_or_companion(self) -> None:
        RUNNER.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            fixture = self.write_fixture(Path(temporary))
            shared = Path(fixture["root"]) / "target/debug/libc.so"
            shared.write_bytes(b"tampered selected shared libc")
            artifact_evidence = self.validate_fixture(fixture)

        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            fixture = self.write_fixture(Path(temporary))
            companion_path = (
                Path(fixture["root"])
                / ".work/target/compat/allocator/upstream-stress/selected-libc-build-current-head.json"
            )
            companion = json.loads(companion_path.read_text(encoding="utf-8"))
            companion["source_unchanged_during_build"] = False
            companion_path.write_text(json.dumps(companion, sort_keys=True) + "\n", encoding="utf-8")
            report = fixture["report"]
            assert isinstance(report, dict)
            report["current_head"]["record"] = self.file_record(
                Path(fixture["root"]), companion_path
            )
            Path(fixture["report_path"]).write_text(
                json.dumps(report, sort_keys=True) + "\n", encoding="utf-8"
            )
            companion_evidence = self.validate_fixture(fixture)

        self.assertEqual(artifact_evidence["status"], "rejected")
        self.assertIn("selected shared libc", artifact_evidence["reason"])
        self.assertEqual(companion_evidence["status"], "rejected")
        self.assertIn("companion", companion_evidence["reason"])

    def test_consumer_rejects_missing_forged_or_legacy_large_object_matrix_rows(self) -> None:
        RUNNER.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            fixture = self.write_fixture(Path(temporary))
            report = fixture["report"]
            assert isinstance(report, dict)
            report["execution"]["case_results"].pop()
            Path(fixture["report_path"]).write_text(
                json.dumps(report, sort_keys=True) + "\n", encoding="utf-8"
            )
            partial_evidence = self.validate_fixture(fixture)

        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            fixture = self.write_fixture(Path(temporary))
            report = fixture["report"]
            assert isinstance(report, dict)
            forged = report["execution"]["case_results"][-1]
            forged["case"]["scale"] = 100
            forged["case"]["arguments"] = ["8", "100", "1"]
            forged["case"]["id"] = "workers-8-scale-100-iterations-1"
            forged["observation"]["command"][-2] = "100"
            forged["observation"]["stdout"] = self.byte_record(
                b"Using 8 threads with a 100% load-per-thread and 1 iterations\n"
            )
            forged_evidence = self.validate_fixture(fixture)

        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            fixture = self.write_fixture(Path(temporary))
            report = fixture["report"]
            assert isinstance(report, dict)
            report["execution"]["case_results"][-4:] = reversed(
                report["execution"]["case_results"][-4:]
            )
            reordered_evidence = self.validate_fixture(fixture)

        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            fixture = self.write_fixture(Path(temporary))
            report = fixture["report"]
            assert isinstance(report, dict)
            report["format"] = 6
            report["execution"]["case_results"] = report["execution"]["case_results"][:8]
            report["execution"]["attempted_process_count"] = 8
            report["execution"]["case_count"] = 8
            report["capability"]["passed_case_count"] = 8
            report["capability"]["required_case_count"] = 8
            report["first_fact"]["completed_case_count"] = 8
            legacy_evidence = self.validate_fixture(fixture)

        with tempfile.TemporaryDirectory(dir=RUNNER.TEMP_ROOT) as temporary:
            fixture = self.write_fixture(Path(temporary))
            report = fixture["report"]
            assert isinstance(report, dict)
            report["format"] = 1
            report["schema"] = (
                "crabc-mimalloc-canonical-upstream-stress-current-head-diagnostic-report"
            )
            Path(fixture["report_path"]).write_text(
                json.dumps(report, sort_keys=True) + "\n", encoding="utf-8"
            )
            diagnostic_evidence = self.validate_fixture(fixture)

        self.assertEqual(partial_evidence["status"], "rejected")
        self.assertIn("partial matrix", partial_evidence["reason"])
        self.assertEqual(forged_evidence["status"], "rejected")
        self.assertIn("matrix result drifted", forged_evidence["reason"])
        self.assertEqual(reordered_evidence["status"], "rejected")
        self.assertIn("matrix result drifted", reordered_evidence["reason"])
        self.assertEqual(legacy_evidence["status"], "rejected")
        self.assertIn("schema", legacy_evidence["reason"])
        self.assertEqual(diagnostic_evidence["status"], "rejected")
        self.assertIn("schema", diagnostic_evidence["reason"])

    def test_consumer_git_reads_disable_optional_locks(self) -> None:
        revision = "a" * 40
        completed = [
            subprocess.CompletedProcess(
                args=["git", "rev-parse", "--verify", "HEAD"],
                returncode=0,
                stdout=f"{revision}\n".encode(),
                stderr=b"",
            ),
            subprocess.CompletedProcess(
                args=["git", "status"], returncode=0, stdout=b"", stderr=b""
            ),
        ]
        with mock.patch.dict(
            RUNNER.os.environ,
            {"HOME": "/attested/home", "PATH": "/attested/bin"},
            clear=True,
        ), mock.patch.object(
            RUNNER.shutil, "which", return_value="/attested/bin/git"
        ), mock.patch.object(RUNNER.subprocess, "run", side_effect=completed) as git_reads:
            state = RUNNER.canonical_current_git_source_state(Path("/attested/root"))

        self.assertEqual(state["revision"], revision)
        self.assertTrue(state["worktree_clean"])
        self.assertEqual(len(git_reads.call_args_list), 2)
        for call in git_reads.call_args_list:
            environment = call.kwargs["env"]
            self.assertEqual(environment["GIT_OPTIONAL_LOCKS"], "0")
            self.assertEqual(environment["HOME"], "/attested/home")
            self.assertEqual(environment["PATH"], "/attested/bin")


if __name__ == "__main__":
    unittest.main()
