#!/usr/bin/env python3
"""Structural contract tests for the private general-TLS RuntimeV1 wire."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MANIFEST = ROOT / "ldso" / "Cargo.toml"
BUILD = ROOT / "ldso" / "build.rs"
LOADER = ROOT / "ldso" / "src" / "x86_64_initial_graph.rs"
GRAPH = ROOT / "ldso" / "src" / "x86_64_general_initial_graph.rs"
STATE = ROOT / "ldso" / "src" / "x86_64_general_initial_tls_state.rs"
COMMON_STATE = ROOT / "ldso" / "src" / "x86_64_general_initial_loader_state.rs"
SOURCE_ROOT = ROOT / "ldso" / "src" / "x86_64_general_initial_tls_runtime_v1_source_root.rs"
ORDINARY_TLS_ROOT = ROOT / "ldso" / "src" / "x86_64_general_initial_tls_source_root.rs"
CONSUMER = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "loader_tls_runtime_v1.rs"
RUNNER = ROOT / "compat" / "x86_64" / "run_loader_libc_general_tls_runtime_v1.sh"
TARGET_RUNNER = (
    ROOT / "compat" / "x86_64" / "run_loader_libc_general_tls_runtime_v1_target_root.sh"
)
MAIN = ROOT / "compat" / "x86_64" / "loader_libc_general_tls_runtime_v1_main.c"
SHARED = ROOT / "compat" / "x86_64" / "loader_libc_general_tls_runtime_v1_shared.c"
STRONG_MAIN = (
    ROOT / "compat" / "x86_64" / "loader_libc_general_tls_runtime_v1_strong_main_record.c"
)
WEAK_DSO = (
    ROOT / "compat" / "x86_64" / "loader_libc_general_tls_runtime_v1_weak_dso_record.c"
)


class GeneralLoaderLibcTlsRuntimeV1Tests(unittest.TestCase):
    def test_cfg_wire_requires_general_graph_and_tls_and_is_disjoint_from_fixed_siblings(self) -> None:
        manifest = MANIFEST.read_text(encoding="utf-8")
        build = BUILD.read_text(encoding="utf-8")
        loader = LOADER.read_text(encoding="utf-8")
        root = SOURCE_ROOT.read_text(encoding="utf-8")
        ordinary_root = ORDINARY_TLS_ROOT.read_text(encoding="utf-8")

        self.assertIn("x86_64-general-initial-tls-runtime-v1-interpreter", manifest)
        for required in (
            "crabc_general_initial_graph",
            "crabc_general_initial_tls_materialization_v1",
            "crabc_general_loader_libc_tls_runtime_v1",
        ):
            with self.subTest(required=required):
                self.assertIn(required, build)
                self.assertIn(required, root)
                self.assertIn(required, loader)
        self.assertNotIn("crabc_general_loader_libc_tls_runtime_v1", ordinary_root)
        for disjoint_sibling in (
            "crabc_loader_libc_tls_runtime_v1",
            "crabc_owned_crt_handoff",
            "crabc_fixed_graph_dlfcn",
            "crabc_bounded_runtime_dlopen",
        ):
            with self.subTest(disjoint_sibling=disjoint_sibling):
                self.assertIn(disjoint_sibling, loader)
        self.assertIn("requires general initial TLS materialization", loader)
        self.assertIn("disjoint from fixed RuntimeV1, CRT, and dlfcn siblings", loader)

    def test_descriptor_is_exact_hidden_writable_and_ready_last(self) -> None:
        state = STATE.read_text(encoding="utf-8")
        loader = LOADER.read_text(encoding="utf-8")

        for required in (
            "struct GeneralLoaderLibcTlsRuntimeV1",
            "magic: u64",
            "version: u32",
            "abi_size: u32",
            "process_mode: u32",
            "owner: u32",
            "state: AtomicU8",
            "reserved: [u8; 7]",
            "thread_pointer: *const u8",
            "dtv: *const usize",
            "dtv_words: usize",
            "module_count: usize",
            "generation: u64",
            "size_of::<GeneralLoaderLibcTlsRuntimeV1>() == 72",
            "#[link_section = \".data.crabc_general_loader_tls_runtime_v1\"]",
            "static mut __crabc_x86_64_loader_tls_runtime_v1",
            "GENERAL_LOADER_TLS_RUNTIME_V1_STATE_UNPUBLISHED",
            "GENERAL_LOADER_TLS_RUNTIME_V1_STATE_PUBLISHING",
            "GENERAL_LOADER_TLS_RUNTIME_V1_STATE_READY",
        ):
            with self.subTest(required=required):
                self.assertIn(required, state)
        self.assertIn('.hidden __crabc_x86_64_loader_tls_runtime_v1', loader)

        publish = state[
            state.index("unsafe fn publish_reserved_loader_tls_runtime_v1") : state.index(
                "impl GeneralInitialTlsState"
            )
        ]
        self.assertNotIn("compare_exchange", publish)
        self.assertNotIn("Result<", publish)
        self.assertLess(publish.index("thread_pointer"), publish.index(".store("))
        self.assertLess(publish.index("dtv_words"), publish.index(".store("))
        self.assertLess(publish.index("module_count"), publish.index(".store("))
        self.assertIn("GENERAL_LOADER_TLS_RUNTIME_V1_STATE_READY", publish)

    def test_paired_pre_fs_reservation_rolls_back_both_and_commit_has_no_fallible_successor(self) -> None:
        graph = GRAPH.read_text(encoding="utf-8")
        state = STATE.read_text(encoding="utf-8")
        common_state = COMMON_STATE.read_text(encoding="utf-8")

        self.assertLess(
            graph.index("state.reserve_publication()"),
            graph.index("state.reserve_runtime_v1_publication()"),
        )
        self.assertLess(
            graph.index("state.reserve_runtime_v1_publication()"),
            graph.index("state.materialize_initial_tls()"),
        )
        self.assertLess(
            graph.index("state.materialize_initial_tls()"),
            graph.index("state.commit_runtime_v1(installed)"),
        )
        commit_call = graph.index("state.commit_runtime_v1(installed)")
        self.assertLess(
            commit_call,
            graph.index("dispatch_dependency_initializers", commit_call),
        )
        self.assertIn("validate_runtime_v1_preflight", state)
        self.assertIn("RuntimeV1PublicationReserved", state)
        self.assertIn("release_loader_tls_runtime_v1_descriptor_reservation", state)

        abort = state[
            state.index("pub(crate) fn abort") : state.index(
                "/// Rolls back a TLS planner failure"
            )
        ]
        self.assertLess(
            abort.index("release_loader_tls_runtime_v1_descriptor_reservation"),
            abort.index("self.loader.abort"),
        )

        common_rollback = common_state[
            common_state.index("pub(crate) fn rollback") : common_state.index(
                "/// Writes and release-publishes"
            )
        ]
        self.assertIn("GENERAL_INITIAL_LOADER_PUBLICATION", common_rollback)
        self.assertLess(
            common_rollback.index("GENERAL_INITIAL_LOADER_PUBLICATION"),
            common_rollback.index("graph.rollback_to_main"),
        )

        commit = state[
            state.index("pub(crate) unsafe fn commit_runtime_v1") : state.index(
                "/// Rolls back the map-owned portion"
            )
        ]
        self.assertNotIn("compare_exchange", commit)
        self.assertNotIn("Result<", commit)
        self.assertLess(
            commit.index("self.loader.commit()"),
            commit.index("publish_reserved_loader_tls_runtime_v1"),
        )

    def test_libc_stays_an_observer_and_validates_before_fs_or_dtv_observation(self) -> None:
        consumer = CONSUMER.read_text(encoding="utf-8")

        validation = consumer.index("unsafe fn validate_loader_tls_runtime_v1")
        fs_observation = consumer.index("unsafe fn current_thread_pointer")
        volatile_read = consumer.index("read_volatile")
        self.assertLess(validation, fs_observation)
        self.assertLess(validation, volatile_read)
        self.assertIn("header.abi_size != RECORD_SIZE", consumer)
        self.assertIn("record.state.load(Ordering::Acquire)", consumer)
        self.assertIn("record.process_mode != PROCESS_MODE_DYNAMIC", consumer)
        self.assertIn("record.owner != OWNER_LDSO", consumer)
        self.assertIn("record.generation != GENERATION_INITIAL", consumer)
        self.assertIn("record.dtv_words < record.module_count.checked_add(1)?", consumer)
        for excluded in ("ARCH_SET_FS", "SYS_MMAP", "fn __tls_get_addr", "alloc::"):
            with self.subTest(excluded=excluded):
                self.assertNotIn(excluded, consumer)

    def test_direct_and_target_root_runner_cover_positive_graph_and_independent_negatives(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        target_runner = TARGET_RUNNER.read_text(encoding="utf-8")
        main = MAIN.read_text(encoding="utf-8")
        shared = SHARED.read_text(encoding="utf-8")
        strong_main = STRONG_MAIN.read_text(encoding="utf-8")
        weak_dso = WEAK_DSO.read_text(encoding="utf-8")

        for required in (
            "build_source_loader",
            "build_cargo_loader",
            "x86_64-general-initial-tls-runtime-v1-interpreter",
            "general-runtime-v1-state-tests",
            "rustc --edition=2021 --test",
            "for malformed in magic version abi_size mode owner generation",
            "poisoned-dtv",
            "SHT_SYMTAB",
            "SHT_DYNSYM",
            "PT_GNU_RELRO",
            "page-rounded PT_GNU_RELRO",
            "--export-dynamic-symbol=general_runtime_v1_constructor_attach",
            "--export-dynamic-symbol=__crabc_x86_64_loader_tls_runtime_v1",
            "strong-main-record.o",
            "libleft-weak-record.so",
            "expect_rejection_before_fs",
            "no-arch-set-fs-trace",
            "run_ldso_general_initial_tls.sh",
            "main-static",
        ):
            with self.subTest(required=required):
                self.assertIn(required, runner)
        self.assertIn("CRABC_LDSO_GENERAL_TLS_RUNTIME_V1_ROOT=crabc-target", target_runner)
        self.assertIn("general_runtime_v1_constructor_attach", main)
        self.assertIn("exact_general_initial_dtv", main)
        self.assertIn("general_shared_initializer", shared)
        self.assertIn("general_runtime_v1_constructor_attach", shared)
        self.assertIn("extern const unsigned char __crabc_x86_64_loader_tls_runtime_v1", strong_main)
        self.assertNotIn("__attribute__((weak))", strong_main)
        self.assertIn("__attribute__((weak))", weak_dso)


if __name__ == "__main__":
    unittest.main()
