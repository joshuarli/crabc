#!/usr/bin/env python3
"""Structural contract for the private x86 dynamic-main-thread RuntimeV1 bridge."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
LDSO_MANIFEST = ROOT / "ldso" / "Cargo.toml"
LDSO_BUILD = ROOT / "ldso" / "build.rs"
LDSO_ROOT = ROOT / "ldso" / "src" / "x86_64_dynamic_main_thread_runtime_v1_source_root.rs"
LDSO = ROOT / "ldso" / "src" / "x86_64_initial_graph.rs"
CRT_BUILDER = ROOT / "crt" / "build_x86_64.py"
CRT_STARTUP = ROOT / "crt" / "src" / "x86_64_dynamic_startup.rs"
LIBC_ROOT = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "dynamic_main_thread_runtime_v1_source_root.rs"
LIBC_RUNTIME = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "dynamic_main_thread_runtime_v1.rs"
RUNNER = ROOT / "compat" / "x86_64" / "run_dynamic_main_thread_runtime_v1.sh"
MAIN = ROOT / "compat" / "x86_64" / "dynamic_main_thread_runtime_v1_main.c"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"


class DynamicMainThreadRuntimeV1Tests(unittest.TestCase):
    def test_bridge_has_its_own_general_loader_cfg_and_root(self) -> None:
        manifest = LDSO_MANIFEST.read_text(encoding="utf-8")
        build = LDSO_BUILD.read_text(encoding="utf-8")
        root = LDSO_ROOT.read_text(encoding="utf-8")
        loader = LDSO.read_text(encoding="utf-8")

        self.assertIn(
            "x86_64-general-initial-tls-runtime-v1-dynamic-main-thread-interpreter",
            manifest,
        )
        for text in (
            "crabc_dynamic_main_thread_runtime_v1",
            "crabc_general_initial_graph",
            "crabc_general_initial_tls_materialization_v1",
            "crabc_general_loader_libc_tls_runtime_v1",
        ):
            with self.subTest(text=text):
                self.assertIn(text, build)
                self.assertIn(text, root)
                self.assertIn(text, loader)

        self.assertIn("__crabc_x86_64_owned_crt_handoff", loader)
        self.assertIn("R_X86_64_GLOB_DAT", loader)
        self.assertIn("crabc_owned_crt_handoff", loader)
        self.assertIn("dynamic main-thread", loader)

    def test_real_scrt1_attachment_precedes_the_dynamic_libc_boundary(self) -> None:
        builder = CRT_BUILDER.read_text(encoding="utf-8")
        startup = CRT_STARTUP.read_text(encoding="utf-8")

        self.assertIn("--dynamic-main-thread-runtime-v1", builder)
        self.assertIn("crabc_dynamic_main_thread_runtime_v1", builder)
        self.assertIn("__crabc_x86_loader_tls_runtime_v1_attach", builder)
        self.assertIn("crabc_dynamic_main_thread_runtime_v1", startup)
        attach = startup.index("__crabc_x86_loader_tls_runtime_v1_attach")
        libc_start = startup.index("__libc_start_main(", attach)
        self.assertLess(attach, libc_start)
        self.assertIn("startup_reject()", startup[attach:libc_start])

    def test_private_dynamic_libc_owns_only_the_minimal_startup_and_dynamic_errno(self) -> None:
        root = LIBC_ROOT.read_text(encoding="utf-8")
        runtime = LIBC_RUNTIME.read_text(encoding="utf-8")

        self.assertIn("errno.rs", root)
        for required in (
            "fn __libc_start_main",
            "rtld_fini.is_some()",
            "errno::get_errno()",
            "init()",
            "main(argc, argv, vectors.envp)",
            "fini()",
            "__crabc_dynamic_main_thread_runtime_v1_fini_state",
            "exit_group",
        ):
            with self.subTest(required=required):
                self.assertIn(required, runtime)
        self.assertNotIn("dlopen", runtime)
        self.assertNotIn("pthread", runtime)

    def test_native_runner_uses_real_scrt1_and_fails_before_callbacks(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        main = MAIN.read_text(encoding="utf-8")
        dispatcher = DISPATCHER.read_text(encoding="utf-8")

        for required in (
            "build_x86_64.py",
            "--dynamic-main-thread-runtime-v1",
            "Scrt1.o",
            "crti.o",
            "crtn.o",
            "__crabc_x86_64_owned_crt_handoff",
            "R_X86_64_GLOB_DAT",
            "no-arch-set-fs-trace",
            "magic version abi_size mode owner generation",
            "poisoned-dtv",
            "PIMFL",
            "libcrabc-dynamic-main-thread-runtime-v1.so",
        ):
            with self.subTest(required=required):
                self.assertIn(required, runner)
        self.assertIn("__thread", main)
        self.assertIn(".preinit_array", main)
        self.assertIn(".init_array", main)
        self.assertIn(".fini_array", main)
        self.assertIn("dynamic-main-thread-runtime-v1)", dispatcher)


if __name__ == "__main__":
    unittest.main()
