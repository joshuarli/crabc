#!/usr/bin/env python3
"""Focused contracts for the private x86 owned-static-sysroot builder."""

from __future__ import annotations

import importlib.util
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "build_x86_64_owned_sysroot.py"
SPEC = importlib.util.spec_from_file_location("build_x86_64_owned_sysroot", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
builder = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = builder
SPEC.loader.exec_module(builder)

DRIVER_SOURCE = ROOT / "compat" / "x86_64" / "crabc_cc_static.py"
DRIVER_SPEC = importlib.util.spec_from_file_location("x86_owned_static_driver", DRIVER_SOURCE)
assert DRIVER_SPEC is not None and DRIVER_SPEC.loader is not None
driver = importlib.util.module_from_spec(DRIVER_SPEC)
sys.modules[DRIVER_SPEC.name] = driver
DRIVER_SPEC.loader.exec_module(driver)


class BuildX86OwnedSysrootTests(unittest.TestCase):
    @staticmethod
    def write_elf64_relocatable(
        path: Path,
        *,
        elf_type: int = 1,
        machine: int = 62,
        section_types: tuple[int, ...] = (),
    ) -> None:
        """Write a structurally valid minimal ELF64 object for parser tests."""

        section_count = 1 + len(section_types)
        header = bytearray(64)
        header[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
        struct.pack_into(
            "<HHIQQQIHHHHHH",
            header,
            16,
            elf_type,
            machine,
            1,
            0,
            0,
            64,
            0,
            64,
            0,
            0,
            64,
            section_count,
            0,
        )
        sections = bytearray(64 * section_count)
        for index, section_type in enumerate(section_types, start=1):
            struct.pack_into("<I", sections, index * 64 + 4, section_type)
        path.write_bytes(header + sections)

    @staticmethod
    def example_producer_tools() -> dict[str, object]:
        """One deterministic stand-in for unit-only installed-tree fixtures."""

        return {
            "schema": 1,
            "toolchain": builder.PINNED_TOOLCHAIN,
            "target": builder.TARGET,
            "selection": {
                "cargo_home": str(builder.PINNED_CARGO_HOME),
                "rustup_home": str(builder.PINNED_RUSTUP_HOME),
                "path": f"{builder.PINNED_CARGO_HOME / 'bin'}:{builder.FIXED_HOST_BUILD_PATH}",
                "rustup_bin": str(builder.PINNED_CARGO_HOME / "bin"),
                "ambient_path_inherited": False,
                "ambient_cargo_home_inherited": False,
                "ambient_rustup_home_inherited": False,
            },
            "rustup": {
                "path": str(builder.PINNED_CARGO_HOME / "bin" / "rustup"),
                "resolved_path": "/opt/rustup-init",
                "sha256": "1" * 64,
            },
            "rustc": {
                "sysroot": "/opt/rustup/toolchains/nightly-2026-07-24-x86_64-unknown-linux-musl",
                "version": {
                    "release": "1.99.0-nightly",
                    "commit_hash": "2" * 40,
                    "commit_date": "2026-07-23",
                    "host": builder.TARGET,
                },
            },
            "llvm_target_tools": {
                name: {
                    "path": f"/opt/rustup/toolchains/nightly-2026-07-24-x86_64-unknown-linux-musl/lib/rustlib/{builder.TARGET}/bin/{name}",
                    "resolved_path": f"/opt/rustup/toolchains/nightly-2026-07-24-x86_64-unknown-linux-musl/lib/rustlib/{builder.TARGET}/bin/{name}",
                    "sha256": "3" * 64,
                }
                for name in builder.PINNED_TARGET_TOOLS
            },
        }

    def materialize_static_driver_sysroot(self, root: Path) -> Path:
        (root / "bin").mkdir(parents=True)
        (root / "usr" / "include").mkdir(parents=True)
        (root / "usr" / "include" / "stdint.h").write_text("\n", encoding="utf-8")
        for relative in driver.REQUIRED_RUNTIME_PATHS:
            artifact = root / relative
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_bytes(b"owned\n")
        installed = root / "bin" / "crabc-cc"
        builder.install_static_driver(installed)
        payload_hashes = builder.regular_file_hashes(root)
        builder.write_json(
            root / "share" / "crabc" / "manifest.json",
            builder.installed_manifest(payload_hashes, self.example_producer_tools()),
        )
        return installed

    def test_static_c_abi_root_uses_complete_complex_leaf_without_legacy_projection(self) -> None:
        """The installed libc build must not define cproj* from two x86 leaves."""

        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        self.assertIn(
            '#[path = "math_complex_complete.rs"]\nmod math_complex_complete;',
            static_root,
        )
        self.assertNotIn(
            '#[path = "complex_projection.rs"]\nmod complex_projection;',
            static_root,
        )

    def test_fixed_graph_dlfcn_import_stub_has_an_allocated_text_section(self) -> None:
        """Static links must not place a callable weak-import stub in GNU-stack."""

        dlfcn_source = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "fixed_graph_dlfcn.rs"
        ).read_text(encoding="utf-8")
        self.assertIn(
            '".section .text.__crabc_x86_fixed_graph_dlfcn_record,\\\"ax\\\",@progbits",',
            dlfcn_source,
        )
        self.assertIn(
            '"__crabc_x86_fixed_graph_dlfcn_record:",',
            dlfcn_source,
        )

    def test_owned_static_sysroot_uses_a_closed_dlfcn_absence_stub(self) -> None:
        """The static product cannot retain a dynamic-loader weak undefined symbol."""

        dlfcn_source = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "fixed_graph_dlfcn.rs"
        ).read_text(encoding="utf-8")
        builder_source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("#[cfg(crabc_owned_static_sysroot)]", dlfcn_source)
        self.assertIn('"xor eax, eax",', dlfcn_source)
        self.assertIn('"--cfg",\n        "crabc_owned_static_sysroot",', builder_source)

    def test_libc_member_classification_separates_owned_and_stock_runtime_members(self) -> None:
        selected, excluded = builder.classify_libc_members(
            (
                "c.one.rcgu.o",
                "c.two.rcgu.o",
                "compiler_builtins-abc.rcgu.o",
                "core-312879cb10d0e978.core.7a0be3b8ae74ffc7-cgu.0.rcgu.o",
                "45c91108d938afe8-addvdi3.o",
            )
        )
        self.assertEqual(selected, ("c.one.rcgu.o", "c.two.rcgu.o"))
        self.assertEqual(
            excluded,
            (
                "compiler_builtins-abc.rcgu.o",
                "core-312879cb10d0e978.core.7a0be3b8ae74ffc7-cgu.0.rcgu.o",
                "45c91108d938afe8-addvdi3.o",
            ),
        )

    def test_libc_member_classification_fails_closed_on_foreign_runtime_input(self) -> None:
        with self.assertRaisesRegex(builder.BuildError, "unclassified target-runtime"):
            builder.classify_libc_members(
                (
                    "c.one.rcgu.o",
                    "compiler_builtins-abc.rcgu.o",
                    "core-312879cb10d0e978.core.7a0be3b8ae74ffc7-cgu.0.rcgu.o",
                    "45c91108d938afe8-addvdi3.o",
                    "crtbegin.o",
                )
            )

    def test_libc_member_classification_rejects_path_like_archive_members(self) -> None:
        """Archive extraction must never receive a member path outside its private root."""

        with self.assertRaisesRegex(builder.BuildError, "unsafe member path"):
            builder.classify_libc_members(
                (
                    "c.one.rcgu.o",
                    "c.dir/../../outside.rcgu.o",
                    "compiler_builtins-abc.rcgu.o",
                    "core-312879cb10d0e978.core.7a0be3b8ae74ffc7-cgu.0.rcgu.o",
                    "45c91108d938afe8-addvdi3.o",
                )
            )

    def test_regular_tree_materialization_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "header.h").write_text("#define VALUE 1\n", encoding="utf-8")
            (source / "alias.h").symlink_to("header.h")
            with self.assertRaisesRegex(builder.BuildError, "contains a symlink"):
                builder.copy_regular_tree(source, root / "installed")

    def test_remove_owned_output_requires_exact_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "output"
            marker = root / "share" / "crabc" / "manifest.json"
            marker.parent.mkdir(parents=True)
            marker.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(builder.BuildError, "unrecognized output"):
                builder.remove_owned_output(root)
            marker.write_text(
                json.dumps({"format": builder.FORMAT, "target": builder.TARGET}) + "\n",
                encoding="utf-8",
            )
            builder.remove_owned_output(root)
            self.assertFalse(root.exists())

    def test_manifest_contract_names_installed_inputs_and_non_promotion_scope(self) -> None:
        producer_tools = self.example_producer_tools()
        manifest = builder.installed_manifest({"usr/lib/crt1.o": "0" * 64}, producer_tools)
        self.assertEqual(manifest["format"], builder.FORMAT)
        self.assertEqual(manifest["target"], builder.TARGET)
        self.assertEqual(manifest["toolchain"], builder.PINNED_TOOLCHAIN)
        self.assertEqual(manifest["producer_tools"], producer_tools)
        self.assertEqual(
            manifest["package"],
            {
                "format": "crabc-x86-64-owned-static-sysroot-package/v1",
                "archive_root": "crabc-x86_64-owned-static-sysroot",
            },
        )
        self.assertEqual(
            manifest["scope"],
            "private-static-pthread-tls-consumer-slice-not-family-completion-not-public-support",
        )
        self.assertEqual(
            manifest["installed"]["files"],
            {"usr/lib/crt1.o": "0" * 64},
        )
        self.assertEqual(manifest["installed"]["sealed_static_driver"], "bin/crabc-cc")
        self.assertEqual(
            manifest["sealed_static_driver"]["status"],
            "planned-owned-static-product-seed-not-family-completion-not-public-support",
        )
        self.assertEqual(
            manifest["sealed_static_driver"]["modes"],
            [
                {"id": "static-et-exec", "elf_type": "ET_EXEC", "crt_object": "crt1.o"},
                {"id": "static-pie", "elf_type": "ET_DYN", "crt_object": "rcrt1.o"},
            ],
        )
        self.assertIn(
            "declared static-product coverage suite",
            manifest["sealed_static_driver"]["not_proven_by_this_seed"],
        )
        self.assertEqual(
            manifest["purity"]["target_runtime_inputs"],
            list(builder.TARGET_RUNTIME_INPUTS),
        )
        for item in (
            "dynamic loader or PT_INTERP",
            "complete compiler-helper closure",
            "sysroot.static-tls family completion",
            "sysroot.owned-artifact family completion",
            "x86-64 promotion or public support",
        ):
            self.assertIn(item, manifest["not_selected"])

    def test_recorded_libc_build_command_retains_the_static_sysroot_cfg(self) -> None:
        """Published provenance must retain the cfg used for the rebuilt archive."""

        source = SCRIPT.read_text(encoding="utf-8")
        actual = source[source.index("cargo_command = ["):source.index("run(cargo_command)")]
        recorded = source[source.index('"cargo_command": ['):source.index('"crt_root": crt_root')]
        self.assertIn('"--cfg",\n        "crabc_owned_static_sysroot",', actual)
        self.assertIn('"--cfg",\n            "crabc_owned_static_sysroot",', recorded)

    def test_owned_static_archive_is_pic_initial_exec_without_optional_runtime_roots(self) -> None:
        """One installed archive must serve both static ELF modes without opt-in roots."""

        source = SCRIPT.read_text(encoding="utf-8")
        actual = source[source.index("cargo_command = ["):source.index("run(cargo_command)")]
        recorded = source[source.index('"cargo_command": ['):source.index('"crt_root": crt_root')]
        for command in (actual, recorded):
            self.assertIn('"relocation-model=pic"', command)
            self.assertIn('"-Ztls-model=initial-exec"', command)
            self.assertNotIn('"--features"', command)
            self.assertNotIn('x86-allocator-runtime', command)
            self.assertNotIn('x86-environment-runtime', command)
            self.assertNotIn('x86-resolver-runtime', command)

    def test_deterministic_environment_removes_ambient_target_search_and_tools(self) -> None:
        names = (
            "PATH",
            "CARGO_HOME",
            "RUSTUP_HOME",
            "HOME",
            "CPATH",
            "LIBRARY_PATH",
            "COMPILER_PATH",
            "GCC_EXEC_PREFIX",
            "RUSTFLAGS",
            "CARGO_BUILD_RUSTFLAGS",
            "RUSTC",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "CC",
            "CFLAGS_x86_64_unknown_linux_musl",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER",
        )
        previous = {name: builder.os.environ.get(name) for name in names}
        try:
            for name in names:
                builder.os.environ[name] = "/ambient/target/input"
            environment = builder.deterministic_environment()
        finally:
            for name, value in previous.items():
                if value is None:
                    builder.os.environ.pop(name, None)
                else:
                    builder.os.environ[name] = value
        for name in names:
            if name not in {"PATH", "CARGO_HOME", "RUSTUP_HOME"}:
                self.assertNotIn(name, environment)
        self.assertEqual(
            environment,
            {
                "CARGO_HOME": str(builder.PINNED_CARGO_HOME),
                "RUSTUP_HOME": str(builder.PINNED_RUSTUP_HOME),
                "PATH": f"{builder.PINNED_CARGO_HOME / 'bin'}:{builder.FIXED_HOST_BUILD_PATH}",
                "CARGO_INCREMENTAL": "0",
                "LC_ALL": "C",
                "SOURCE_DATE_EPOCH": "1",
                "TZ": "UTC",
            },
        )

    def test_pinned_producer_tools_ignore_ambient_paths_and_record_hashed_identities(self) -> None:
        """The static producer may use only the fixed nightly installation."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cargo_home = root / "cargo"
            rustup_home = root / "rustup"
            rustup = cargo_home / "bin" / "rustup"
            rustup.parent.mkdir(parents=True)
            rustup.write_text("#!/bin/sh\n", encoding="utf-8")
            rustup.chmod(0o755)
            sysroot = rustup_home / "toolchains" / (
                f"{builder.PINNED_TOOLCHAIN}-x86_64-unknown-linux-musl"
            )
            target_bin = sysroot / "lib" / "rustlib" / builder.TARGET / "bin"
            target_bin.mkdir(parents=True)
            for name in builder.PINNED_TARGET_TOOLS:
                tool = target_bin / name
                tool.write_text(f"{name}\n", encoding="utf-8")
                tool.chmod(0o755)

            calls: list[tuple[list[str], dict[str, object]]] = []

            def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                calls.append((command, kwargs))
                if command[-2:] == ["--print", "sysroot"]:
                    return subprocess.CompletedProcess(command, 0, f"{sysroot}\n", "")
                self.assertEqual(command[-1], "-Vv")
                return subprocess.CompletedProcess(
                    command,
                    0,
                    "binary: rustc\n"
                    "commit-hash: " + "a" * 40 + "\n"
                    "commit-date: 2026-07-23\n"
                    f"host: {builder.TARGET}\n"
                    "release: 1.99.0-nightly\n",
                    "",
                )

            with (
                mock.patch.dict(
                    builder.os.environ,
                    {
                        "PATH": "/ambient/bin",
                        "CARGO_HOME": "/ambient/cargo",
                        "RUSTUP_HOME": "/ambient/rustup",
                    },
                    clear=False,
                ),
                mock.patch.object(builder, "PINNED_CARGO_HOME", cargo_home),
                mock.patch.object(builder, "PINNED_RUSTUP_HOME", rustup_home),
                mock.patch.object(builder.subprocess, "run", side_effect=fake_run),
                mock.patch.object(
                    builder.shutil,
                    "which",
                    side_effect=AssertionError("the builder must not search ambient PATH"),
                ),
            ):
                producer_tools = builder.resolve_pinned_producer_tools()

            self.assertEqual(
                producer_tools["selection"],
                {
                    "cargo_home": str(cargo_home),
                    "rustup_home": str(rustup_home),
                    "path": f"{cargo_home / 'bin'}:{builder.FIXED_HOST_BUILD_PATH}",
                    "rustup_bin": str(cargo_home / "bin"),
                    "ambient_path_inherited": False,
                    "ambient_cargo_home_inherited": False,
                    "ambient_rustup_home_inherited": False,
                },
            )
            self.assertEqual(producer_tools["rustup"]["path"], str(rustup))
            self.assertEqual(producer_tools["rustc"]["sysroot"], str(sysroot))
            self.assertEqual(
                producer_tools["rustc"]["version"]["commit_hash"], "a" * 40
            )
            for name in builder.PINNED_TARGET_TOOLS:
                identity = producer_tools["llvm_target_tools"][name]
                self.assertEqual(identity["path"], str(target_bin / name))
                self.assertEqual(identity["sha256"], builder.sha256_file(target_bin / name))
            self.assertEqual(len(calls), 2)
            for command, kwargs in calls:
                self.assertEqual(
                    command[:4],
                    [str(rustup), "run", builder.PINNED_TOOLCHAIN, "rustc"],
                )
                self.assertEqual(
                    kwargs["env"],
                    {
                        "CARGO_HOME": str(cargo_home),
                        "RUSTUP_HOME": str(rustup_home),
                        "PATH": f"{cargo_home / 'bin'}:{builder.FIXED_HOST_BUILD_PATH}",
                        "CARGO_INCREMENTAL": "0",
                        "LC_ALL": "C",
                        "SOURCE_DATE_EPOCH": "1",
                        "TZ": "UTC",
                    },
                )

    def test_pinned_target_tool_rejects_a_symlink_outside_the_selected_sysroot(self) -> None:
        """A nightly target-tool name may not resolve into an ambient directory."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sysroot = root / "toolchains" / (
                f"{builder.PINNED_TOOLCHAIN}-x86_64-unknown-linux-musl"
            )
            target_bin = sysroot / "lib" / "rustlib" / builder.TARGET / "bin"
            target_bin.mkdir(parents=True)
            ambient_tool = root / "ambient-llvm-ar"
            ambient_tool.write_text("ambient\n", encoding="utf-8")
            ambient_tool.chmod(0o755)
            (target_bin / "llvm-ar").symlink_to(ambient_tool)

            with self.assertRaisesRegex(builder.BuildError, "escapes its pinned toolchain root"):
                builder.pinned_target_tool(sysroot, "llvm-ar")

    def test_producer_tool_provenance_is_persisted_in_the_build_record(self) -> None:
        producer_tools = self.example_producer_tools()
        record = builder.build_commands_record(["rustup", "run", builder.PINNED_TOOLCHAIN], producer_tools)
        self.assertEqual(record["producer_tools"], producer_tools)
        self.assertEqual(record["target"], builder.TARGET)

    def test_static_driver_plan_selects_only_owned_et_exec_or_static_pie_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "sysroot"
            installed = self.materialize_static_driver_sysroot(root)
            self.assertTrue(os.access(installed, os.X_OK))

            for mode, elf_type, crt in (
                ("-static", "ET_EXEC", "crt1.o"),
                ("-static-pie", "ET_DYN", "rcrt1.o"),
            ):
                with self.subTest(mode=mode):
                    completed = subprocess.run(
                        [str(installed), "--print-link-plan", mode],
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    plan = json.loads(completed.stdout)
                    self.assertEqual(plan["mode"]["elf_type"], elf_type)
                    self.assertEqual(plan["mode"]["crt_object"], crt)
                    self.assertEqual(plan["headers"], str(root / "usr" / "include"))
                    self.assertIn(str(root / "usr" / "lib" / crt), plan["linker"])
                    self.assertIn(str(root / "usr" / "lib" / "libc.a"), plan["linker"])
                    self.assertIn(
                        str(root / "usr" / "lib" / "libcrabc-builtins.a"), plan["linker"]
                    )
                    self.assertEqual("-pie" in plan["linker"], mode == "-static-pie")
                    self.assertIn("--gc-sections", plan["linker"])
                    self.assertIn(
                        "sysroot.static-tls family completion",
                        plan["not_proven_by_this_seed"],
                    )
                    self.assertNotIn(
                        "two-clean-build and extracted-install product reproducibility",
                        plan["not_proven_by_this_seed"],
                    )
                    for item in plan["linker"]:
                        if item.startswith("/"):
                            self.assertTrue(item.startswith(str(root)), item)

    def test_static_driver_rejects_a_manifest_hash_mismatch_before_printing_a_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "sysroot"
            installed = self.materialize_static_driver_sysroot(root)
            (root / "usr" / "lib" / "libc.a").write_bytes(b"tampered\n")
            completed = subprocess.run(
                [str(installed), "--print-link-plan", "-static"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(completed.stdout, "")
            self.assertIn("payload hash mismatch: usr/lib/libc.a", completed.stderr)

    def test_static_driver_rejects_undeclared_or_linked_installed_payload_before_planning(self) -> None:
        """An installed include path is closed to the manifest's regular-file payload."""

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            external = workspace / "external.h"
            external.write_text("#define EXTERNAL_HEADER 1\n", encoding="utf-8")
            for label, install_extra, expected_error in (
                (
                    "undeclared-regular",
                    lambda header: header.write_text("#define EXTRA_HEADER 1\n", encoding="utf-8"),
                    "undeclared installed regular file: usr/include/extra.h",
                ),
                (
                    "linked",
                    lambda header: header.symlink_to(external),
                    "installed tree contains a symlink: usr/include/extra.h",
                ),
            ):
                with self.subTest(label=label):
                    root = workspace / label / "sysroot"
                    installed = self.materialize_static_driver_sysroot(root)
                    install_extra(root / "usr" / "include" / "extra.h")
                    completed = subprocess.run(
                        [str(installed), "--print-link-plan", "-static"],
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    self.assertEqual(completed.returncode, 1)
                    self.assertEqual(completed.stdout, "")
                    self.assertIn(expected_error, completed.stderr)

    def test_static_driver_rejects_ambient_runtime_injection_before_invocation(self) -> None:
        for arguments in (
            ("-I", "/ambient/headers", "application.c"),
            ("-isystem", "/ambient/headers", "application.c"),
            ("-L/ambient/lib", "application.c"),
            ("-l:libc.a", "application.c"),
            ("-Wl,--dynamic-linker,/ambient/loader", "application.c"),
            ("-Wp,-include,/ambient/header.h", "application.c"),
            ("-Wp,-isystem,/ambient/headers", "application.c"),
            ("-Wa,--execstack", "application.c"),
            ("-Xlinker", "/ambient/loader", "application.c"),
            ("-shared", "application.c"),
            ("-rtlib=compiler-rt", "application.c"),
            ("/ambient/crt1.o",),
            ("/ambient/libgcc.o",),
            ("/ambient/compiler-rt.o",),
            ("-static", "-static-pie", "application.c"),
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaisesRegex(driver.DriverError, "rejected|exactly one"):
                    driver.parse_invocation(arguments)

    def test_static_driver_keeps_warning_flags_but_rejects_phase_forwarding(self) -> None:
        """``-Wp``/``-Wa`` are compiler authority, not ``-W`` diagnostics."""

        invocation = driver.parse_invocation(
            (
                "-Wall",
                "-Werror",
                "-Wno-unused-parameter",
                "-Wpedantic",
                "-Walloca",
                "application.c",
            )
        )
        self.assertEqual(
            invocation.compiler_flags,
            ("-Wall", "-Werror", "-Wno-unused-parameter", "-Wpedantic", "-Walloca"),
        )
        for argument in (
            "-Wp,-include,/ambient/header.h",
            "-Wp,-isystem,/ambient/headers",
            "-Wa,--execstack",
        ):
            with self.subTest(argument=argument):
                with self.assertRaisesRegex(driver.DriverError, "rejected"):
                    driver.parse_invocation((argument, "application.c"))

    def test_static_driver_admits_only_native_relocatable_application_objects_before_planning(self) -> None:
        """A caller ``.o`` cannot make LLD reinterpret it as another input kind."""

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            root = workspace / "sysroot"
            root.mkdir()
            source = workspace / "legitimate.c"
            source.write_text("int legitimate_object;\n", encoding="utf-8")
            legitimate = workspace / "legitimate.o"
            subprocess.run(
                [driver.compiler(), "-c", str(source), "-o", str(legitimate)],
                check=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(
                driver.require_x86_64_relocatable_object(root, legitimate),
                legitimate.resolve(),
            )

            rejected: list[tuple[str, bytes]] = [
                ("linker-script.o", b"INPUT(/ambient/escape.o)\n"),
                ("thin-archive.o", b"!<thin>\n"),
                ("arbitrary.o", b"not an ELF object\n"),
            ]
            for name, payload in rejected:
                (workspace / name).write_bytes(payload)
            for name, elf_type, machine, section_types in (
                ("not-rel.o", 3, 62, ()),
                ("wrong-machine.o", 1, 183, ()),
                ("linker-options.o", 1, 62, (0x6FFF4C01,)),
                ("dependent-libraries.o", 1, 62, (0x6FFF4C04,)),
            ):
                self.write_elf64_relocatable(
                    workspace / name,
                    elf_type=elf_type,
                    machine=machine,
                    section_types=section_types,
                )
                rejected.append((name, b""))

            for name, _ in rejected:
                with self.subTest(name=name):
                    invocation = driver.parse_invocation(("-static", str(workspace / name)))
                    with mock.patch.object(
                        driver,
                        "materialize_link_plan",
                        side_effect=AssertionError("invalid object reached link planning"),
                    ) as link_plan:
                        with self.assertRaisesRegex(
                            driver.DriverError,
                            "not a Linux/x86-64 ELF64 ET_REL object|forbidden LLVM linker-control section",
                        ):
                            driver.execute(root, invocation)
                    link_plan.assert_not_called()

    def test_static_driver_rejects_normalized_output_input_aliases_before_work(self) -> None:
        """A receipt cannot hash an object after its output path has replaced it."""

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            root = workspace / "sysroot"
            root.mkdir()
            source = workspace / "application.c"
            source.write_text("int application_object;\n", encoding="utf-8")
            object_path = workspace / "application.o"
            subprocess.run(
                [driver.compiler(), "-c", str(source), "-o", str(object_path)],
                check=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            original_cwd = Path.cwd()
            try:
                os.chdir(workspace)
                link_invocation = driver.parse_invocation(
                    (
                        "-static",
                        "--link-receipt",
                        "evidence.json",
                        "-o",
                        "./application.o",
                        "application.o",
                    )
                )
                with mock.patch.object(
                    driver,
                    "materialize_link_plan",
                    side_effect=AssertionError("output/input collision reached link planning"),
                ) as link_plan:
                    with self.assertRaisesRegex(
                        driver.DriverError, "output collides with admitted application input"
                    ):
                        driver.execute(root, link_invocation)
                link_plan.assert_not_called()

                hard_link = workspace / "same-inode.o"
                hard_link.hardlink_to(object_path)
                hard_link_invocation = driver.parse_invocation(
                    ("-static", "-o", str(hard_link), str(object_path))
                )
                with mock.patch.object(
                    driver,
                    "materialize_link_plan",
                    side_effect=AssertionError("hard-link alias reached link planning"),
                ) as link_plan:
                    with self.assertRaisesRegex(
                        driver.DriverError, "output collides with admitted application input"
                    ):
                        driver.execute(root, hard_link_invocation)
                link_plan.assert_not_called()

                compile_invocation = driver.parse_invocation(
                    ("-c", "application.c", "-o", "./application.c")
                )
                with mock.patch.object(
                    driver,
                    "compile_source",
                    side_effect=AssertionError("output/input collision reached source compilation"),
                ) as compile_source:
                    with self.assertRaisesRegex(
                        driver.DriverError, "output collides with admitted application input"
                    ):
                        driver.execute(root, compile_invocation)
                compile_source.assert_not_called()
            finally:
                os.chdir(original_cwd)

    def test_static_driver_receipt_trace_requires_exact_owned_and_admitted_inputs(self) -> None:
        """A receipt cannot attest a link whose trace reached an ambient input."""

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            root = workspace / "sysroot"
            library = root / "usr" / "lib"
            library.mkdir(parents=True)
            application = (workspace / "application.o").resolve()
            application.write_bytes(b"caller-owned object\n")
            trace = workspace / "link.trace"
            expected = [
                str(library / "crt1.o"),
                str(library / "crti.o"),
                str(application),
                f"{library / 'libc.a'}(member.o)",
                f"{library / 'libcrabc-builtins.a'}(member.o)",
                str(library / "crtn.o"),
            ]
            trace.write_text("\n".join(expected) + "\n", encoding="utf-8")
            driver.validate_link_trace(root, driver.STATIC_ET_EXEC, (application,), trace)

            for lines, error in (
                (expected + ["/ambient/escape.o"], "unadmitted input"),
                (expected[:-1], "omitted expected input"),
            ):
                with self.subTest(lines=lines):
                    trace.write_text("\n".join(lines) + "\n", encoding="utf-8")
                    with self.assertRaisesRegex(driver.DriverError, error):
                        driver.validate_link_trace(root, driver.STATIC_ET_EXEC, (application,), trace)

    def test_static_driver_receipt_is_link_only_and_cannot_inject_a_linker_flag(self) -> None:
        """The receipt sidecar is driver-owned audit output, never linker authority."""

        invocation = driver.parse_invocation(
            ("-static-pie", "--link-receipt", "evidence.json", "-o", "candidate", "probe.o")
        )
        self.assertEqual(invocation.mode, driver.STATIC_PIE)
        self.assertEqual(invocation.link_receipt, Path("evidence.json"))
        for arguments in (
            ("--print-link-plan", "--link-receipt", "evidence.json"),
            ("-c", "--link-receipt", "evidence.json", "probe.c"),
            ("--link-receipt", "-Map=/ambient/map", "probe.c"),
            ("--link-receipt", "one.json", "--link-receipt", "two.json", "probe.c"),
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaisesRegex(
                    driver.DriverError, "receipt|requires a non-option|unsupported|optional static mode"
                ):
                    driver.parse_invocation(arguments)

    def test_static_driver_receipt_rejects_source_inputs_but_plain_links_keep_them(self) -> None:
        """Receipts record only durable, caller-owned application objects."""

        ordinary = driver.parse_invocation(("-static", "application.c"))
        self.assertEqual(ordinary.sources, (Path("application.c"),))
        self.assertEqual(ordinary.objects, ())

        with self.assertRaisesRegex(
            driver.DriverError, "caller-owned.*application.*object"
        ):
            driver.parse_invocation(
                ("-static-pie", "--link-receipt", "evidence.json", "application.c")
            )

        audited = driver.parse_invocation(
            ("-static-pie", "--link-receipt", "evidence.json", "application.o")
        )
        self.assertEqual(audited.sources, ())
        self.assertEqual(audited.objects, (Path("application.o"),))

    def test_static_driver_receipt_rejects_normalized_output_sidecar_aliases_before_linking(self) -> None:
        """The output must stay pairwise disjoint from receipt/map/trace paths."""

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            root = workspace / "sysroot"
            root.mkdir()
            application = workspace / "application.o"
            application.write_bytes(b"caller-owned object\n")
            (workspace / "alias-parent").mkdir()
            original_cwd = Path.cwd()
            try:
                os.chdir(workspace)
                for output, expected_sidecar in (
                    (Path("./receipt.json"), "JSON"),
                    (Path("alias-parent/../receipt.map"), "map"),
                    (workspace / "receipt.trace", "trace"),
                ):
                    with self.subTest(output=output, expected_sidecar=expected_sidecar):
                        invocation = driver.parse_invocation(
                            (
                                "-static",
                                "--link-receipt",
                                "receipt.json",
                                "-o",
                                str(output),
                                str(application),
                            )
                        )
                        with mock.patch.object(driver, "materialize_link_plan") as link_plan:
                            with self.assertRaisesRegex(
                                driver.DriverError,
                                f"output collides with --link-receipt {expected_sidecar} sidecar",
                            ):
                                driver.execute(root, invocation)
                        link_plan.assert_not_called()
            finally:
                os.chdir(original_cwd)

    def test_static_driver_keeps_application_inputs_and_outputs_outside_the_installed_root(self) -> None:
        """The sealed payload cannot be changed or impersonated by an application path."""

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            root = workspace / "sysroot"
            self.materialize_static_driver_sysroot(root)
            outside = workspace / "application"
            outside.mkdir()
            source = outside / "probe.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            object_file = outside / "probe.o"
            object_file.write_bytes(b"application object\n")

            for output in (root / "usr" / "lib" / "libc.a", root / "new-output.o"):
                with self.subTest(output=output):
                    with self.assertRaisesRegex(driver.DriverError, "must not modify the installed sysroot"):
                        driver.validate_application_output(root, output)

            redirected_parent = outside / "redirected"
            redirected_parent.symlink_to(workspace / "elsewhere", target_is_directory=True)
            with self.assertRaisesRegex(driver.DriverError, "traverses an existing symlink"):
                driver.validate_application_output(root, redirected_parent / "candidate")

            for application_input, kind in (
                (root / "inside.c", "source"),
                (root / "inside.o", "object"),
            ):
                application_input.write_bytes(b"sealed-root application input\n")
                with self.subTest(application_input=application_input):
                    with self.assertRaisesRegex(driver.DriverError, "inside the installed sysroot"):
                        driver.require_application_file(root, application_input, kind)

            compile_invocation = driver.parse_invocation(
                ("-c", str(source), "-o", str(root / "usr" / "lib" / "libc.a"))
            )
            with self.assertRaisesRegex(driver.DriverError, "must not modify the installed sysroot"):
                driver.execute(root, compile_invocation)

            link_invocation = driver.parse_invocation(
                ("-static", str(object_file), "-o", str(root / "new-candidate"))
            )
            with self.assertRaisesRegex(driver.DriverError, "must not modify the installed sysroot"):
                driver.execute(root, link_invocation)


if __name__ == "__main__":
    unittest.main()
