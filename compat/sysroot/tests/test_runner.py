#!/usr/bin/env python3
"""Host-only contract tests for the owned-sysroot assembler and driver."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
TOOL_PATH = ROOT / "scripts/crabc_sysroot.py"
RUNNER_PATH = ROOT / "compat/sysroot/run.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


TOOL = load_module("crabc_sysroot_test_tool", TOOL_PATH)
RUNNER = load_module("crabc_sysroot_test_runner", RUNNER_PATH)


def make_sysroot(root: Path) -> Path:
    sysroot = root / "sysroot"
    for directory in ("bin", "lib", "usr/include", "usr/lib", "share/crabc"):
        (sysroot / directory).mkdir(parents=True, exist_ok=True)
    for name in ("libc.so", "libc.a", "libcrabc-builtins.a", *TOOL.CRT_OBJECTS):
        (sysroot / "usr/lib" / name).write_bytes(b"placeholder")
    (sysroot / "lib/ld-crabc-aarch64.so.1").write_bytes(b"placeholder")
    manifest = {
        "schema": 1,
        "target": TOOL.TARGET_TRIPLE,
        "canonical_interpreter": TOOL.CANONICAL_INTERPRETER,
        "toolchain": {"clang": "clang", "lld": "ld.lld", "resource_dir": "/resource", "clang_version": "test", "lld_version": "test"},
    }
    (sysroot / "share/crabc/manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return sysroot


class DriverRequestTests(unittest.TestCase):
    def test_dynamic_pie_selects_owned_pie_crt_and_canonical_interpreter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = make_sysroot(Path(temporary))
            request = TOOL.parse_driver_request(["hello.c", "-o", "hello"])
            plan = TOOL.build_driver_plan(
                sysroot,
                request,
                clang=Path("/host/clang"),
                lld=Path("/host/ld.lld"),
                resource_include=Path("/host/resource/include"),
            )
        self.assertEqual(plan.mode, TOOL.LinkMode.DYNAMIC_PIE)
        self.assertEqual([path.name for path in plan.startup_objects], ["Scrt1.o", "crti.o"])
        self.assertEqual([path.name for path in plan.end_objects], ["crtn.o"])
        self.assertEqual(plan.interpreter, TOOL.CANONICAL_INTERPRETER)
        self.assertIn("-mno-outline-atomics", plan.command)
        self.assertIn("-nostdlib", plan.command)
        self.assertIn("-l:libcrabc-builtins.a", plan.default_libraries)

    def test_static_pie_selects_rcrt1_and_has_no_interpreter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = make_sysroot(Path(temporary))
            request = TOOL.parse_driver_request(["-static-pie", "hello.c", "-o", "hello"])
            plan = TOOL.build_driver_plan(sysroot, request, clang=Path("/host/clang"), lld=Path("/host/ld.lld"), resource_include=Path("/r/i"))
        self.assertEqual(plan.mode, TOOL.LinkMode.STATIC_PIE)
        self.assertEqual(plan.startup_objects[0].name, "rcrt1.o")
        self.assertIsNone(plan.interpreter)
        self.assertIn("-static-pie", plan.command)

    def test_non_pie_static_shared_and_relocatable_have_distinct_runtime_contracts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = make_sysroot(Path(temporary))
            plans = {
                name: TOOL.build_driver_plan(
                    sysroot,
                    TOOL.parse_driver_request(arguments),
                    clang=Path("/host/clang"),
                    lld=Path("/host/ld.lld"),
                    resource_include=Path("/r/i"),
                )
                for name, arguments in {
                    "dynamic_exec": ["-no-pie", "hello.c"],
                    "static_exec": ["-static", "hello.c"],
                    "shared": ["-shared", "hello.c"],
                    "relocatable": ["-r", "hello.o"],
                }.items()
            }
        self.assertEqual(plans["dynamic_exec"].startup_objects[0].name, "crt1.o")
        self.assertEqual(plans["dynamic_exec"].interpreter, TOOL.CANONICAL_INTERPRETER)
        self.assertEqual(plans["static_exec"].startup_objects[0].name, "crt1.o")
        self.assertIsNone(plans["static_exec"].interpreter)
        self.assertEqual([path.name for path in plans["shared"].startup_objects], ["crti.o"])
        self.assertEqual([path.name for path in plans["shared"].end_objects], ["crtn.o"])
        self.assertEqual(plans["shared"].default_libraries, ())
        self.assertIn("-fPIC", plans["shared"].command)
        self.assertEqual(plans["relocatable"].startup_objects, ())
        self.assertEqual(plans["relocatable"].default_libraries, ())
        self.assertNotIn("-Wl,-z,relro", plans["relocatable"].command)

    def test_compile_only_has_no_link_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = make_sysroot(Path(temporary))
            request = TOOL.parse_driver_request(["-c", "hello.c", "-o", "hello.o"])
            plan = TOOL.build_driver_plan(
                sysroot, request, clang=Path("/host/clang"), lld=Path("/host/ld.lld"), resource_include=Path("/r/i")
            )
        self.assertEqual(plan.mode, TOOL.LinkMode.COMPILE)
        self.assertEqual(plan.startup_objects, ())
        self.assertEqual(plan.default_libraries, ())

    def test_nostdlib_omits_start_and_default_libraries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = make_sysroot(Path(temporary))
            request = TOOL.parse_driver_request(["-nostdlib", "hello.c", "-o", "hello"])
            plan = TOOL.build_driver_plan(sysroot, request, clang=Path("/host/clang"), lld=Path("/host/ld.lld"), resource_include=Path("/r/i"))
        self.assertEqual(plan.startup_objects, ())
        self.assertEqual(plan.end_objects, ())
        self.assertEqual(plan.default_libraries, ())

    def test_nostartfiles_and_nodefaultlibs_are_independent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = make_sysroot(Path(temporary))
            no_start = TOOL.build_driver_plan(
                sysroot,
                TOOL.parse_driver_request(["-nostartfiles", "-pthread", "hello.c"]),
                clang=Path("/host/clang"),
                lld=Path("/host/ld.lld"),
                resource_include=Path("/r/i"),
            )
            no_libraries = TOOL.build_driver_plan(
                sysroot,
                TOOL.parse_driver_request(["-nodefaultlibs", "hello.c"]),
                clang=Path("/host/clang"),
                lld=Path("/host/ld.lld"),
                resource_include=Path("/r/i"),
            )
        self.assertEqual(no_start.startup_objects, ())
        self.assertTrue(no_start.default_libraries)
        self.assertIn("-pthread", no_start.command)
        self.assertTrue(no_libraries.startup_objects)
        self.assertEqual(no_libraries.default_libraries, ())

    def test_preprocess_and_assembly_modes_are_never_link_modes(self) -> None:
        self.assertEqual(TOOL.parse_driver_request(["-E", "hello.c"]).mode, TOOL.LinkMode.PREPROCESS)
        self.assertEqual(TOOL.parse_driver_request(["-S", "hello.c"]).mode, TOOL.LinkMode.ASSEMBLY)

    def test_wrapper_rejects_sysroot_replacement_and_interpreter_override(self) -> None:
        for arguments in (("--sysroot=/bad", "hello.c"), ("-Wl,--dynamic-linker,/bad", "hello.c")):
            with self.assertRaises(TOOL.SysrootError):
                TOOL.parse_driver_request(arguments)

    def test_wrapper_rejects_sealed_target_toolchain_and_runtime_overrides(self) -> None:
        rejected = (
            ("hello.c", "--target=other-linux"),
            ("hello.c", "--target", "other-linux"),
            ("hello.c", "-target", "other-linux"),
            ("hello.c", "-target=other-linux"),
            ("hello.c", "-B/other/toolchain"),
            ("hello.c", "-B", "/other/toolchain"),
            ("hello.c", "-B=/other/toolchain"),
            ("hello.c", "--gcc-toolchain=/other/toolchain"),
            ("hello.c", "--gcc-toolchain", "/other/toolchain"),
            ("hello.c", "-gcc-toolchain=/other/toolchain"),
            ("hello.c", "-fuse-ld=gold"),
            ("hello.c", "-fuse-ld", "gold"),
            ("hello.c", "-isysroot=/other/sysroot"),
            ("hello.c", "-isysroot", "/other/sysroot"),
            ("hello.c", "-isysroot/other/sysroot"),
            ("hello.c", "-resource-dir=/other/clang"),
            ("hello.c", "-resource-dir", "/other/clang"),
            ("hello.c", "-rtlib=compiler-rt"),
            ("hello.c", "-unwindlib=libunwind"),
            ("hello.c", "-moutline-atomics"),
            ("hello.c", "-Xclang", "-triple", "other-linux"),
            ("hello.c", "-Xclang", "-target-feature", "+outline-atomics"),
            ("hello.c", "-Xlinker", "-L", "-Xlinker", "/foreign/lib"),
            ("hello.c", "-Xlinker", "--sysroot=/foreign"),
            ("hello.c", "-Xlinker", "-Tforeign.ld"),
            ("hello.c", "-Wl,-L,/foreign/lib"),
            ("hello.c", "-Wl,--script=foreign.ld"),
        )
        for arguments in rejected:
            with self.subTest(arguments=arguments):
                with self.assertRaises(TOOL.SysrootError):
                    TOOL.parse_driver_request(arguments)

    def test_wrapper_preserves_unrelated_clang_flags(self) -> None:
        arguments = ("-c", "-DNAME=value", "-isystem", "app/include", "-fPIC", "hello.c", "-o", "hello.o")
        request = TOOL.parse_driver_request(arguments)
        self.assertEqual(request.user_arguments, arguments)


class SealingAndAuditTests(unittest.TestCase):
    def test_static_runtime_lifecycle_tls_requires_named_initial_exec_root(self) -> None:
        member = {
            "elf": {
                "defined_symbols": [
                    {
                        "name": "_RNvNtC_test_14crabc_mimalloc17runtime_lifecycle16THREAD_LIFECYCLE",
                        "type": TOOL.ELF_STT_TLS,
                        "binding": TOOL.ELF_STB_LOCAL,
                        "visibility": TOOL.ELF_STV_DEFAULT,
                        "size": 392,
                        "table_index": 7,
                        "entry_index": 21,
                    }
                ],
                "relocations": [
                    {
                        "symbol_table_index": 7,
                        "symbol_index": 21,
                        "type": relocation,
                    }
                    for relocation in TOOL.STATIC_RUNTIME_LIFECYCLE_TLS_RELOCATION_TYPES
                ],
            }
        }

        audit = TOOL.audit_static_runtime_lifecycle_tls(member)

        self.assertEqual(audit["status"], "verified")
        self.assertEqual(audit["access_model"], "initial-exec")
        self.assertEqual(
            audit["required_relocations"],
            [
                "R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21",
                "R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC",
            ],
        )

    def test_static_runtime_lifecycle_tls_rejects_dynamic_descriptor(self) -> None:
        member = {
            "elf": {
                "defined_symbols": [
                    {
                        "name": "_RNvNtC_test_14crabc_mimalloc17runtime_lifecycle16THREAD_LIFECYCLE",
                        "type": TOOL.ELF_STT_TLS,
                        "binding": TOOL.ELF_STB_LOCAL,
                        "visibility": TOOL.ELF_STV_DEFAULT,
                        "size": 392,
                        "table_index": 7,
                        "entry_index": 21,
                    }
                ],
                "relocations": [
                    {
                        "symbol_table_index": 7,
                        "symbol_index": 21,
                        "type": TOOL.R_AARCH64_TLSDESC_FIRST,
                    }
                ],
            }
        }

        audit = TOOL.audit_static_runtime_lifecycle_tls(member)

        self.assertEqual(audit["status"], "rejected")

    def test_shared_runtime_tls_rejects_dynamic_descriptor(self) -> None:
        with mock.patch.object(
            TOOL,
            "inspect_elf",
            return_value={
                "relocations": [
                    {"type": TOOL.R_AARCH64_TLS_TPREL64},
                    {"type": TOOL.R_AARCH64_TLSDESC_FIRST},
                ],
                "undefined_symbols": [],
            },
        ):
            audit = TOOL.audit_shared_runtime_tls(Path("libc.so"))

        self.assertEqual(audit["status"], "rejected")

    def test_sealed_environment_removes_all_target_search_overrides(self) -> None:
        source = {key: "/ambient" for key in TOOL.SEALED_ENVIRONMENT_KEYS}
        source["PATH"] = "/tools"
        sealed = TOOL.seal_environment(source)
        self.assertEqual(sealed["PATH"], "/tools")
        self.assertEqual(sealed["LC_ALL"], "C")
        for key in TOOL.SEALED_ENVIRONMENT_KEYS:
            self.assertNotIn(key, sealed)

    def test_source_audit_rejects_runtime_c_but_classifies_headers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "lib.rs").write_text("#![no_std]\n", encoding="utf-8")
            (root / "public.h").write_text("int api(void);\n", encoding="utf-8")
            (root / "runtime.c").write_text("int bad(void) { return 0; }\n", encoding="utf-8")
            audit = TOOL.audit_runtime_sources([root])
        self.assertEqual(audit["status"], "rejected")
        self.assertIn("runtime.c", audit["rejected_native_sources"][0])
        self.assertEqual(audit["counts"]["C public declaration or fixture"], 1)

    def test_source_audit_excludes_explicit_non_target_x86_64_assembly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "libc/src"
            source = root / "c_abi/x86_64/evidence.S"
            source.parent.mkdir(parents=True)
            source.write_text("x86-only evidence\n", encoding="utf-8")
            audit = TOOL.audit_runtime_sources([root])
        self.assertEqual(audit["status"], "partial")
        self.assertEqual(audit["rejected_native_sources"], [])
        self.assertEqual(
            audit["excluded_non_target_native_sources"],
            ["libc/src/c_abi/x86_64/evidence.S"],
        )

    def test_embedded_build_path_audit_catches_arbitrary_roots(self) -> None:
        paths = TOOL.embedded_build_paths(
            b"/home/alice/work/lib.rs\0"
            b"/opt/build-root/target/runtime.o\0"
            b"/arbitrary/root/source/module.rs\0"
            b"/crabc/libc/src/lib.rs\0"
            b"/etc/resolv.conf\0"
            b"/lib/ld-crabc-aarch64.so.1\0"
        )
        self.assertEqual(
            paths,
            [
                "/arbitrary/root/source/module.rs",
                "/home/alice/work/lib.rs",
                "/opt/build-root/target/runtime.o",
            ],
        )

    def test_source_audit_is_partial_without_every_runtime_owner(self) -> None:
        audit = TOOL.audit_runtime_sources([ROOT / "libc/src"])
        self.assertEqual(audit["status"], "partial")
        self.assertIn("crt/src", audit["missing_full_runtime_roots"])

    def test_link_audit_rejects_musl_and_accepts_owned_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sysroot = make_sysroot(root)
            owned = sysroot / "usr/lib/libc.so"
            musl = root / "opt/musl-1.2.6/lib/crt1.o"
            musl.parent.mkdir(parents=True)
            musl.write_bytes(b"borrowed")
            audit = TOOL.audit_link_inputs([owned, musl], sysroot)
        self.assertEqual(audit["status"], "rejected")
        self.assertEqual(audit["inputs"][0]["classification"], "crabc Rust runtime")
        self.assertEqual(audit["inputs"][1]["classification"], "rejected foreign target runtime")

    def test_linker_trace_uses_resolved_existing_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sysroot = make_sysroot(root)
            owned = sysroot / "usr/lib/libc.so"
            trace = f"ld.lld: {owned}\nnot-a-path\n".encode()
            audit = TOOL.audit_linker_trace(trace, sysroot)
        self.assertEqual(audit["status"], "passed")
        self.assertEqual(audit["trace_paths"], [str(owned.resolve())])

    def test_linker_trace_retains_archive_member_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sysroot = make_sysroot(root)
            archive = sysroot / "usr/lib/libc.a"
            trace = f"ld.lld: {archive}(compiler_builtins-forbidden.o)\n".encode()
            audit = TOOL.audit_linker_trace(trace, sysroot)
        self.assertEqual(audit["status"], "passed")
        self.assertEqual(
            audit["archive_member_inputs"],
            [
                {
                    "path": str(archive.resolve()),
                    "archive_member": "compiler_builtins-forbidden.o",
                    "classification": "crabc Rust runtime",
                    "reason": "installed crabc sysroot input",
                }
            ],
        )

    def test_linker_trace_allows_declared_application_library_root_but_not_foreign_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sysroot = make_sysroot(root)
            application_lib = root / "application-lib"
            application_lib.mkdir()
            application_dso = application_lib / "libapp.so"
            application_dso.write_bytes(b"application")
            foreign = application_lib / "libgcc_s.so"
            foreign.write_bytes(b"foreign")
            trace = f"{application_dso}\n{foreign}\n".encode()
            audit = TOOL.audit_linker_trace(trace, sysroot, application_library_roots=[application_lib])
        self.assertEqual(audit["status"], "rejected")
        self.assertEqual(audit["inputs"][0]["classification"], "application object")
        self.assertEqual(audit["inputs"][1]["classification"], "rejected foreign target runtime")

    def test_relative_symlink_check_rejects_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "lib").mkdir()
            (root / "lib/ok").symlink_to("loader")
            (root / "lib/bad").symlink_to("../../outside")
            violations = RUNNER.relative_symlink_violations(root)
        self.assertEqual(violations, ["lib/bad -> ../../outside"])

    def test_header_trace_audit_rejects_ambient_headers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            allowed = root / "allowed"
            ambient = root / "ambient"
            allowed.mkdir()
            ambient.mkdir()
            allowed_header = allowed / "ok.h"
            ambient_header = ambient / "bad.h"
            allowed_header.write_text("ok\n", encoding="utf-8")
            ambient_header.write_text("bad\n", encoding="utf-8")
            trace = f". {allowed_header}\n.. {ambient_header}\n".encode()
            audit = RUNNER.audit_header_trace(trace, [allowed])
        self.assertEqual(audit["status"], "rejected")
        self.assertEqual(audit["ambient_headers"], [str(ambient_header.resolve())])

    def test_process_map_audit_requires_owned_dynamic_loader_and_libc(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sysroot = make_sysroot(root)
            loader = sysroot / "lib/ld-crabc-aarch64.so.1"
            libc = sysroot / "usr/lib/libc.so"
            maps = (
                f"0000-1000 r-xp 00000000 00:00 0 {loader}\n"
                f"1000-2000 r-xp 00000000 00:00 0 {libc}\n"
            ).encode()
            audit = RUNNER.audit_process_maps(maps, sysroot, dynamic=True)
        self.assertEqual(audit["status"], "passed")

    def test_dynamic_map_snapshot_waits_past_loader_only_startup_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sysroot = make_sysroot(root)
            loader = sysroot / "lib/ld-crabc-aarch64.so.1"
            libc = sysroot / "usr/lib/libc.so"
            loader.write_bytes(b"loader")
            libc.write_bytes(b"libc")
            loader_only = f"0000-1000 r-xp 00000000 00:00 0 {loader}\n".encode()
            complete = loader_only + f"1000-2000 r-xp 00000000 00:00 0 {libc}\n".encode()
            self.assertFalse(RUNNER.map_snapshot_is_ready(loader_only, sysroot, dynamic=True))
            self.assertTrue(RUNNER.map_snapshot_is_ready(complete, sysroot, dynamic=True))

    def test_assembler_rejects_borrowed_crt_before_creating_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            include = root / "include"
            include.mkdir()
            (include / "stdio.h").write_text("/* declaration */\n", encoding="utf-8")
            artifacts = root / "artifacts"
            artifacts.mkdir()
            for name in ("libc.so", "libc.a", "libldso.so", "libcrabc-builtins.a"):
                (artifacts / name).write_bytes(b"not inspected because CRT is foreign")
            borrowed_crt = root / "opt/musl-1.2.6/crt"
            borrowed_crt.mkdir(parents=True)
            for name in TOOL.CRT_OBJECTS:
                (borrowed_crt / name).write_bytes(b"borrowed")
            inputs = TOOL.RuntimeInputs(
                include_dir=include,
                libc_shared=artifacts / "libc.so",
                libc_static=artifacts / "libc.a",
                loader=artifacts / "libldso.so",
                crt_dir=borrowed_crt,
                builtins=artifacts / "libcrabc-builtins.a",
                crt_provenance=None,
                crt_commands=None,
                builtins_provenance=None,
                builtins_commands=None,
            )
            output = root / "new-sysroot"
            toolchain = TOOL.Toolchain(Path("/clang"), Path("/ld.lld"), Path("/resource"), "test", "test")
            with self.assertRaises(TOOL.SysrootError):
                TOOL.assemble_sysroot(output, inputs, toolchain)
            self.assertFalse(output.exists())


class HarnessContractTests(unittest.TestCase):
    def test_harness_manifest_and_fixture_contract(self) -> None:
        manifest = RUNNER.load_manifest()
        self.assertEqual(manifest["target"]["triple"], TOOL.TARGET_TRIPLE)
        self.assertEqual(manifest["target"]["interpreter"], TOOL.CANONICAL_INTERPRETER)
        self.assertTrue((RUNNER.FIXTURES / manifest["fixtures"]["main"]).is_file())
        self.assertTrue((RUNNER.FIXTURES / manifest["fixtures"]["shared"]).is_file())

    def test_crt_provenance_never_defaults_to_verified(self) -> None:
        self.assertEqual(TOOL.read_crt_provenance(None, {}, None)["status"], "unverified")

    def test_crt_provenance_binds_every_object_and_producer_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            objects: dict[str, Path] = {}
            commands: list[dict[str, object]] = [{"kind": "toolchain", "command": ["rustup", "run", TOOL.CRT_PINNED_TOOLCHAIN, "rustc", "-Vv"]}]
            object_records: dict[str, object] = {}
            for name in TOOL.CRT_OBJECTS:
                object_path = root / name
                object_path.write_bytes(name.encode("ascii"))
                objects[name] = object_path
                command = [
                    "rustup",
                    "run",
                    TOOL.CRT_PINNED_TOOLCHAIN,
                    "rustc",
                    "--emit=obj",
                    "--target",
                    TOOL.TARGET_TRIPLE,
                    "-o",
                    f"$CRABC_CRT_OUT/{name}",
                ]
                commands.append({"kind": "compile", "object": name, "command": command, "returncode": 0})
                commands.append(
                    {
                        "kind": "machine_entry_audit",
                        "object": name,
                        "command": ["llvm-objdump", "-d", "--disassemble-symbols=_start", f"$CRABC_CRT_OUT/{name}"],
                        "returncode": 0,
                    }
                )
                machine_contract: dict[str, object] = {"status": "not_applicable"}
                if name in {"crt1.o", "Scrt1.o", "rcrt1.o"}:
                    machine_contract = {
                        "status": "verified",
                        "no_return_or_call_before_handoff": True,
                        "no_early_system_or_tls_register_read": True,
                    }
                object_records[name] = {
                    "path": name,
                    "sha256": TOOL.sha256_file(object_path),
                    "source": f"/crabc/crt/src/{TOOL.CRT_SOURCE_FILES[name]}",
                    "source_languages": ["Rust"],
                    "producer": command,
                    "entry_machine_contract": machine_contract,
                }
            commands_path = root / "commands.json"
            commands_path.write_text(json.dumps(commands), encoding="utf-8")
            provenance_path = root / "objects.json"
            provenance_path.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "target": TOOL.TARGET_TRIPLE,
                        "toolchain": TOOL.CRT_PINNED_TOOLCHAIN,
                        "objects": object_records,
                        "commands": {"name": commands_path.name, "sha256": TOOL.sha256_file(commands_path)},
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(TOOL.read_crt_provenance(provenance_path, objects, commands_path)["status"], "verified")
            commands[1]["command"].append("--substituted")
            commands_path.write_text(json.dumps(commands), encoding="utf-8")
            self.assertEqual(TOOL.read_crt_provenance(provenance_path, objects, commands_path)["status"], "rejected")
            commands[1]["command"].pop()
            commands_path.write_text(json.dumps(commands), encoding="utf-8")
            objects["crt1.o"].write_bytes(b"changed")
            self.assertEqual(TOOL.read_crt_provenance(provenance_path, objects, commands_path)["status"], "rejected")

    def test_builtins_provenance_requires_the_locked_source_built_lane(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "libcrabc-builtins.a"
            archive.write_bytes(b"pure-rust-helpers")
            commands_path = root / "libcrabc-builtins.a.commands.json"
            commands = {
                "schema": 1,
                "archive": archive.name,
                "operations": [
                    {"kind": "compile_local_helpers", "command": ["rustc", "--emit=obj", "--target", TOOL.TARGET_TRIPLE]},
                    {
                        "kind": "source_build_compiler_builtins",
                        "command": ["cargo", "build", "--locked", "-Zbuild-std=core,compiler_builtins"],
                        "audit": {"native_build_commands": [], "target_link_directives": []},
                    },
                    {"kind": "extract_source_built_members", "command": ["llvm-ar", "x", "source.rlib"]},
                    {
                        "kind": "create_deterministic_archive",
                        "command": ["llvm-ar", "rcsD", f"$CRABC_BUILTINS_OUT/{archive.name}"],
                    },
                    {"kind": "audit_archive_surface", "commands": []},
                ],
            }
            commands_path.write_text(json.dumps(commands), encoding="utf-8")
            provenance = {
                "component": {
                    "name": "crabc-builtins",
                    "target": TOOL.TARGET_TRIPLE,
                },
                "archive": {
                    "name": "libcrabc-builtins.a",
                    "sha256": TOOL.sha256_file(archive),
                    "defined_symbols": sorted(TOOL.REQUIRED_RUST_COMPILER_HELPERS),
                    "undefined_symbols": [],
                    "members": ["crabc-builtins.o", "compiler_builtins-fixture.o"],
                },
                "source": {
                    "languages": ["Rust"],
                    "upstream_selected_files": [
                        {
                            "path": "rust-src/library/compiler-builtins/compiler-builtins/src/lib.rs",
                            "sha256": "0" * 64,
                        }
                    ],
                    "upstream_build_script_inputs": [
                        {
                            "path": "rust-src/library/compiler-builtins/libm/configure.rs",
                            "sha256": "1" * 64,
                        }
                    ],
                },
                "dependency_purity": {
                    "uses_alloc": False,
                    "uses_native_source": False,
                    "uses_native_assembly": False,
                    "uses_unwinding": False,
                    "requires_panic_runtime": False,
                    "upstream_source_build": {
                        "package": "compiler_builtins",
                        "version": "0.1.160",
                        "links_metadata": "compiler-rt",
                        "selected_features": sorted(TOOL.REQUIRED_COMPILER_BUILTINS_FEATURES),
                        "disabled_features": ["c", "mem"],
                        "native_build_commands": [],
                        "target_link_directives": [],
                        "prebuilt_compiler_builtins_input": False,
                        "source_built_standard_components": ["core", "compiler_builtins"],
                        "source_built_rlib_sha256": "2" * 64,
                    },
                },
                "build": {
                    "exact_command_record": {
                        "name": commands_path.name,
                        "sha256": TOOL.sha256_file(commands_path),
                    }
                },
            }
            provenance_path = root / "provenance.json"
            provenance_path.write_text(json.dumps(provenance), encoding="utf-8")
            self.assertEqual(TOOL.read_builtins_provenance(provenance_path, archive, commands_path)["status"], "verified")

            commands["operations"][0]["command"].append("--substituted")
            commands_path.write_text(json.dumps(commands), encoding="utf-8")
            self.assertEqual(TOOL.read_builtins_provenance(provenance_path, archive, commands_path)["status"], "rejected")
            commands["operations"][0]["command"].pop()
            commands_path.write_text(json.dumps(commands), encoding="utf-8")

            provenance["dependency_purity"]["upstream_source_build"]["selected_features"].append("c")
            provenance_path.write_text(json.dumps(provenance), encoding="utf-8")
            self.assertEqual(TOOL.read_builtins_provenance(provenance_path, archive, commands_path)["status"], "rejected")

    def test_dependency_audit_is_partial_without_complete_cargo_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "Cargo.toml"
            manifest.write_text("[package]\nname = 'fixture'\nversion = '0.1.0'\n", encoding="utf-8")
            audit = TOOL.audit_dependencies([manifest])
        self.assertEqual(audit["status"], "partial")
        self.assertEqual(audit["closure_status"], "partial")

    def test_dependency_audit_requires_metadata_to_cover_each_explicit_component(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first/Cargo.toml"
            second = root / "second/Cargo.toml"
            first.parent.mkdir()
            second.parent.mkdir()
            for path, name in ((first, "first"), (second, "second")):
                path.write_text(f"[package]\nname = '{name}'\nversion = '0.1.0'\n", encoding="utf-8")
            metadata = root / "metadata.json"
            metadata.write_text(json.dumps({"packages": [{"manifest_path": str(first)}]}), encoding="utf-8")
            audit = TOOL.audit_dependencies([first, second], cargo_metadata=[metadata])
        self.assertEqual(audit["status"], "rejected")
        self.assertEqual(audit["uncovered_explicit_manifests"], ["second/Cargo.toml"])

    def test_dependency_audit_rejects_native_selected_source_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "Cargo.toml"
            source = root / "src"
            source.mkdir()
            manifest.write_text("[package]\nname = 'fixture'\nversion = '0.1.0'\n", encoding="utf-8")
            (source / "foreign.S").write_text("foreign assembly\n", encoding="utf-8")
            audit = TOOL.audit_dependencies([manifest])
        self.assertEqual(audit["status"], "rejected")
        self.assertIn("native implementation", audit["rejected"][0]["reason"])

    def test_dependency_audit_excludes_crabc_libc_x86_64_assembly_from_aarch64(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "libc"
            source = root / "src/c_abi/x86_64/evidence.S"
            source.parent.mkdir(parents=True)
            (root / "Cargo.toml").write_text(
                "[package]\nname = 'crabc-libc'\nversion = '0.1.0'\n",
                encoding="utf-8",
            )
            source.write_text("x86-only evidence\n", encoding="utf-8")
            audit = TOOL.audit_dependencies([root / "Cargo.toml"])
        self.assertEqual(audit["status"], "partial")
        self.assertEqual(audit["rejected"], [])
        self.assertEqual(
            audit["manifests"][0]["excluded_non_target_native_source_inputs"],
            ["libc/src/c_abi/x86_64/evidence.S"],
        )

    def test_dependency_audit_excludes_dev_only_packages_from_runtime_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            allocator = root / "allocator"
            compiler_helper = root / "cc"
            generator = root / "generator"
            for directory, name, extra in (
                (runtime, "runtime", ""),
                (allocator, "libmimalloc-sys", "links = 'mimalloc'\nbuild = 'build.rs'\n"),
                (compiler_helper, "cc", ""),
                (generator, "generator", ""),
            ):
                (directory / "src").mkdir(parents=True)
                version = "0.1.49" if name == "libmimalloc-sys" else "1.4.3" if name == "cc" else "0.1.0"
                (directory / "Cargo.toml").write_text(
                    f"[package]\nname = '{name}'\nversion = '{version}'\n{extra}", encoding="utf-8"
                )
            (allocator / "c_src/mimalloc/v3/src").mkdir(parents=True)
            (allocator / "c_src/mimalloc/v3/src/static.c").write_text("native allocator\n", encoding="utf-8")
            (allocator / "build.rs").write_text(
                'let static_source = include_root.join("src").join("static.c");\n'
                "build.file(&static_source);\n"
                'build.compile("mimalloc");\n',
                encoding="utf-8",
            )
            (compiler_helper / "src/detect_compiler_family.c").write_text("host compiler probe\n", encoding="utf-8")
            (generator / "src/fixture.S").write_text("foreign assembly\n", encoding="utf-8")
            metadata = root / "metadata.json"
            metadata.write_text(
                json.dumps(
                    {
                        "packages": [
                            {"id": "runtime", "name": "runtime", "manifest_path": str(runtime / "Cargo.toml")},
                            {"id": "allocator", "name": "libmimalloc-sys", "manifest_path": str(allocator / "Cargo.toml")},
                            {"id": "cc", "name": "cc", "manifest_path": str(compiler_helper / "Cargo.toml")},
                            {"id": "generator", "name": "generator", "manifest_path": str(generator / "Cargo.toml")},
                        ],
                        "resolve": {
                            "nodes": [
                                {
                                    "id": "runtime",
                                    "deps": [
                                        {"pkg": "allocator", "dep_kinds": [{"kind": None}]},
                                        {"pkg": "generator", "dep_kinds": [{"kind": "dev"}]},
                                    ],
                                },
                                {"id": "allocator", "deps": [{"pkg": "cc", "dep_kinds": [{"kind": "build"}]}]},
                                {"id": "cc", "deps": []},
                                {"id": "generator", "deps": []},
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            audit = TOOL.audit_dependencies([runtime / "Cargo.toml"], cargo_metadata=[metadata])
        self.assertEqual(audit["status"], "blocked_by_native_allocator")
        self.assertEqual(audit["production_closure"]["excluded_dev_package_ids"], ["generator"])
        self.assertEqual([entry["package"] for entry in audit["manifests"]], ["libmimalloc-sys", "cc", "runtime"])
        self.assertEqual(audit["unapproved_rejected"], [])
        self.assertEqual(audit["allocator_exception"]["verified_build_helper_package_ids"], ["cc"])

    def test_dependency_audit_does_not_bless_allocator_transitive_native_package(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            allocator = root / "allocator"
            transitive = root / "transitive"
            for directory, name, extra in (
                (runtime, "runtime", ""),
                (allocator, "libmimalloc-sys", "links = 'mimalloc'\n"),
                (transitive, "unexpected-native", "links = 'unexpected'\n"),
            ):
                directory.mkdir(parents=True)
                version = "0.1.49" if name == "libmimalloc-sys" else "0.1.0"
                (directory / "Cargo.toml").write_text(
                    f"[package]\nname = '{name}'\nversion = '{version}'\n{extra}", encoding="utf-8"
                )
            (allocator / "c_src/mimalloc/v3/src").mkdir(parents=True)
            (allocator / "c_src/mimalloc/v3/src/static.c").write_text("native allocator\n", encoding="utf-8")
            (allocator / "build.rs").write_text(
                'let static_source = include_root.join("src").join("static.c");\n'
                "build.file(&static_source);\n"
                'build.compile("mimalloc");\n',
                encoding="utf-8",
            )
            metadata = root / "metadata.json"
            metadata.write_text(
                json.dumps(
                    {
                        "packages": [
                            {"id": "runtime", "name": "runtime", "manifest_path": str(runtime / "Cargo.toml")},
                            {"id": "allocator", "name": "libmimalloc-sys", "manifest_path": str(allocator / "Cargo.toml")},
                            {"id": "transitive", "name": "unexpected-native", "manifest_path": str(transitive / "Cargo.toml")},
                        ],
                        "resolve": {
                            "nodes": [
                                {"id": "runtime", "deps": [{"pkg": "allocator", "dep_kinds": [{"kind": None}]}]},
                                {"id": "allocator", "deps": [{"pkg": "transitive", "dep_kinds": [{"kind": "build"}]}]},
                                {"id": "transitive", "deps": []},
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            audit = TOOL.audit_dependencies([runtime / "Cargo.toml"], cargo_metadata=[metadata])
        self.assertEqual(audit["status"], "rejected")
        self.assertTrue(any(entry["package_id"] == "transitive" for entry in audit["unapproved_rejected"]))


if __name__ == "__main__":
    unittest.main()
