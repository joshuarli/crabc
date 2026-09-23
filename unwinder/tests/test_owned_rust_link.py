"""The owned Rust linker admits only the complete explicit product link."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "owned_rust_link", Path(__file__).parents[1] / "owned_rust_link.py"
)
linker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(linker)

WORK = Path(__file__).parents[2] / ".work/x86_64/unwinder-output-tests"
PINNED_CDYLIB_EXPORT_SCRIPT = (
    "{\n  global:\n    crabc_owned_cleanup_dso;\n"
    "    crabc_owned_cleanup_dso_ready;\n    crabc_owned_cleanup_dso_release;\n"
    "    _Unwind_Backtrace;\n    _Unwind_DeleteException;\n"
    "    _Unwind_FindEnclosingFunction;\n    _Unwind_ForcedUnwind;\n"
    "    _Unwind_GetCFA;\n    _Unwind_GetDataRelBase;\n    _Unwind_GetGR;\n"
    "    _Unwind_GetIP;\n    _Unwind_GetIPInfo;\n"
    "    _Unwind_GetLanguageSpecificData;\n    _Unwind_GetRegionStart;\n"
    "    _Unwind_GetTextRelBase;\n    _Unwind_RaiseException;\n"
    "    _Unwind_Resume;\n    _Unwind_Resume_or_Rethrow;\n"
    "    _Unwind_SetGR;\n    _Unwind_SetIP;\n\n  local:\n    *;\n};\n"
)
PINNED_CDYLIB_EXPORT_SCRIPT_SHA256 = "5ffdc0a045a216d75978a24d62fee6494ab9d4693609946f6670a3c52a152f1f"


class OwnedRustLinkContract(unittest.TestCase):
    def setUp(self):
        WORK.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=WORK)
        root = Path(self.temporary.name)
        self.application = root / "application"
        self.stock = root / "stock"
        self.application.mkdir()
        self.stock.mkdir()
        self.source_built = root / "source-built"
        self.source_built.mkdir()
        self.toolchain_search = root / "toolchain-target-lib"
        self.toolchain_search.mkdir()
        self.host_build = root / "cargo-target/release/build"
        self.host_build.mkdir(parents=True)
        (self.application / "fixture.o").write_bytes(b"object")
        (self.application / "libapp-0123456789abcdef.rlib").write_bytes(b"archive")
        (self.stock / "libstd-0123456789abcdef.rlib").write_bytes(b"archive")
        (self.stock / "libunwind-0123456789abcdef.rlib").write_bytes(b"archive")
        (self.stock / "libcompiler_builtins-0123456789abcdef.rlib").write_bytes(b"archive")
        for name in (
            "libstd-0123456789abcdef.rlib",
            "libcore-0123456789abcdef.rlib",
            "liballoc-0123456789abcdef.rlib",
            "libpanic_unwind-0123456789abcdef.rlib",
            "libunwind-0123456789abcdef.rlib",
            "libcompiler_builtins-0123456789abcdef.rlib",
            "libcrabc_unwinder-0123456789abcdef.rlib",
            "libunwinding-0123456789abcdef.rlib",
        ):
            (self.source_built / name).write_bytes(b"archive")
        (self.application / "raw-dylibs").mkdir()
        (self.application / "rust-cdylib.map").write_text(
            "{\n  global:\n    crabc_owned_cleanup_dso;\n"
            "    crabc_owned_cleanup_dso_ready;\n"
            "    crabc_owned_cleanup_dso_release;\n"
            "  local:\n    *;\n};\n"
        )

    def tearDown(self):
        self.temporary.cleanup()

    def arguments(self):
        return [
            "-m64", str(self.application / "fixture.o"), "-Wl,--as-needed", "-Wl,-Bstatic",
            str(self.application / "libapp-0123456789abcdef.rlib"),
            str(self.stock / "libstd-0123456789abcdef.rlib"),
            str(self.stock / "libunwind-0123456789abcdef.rlib"),
            str(self.stock / "libcompiler_builtins-0123456789abcdef.rlib"),
            "-Wl,-Bdynamic", "-lgcc_s", "-lc", "-L", str(self.application / "raw-dylibs"),
            "-L", str(self.stock), "-Wl,--eh-frame-hdr", "-Wl,-z,noexecstack", "-o",
            str(self.application / "cleanup"), "-Wl,--gc-sections", "-pie", "-Wl,-z,relro,-z,now",
            "-Wl,-O1", "-Wl,--strip-debug", "-nodefaultlibs",
        ]

    def parse(self, arguments=None):
        return linker.parse_arguments(arguments or self.arguments(), self.application, self.stock)

    def source_built_arguments(self):
        return [
            "-m64", str(self.application / "fixture.o"), "-Wl,--as-needed", "-Wl,-Bstatic",
            str(self.source_built / "libcompiler_builtins-0123456789abcdef.rlib"),
            "-Wl,-Bdynamic", "-lgcc_s", "-lc", "-L", str(self.application / "raw-dylibs"),
            "-L", str(self.source_built), "-Wl,--eh-frame-hdr", "-Wl,-z,noexecstack", "-o",
            str(self.application / "cleanup"), "-Wl,--gc-sections", "-pie", "-Wl,-z,relro,-z,now",
            "-Wl,-O1", "-Wl,--strip-debug", "-nodefaultlibs",
        ]

    def source_cdylib_exports(self):
        unwind_abi = (
            "_Unwind_Backtrace", "_Unwind_DeleteException", "_Unwind_FindEnclosingFunction",
            "_Unwind_ForcedUnwind", "_Unwind_GetCFA", "_Unwind_GetDataRelBase", "_Unwind_GetGR",
            "_Unwind_GetIP", "_Unwind_GetIPInfo", "_Unwind_GetLanguageSpecificData",
            "_Unwind_GetRegionStart", "_Unwind_GetTextRelBase", "_Unwind_RaiseException",
            "_Unwind_Resume", "_Unwind_Resume_or_Rethrow", "_Unwind_SetGR", "_Unwind_SetIP",
        )
        return linker.rust_cdylib_export_symbols(unwind_abi)

    def test_complete_stock_input_replaces_both_ambient_unwind_paths(self):
        parsed = self.parse()
        self.assertEqual(parsed["stock_unwind"], self.stock / "libunwind-0123456789abcdef.rlib")
        self.assertEqual(parsed["compiler_builtins"], self.stock / "libcompiler_builtins-0123456789abcdef.rlib")
        self.assertNotIn(parsed["stock_unwind"], parsed["archives"])
        self.assertNotIn(parsed["compiler_builtins"], parsed["archives"])
        self.assertEqual(parsed["native_requests"], ["-lgcc_s", "-lc"])

    def test_missing_stock_unwind_archive_fails_closed(self):
        arguments = [item for item in self.arguments() if "libunwind-" not in item]
        with self.assertRaisesRegex(linker.LinkError, "stock Rust libunwind"):
            self.parse(arguments)

    def test_source_built_fat_lto_omits_all_direct_runtime_archives(self):
        parsed = linker.parse_arguments(
            self.source_built_arguments(), self.application, self.stock, self.source_built
        )
        self.assertIsNone(parsed["source_built_unwind"])
        self.assertEqual(
            parsed["source_built_compiler_builtins"],
            self.source_built / "libcompiler_builtins-0123456789abcdef.rlib",
        )
        self.assertEqual(parsed["rust_library_origin"], "source-built")
        self.assertEqual(parsed["archives"], [])

    def test_source_built_direct_libunwind_archive_is_rejected(self):
        with self.assertRaisesRegex(linker.LinkError, "libunwind archive must not enter"):
            linker.parse_arguments(
                [*self.source_built_arguments(), str(self.source_built / "libunwind-0123456789abcdef.rlib")],
                self.application, self.stock, self.source_built,
            )

    def test_source_built_link_admits_only_the_declared_unused_toolchain_search_path(self):
        arguments = self.source_built_arguments()
        last_search = max(index for index, argument in enumerate(arguments) if argument == "-L")
        arguments[last_search + 1] = str(self.toolchain_search)
        parsed = linker.parse_arguments(
            arguments, self.application, self.stock, self.source_built,
            toolchain_search_root=self.toolchain_search,
        )
        self.assertIn(self.toolchain_search, parsed["search_paths"])
        self.assertEqual(parsed["archives"], [])
        stock_core = self.toolchain_search / "libcore-0123456789abcdef.rlib"
        stock_core.write_bytes(b"archive")
        with self.assertRaisesRegex(linker.LinkError, "source-built Rust archive"):
            linker.parse_arguments(
                [*arguments, str(stock_core)], self.application, self.stock, self.source_built,
                toolchain_search_root=self.toolchain_search,
            )

    def test_source_built_fat_lto_rejects_a_direct_cargo_graph_provider(self):
        with self.assertRaisesRegex(linker.LinkError, "fat-LTO final link carries"):
            linker.parse_arguments(
                [*self.source_built_arguments(), str(self.source_built / "libcrabc_unwinder-0123456789abcdef.rlib")],
                self.application, self.stock, self.source_built,
            )

    def test_source_built_fat_lto_object_must_retain_the_declared_abi_and_personality(self):
        object_file = self.application / "fixture.o"
        cargo_object, retained_object = linker.retain_source_lto_object(
            object_file, self.application / "cleanup", self.application,
        )
        self.assertTrue(retained_object.name.endswith(".crabc-owned-source-lto.o"))
        self.assertEqual(cargo_object["sha256"], linker.sha256(retained_object))
        with self.assertRaisesRegex(linker.LinkError, "evidence object must be fresh"):
            linker.retain_source_lto_object(object_file, self.application / "cleanup", self.application)
        expected = ["_Unwind_Backtrace", "_Unwind_RaiseException"]
        nm_output = "\n".join([
            "00000000 T _Unwind_Backtrace",
            "00000000 T _Unwind_RaiseException",
            "00000000 T rust_eh_personality",
        ]) + "\n"
        with patch.dict(os.environ, {linker.SOURCE_LTO_UNWIND_ABI_ENV: json.dumps(expected)}), \
             patch.object(linker, "run", return_value=nm_output):
            receipt = linker.source_lto_object_receipt(cargo_object, retained_object, Path("/pinned/llvm-nm"))
        self.assertEqual(receipt["defined_unwind_abi"], expected)
        self.assertTrue(receipt["rust_eh_personality"])
        self.assertEqual(receipt["cargo_object"], cargo_object)
        self.assertEqual(receipt["retained_object"], {
            "path": str(retained_object), "sha256": linker.sha256(retained_object),
        })
        object_file.unlink()
        self.assertEqual(cargo_object["sha256"], linker.sha256(retained_object))
        with patch.dict(os.environ, {linker.SOURCE_LTO_UNWIND_ABI_ENV: json.dumps(expected)}), \
             patch.object(linker, "run", return_value=nm_output.replace("rust_eh_personality\n", "")):
            with self.assertRaisesRegex(linker.LinkError, "rust_eh_personality"):
                linker.source_lto_object_receipt(cargo_object, retained_object, Path("/pinned/llvm-nm"))

    def test_source_built_host_build_script_is_separate_from_the_final_owned_link(self):
        """Cargo must not send its same-triple host build script to the target linker."""

        package = self.host_build / "compiler_builtins-0123456789abcdef"
        package.mkdir()
        output = package / "build_script_build-0123456789abcdef"
        selected = linker.host_build_script_output(
            ["-m64", str(self.application / "fixture.o"), "-o", str(output), "-static-pie"],
            self.host_build,
        )
        self.assertEqual(selected, output)

    def test_pinned_compiler_builtins_out_dir_build_script_is_admitted(self):
        """Pinned build-std compiles this host script to Cargo's OUT_DIR name."""

        rust_source = Path(self.temporary.name) / "rust-src/library"
        package_source = rust_source / "compiler-builtins/compiler-builtins"
        package_source.mkdir(parents=True)
        (package_source / "Cargo.toml").write_text('[package]\nname = "compiler_builtins"\n')
        (package_source / "build.rs").write_text("fn main() {}\n")
        package_build = self.host_build / "compiler_builtins/0123456789abcdef/out"
        package_build.mkdir(parents=True)
        output = package_build / "build_script_build"
        environment = {
            "CRABC_OWNED_RUST_SOURCE_LIBRARY": str(rust_source),
            "CARGO_MANIFEST_DIR": str(package_source),
            "CARGO_MANIFEST_PATH": str(package_source / "Cargo.toml"),
            "CARGO_CRATE_NAME": "build_script_build",
            "CARGO_PKG_NAME": "compiler_builtins",
        }
        with patch.dict(os.environ, environment):
            selected = linker.host_build_script_output(
                ["-m64", "fixture.o", "-o", str(output), "-static-pie"], self.host_build,
            )
        self.assertEqual(selected, output)

    def test_out_dir_build_script_shape_does_not_admit_another_package(self):
        package_build = self.host_build / "arbitrary_package/0123456789abcdef/out"
        package_build.mkdir(parents=True)
        output = package_build / "build_script_build"
        with self.assertRaisesRegex(linker.LinkError, "not an admitted build script"):
            linker.host_build_script_output(["-o", str(output)], self.host_build)

    def test_approved_vendor_out_dir_build_script_is_admitted(self):
        rust_source = Path(self.temporary.name) / "rust-src/library"
        rust_source.mkdir(parents=True)
        package_source = Path(self.temporary.name) / "cargo-vendor/libc-0.2.189"
        package_source.mkdir(parents=True)
        manifest = package_source / "Cargo.toml"
        source = package_source / "build.rs"
        manifest.write_text('[package]\nname = "libc"\n')
        source.write_text("fn main() {}\n")
        output = self.host_build / "libc/0123456789abcdef/out/build_script_build"
        output.parent.mkdir(parents=True)
        environment = {
            linker.SOURCE_LIBRARY_ENV: str(rust_source),
            linker.HOST_BUILD_SOURCES_ENV: json.dumps([{"manifest": str(manifest), "source": str(source)}]),
            "CARGO_MANIFEST_DIR": str(package_source),
            "CARGO_MANIFEST_PATH": str(manifest),
            "CARGO_CRATE_NAME": "build_script_build",
            "CARGO_PKG_NAME": "libc",
        }
        with patch.dict(os.environ, environment):
            selected = linker.host_build_script_output(["-o", str(output)], self.host_build)
        self.assertEqual(selected, output)

    def test_host_build_script_link_writes_one_exclusive_receipt(self):
        package = self.host_build / "compiler_builtins-0123456789abcdef"
        package.mkdir()
        source = package / "host.c"
        source.write_text("int main(void) { return 0; }\n")
        object_file = package / "host.o"
        host_linker = Path("/usr/bin/gcc")
        subprocess.run(
            [str(host_linker), "-c", str(source), "-o", str(object_file)],
            check=True,
        )
        output = package / "build_script_build-0123456789abcdef"
        receipts = Path(self.temporary.name) / "host-build-receipts"
        receipts.mkdir()
        with patch.dict(os.environ, {
            "CRABC_OWNED_RUST_HOST_BUILD_LINKER": str(host_linker),
            "CRABC_OWNED_RUST_HOST_BUILD_RECEIPTS": str(receipts),
        }):
            linker.delegate_host_build_script([str(object_file), "-o", str(output)], output)
        receipt = receipts / (hashlib.sha256(str(output).encode()).hexdigest() + ".json")
        self.assertEqual(json.loads(receipt.read_text())["output"], {
            "path": str(output), "sha256": linker.sha256(output),
        })

    def test_source_built_std_rejects_stock_target_archives(self):
        arguments = self.source_built_arguments()
        arguments.append(str(self.stock / "libstd-0123456789abcdef.rlib"))
        with self.assertRaisesRegex(linker.LinkError, "source-built Rust archive"):
            linker.parse_arguments(arguments, self.application, self.stock, self.source_built)

    def test_source_built_std_rejects_an_application_rlib(self):
        arguments = self.source_built_arguments()
        application_std = self.application / "libstd-0123456789abcdef.rlib"
        application_std.write_bytes(b"archive")
        arguments.append(str(application_std))
        with self.assertRaisesRegex(linker.LinkError, "source-built Rust archive"):
            linker.parse_arguments(arguments, self.application, self.stock, self.source_built)

    def test_shared_rust_plugin_accepts_nested_cargo_output(self):
        nested = self.application / "deps"
        nested.mkdir()
        arguments = self.source_built_arguments()
        arguments[arguments.index("-pie")] = "-shared"
        arguments[arguments.index(str(self.application / "cleanup"))] = str(nested / "libcleanup.so")
        arguments.extend((
            "-Wl,-soname=libcleanup.so",
            f"-Wl,--version-script={self.application / 'rust-cdylib.map'}",
            "-Wl,--no-undefined-version",
        ))
        parsed = linker.parse_arguments(arguments, self.application, self.stock, self.source_built)
        self.assertEqual(parsed["rust_mode"], "shared")
        self.assertEqual(parsed["output"], nested / "libcleanup.so")
        self.assertTrue(parsed["no_undefined_version"])
        command = linker.link_command(
            linker=Path("/pinned/ld.lld"), root=self.application, mode="dynamic", provider=None,
            objects=[], archives=[], output=parsed["output"], export_dynamic=False,
            rust_mode=parsed["rust_mode"], version_script=parsed["version_script"],
            no_undefined_version=parsed["no_undefined_version"],
        )
        self.assertIn("--no-undefined-version", command)

    def test_no_undefined_version_rejects_a_non_shared_or_unmapped_link(self):
        with self.assertRaisesRegex(linker.LinkError, "requires a shared export script"):
            linker.parse_arguments(
                [*self.source_built_arguments(), "-Wl,--no-undefined-version"],
                self.application, self.stock, self.source_built,
            )
        with self.assertRaisesRegex(linker.LinkError, "unrecognized Rust link argument"):
            linker.parse_arguments(
                [*self.source_built_arguments(), "-Wl,--no-undefined-version=forged"],
                self.application, self.stock, self.source_built,
            )
        with self.assertRaisesRegex(linker.LinkError, "duplicate Rust no-undefined-version"):
            arguments = self.source_built_arguments()
            arguments[arguments.index("-pie")] = "-shared"
            linker.parse_arguments(
                [
                    *arguments,
                    f"-Wl,--version-script={self.application / 'rust-cdylib.map'}",
                    "-Wl,--no-undefined-version", "-Wl,--no-undefined-version",
                ], self.application, self.stock, self.source_built,
            )

    def test_shared_rust_plugin_retains_only_its_rustc_export_script(self):
        nested = self.application / "deps"
        nested.mkdir()
        arguments = self.source_built_arguments()
        arguments[arguments.index("-pie")] = "-shared"
        arguments[arguments.index(str(self.application / "cleanup"))] = str(nested / "libcleanup.so")
        arguments.extend((
            "-Wl,-soname=libcleanup.so",
            f"-Wl,--version-script={self.application / 'rust-cdylib.map'}",
        ))
        parsed = linker.parse_arguments(arguments, self.application, self.stock, self.source_built)
        self.assertEqual(parsed["shared_soname"], "libcleanup.so")
        self.assertEqual(parsed["version_script"], self.application / "rust-cdylib.map")

    def test_shared_rust_plugin_retains_the_raw_cargo_script_before_contract_rejection(self):
        cargo_script = self.application / "rust-cdylib.map"
        cargo_script.write_text("{ GLOBAL: unexpected_export; LOCAL: *; };\n", encoding="ascii")
        output = self.application / "deps/libcleanup.so"
        output.parent.mkdir()
        record, retained = linker.retain_rust_cdylib_export_script(cargo_script, output, self.application)
        self.assertEqual(retained.read_bytes(), cargo_script.read_bytes())
        self.assertEqual(record["cargo_script"]["sha256"], record["retained_script"]["sha256"])
        self.assertEqual(retained.name, "libcleanup.so.crabc-owned-rust-export-script.map")
        with self.assertRaisesRegex(linker.LinkError, "export script differs"):
            linker.audit_rust_cdylib_export_script(retained, self.source_cdylib_exports())

    def test_source_cdylib_export_script_matches_the_pinned_compiler_rendering(self):
        """The 5fed public diagnostic preserved this exact nightly script."""

        script = self.application / "rust-cdylib.map"
        script.write_text(PINNED_CDYLIB_EXPORT_SCRIPT, encoding="ascii")
        self.assertEqual(hashlib.sha256(script.read_bytes()).hexdigest(), PINNED_CDYLIB_EXPORT_SCRIPT_SHA256)
        linker.audit_rust_cdylib_export_script(script, self.source_cdylib_exports())

    def test_source_cdylib_export_script_rejects_wrong_export_roster_or_local_scope(self):
        script = self.application / "rust-cdylib.map"
        expected = self.source_cdylib_exports()
        malformed = {
            "extra": PINNED_CDYLIB_EXPORT_SCRIPT.replace(
                "\n\n  local:", "\n    unapproved_export;\n\n  local:",
            ),
            "missing": PINNED_CDYLIB_EXPORT_SCRIPT.replace("    _Unwind_RaiseException;\n", ""),
            "duplicate": PINNED_CDYLIB_EXPORT_SCRIPT.replace(
                "    _Unwind_RaiseException;\n",
                "    _Unwind_RaiseException;\n    _Unwind_RaiseException;\n",
            ),
            "case": PINNED_CDYLIB_EXPORT_SCRIPT.replace(
                "    crabc_owned_cleanup_dso;\n", "    CRABC_OWNED_CLEANUP_DSO;\n",
            ),
            "local": PINNED_CDYLIB_EXPORT_SCRIPT.replace("    *;\n};\n", "    unapproved_export;\n};\n"),
        }
        for name, contents in malformed.items():
            with self.subTest(name=name):
                script.write_text(contents, encoding="ascii")
                with self.assertRaisesRegex(linker.LinkError, "export script differs"):
                    linker.audit_rust_cdylib_export_script(script, expected)

    def test_source_cdylib_dynamic_exports_match_the_same_exact_roster(self):
        expected = self.source_cdylib_exports()
        nm_output = "\n".join(f"0000000000000000 T {symbol}" for symbol in expected) + "\n"
        with patch.object(linker, "run", return_value=nm_output):
            exports = linker.audit_rust_cdylib_dynamic_exports(
                self.application / "libcleanup.so", Path("/pinned/llvm-nm"), expected,
            )
        self.assertEqual(exports, sorted(expected))
        malformed = {
            "extra": nm_output + "0000000000000000 T unapproved_export\n",
            "missing": "\n".join(f"0000000000000000 T {symbol}" for symbol in expected[:-1]) + "\n",
            "duplicate": nm_output + f"0000000000000000 T {expected[0]}\n",
        }
        for name, output in malformed.items():
            with self.subTest(name=name), patch.object(linker, "run", return_value=output):
                with self.assertRaisesRegex(linker.LinkError, "dynamic exports differ"):
                    linker.audit_rust_cdylib_dynamic_exports(
                        self.application / "libcleanup.so", Path("/pinned/llvm-nm"), expected,
                    )

    def test_shared_rust_plugin_admits_the_saved_pointer_close_handshake_exports(self):
        self.application.joinpath("rust-cdylib.map").write_text(
            "{\n  global:\n    crabc_owned_cleanup_dso;\n"
            "    crabc_owned_cleanup_dso_ready;\n"
            "    crabc_owned_cleanup_dso_release;\n"
            "  local:\n    *;\n};\n"
        )
        nested = self.application / "deps"
        nested.mkdir()
        arguments = self.source_built_arguments()
        arguments[arguments.index("-pie")] = "-shared"
        arguments[arguments.index(str(self.application / "cleanup"))] = str(nested / "libcleanup.so")
        arguments.extend((
            "-Wl,-soname=libcleanup.so",
            f"-Wl,--version-script={self.application / 'rust-cdylib.map'}",
        ))
        parsed = linker.parse_arguments(arguments, self.application, self.stock, self.source_built)
        self.assertEqual(parsed["version_script"], self.application / "rust-cdylib.map")

    def test_direct_or_forwarded_native_fallback_cannot_escape_translation(self):
        for value in ("/usr/lib/libgcc_s.so.1", "-l:libunwind.a", "-Wl,-lgcc_s", "@response"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(linker.LinkError, "runtime|response"):
                    self.parse([*self.arguments(), value])

    def test_product_link_commands_have_no_native_search_or_foreign_runtime(self):
        root = Path(self.temporary.name) / "owned"
        library = root / "usr/lib"
        library.mkdir(parents=True)
        provider = Path(self.temporary.name) / "libcrabc-unwind.a"
        provider.write_bytes(b"provider")
        parsed = self.parse()
        for mode in ("static", "dynamic"):
            command = linker.link_command(
                linker=Path("/pinned/ld.lld"), root=root, mode=mode, provider=provider,
                objects=parsed["objects"], archives=parsed["archives"], output=self.application / f"cleanup-{mode}",
                export_dynamic=False,
            )
            self.assertNotIn("-l", command)
            self.assertNotIn(str(parsed["stock_unwind"]), command)
            self.assertNotIn(str(parsed["compiler_builtins"]), command)
            self.assertIn(str(provider), command)
            if mode == "static":
                self.assertIn("-static", command)
                self.assertIn("--no-dynamic-linker", command)
                self.assertNotIn(str(library / "Scrt1.o"), command)
            else:
                self.assertIn("--dynamic-linker", command)
                self.assertIn(str(library / "Scrt1.o"), command)

    def test_shared_rust_plugin_uses_dynamic_product_without_executable_crt(self):
        root = Path(self.temporary.name) / "owned"
        library = root / "usr/lib"
        library.mkdir(parents=True)
        provider = Path(self.temporary.name) / "libcrabc-unwind.a"
        provider.write_bytes(b"provider")
        parsed = linker.parse_arguments(
            self.source_built_arguments(), self.application, self.stock, self.source_built
        )
        command = linker.link_command(
            linker=Path("/pinned/ld.lld"), root=root, mode="dynamic", provider=None,
            objects=parsed["objects"], archives=parsed["archives"],
            output=self.application / "deps/libcleanup.so", export_dynamic=False, rust_mode="shared",
        )
        self.assertIn("-shared", command)
        self.assertIn("-soname", command)
        self.assertIn(str(library / "crti.o"), command)
        self.assertNotIn(str(self.source_built / "libcrabc_unwinder-0123456789abcdef.rlib"), command)
        self.assertNotIn(str(provider), command)
        self.assertNotIn(str(library / "Scrt1.o"), command)
        self.assertNotIn(str(library / "crabc-dynamic-attach.o"), command)

    def test_trace_rejects_stock_or_ambient_unwind_after_translation(self):
        provider = Path(self.temporary.name) / "libcrabc-unwind.a"
        provider.write_bytes(b"provider")
        with self.assertRaisesRegex(linker.LinkError, "unowned|ambient"):
            linker.validate_trace(
                str(self.stock / "libunwind-0123456789abcdef.rlib"), {provider}
            )


if __name__ == "__main__":
    unittest.main()
