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
        ))
        parsed = linker.parse_arguments(arguments, self.application, self.stock, self.source_built)
        self.assertEqual(parsed["rust_mode"], "shared")
        self.assertEqual(parsed["output"], nested / "libcleanup.so")

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
