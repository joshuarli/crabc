"""The owned Rust linker admits only the complete explicit product link."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    "owned_rust_link", Path(__file__).parents[1] / "owned_rust_link.py"
)
linker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(linker)


class OwnedRustLinkContract(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.application = root / "application"
        self.stock = root / "stock"
        self.application.mkdir()
        self.stock.mkdir()
        (self.application / "fixture.o").write_bytes(b"object")
        (self.application / "libapp-0123456789abcdef.rlib").write_bytes(b"archive")
        (self.stock / "libstd-0123456789abcdef.rlib").write_bytes(b"archive")
        (self.stock / "libunwind-0123456789abcdef.rlib").write_bytes(b"archive")
        (self.stock / "libcompiler_builtins-0123456789abcdef.rlib").write_bytes(b"archive")
        (self.application / "raw-dylibs").mkdir()

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

    def test_trace_rejects_stock_or_ambient_unwind_after_translation(self):
        provider = Path(self.temporary.name) / "libcrabc-unwind.a"
        provider.write_bytes(b"provider")
        with self.assertRaisesRegex(linker.LinkError, "unowned|ambient"):
            linker.validate_trace(
                str(self.stock / "libunwind-0123456789abcdef.rlib"), {provider}
            )


if __name__ == "__main__":
    unittest.main()
