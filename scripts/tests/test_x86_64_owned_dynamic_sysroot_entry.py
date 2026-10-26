"""The dynamic sysroot producer must start under a qualification case's Python policy."""
import os
import importlib.util
import json
import tempfile
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
PRODUCER = ROOT / "scripts/build_x86_64_owned_dynamic_sysroot.py"


class DynamicSysrootEntryTests(unittest.TestCase):
    # The producer resolves its Rust and LLVM tools only from the fixed
    # toolchain roots of the evidence image.
    @unittest.skipUnless(
        Path("/opt/cargo/bin/rustup").is_file(), "pinned evidence-image toolchain is absent"
    )
    def test_shared_libc_extracts_private_helpers_without_allocator_imports(self):
        spec = importlib.util.spec_from_file_location("dynamic_private_helper_link", PRODUCER)
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        tools = builder.common.resolve_pinned_producer_tools()
        linker = builder.common.native_build_tools.MOLD
        ar = builder.common.producer_tool_path(tools, "llvm-ar")
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as temporary:
            work = Path(temporary)
            objects = work / "objects"
            objects.mkdir()
            library = work / "library"
            library.mkdir()
            map_path = work / "libc.map"

            def run(command):
                completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))
                return completed.stdout.decode()

            for name, source in {
                "libc": "extern unsigned __int128 __addoti4(unsigned __int128, unsigned __int128, int *);\n"
                        "int owned_entry(void) { int overflow; return (int)__addoti4(1, 2, &overflow); }\n"
                        "int fixture_private_errno;\n",
                "crabc-builtins": "int fixture_private_helper_one(unsigned long v) { return !!v; }\n"
                                  "unsigned long fixture_private_helper_two(unsigned long a, unsigned long b) { return a / b; }\n"
                                  "unsigned __int128 __addoti4(unsigned __int128 left, unsigned __int128 right, int *overflow) {\n"
                                  "unsigned __int128 result = left + right; *overflow = result < left; return result; }\n",
                "unrelated": "int unrelated_archive_entry(void) { return 9; }\n",
            }.items():
                path = work / (name + ".c")
                path.write_text(source)
                run(["/usr/bin/gcc", "-O2", "-fPIC", "-ffreestanding", "-nostdinc",
                     "-fno-stack-protector", "-ffunction-sections", "-c", str(path), "-o",
                     str(objects / (name + ".o"))])
            archive = work / "libcrabc-builtins.a"
            unrelated = objects / "unrelated.a"
            run([ar, "rcs", str(archive), str(objects / "crabc-builtins.o")])
            run([ar, "rcs", str(unrelated), str(objects / "unrelated.o")])
            dynamic_list = work / "exports.list"
            dynamic_list.write_text("{ owned_entry; };\n")
            aliases = work / "aliases.map"
            aliases.write_text("{ local: fixture_private_errno; };\n")
            command = builder.shared_libc_link_command(
                linker, dynamic_list, None, aliases, objects, ("libc.o", "unrelated.a"), archive, library)
            command[1:1] = ["--trace", "-Map", str(map_path)]
            command.append(str(unrelated))
            trace_lines = run(command).splitlines()
            sys.path.insert(0, str(ROOT / "compat/x86_64"))
            import compiler_helper_evidence as helper_evidence
            transfer = helper_evidence._compiler_helper_transfers(
                root=ROOT, archive=archive, workload=objects / "libc.o",
                executable=library / "libc.so", map_path=map_path, trace_lines=trace_lines,
                source_mount=str(ROOT), names=("__addoti4",),
                binding_policy=helper_evidence._helper_final_policy_for_linkage("pie"))
            self.assertEqual(set(transfer["transfers"]), {"__addoti4"})
            symbols = run(["/usr/bin/readelf", "-sW", str(library / "libc.so")])
            from native_abi_inventory import parse_elf_symbol_tables
            tables = parse_elf_symbol_tables(symbols)
            self.assertEqual(builder.elf_imports(
                builder.common.producer_tool_path(tools, "llvm-nm"), library / "libc.so"), set())
            regular = next(table["rows"] for table in tables if table["name"] == ".symtab")
            dynamic = next(table["rows"] for table in tables if table["name"] == ".dynsym")
            names = {"fixture_private_helper_one", "fixture_private_helper_two", "__addoti4"}
            selected = [row for row in regular if row["name"] in names]
            self.assertEqual({row["name"] for row in selected}, names)
            for row in selected:
                self.assertEqual((row["type"], row["binding"], row["visibility"]),
                                 ("FUNC", "LOCAL", "HIDDEN"))
                self.assertTrue(row["section_index"].isdigit())
            self.assertFalse(any(row["name"] in names for row in dynamic))
            self.assertFalse(any(row["name"] == "unrelated_archive_entry" for row in regular))
            self.assertTrue(any(row["name"] == "owned_entry" and row["section_index"].isdigit()
                                for row in dynamic))
            elf = helper_evidence.Elf(library / "libc.so")
            helper_rows = [(section_index, section, row_index)
                           for section_index, section in enumerate(elf.sections) if section[1] == 2
                           for row_index in range(section[5] // 24)
                           if elf.symbol_row(section_index, row_index)["name"] == "__addoti4"]
            self.assertEqual(len(helper_rows), 1)
            _, symbol_table, row_index = helper_rows[0]
            tampered_bytes = bytearray(elf.data)
            visibility_offset = symbol_table[4] + row_index * 24 + 5
            self.assertEqual(tampered_bytes[visibility_offset] & 3, 2)
            tampered_bytes[visibility_offset] &= 0xfc
            tampered = library / "libc-tampered.so"
            tampered.write_bytes(tampered_bytes)
            with self.assertRaisesRegex(helper_evidence.CompilerHelperEvidenceError, "provider metadata"):
                helper_evidence._compiler_helper_transfers(
                    root=ROOT, archive=archive, workload=objects / "libc.o", executable=tampered,
                    map_path=map_path, trace_lines=trace_lines, source_mount=str(ROOT), names=("__addoti4",),
                    binding_policy=helper_evidence._helper_final_policy_for_linkage("pie"))

            missing_source = work / "missing.c"
            missing_source.write_text("extern int foreign_dependency(void);\n"
                                      "int bad_entry(void) { return foreign_dependency(); }\n")
            run(["/usr/bin/gcc", "-O2", "-fPIC", "-fno-plt", "-c", str(missing_source),
                 "-o", str(objects / "missing.o")])
            run(builder.shared_libc_link_command(
                linker, dynamic_list, None, aliases, objects, ("libc.o", "missing.o"), archive, library))
            self.assertEqual(builder.elf_imports(
                builder.common.producer_tool_path(tools, "llvm-nm"), library / "libc.so"),
                {"foreign_dependency"})

    def test_shared_helper_policy_and_roots_project_the_current_contract(self):
        spec = importlib.util.spec_from_file_location("dynamic_helper_policy_contract", PRODUCER)
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        contract = builder.tomllib.loads(builder.COMPILER_HELPER_CONTRACT.read_text(encoding="utf-8"))

        policy = builder.shared_libc_compiler_helper_archive_policy()

        self.assertEqual(policy, {
            "source": builder._source_file_identity(
                builder.COMPILER_HELPER_CONTRACT, "native compiler-helper contract"
            ),
            "archive": contract["archive"]["name"],
            "member": contract["archive"]["member"],
            **contract["shared_libc"],
        })
        self.assertEqual(builder.debug_shared_libc_compiler_helper_root_arguments(), [
            f"--undefined={row['name']}" for row in contract["helpers"]
        ])

    def test_debug_manifest_seals_source_without_release_materialization_fields(self):
        spec = importlib.util.spec_from_file_location("dynamic_debug_source_producer", PRODUCER)
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as temporary:
            output = Path(temporary)
            metadata = output / "share/crabc"
            metadata.mkdir(parents=True)
            state = {"build_profile": "debug", "allocator_backend": "native-shadow",
                     "allocator_lifecycle_test_audit": False, "status": "materialized-unqualified"}
            builder.common.write_json(metadata / "dynamic-product-state.json", state)
            with mock.patch.object(builder.qualification, "source_digest", return_value="a" * 64):
                builder.write_product_manifest(output, metadata, profile="debug")
            manifest = json.loads((metadata / "manifest.json").read_text())
            self.assertEqual(manifest["source_sha256"], "a" * 64)
            self.assertEqual(manifest["build_profile"], "debug")
            self.assertEqual(json.loads((metadata / "dynamic-product-state.json").read_text()), state)
            self.assertEqual(manifest["files"]["share/crabc/dynamic-product-state.json"], builder.common.sha256_file(metadata / "dynamic-product-state.json"))
            builder.write_product_manifest(output, metadata, profile="release")
            self.assertNotIn("source_sha256", json.loads((metadata / "manifest.json").read_text()))

    def test_debug_source_change_during_build_refuses_publication(self):
        spec = importlib.util.spec_from_file_location("dynamic_debug_source_change", PRODUCER)
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as temporary:
            output = Path(temporary) / "candidate"
            with (mock.patch.object(builder.common, "assert_native_target"),
                  mock.patch.object(builder, "build_staged_payload"),
                  mock.patch.object(builder.qualification, "source_digest", side_effect=["a" * 64, "b" * 64]),
                  mock.patch.object(builder.installed_driver, "validate") as installed,
                  mock.patch.object(builder.shared_package, "publish_noreplace") as publish):
                with self.assertRaisesRegex(builder.common.BuildError, "source changed"):
                    builder.build(output, profile="debug", allocator_backend="native-shadow")
                installed.assert_not_called()
                publish.assert_not_called()
                self.assertFalse(output.exists())

    def test_producer_imports_its_shared_static_module_with_pythonsafepath(self):
        # A qualification case may run this producer directly with
        # PYTHONSAFEPATH=1, which omits the script directory from sys.path.
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONSAFEPATH": "1",
            "PYTHONNOUSERSITE": "1",
        }
        completed = subprocess.run(
            [sys.executable, "-B", str(PRODUCER), "--help"],
            cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))
        self.assertIn(b"usage:", completed.stdout)


if __name__ == "__main__":
    unittest.main()
