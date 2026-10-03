"""Source-contract checks for the finite native compiler-helper archive."""
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import sys
import subprocess
import tempfile
import tomllib
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BUILDER_PATH = ROOT / "build_x86_64.py"
SPEC = importlib.util.spec_from_file_location("crabc_builtins_x86_contract", BUILDER_PATH)
assert SPEC and SPEC.loader
BUILDER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BUILDER
SPEC.loader.exec_module(BUILDER)


class NativeCompilerHelperContractTests(unittest.TestCase):
    def test_independent_archive_builds_preserve_installed_provenance(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crabc-builtins-provenance-") as temporary:
            root = Path(temporary)
            outputs = [root / name / BUILDER.ARCHIVE_NAME for name in ("first", "second")]
            with mock.patch.object(BUILDER, "run", wraps=BUILDER.run) as run:
                records = [BUILDER.build(output) for output in outputs]
            self.assertEqual(outputs[0].read_bytes(), outputs[1].read_bytes())
            llvm_ar = BUILDER.tool("llvm-ar")
            members = [subprocess.run([llvm_ar, "p", str(output), BUILDER.MEMBER_NAME], check=True,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout for output in outputs]
            self.assertEqual(members[0], members[1])
            commands = [call.args[0] for call in run.call_args_list if "--emit=obj" in call.args[0]]
            self.assertEqual(len(commands), 2)
            destinations = [command[command.index("-o") + 1] for command in commands]
            self.assertNotEqual(destinations[0], destinations[1])
            for output, destination, command, record in zip(outputs, destinations, commands, records):
                self.assertEqual(Path(destination).parent.parent, output.parent)
                self.assertEqual(Path(destination).name, BUILDER.MEMBER_NAME)
                expected = list(command)
                expected[expected.index("-o") + 1] = f"$CRABC_BUILTINS_STAGE/{BUILDER.MEMBER_NAME}"
                self.assertEqual(record["compile_command"], expected)
                portable = record["portable_compile_command"]
                self.assertEqual(portable[portable.index("-o") + 1], expected[expected.index("-o") + 1])
            self.assertEqual(records[0], records[1])

    def test_debug_compilation_uses_opt0_and_the_explicit_source_runtime_metadata(self) -> None:
        core = Path("/owned/core.rmeta")
        compiler = Path("/owned/compiler_builtins.rmeta")
        with mock.patch.object(BUILDER, "rustc", return_value=["pinned-rustc"]), mock.patch.object(BUILDER, "run"):
            command = BUILDER.compile_object(Path("/owned/helper.o"), profile="debug", runtime_core=core,
                                             runtime_compiler_builtins=compiler)
        self.assertIn("opt-level=0", command)
        self.assertNotIn("opt-level=2", command)
        self.assertIn("panic=immediate-abort", command)
        self.assertIn(f"noprelude:core={core}", command)
        self.assertIn(f"noprelude:compiler_builtins={compiler}", command)
        with self.assertRaisesRegex(BUILDER.BuildError, "source-runtime"):
            BUILDER.compile_object(Path("/owned/helper.o"), profile="debug")
    def test_contract_is_the_exact_native_builder_symbol_roster(self) -> None:
        contract = BUILDER.load_native_contract()
        names = tuple(helper["name"] for helper in contract["helpers"])
        self.assertEqual(set(names), BUILDER.REQUIRED_SYMBOLS)
        self.assertEqual(contract["archive"]["member"], "crabc-builtins.o")
        self.assertEqual(contract["archive"]["placements"], ["static-builtins", "dynamic-builtins"])
        self.assertEqual(contract["shared_libc"], BUILDER.SHARED_LIBC_METADATA)
        self.assertTrue(all(helper["metadata"] == {
            "binding": "GLOBAL", "type": "FUNC", "version": None,
            "version_default": False, "visibility": "DEFAULT",
        } for helper in contract["helpers"]))

    def test_contract_names_each_no_mangle_c_abi_definition_once(self) -> None:
        contract = BUILDER.load_native_contract()
        definitions = BUILDER.native_source_definitions(ROOT / "src/lib.rs")
        self.assertEqual(set(definitions), set(BUILDER.REQUIRED_SYMBOLS))
        self.assertEqual(
            {helper["name"]: helper["source_definition"] for helper in contract["helpers"]},
            definitions,
        )

    def test_builder_rejects_an_extra_public_archive_definition(self) -> None:
        with self.assertRaisesRegex(BUILDER.BuildError, "unexpected"):
            BUILDER.require_exact_defined_symbols(set(BUILDER.REQUIRED_SYMBOLS) | {"unexpected_helper"})

    def test_contract_rejects_numeric_boolean_metadata(self) -> None:
        contract = BUILDER.load_native_contract()
        malformed = copy.deepcopy(contract)
        malformed["helpers"][0]["metadata"]["version_default"] = 0
        with self.assertRaisesRegex(BUILDER.BuildError, "metadata types"):
            BUILDER.load_native_contract_value(malformed)

    def test_contract_rejects_a_public_shared_libc_copy(self) -> None:
        malformed = tomllib.loads((ROOT / "x86_64-helper-contract.toml").read_text(encoding="utf-8"))
        malformed["shared_libc"]["dynsym"] = 0
        with self.assertRaisesRegex(BUILDER.BuildError, "shared-libc placement"):
            BUILDER.load_native_contract_value(malformed)

    def test_builder_provenance_records_the_contract_not_a_five_symbol_floor(self) -> None:
        contract = BUILDER.load_native_contract()
        with self.subTest("all helpers"):
            self.assertEqual(BUILDER.REQUIRED_SYMBOLS, {item["name"] for item in contract["helpers"]})
        with self.subTest("source-backed roles"):
            self.assertEqual({item["c_abi"] for item in contract["helpers"]}, {
                "u128-to-binary64", "binary64-to-u128", "u128-to-binary32", "binary32-to-u128",
                "i128-to-binary80", "u128-to-binary80", "binary80-to-i128", "binary80-to-u128", "complex-binary80",
                "complex-float", "complex-double", "u128-binary", "u128-bit-count", "u128-byte-swap",
                "u128-divmod-slot", "u128-overflow-slot", "u128-shift", "u32-byte-swap",
                "u64-bit-count", "u64-byte-swap",
            })


if __name__ == "__main__":
    unittest.main()
