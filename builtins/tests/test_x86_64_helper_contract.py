"""Source-contract checks for the finite native compiler-helper archive."""
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
BUILDER_PATH = ROOT / "build_x86_64.py"
SPEC = importlib.util.spec_from_file_location("crabc_builtins_x86_contract", BUILDER_PATH)
assert SPEC and SPEC.loader
BUILDER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BUILDER
SPEC.loader.exec_module(BUILDER)


class NativeCompilerHelperContractTests(unittest.TestCase):
    def test_contract_is_the_exact_native_builder_symbol_roster(self) -> None:
        contract = BUILDER.load_native_contract()
        names = tuple(helper["name"] for helper in contract["helpers"])
        self.assertEqual(len(names), 23)
        self.assertEqual(set(names), BUILDER.REQUIRED_SYMBOLS)
        self.assertEqual(contract["archive"]["member"], "crabc-builtins.o")
        self.assertEqual(contract["archive"]["placements"], ["static-builtins", "dynamic-builtins"])
        self.assertTrue(all(helper["metadata"] == {
            "binding": "GLOBAL", "type": "FUNC", "version": None,
            "version_default": False, "visibility": "DEFAULT",
        } for helper in contract["helpers"]))

    def test_contract_names_each_no_mangle_c_abi_definition_once(self) -> None:
        contract = BUILDER.load_native_contract()
        definitions = BUILDER.native_source_definitions(ROOT / "src/lib.rs")
        self.assertEqual(set(definitions), set(BUILDER.REQUIRED_SYMBOLS))
        self.assertEqual(
            {helper["name"]: helper["rust_signature"] for helper in contract["helpers"]},
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

    def test_builder_provenance_records_the_contract_not_a_five_symbol_floor(self) -> None:
        contract = BUILDER.load_native_contract()
        with self.subTest("all helpers"):
            self.assertEqual(BUILDER.REQUIRED_SYMBOLS, {item["name"] for item in contract["helpers"]})
        with self.subTest("source-backed roles"):
            self.assertEqual({item["c_abi"] for item in contract["helpers"]}, {
                "complex-double", "u128-binary", "u128-bit-count", "u128-byte-swap",
                "u128-divmod-slot", "u128-overflow-slot", "u128-shift", "u32-byte-swap",
                "u64-bit-count", "u64-byte-swap",
            })


if __name__ == "__main__":
    unittest.main()
