#!/usr/bin/env python3
"""Contract checks for the bounded installed text/locale/numeric component."""

from __future__ import annotations

import inspect
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))

import owned_text_locale_numeric_component_contract as contract
import owned_text_locale_numeric_component_evidence as evidence
import owned_text_locale_numeric_component_receipt as receipt


RUNNER = ROOT / "compat/x86_64/run_owned_text_locale_numeric_component.sh"
DRIVER = ROOT / "compat/x86_64/owned_text_locale_numeric_component_driver.c"
SOURCE_SPECIFIC_DRIVER = ROOT / "compat/x86_64/owned_text_locale_numeric_source_specific_driver.c"
DOCUMENT = ROOT / "compat/x86_64/owned-text-locale-numeric-component.md"
DISPATCHER = ROOT / "scripts/dev-x86_64.sh"


class OwnedTextLocaleNumericComponentTests(unittest.TestCase):
    def test_fixed_eleven_row_contract_uses_existing_rich_probes(self) -> None:
        self.assertEqual(
            contract.ROWS,
            (
                ("numeric.parse-float-locale", "float-parse", ("float-parse",)),
                ("locale.core", "ctype-locators", ("ctype-locators",)),
                ("locale.core", "narrow-ctype-collation", ("locale-narrow",)),
                ("locale.core", "object-wide", ("locale-object-wide",)),
                ("locale.core", "alias-contract", ("locale-alias-contract",)),
                ("locale.core", "strfmon", ("strfmon",)),
                ("text.wide-multibyte", "locale-object-wide", ("locale-object-wide",)),
                ("text.wide-multibyte", "multibyte", ("locale-multibyte",)),
                ("text.wide-multibyte", "wide-character", ("wide-character",)),
                ("text.wide-multibyte", "wide-conversion", ("wide-conversion",)),
                ("text.iconv", "utf16-32-iconv", ("locale-wide-iconv",)),
            ),
        )
        self.assertEqual(contract.CAPABILITIES, (
            "numeric.parse-float-locale", "locale.core", "text.wide-multibyte", "text.iconv",
        ))
        self.assertEqual(contract.EXECUTION_CELLS, (
            "static-run", "static-pie-run", "dynamic-pie-kernel", "dynamic-pie-direct",
            "dynamic-non-pie-kernel", "dynamic-non-pie-direct",
        ))

        expected_sources = {
            "compat/x86_64/owned_text_locale_numeric_component_driver.c",
            "compat/x86_64/libc_float_parse_probe.c",
            "compat/x86_64/libc_locale_ctype_locators_probe.c",
            "compat/x86_64/libc_locale_narrow_probe.c",
            "compat/x86_64/libc_locale_object_wide_probe.c",
            "compat/x86_64/libc_locale_wide_iconv_probe.c",
            "compat/x86_64/libc_locale_multibyte_probe.c",
            "compat/x86_64/libc_wide_character_probe.c",
            "compat/x86_64/locale_alias_contract_probe.c",
            "compat/x86_64/owned_strfmon_probe.c",
            "compat/x86_64/owned_wide_conversion_probe.c",
        }
        self.assertEqual({relative for _, relative, _, _ in contract.OBJECT_ROLES}, expected_sources)
        self.assertEqual(contract.ALIAS_ROLE, "locale-alias-contract")
        for _, relative, _, _ in contract.OBJECT_ROLES:
            self.assertTrue((ROOT / relative).is_file(), relative)
        self.assertEqual(
            tuple(row[0] for row in contract.SOURCE_SPECIFIC_ROWS),
            (
                "candidate-locale-object-wide-profile",
                "candidate-locale-wide-iconv-profile",
                "candidate-locale-multibyte-profile",
            ),
        )
        self.assertEqual(contract.SOURCE_SPECIFIC_EXECUTION_CELLS, (
            "candidate-static-run", "candidate-static-pie-run", "candidate-dynamic-pie-kernel",
            "candidate-dynamic-pie-direct", "candidate-dynamic-non-pie-kernel",
            "candidate-dynamic-non-pie-direct",
        ))
        self.assertTrue(SOURCE_SPECIFIC_DRIVER.is_file())
        self.assertEqual(
            {role for role, _, _, _ in contract.SOURCE_SPECIFIC_OBJECT_ROLES},
            {
                "source-specific-driver", "candidate-locale-object-wide-profile",
                "candidate-locale-wide-iconv-profile", "candidate-locale-multibyte-profile",
            },
        )

    def test_driver_composes_normal_roles_but_keeps_override_contract_separate(self) -> None:
        source = DRIVER.read_text(encoding="utf-8")
        for callable_name in (
            "crabc_x86_64_float_parse_probe",
            "crabc_x86_64_locale_ctype_locators_probe",
            "crabc_x86_64_locale_narrow_probe",
            "crabc_x86_64_locale_object_wide_probe",
            "crabc_x86_64_locale_wide_iconv_probe",
            "crabc_x86_64_locale_multibyte_probe",
            "crabc_x86_64_wide_character_probe",
            "crabc_x86_64_owned_strfmon_probe",
            "crabc_x86_64_owned_wide_conversion_probe",
        ):
            self.assertIn(callable_name, source)
        self.assertNotIn("crabc_x86_64_locale_alias_contract_probe", source)

        for relative, callable_name, guard in (
            ("compat/x86_64/owned_strfmon_probe.c", "crabc_x86_64_owned_strfmon_probe",
             "CRABC_OWNED_STRFMON_COMPONENT_FREESTANDING"),
            ("compat/x86_64/owned_wide_conversion_probe.c", "crabc_x86_64_owned_wide_conversion_probe",
             "CRABC_OWNED_WIDE_CONVERSION_COMPONENT_FREESTANDING"),
        ):
            probe = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn(callable_name, probe)
            self.assertIn(guard, probe)

    def test_exact_coverage_boundary_and_abi_proof_are_not_symbol_only(self) -> None:
        roster = contract.load_capability_roster(ROOT)
        self.assertEqual(tuple(roster), contract.CAPABILITIES)
        self.assertEqual(len(roster["numeric.parse-float-locale"]), 23)
        self.assertIn("strtold", roster["numeric.parse-float-locale"])
        self.assertIn("strfmon_l", roster["locale.core"])
        self.assertIn("wcsdup", roster["text.wide-multibyte"])
        self.assertEqual(roster["text.iconv"], ("iconv", "iconv_close", "iconv_open"))
        self.assertTrue(evidence.REQUIRED_PROVIDER_SYMBOLS)
        self.assertIn("strtold", evidence.REQUIRED_PROVIDER_SYMBOLS)
        self.assertIn("strfmon_l", evidence.REQUIRED_PROVIDER_SYMBOLS)
        self.assertIn("iconv_open", evidence.REQUIRED_PROVIDER_SYMBOLS)
        self.assertIn("locale_t", contract.ABI_CONTRACT)
        self.assertIn("binary80", contract.ABI_CONTRACT)
        self.assertIn("mbstate_t", contract.ABI_CONTRACT)

    def test_reader_exposes_aggregate_validation_for_three_pairs(self) -> None:
        self.assertEqual(receipt.PAIR_NAMES, ("primary", "reproduction", "extracted"))
        self.assertEqual(receipt.EXECUTION_CELLS, contract.EXECUTION_CELLS)
        self.assertEqual(receipt.SCHEMA, "crabc.x86_64-owned-text-locale-numeric-receipt/v1")
        self.assertEqual(receipt.REPORT_SCHEMA, "crabc.x86_64-owned-text-locale-numeric/v1")
        self.assertEqual(tuple(inspect.signature(receipt.validate).parameters), ("root", "receipt"))
        self.assertEqual(receipt.RECEIPT_FIELDS, (
            "schema", "source", "inputs", "products", "rows", "pair_evidence_roots",
            "pairs", "cell_count", "family_completion", "promotion_ready", "public_support",
        ))
        self.assertIn("source_specific_evidence", receipt.REPORT_FIELDS)
        self.assertEqual(
            receipt.source_specific_row_records()[0]["credit"],
            False,
        )

    def test_runner_usage_and_dispatcher_registration_are_fixed(self) -> None:
        for arguments in ((), ("--static-sysroot",), ("--static-sysroot", "/one"),
                          ("/one", "/two"), ("-x",)):
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    ["bash", str(RUNNER), *arguments], cwd=ROOT,
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertEqual(
                    result.stderr,
                    f"usage: {RUNNER} --static-sysroot STATIC_SYSROOT DYNAMIC_SYSROOT\n",
                )
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        self.assertTrue("owned-text-locale-numeric-component" in dispatcher,
                        "dispatcher lacks the component command")
        self.assertTrue("run_owned_text_locale_numeric_component.sh" in dispatcher,
                        "dispatcher lacks the component runner")

    def test_document_states_the_remaining_wide_stdio_and_locale_gaps(self) -> None:
        document = DOCUMENT.read_text(encoding="utf-8")
        self.assertIn("wide FILE/orientation/formatting", document)
        self.assertIn("does not complete", document)
        self.assertIn("general locale database", document)
        self.assertIn("source-specific", document)
        self.assertIn("unclosed family/parity gap", document)


if __name__ == "__main__":
    unittest.main()
