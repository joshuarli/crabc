#!/usr/bin/env python3
"""Pure-Python contract tests for native x86-64 pinned-C release evidence."""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_release_evidence.py"
spec = importlib.util.spec_from_file_location("release_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class ReleaseEvidenceTests(unittest.TestCase):
    def load_mutated_schema(self, mutate):
        schema = evidence.load_schema()
        mutate(schema)
        temporary = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        with temporary:
            json.dump(schema, temporary)
        self.addCleanup(Path(temporary.name).unlink, missing_ok=True)
        return mock.patch.object(evidence, "SCHEMA_PATH", Path(temporary.name))

    def test_schema_is_target_local_and_fixed(self):
        schema = evidence.load_schema()
        self.assertEqual(schema["target"], evidence.EXPECTED_TARGET)
        self.assertEqual(schema["profile"], evidence.EXPECTED_PROFILE)
        self.assertEqual(schema["upstream"], evidence.EXPECTED_UPSTREAM)
        self.assertEqual(schema["scope"], evidence.EXPECTED_SCOPE)
        self.assertEqual(schema["release_source_set"], list(evidence.run.ORACLE_SOURCES))
        self.assertEqual(schema["release_flags"], list(evidence.run.CONFIGURATION_PROFILES["release"]))
        self.assertEqual(schema["compile_definitions"], list(evidence.EXPECTED_COMPILE_DEFINITIONS))
        self.assertEqual(schema["target_mode_assertions"], list(evidence.TARGET_MODE_ASSERTIONS))
        self.assertEqual(schema["object_global_mi_symbol_inventory"]["count"], 225)
        self.assertEqual(schema["dynamic_default_visible_mi_symbol_inventory"]["count"], 190)
        self.assertNotEqual(
            schema["object_global_mi_symbol_inventory"]["sorted_names_sha256"],
            schema["dynamic_default_visible_mi_symbol_inventory"]["sorted_names_sha256"],
        )

    def test_schema_rejects_scope_target_upstream_and_compile_definition_drift(self):
        mutations = (
            (lambda schema: schema["target"].update({"architecture": "aarch64"}), "exact native Linux/x86_64 target"),
            (lambda schema: schema.update({"profile": "linux-aarch64-pinned-mimalloc-release"}), "fixed native x86_64 release profile"),
            (lambda schema: schema["upstream"].update({"version": "3.4.0"}), "exact mimalloc 3.5.0 pin"),
            (lambda schema: schema["scope"].update({"aarch64_status_reused": True}), "exact native-only scope"),
            (lambda schema: schema.update({"compile_definitions": ["-DMI_SHARED_LIB"]}), "canonical shared musl profile"),
            (lambda schema: schema.update({"target_mode_assertions": ["__aarch64__"]}), "fixed x86_64 profile"),
        )
        for mutate, message in mutations:
            with self.subTest(message=message), self.load_mutated_schema(mutate):
                with self.assertRaisesRegex(evidence.EvidenceError, message):
                    evidence.load_schema()

    def test_schema_rejects_source_inventory_contract_mutation(self):
        mutations = (
            lambda schema: schema["source_declaration_inventory"]["base_header"].update({"declaration_count": 181}),
            lambda schema: schema["source_declaration_inventory"]["statistics_header"].update({"declaration_names_sha256": "0" * 64}),
            lambda schema: schema["source_declaration_inventory"]["normal_release_exceptions"].append("mi_malloc"),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate), self.load_mutated_schema(mutate):
                with self.assertRaisesRegex(evidence.EvidenceError, "source declaration inventory contract"):
                    evidence.load_source_symbol_inventory(evidence.load_schema())

    def test_target_local_x86_ledger_digest_and_count_drift_is_rejected(self):
        api = json.loads(evidence.SOURCE_API_PATH.read_text(encoding="utf-8"))
        api["declarations"][0]["name"] = "mi_mutated_ledger_entry"
        temporary = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        with temporary:
            json.dump(api, temporary)
        self.addCleanup(Path(temporary.name).unlink, missing_ok=True)
        with mock.patch.object(evidence, "SOURCE_API_PATH", Path(temporary.name)):
            with self.assertRaisesRegex(evidence.EvidenceError, "x86 C API declaration digest drifted"):
                evidence.load_schema()

    def test_dynamic_inventory_is_bound_to_target_local_source_ledgers(self):
        source_inventory = evidence.load_source_symbol_inventory(evidence.load_schema())
        self.assertEqual(source_inventory["source_union_count"], 194)
        self.assertEqual(source_inventory["expected_dynamic_count"], 190)
        self.assertEqual(
            set(source_inventory["normal_release_exceptions"]),
            {
                "mi_collect_reduce",
                "mi_malloc_size",
                "mi_malloc_usable_size",
                "mi_stats_merge",
            },
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "target-local x86 source ledgers"):
            evidence.check_dynamic_source_inventory(
                source_inventory["expected_dynamic_names"][:-1], source_inventory
            )

    def test_release_command_must_carry_exact_compile_definitions(self):
        schema = evidence.load_schema()
        command = ["musl-gcc", *schema["compile_definitions"]]
        evidence.check_profile_definitions(command, schema)
        with self.assertRaisesRegex(evidence.EvidenceError, "compile definitions"):
            evidence.check_profile_definitions(["musl-gcc", "-DMI_SHARED_LIB"], schema)

    def test_object_inventory_hash_is_independent_of_header_ledger(self):
        inventory = evidence.load_schema()["object_global_mi_symbol_inventory"]
        names = ["mi_b", "internal", "mi_a", "mi_a"]
        self.assertEqual(evidence.public_symbols(names), ["mi_a", "mi_b"])
        with self.assertRaisesRegex(evidence.EvidenceError, "fixed release schema"):
            evidence.check_inventory(names, inventory, "test")

    def test_native_gate_rejects_emulation_and_foreign_machine(self):
        with mock.patch.object(evidence.run, "require_native_x86_64", side_effect=evidence.run.HarnessError("canonical native provenance")):
            with self.assertRaisesRegex(evidence.EvidenceError, "canonical native provenance"):
                evidence.require_native_x86_64()
        with mock.patch.object(evidence.run, "require_native_x86_64", side_effect=evidence.run.HarnessError("refuses emulation")):
            with self.assertRaisesRegex(evidence.EvidenceError, "refuses emulation"):
                evidence.require_native_x86_64()

    def test_target_mode_probe_is_target_local_and_elf_identity_is_strict(self):
        self.assertIn("__x86_64__", evidence.MODE_PROBE_SOURCE)
        self.assertIn("MI_MAX_VABITS != 47", evidence.MODE_PROBE_SOURCE)
        identity = evidence.run.parse_elf_identity(
            "  Class:                             ELF64\n"
            "  Data:                              2's complement, little endian\n"
            "  Machine:                           Advanced Micro Devices X86-64\n",
            "x86_64",
        )
        self.assertEqual(identity, {"class": "ELF64", "endianness": "little", "machine": "Advanced Micro Devices X86-64"})
        with self.assertRaises(evidence.run.HarnessError):
            evidence.run.parse_elf_identity(
                "  Class:                             ELF64\n"
                "  Data:                              2's complement, little endian\n"
                "  Machine:                           AArch64\n",
                "x86_64",
            )


if __name__ == "__main__":
    unittest.main()
