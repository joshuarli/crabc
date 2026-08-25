#!/usr/bin/env python3
"""Pure contracts for native x86-64 staged public-header evidence."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_header_mode_evidence.py"
spec = importlib.util.spec_from_file_location("header_mode_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class HeaderModeEvidenceTests(unittest.TestCase):
    def mutated_schema(self, mutate):
        value = evidence.load_schema()
        mutate(value)
        stream = tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8", delete=False)
        with stream:
            json.dump(value, stream)
        path = Path(stream.name)
        self.addCleanup(path.unlink, missing_ok=True)
        return mock.patch.object(evidence, "SCHEMA_PATH", path)

    def complete_report(self) -> dict[str, object]:
        schema = evidence.load_schema()
        temporary = Path("/tmp/header-mode-evidence")
        source = temporary / "source/mimalloc-3.5.0"
        shared = evidence.normalize_command(
            evidence.shared_command(
                "/usr/bin/musl-gcc",
                source,
                temporary / "libmimalloc-header-modes.so",
                schema,
            ),
            temporary,
            source,
        )
        modes = []
        for mode in evidence.MODES:
            suffix = ".cpp" if mode.startswith("cxx-") else ".c"
            command = evidence.consumer_command(
                mode=mode,
                c_compiler="/usr/bin/musl-gcc",
                cxx_compiler="/usr/bin/g++",
                include=temporary / "include",
                library_directory=temporary,
                probe=temporary / f"{mode}{suffix}",
                output=temporary / mode,
            )
            modes.append(
                {
                    "build_command": evidence.normalize_command(command, temporary, source),
                    "elf": evidence.EXPECTED_C_ELF,
                    "mode": mode,
                    "probe_sha256": evidence.expected_probe_sources()[mode],
                    "status": "passed",
                }
            )
        return evidence.report_from_results(
            schema=schema,
            provenance={"execution_mode": "native", "host_architecture": "x86_64"},
            shared_library={"build_command": shared, "elf": evidence.EXPECTED_C_ELF},
            modes=modes,
        )

    def test_schema_is_fixed_native_release_staged_header_contract(self):
        value = evidence.load_schema()
        self.assertEqual(value["target"], evidence.TARGET)
        self.assertEqual(value["upstream"], evidence.UPSTREAM)
        self.assertEqual(value["selected_modes"], list(evidence.MODES))
        self.assertEqual(value["public_header_bytes"], evidence.PUBLIC_HEADER_BYTES)
        self.assertEqual(value["probe_sources"], evidence.expected_probe_sources())
        self.assertTrue(value["scope"]["staged_pinned_public_headers_only"])
        self.assertFalse(value["scope"]["cmake_install_claimed"])

    def test_schema_rejects_unknown_bool_integer_and_probe_drift(self):
        mutations = (
            lambda value: value.update({"unexpected": 1}),
            lambda value: value.update({"format": True}),
            lambda value: value["scope"].update({"execution_claimed": 1}),
            lambda value: value["scope"].update({"staged_pinned_public_headers_only": 1}),
            lambda value: value["public_header_bytes"].update({"include/mimalloc.h": "0" * 64}),
            lambda value: value["probe_sources"].update({"cxx-base": "0" * 64}),
            lambda value: value["cxx_tool"].update({"driver": "clang++"}),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate), self.mutated_schema(mutate):
                with self.assertRaises(evidence.EvidenceError):
                    evidence.load_schema()

    def test_shared_command_carries_the_fixed_shared_release_selection(self):
        schema = evidence.load_schema()
        command = evidence.shared_command(
            "/usr/bin/musl-gcc",
            Path("/tmp/source/mimalloc-3.5.0"),
            Path("/tmp/libmimalloc-header-modes.so"),
            schema,
        )
        evidence.validate_shared_command(command, schema)
        weakened = [part for part in command if part != "-DMI_LIBC_MUSL=1"]
        with self.assertRaisesRegex(evidence.EvidenceError, "compile definitions"):
            evidence.validate_shared_command(weakened, schema)

    def test_cxx_and_stats_probes_exercise_valid_header_forms_without_execution(self):
        self.assertIn("mi_stl_allocator<int>", evidence.CXX_PROBES["cxx-base"])
        self.assertNotIn("mi_new<int>", evidence.CXX_PROBES["cxx-base"])
        self.assertIn("mi_stats_get", evidence.C_PROBES["c-stats"])
        self.assertNotIn("mi_stats_print", evidence.C_PROBES["c-stats"])
        self.assertFalse(evidence.SCOPE["execution_claimed"])
        self.assertFalse(evidence.SCOPE["behavior_claimed"])

    def test_report_binds_shared_and_each_consumer_elf_identity(self):
        report = self.complete_report()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(len(report["modes"]), 5)
        self.assertEqual(report["shared_library"]["elf"], evidence.EXPECTED_C_ELF)
        self.assertEqual(report["modes"][2]["elf"], evidence.EXPECTED_C_ELF)

        weakened = copy.deepcopy(report)
        weakened["modes"][0]["elf"] = {}
        with self.assertRaisesRegex(evidence.EvidenceError, "consumer ELF identity"):
            evidence.validate_report(weakened)
        weakened = copy.deepcopy(report)
        weakened["scope"]["cmake_install_claimed"] = True
        with self.assertRaisesRegex(evidence.EvidenceError, "target or scope"):
            evidence.validate_report(weakened)

    def test_native_gate_delegates_to_canonical_provenance(self):
        with mock.patch.object(
            evidence.run,
            "require_native_x86_64",
            side_effect=evidence.run.HarnessError("native provenance required"),
        ):
            with self.assertRaisesRegex(evidence.EvidenceError, "native provenance required"):
                evidence.require_native_x86_64()


if __name__ == "__main__":
    unittest.main()
