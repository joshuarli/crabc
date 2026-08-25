#!/usr/bin/env python3
"""Pure contracts for native x86-64 static/object allocator evidence."""

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
SCRIPT = ROOT / "compat/allocator/x86_64_static_mode_evidence.py"
spec = importlib.util.spec_from_file_location("static_mode_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class StaticModeEvidenceTests(unittest.TestCase):
    def mutated_schema(self, mutate):
        value = evidence.load_schema()
        mutate(value)
        stream = tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8", delete=False)
        with stream:
            json.dump(value, stream)
        path = Path(stream.name)
        self.addCleanup(path.unlink, missing_ok=True)
        return mock.patch.object(evidence, "SCHEMA_PATH", path)

    def complete_report(self):
        schema = evidence.load_schema()
        temporary = Path("/tmp/static-mode-evidence")
        source = temporary / "source/mimalloc-3.5.0"
        objects = [evidence.object_name(member) for member in schema["static_library_source_set"]]
        compile_commands = []
        for member, object_file in zip(schema["static_library_source_set"], objects):
            compile_commands.append(evidence.normalize_command(
                evidence.static_compile_command(
                    "/usr/bin/musl-gcc", source, member, temporary / "library-objects" / object_file, schema
                ), temporary, source
            ))
        archive = evidence.normalize_command(
            ["/usr/bin/ar", "rcs", str(temporary / "libmimalloc-static.a"),
             *(str(temporary / "library-objects" / name) for name in objects)],
            temporary, source,
        )
        archive_listing = evidence.normalize_command(
            ["/usr/bin/ar", "t", str(temporary / "libmimalloc-static.a")], temporary, source
        )
        object_command = evidence.normalize_command(
            evidence.object_compile_command("/usr/bin/musl-gcc", source, temporary / "mimalloc-static-override.o", schema),
            temporary, source,
        )
        nm_command = evidence.normalize_command(
            ["/usr/bin/nm", "-g", "--defined-only", str(temporary / "mimalloc-static-override.o")],
            temporary, source,
        )
        modes = []
        for mode in evidence.MODES:
            probe = temporary / f"{mode}.c"
            output = temporary / mode
            command = evidence.consumer_command(
                mode=mode, compiler="/usr/bin/musl-gcc", include=source / "include",
                artifact_root=temporary, probe=probe, output=output,
                object_path=temporary / "mimalloc-static-override.o",
            )
            modes.append({
                "build_command": evidence.normalize_command(command, temporary, source),
                "elf": evidence.EXPECTED_ELF,
                "mode": mode,
                "probe_sha256": evidence.expected_probe_sources()[mode],
                "status": "passed",
            })
        report = {
            "format": 1,
            "schema": schema["schema"],
            "status": "passed",
            "provenance": {"execution_mode": "native", "host_architecture": "x86_64"},
            "target": schema["target"],
            "upstream": schema["upstream"],
            "profile": schema["profile"],
            "source": {
                "consumer_compile_flags": schema["consumer_compile_flags"],
                "release_flags": schema["release_flags"],
                "static_compile_flags": schema["static_compile_flags"],
                "static_library_definitions": schema["static_library_definitions"],
                "static_library_source_set": schema["static_library_source_set"],
                "static_object_definitions": schema["static_object_definitions"],
                "static_object_source": schema["static_object_source"],
            },
            "static_library": {
                "archive_command": archive,
                "archive_member_listing_command": archive_listing,
                "compile_commands": compile_commands,
                "member_count": len(objects),
                "expected_member_names": objects,
                "observed_member_names": objects,
                "status": "passed",
            },
            "static_object": {
                "compile_command": object_command,
                "elf": evidence.EXPECTED_ELF,
                "nm_command": nm_command,
                "observed_defined_symbols": ["free", "malloc", "mi_free", "mi_malloc"],
                "required_symbols": list(schema["static_object_required_symbols"]),
                "status": "passed",
            },
            "modes": modes,
            "scope": schema["scope"],
        }
        evidence.validate_report(report)
        return report

    def test_schema_binds_pinned_release_static_and_object_forms(self):
        schema = evidence.load_schema()
        self.assertEqual(schema["upstream"], evidence.UPSTREAM)
        self.assertEqual(schema["static_library_source_set"], list(evidence.run.ORACLE_SOURCES))
        self.assertEqual(schema["static_object_source"], "src/static.c")
        self.assertIn("-ftls-model=local-dynamic", schema["static_compile_flags"])
        self.assertEqual(schema["static_object_required_symbols"], ["free", "malloc", "mi_free", "mi_malloc"])
        self.assertEqual(schema["probe_sources"], evidence.expected_probe_sources())
        self.assertTrue(schema["scope"]["static_object_override_linkability_only"])
        self.assertFalse(schema["scope"]["execution_claimed"])

    def test_schema_rejects_bool_integer_and_source_drift(self):
        mutations = (
            lambda value: value.update({"unexpected": 1}),
            lambda value: value.update({"format": True}),
            lambda value: value["scope"].update({"behavior_claimed": 1}),
            lambda value: value["static_object_definitions"].append("-DWRONG"),
            lambda value: value["static_library_source_set"].append("src/static.c"),
            lambda value: value["probe_sources"].update({"static-library": "0" * 64}),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate), self.mutated_schema(mutate):
                with self.assertRaises(evidence.EvidenceError):
                    evidence.load_schema()

    def test_static_object_is_source_amalgamation_not_cmake_install_claim(self):
        schema = evidence.load_schema()
        self.assertEqual(schema["static_object_source"], "src/static.c")
        self.assertIn("-DMI_MALLOC_OVERRIDE", schema["static_object_definitions"])
        self.assertIn("CMake installation", evidence.__doc__)
        self.assertFalse(schema["scope"]["cmake_install_claimed"])

    def test_consumer_forms_are_compile_link_only(self):
        self.assertIn("mi_malloc", evidence.PROBES["static-library"])
        self.assertIn("malloc", evidence.PROBES["static-object-override"])
        self.assertIn("-fno-builtin-malloc", evidence.consumer_command(
            mode="static-object-override", compiler="musl-gcc", include=Path("/i"),
            artifact_root=Path("/a"), probe=Path("/p"), output=Path("/o"), object_path=Path("/x"),
        ))
        self.assertFalse(evidence.SCOPE["execution_claimed"])

    def test_report_binds_archive_object_and_consumer_elf_identity(self):
        report = self.complete_report()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["static_library"]["member_count"], len(evidence.run.ORACLE_SOURCES))
        self.assertEqual(report["static_library"]["observed_member_names"], report["static_library"]["expected_member_names"])
        self.assertEqual(report["static_object"]["elf"], evidence.EXPECTED_ELF)
        self.assertIn("malloc", report["static_object"]["observed_defined_symbols"])
        weakened = copy.deepcopy(report)
        weakened["static_object"]["elf"] = {}
        with self.assertRaisesRegex(evidence.EvidenceError, "object ELF"):
            evidence.validate_report(weakened)
        weakened = copy.deepcopy(report)
        weakened["static_library"]["observed_member_names"] = []
        with self.assertRaisesRegex(evidence.EvidenceError, "observed static-library"):
            evidence.validate_report(weakened)
        weakened = copy.deepcopy(report)
        weakened["static_object"]["observed_defined_symbols"] = ["mi_malloc"]
        with self.assertRaisesRegex(evidence.EvidenceError, "observed override"):
            evidence.validate_report(weakened)
        weakened = copy.deepcopy(report)
        weakened["static_library"]["compile_commands"][0][-5] = "-ftls-model=initial-exec"
        with self.assertRaisesRegex(evidence.EvidenceError, "static compilation"):
            evidence.validate_report(weakened)
        weakened = copy.deepcopy(report)
        weakened["modes"][1]["build_command"][-2] = "-Wl,--as-needed"
        with self.assertRaisesRegex(evidence.EvidenceError, "consumer link"):
            evidence.validate_report(weakened)
        weakened = copy.deepcopy(report)
        weakened["scope"]["execution_claimed"] = True
        with self.assertRaisesRegex(evidence.EvidenceError, "scope"):
            evidence.validate_report(weakened)

    def test_native_gate_delegates_to_canonical_provenance(self):
        with mock.patch.object(
            evidence.run, "require_native_x86_64",
            side_effect=evidence.run.HarnessError("native provenance required"),
        ):
            with self.assertRaisesRegex(evidence.EvidenceError, "native provenance required"):
                evidence.require_native_x86_64()


if __name__ == "__main__":
    unittest.main()
