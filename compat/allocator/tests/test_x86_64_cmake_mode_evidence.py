#!/usr/bin/env python3
"""Pure contracts for native x86-64 CMake configure/build/install evidence."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_cmake_mode_evidence.py"
spec = importlib.util.spec_from_file_location("cmake_mode_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class CmakeModeEvidenceTests(unittest.TestCase):
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
        temporary = Path("/tmp/cmake-mode-evidence")
        source = temporary / "source/mimalloc-3.5.0"
        build = temporary / "build"
        prefix = temporary / "install"
        configuration = {
            "command": evidence.normalize_command(
                evidence.configure_command("/usr/bin/cmake", "/usr/bin/musl-gcc", source, build, prefix),
                temporary,
                source,
            ),
            "cache_values": schema["configuration"]["cache_values"],
            "compile_mode": schema["configuration"]["compile_mode"],
            "status": "passed",
        }
        build_record = {
            "command": evidence.normalize_command(
                evidence.build_command("/usr/bin/cmake", build), temporary, source
            ),
            "shared_library": {
                "bytes": 1,
                "elf": evidence.EXPECTED_ELF,
                "needed": [],
                "path": "lib/libmimalloc.so.3.5",
                "sha256": "0" * 64,
                "soname": "libmimalloc.so.3",
            },
            "status": "passed",
        }
        install = {
            "command": evidence.normalize_command(
                evidence.install_command("/usr/bin/cmake", build), temporary, source
            ),
            "headers": {
                member: schema["source"]["installed_header_records"][member]
                for member in schema["source"]["installed_public_headers"]
            },
            "manifest": sorted(
                [
                    *schema["source"]["installed_public_headers"],
                    "lib/libmimalloc.so.3.5",
                ]
            ),
            "status": "passed",
        }
        return evidence.report_from_results(
            schema=schema,
            provenance={"execution_mode": "native", "host_architecture": "x86_64"},
            configuration=configuration,
            build=build_record,
            install=install,
        )

    def test_schema_is_the_fixed_native_linux_x86_64_cmake_profile(self):
        schema = evidence.load_schema()
        self.assertEqual(schema["target"], evidence.TARGET)
        self.assertEqual(schema["upstream"], evidence.UPSTREAM)
        self.assertEqual(schema["profile"], evidence.PROFILE)
        self.assertEqual(
            schema["configuration"]["cache_values"], evidence.CACHE_VALUES
        )
        self.assertEqual(
            schema["configuration"]["compile_mode"], evidence.COMPILE_MODE
        )
        self.assertEqual(
            schema["source"]["installed_public_headers"],
            list(evidence.INSTALLED_PUBLIC_HEADERS),
        )
        self.assertTrue(schema["scope"]["cmake_configure_build_install_claimed"])
        self.assertFalse(schema["scope"]["behavior_claimed"])
        self.assertFalse(schema["scope"]["consumer_execution_claimed"])
        self.assertFalse(schema["scope"]["rust_implementation_claimed"])
        self.assertFalse(schema["scope"]["public_crabc_support"])
        self.assertFalse(schema["scope"]["aarch64_status_reused"])

    def test_schema_rejects_cache_source_and_scope_drift(self):
        mutations = (
            lambda value: value.update({"unexpected": 1}),
            lambda value: value["configuration"]["cache_values"].update({"MI_BUILD_SHARED": "OFF"}),
            lambda value: value["configuration"]["compile_mode"].update({"flags": []}),
            lambda value: value["source"].update({"root_cmake": {"member": "CMakeLists.txt", "sha256": "0" * 64}}),
            lambda value: value["source"]["selected_mode_declarations"][0].update({"source_line": 31}),
            lambda value: value["scope"].update({"behavior_claimed": True}),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate), self.mutated_schema(mutate):
                with self.assertRaises(evidence.EvidenceError):
                    evidence.load_schema()

    def test_configure_command_is_the_closed_shared_normal_release_selection(self):
        command = evidence.configure_command(
            "/usr/bin/cmake",
            "/usr/bin/musl-gcc",
            Path("/tmp/source/mimalloc-3.5.0"),
            Path("/tmp/build"),
            Path("/tmp/install"),
        )
        self.assertIn("-G", command)
        self.assertIn("Unix Makefiles", command)
        self.assertIn("-DCMAKE_BUILD_TYPE=Release", command)
        self.assertIn("-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", command)
        for name, value in evidence.CACHE_VALUES.items():
            if name != "CMAKE_BUILD_TYPE":
                self.assertIn(f"-D{name}={value}", command)
        normalized = evidence.normalize_command(
            command,
            Path("/tmp"),
            Path("/tmp/source/mimalloc-3.5.0"),
        )
        evidence.validate_normalized_configure_command(normalized)

    def test_report_is_strictly_native_configure_build_install_evidence(self):
        report = self.complete_report()
        evidence.validate_report(report)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["configuration"]["status"], "passed")
        self.assertEqual(report["build"]["status"], "passed")
        self.assertEqual(report["install"]["status"], "passed")

    def test_report_rejects_non_native_or_missing_install_outputs(self):
        report = self.complete_report()
        report["provenance"] = {"execution_mode": "emulated", "host_architecture": "x86_64"}
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_report(report)

        report = self.complete_report()
        report["install"]["headers"].pop("include/mimalloc.h")
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_report(report)

        report = self.complete_report()
        report["build"]["shared_library"]["elf"] = {"class": "ELF32"}
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_report(report)

        report = self.complete_report()
        report["install"]["manifest"] = ["../escape"]
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_report(report)

        report = self.complete_report()
        report["install"]["manifest"] = sorted(evidence.INSTALLED_PUBLIC_HEADERS)
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_report(report)

    def test_install_manifest_preserves_legal_shared_library_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            build = temporary / "build"
            prefix = temporary / "install"
            library_directory = prefix / "lib"
            build.mkdir()
            library_directory.mkdir(parents=True)
            real_library = library_directory / "libmimalloc.so.3.5"
            real_library.write_bytes(b"shared-library")
            (library_directory / "libmimalloc.so.3").symlink_to(
                real_library.name
            )
            (library_directory / "libmimalloc.so").symlink_to(
                real_library.name
            )
            (build / "install_manifest.txt").write_text(
                "\n".join(
                    str(path)
                    for path in (
                        real_library,
                        library_directory / "libmimalloc.so.3",
                        library_directory / "libmimalloc.so",
                    )
                )
                + "\n",
                encoding="utf-8",
            )

            self.assertEqual(
                evidence.installed_manifest(build, prefix),
                [
                    "lib/libmimalloc.so",
                    "lib/libmimalloc.so.3",
                    "lib/libmimalloc.so.3.5",
                ],
            )


if __name__ == "__main__":
    unittest.main()
