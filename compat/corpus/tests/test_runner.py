#!/usr/bin/env python3
"""Host-side tests for the corpus manifest and pure comparison helpers."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


RUNNER_PATH = Path(__file__).resolve().parents[1] / "run.py"
SPEC = importlib.util.spec_from_file_location("crabc_corpus_runner", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class ManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = RUNNER.load_manifest(RUNNER.MANIFEST)

    def test_manifest_is_pinned_to_native_alpine_aarch64(self) -> None:
        self.assertEqual(self.manifest.schema, 1)
        self.assertEqual(self.manifest.alpine_release, "3.24.1")
        self.assertEqual(self.manifest.architecture, "aarch64")
        self.assertEqual(self.manifest.musl_version, "1.2.6")
        self.assertIn("@sha256:", self.manifest.image)
        self.assertTrue(all(len(package.sha256) == 64 for package in self.manifest.packages))

    def test_default_tier_contains_real_relr_cases(self) -> None:
        selected = RUNNER.select_cases(self.manifest, ["A"])
        self.assertEqual([case.id for case in selected[:3]], [
            "tier-a-true",
            "tier-a-echo",
            "tier-a-cat",
        ])
        self.assertTrue(all(case.requires_dt_relr for case in selected[:3]))
        self.assertEqual({case.path for case in selected[:3]}, {"/bin/true", "/bin/echo", "/bin/cat"})

    def test_case_selection_preserves_manifest_order(self) -> None:
        selected = RUNNER.select_cases(self.manifest, ["B", "A"], ["tier-a-cat", "tier-b-grep"])
        self.assertEqual([case.id for case in selected], ["tier-a-cat", "tier-b-grep"])
        with self.assertRaises(RUNNER.CorpusError):
            RUNNER.select_cases(self.manifest, ["A"], ["not-a-case"])

    def test_every_tier_b_to_d_package_has_a_stateful_case(self) -> None:
        packages = {
            case.package
            for case in self.manifest.cases
            if case.tier in {"B", "C", "D"}
        }
        self.assertEqual(
            packages,
            {
                "grep",
                "sed",
                "file",
                "tar",
                "gzip",
                "zstd",
                "sqlite",
                "curl",
                "openssl",
                "openssh-client-default",
                "git",
                "python3",
            },
        )
        for package in packages:
            self.assertTrue(
                any(
                    case.package == package
                    and case.tier in {"B", "C", "D"}
                    and case.stateful
                    for case in self.manifest.cases
                ),
                package,
            )

    def test_stateful_cases_use_deterministic_fixture_inputs(self) -> None:
        stateful = [case for case in self.manifest.cases if case.stateful]
        self.assertGreaterEqual(len(stateful), 11)
        self.assertTrue(all(case.tier in {"B", "C", "D"} for case in stateful))
        self.assertTrue(all(case.setup or case.package in {"git", "sqlite"} for case in stateful))


class PureHelperTests(unittest.TestCase):
    def test_dynamic_tag_match_is_exact_enough_for_readelf_lines(self) -> None:
        self.assertTrue(RUNNER.has_dynamic_tag("0x24 (RELR) 0x100\n", "RELR"))
        self.assertFalse(RUNNER.has_dynamic_tag("0x24 (RELRSZ) 0x100\n", "RELR"))

    def test_interpreter_patch_changes_only_the_pt_interp_payload(self) -> None:
        binary = bytearray(256)
        binary[:4] = b"\x7fELF"
        binary[4] = 2
        binary[5] = 1
        binary[18:20] = (183).to_bytes(2, "little")
        binary[32:40] = (64).to_bytes(8, "little")
        binary[54:56] = (56).to_bytes(2, "little")
        binary[56:58] = (1).to_bytes(2, "little")
        binary[64:68] = (3).to_bytes(4, "little")
        binary[72:80] = (192).to_bytes(8, "little")
        binary[96:104] = (26).to_bytes(8, "little")
        binary[192:218] = b"/lib/ld-musl-aarch64.so.1\0"
        patched = RUNNER.patched_interpreter_bytes(bytes(binary), "/tmp/crabc-ref")
        self.assertEqual(patched[:192], bytes(binary[:192]))
        self.assertEqual(patched[192:218], b"/tmp/crabc-ref\0" + b"\0" * (26 - len("/tmp/crabc-ref") - 1))

    def test_results_keep_raw_streams_and_status(self) -> None:
        reference = RUNNER.ProcessResult(0, b"ok\x00\n", b"")
        candidate = RUNNER.ProcessResult(0, b"ok\x00\n", b"")
        comparison = RUNNER.compare_results(reference, candidate)
        self.assertTrue(comparison["passed"])
        self.assertEqual(comparison["normalization"], "none")
        self.assertEqual(comparison["reference"]["stdout"]["hex"], "6f6b000a")

    def test_result_difference_does_not_normalize_stderr(self) -> None:
        reference = RUNNER.ProcessResult(-11, b"", b"loader\n")
        candidate = RUNNER.ProcessResult(139, b"", b"loader\n")
        comparison = RUNNER.compare_results(reference, candidate)
        self.assertFalse(comparison["passed"])
        self.assertFalse(comparison["status_match"])
        self.assertEqual(comparison["reference"]["stderr"]["hex"], "6c6f616465720a")

    def test_command_is_the_package_binary_not_the_loader(self) -> None:
        case = RUNNER.CaseSpec("case", "A", "busybox", "/bin/true", ("true",))
        self.assertEqual(RUNNER.command_for_case(case), ["/bin/true"])
        self.assertNotIn("libldso.so", RUNNER.command_for_case(case))

    def test_safe_archive_members_reject_escape(self) -> None:
        self.assertEqual(RUNNER.safe_archive_members(["bin/true", "usr/bin/file"]), ("bin/true", "usr/bin/file"))
        with self.assertRaises(RUNNER.CorpusError):
            RUNNER.safe_archive_members(["../outside"])
        with self.assertRaises(RUNNER.CorpusError):
            RUNNER.safe_archive_members(["/absolute"])

    def test_environment_does_not_select_candidate_with_library_path(self) -> None:
        environment = RUNNER.sanitize_environment({"LD_LIBRARY_PATH": "/candidate", "PATH": "/host", "LANG": "C"})
        self.assertNotIn("LD_LIBRARY_PATH", environment)
        self.assertEqual(environment["PATH"], "/bin:/usr/bin")
        self.assertEqual(environment["HOME"], "/root")


if __name__ == "__main__":
    unittest.main()
