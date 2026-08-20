#!/usr/bin/env python3
"""Pure host tests for the LTO evidence helpers."""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[3]
RUNNER_PATH = ROOT / "compat/lto/run.py"
SPEC = importlib.util.spec_from_file_location("crabc_lto_runner", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
sys.modules["crabc_lto_runner"] = runner
SPEC.loader.exec_module(runner)


class RunnerHelpersTest(unittest.TestCase):
    def test_configuration_matrix_matches_stage_16(self) -> None:
        self.assertEqual([item.key for item in runner.CONFIGURATIONS], ["A", "B", "C", "D"])
        self.assertEqual(runner.CONFIGURATIONS[0].runtime, "musl")
        self.assertTrue(runner.CONFIGURATIONS[1].static)
        self.assertFalse(runner.CONFIGURATIONS[0].build_std)
        self.assertFalse(runner.CONFIGURATIONS[0].stock_std)
        self.assertEqual(runner.CONFIGURATIONS[0].workload, "c-static")
        self.assertFalse(runner.CONFIGURATIONS[1].build_std)
        self.assertFalse(runner.CONFIGURATIONS[1].stock_std)
        self.assertEqual(runner.CONFIGURATIONS[1].workload, "c-static")
        self.assertTrue(runner.CONFIGURATIONS[2].build_std)
        self.assertFalse(runner.CONFIGURATIONS[2].stock_std)
        self.assertEqual(runner.CONFIGURATIONS[2].workload, "rust")
        self.assertTrue(runner.CONFIGURATIONS[3].build_std)
        self.assertEqual(runner.CONFIGURATIONS[3].runtime, "crabc-static-lto")
        self.assertEqual(runner.CONFIGURATIONS[3].lto, "fat")
        self.assertTrue(runner.CONFIGURATIONS[3].linker_plugin_lto)

    def test_snapshot_retains_hash_and_truncates_only_preview(self) -> None:
        value = b"abc" * 20
        evidence = runner.snapshot(value, preview_limit=5)
        self.assertEqual(evidence["byte_length"], len(value))
        self.assertEqual(evidence["sha256"], runner.sha256_bytes(value))
        self.assertEqual(evidence["preview"], "abcab")
        self.assertTrue(evidence["preview_truncated"])

    def test_parse_text_size_sums_text_sections(self) -> None:
        output = """
  [ 1] .text PROGBITS 0000000000000000 000040 000010 00 AX  0   0  4
  [ 2] .text.hot PROGBITS 0000000000000000 000050 000006 00 AX  0   0  4
  [ 3] .data PROGBITS 0000000000000000 000056 000004 00 WA  0   0  4
"""
        self.assertEqual(runner.parse_text_size(output), 0x16)

    def test_parse_text_size_missing_section_is_unknown(self) -> None:
        self.assertIsNone(runner.parse_text_size("readelf: no sections"))

    def test_parse_named_section_sizes_extracts_bitcode_sections(self) -> None:
        output = "  [ 4] .llvmbc PROGBITS 0000000000000000 000100 000020 00    0   0  1\n"
        self.assertEqual(runner.parse_named_section_sizes(output, ".llvmbc"), [0x20])

    def test_archive_member_names_are_selection_anchors(self) -> None:
        output = """
crabc-cgu.0.rcgu.o:
---------------- T getpid
crabc-cgu.1.rcgu.o:
---------------- T write
"""
        self.assertEqual(
            runner.archive_member_names(output),
            ["crabc-cgu.0.rcgu.o", "crabc-cgu.1.rcgu.o"],
        )

    def test_fixture_helper_mentions_are_bounded_symbol_evidence(self) -> None:
        mentions = runner.fixture_helper_mentions("main workload libc_probe")
        self.assertEqual(
            mentions,
            {"mix": False, "workload": True, "libc_probe": True},
        )

    def test_parse_syscall_summary_uses_calls_and_errors_columns(self) -> None:
        output = """
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 50.00    0.000010           5         2         0 read
 50.00    0.000010           5         1         1 write
  00.00    0.000000           0         4           close
------ ----------- ----------- --------- --------- ----------------
100.00    0.000020           6         3         1 total
"""
        parsed = runner.parse_syscall_summary(output)
        self.assertEqual(parsed["total_calls"], 7)
        self.assertEqual(parsed["syscalls"], [
            {"syscall": "read", "calls": 2, "errors": 0},
            {"syscall": "write", "calls": 1, "errors": 1},
            {"syscall": "close", "calls": 4, "errors": 0},
        ])

    def test_interpreter_patch_changes_only_payload(self) -> None:
        data = bytearray(256)
        data[:4] = b"\x7fELF"
        data[4] = 2
        data[5] = 1
        data[18:20] = (183).to_bytes(2, "little")
        data[32:40] = (64).to_bytes(8, "little")
        data[54:56] = (56).to_bytes(2, "little")
        data[56:58] = (1).to_bytes(2, "little")
        data[64:68] = (3).to_bytes(4, "little")
        data[72:80] = (128).to_bytes(8, "little")
        data[96:104] = (32).to_bytes(8, "little")
        data[128:160] = b"/lib/ld-musl-aarch64.so.1\0\0\0\0\0\0"
        patched = runner.patched_interpreter_bytes(bytes(data), "/tmp/r")
        self.assertEqual(patched[:128], bytes(data[:128]))
        self.assertEqual(patched[128:160], b"/tmp/r\0" + b"\0" * 25)

    def test_failure_classification_keeps_lto_unsupported_distinct(self) -> None:
        configuration = runner.CONFIGURATIONS[3]
        self.assertEqual(
            runner.classify_build_failure(configuration, "linker-plugin-lto is not supported"),
            "unsupported",
        )
        self.assertEqual(
            runner.classify_build_failure(configuration, "undefined reference to foo"),
            "unbuildable",
        )

    def test_matrix_rejects_byte_identical_crabc_static_baseline(self) -> None:
        configurations = {
            "A": {"status": "built", "build": {"binary_sha256": "same"}},
            "B": {
                "status": "built",
                "build": {
                    "binary_sha256": "same",
                    "claims": {"static_crabc_linkage_proven": True},
                },
            },
        }
        runner.enforce_matrix_contract(configurations)
        self.assertEqual(configurations["B"]["status"], "invalid")
        self.assertFalse(configurations["B"]["build"]["claims"]["static_crabc_linkage_proven"])


if __name__ == "__main__":
    unittest.main()
