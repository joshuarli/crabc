#!/usr/bin/env python3
"""Closed receipt and scalar-trace checks for startup regular-arena evidence."""

from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_startup_regular_arena_evidence.py"
SPEC = importlib.util.spec_from_file_location("startup_regular_arena_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
EVIDENCE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = EVIDENCE
SPEC.loader.exec_module(EVIDENCE)


class TraceTests(unittest.TestCase):
    def test_scalar_trace_requires_one_ordered_complete_integer_record(self) -> None:
        trace = "\n".join(
            [
                EVIDENCE.C_TRACE_BEGIN,
                *(f"{field}={EVIDENCE.C_EXPECTED['reuse'][field]}" for field in EVIDENCE.C_TRACE_FIELDS),
                EVIDENCE.C_TRACE_END,
            ]
        )
        self.assertEqual(
            EVIDENCE.parse_scalar_trace(
                trace,
                begin=EVIDENCE.C_TRACE_BEGIN,
                end=EVIDENCE.C_TRACE_END,
                fields=EVIDENCE.C_TRACE_FIELDS,
                source="test C trace",
            ),
            EVIDENCE.C_EXPECTED["reuse"],
        )
        malformed = trace.replace("registry_after_init=1", "registry_after_init=1\nregistry_after_init=1")
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "invalid scalar trace row"):
            EVIDENCE.parse_scalar_trace(
                malformed,
                begin=EVIDENCE.C_TRACE_BEGIN,
                end=EVIDENCE.C_TRACE_END,
                fields=EVIDENCE.C_TRACE_FIELDS,
                source="test C trace",
            )


class ReportTests(unittest.TestCase):
    @staticmethod
    def digest(character: str) -> str:
        return character * 64

    def source_snapshot(self) -> dict[str, object]:
        return {
            "git_revision": "a" * 40,
            "git_tree": "b" * 40,
            "git_status_porcelain": "",
            "files": [
                {"path": EVIDENCE.relative(path), "sha256": self.digest("c")}
                for path in EVIDENCE.source_input_paths()
            ],
        }

    def c_command(self) -> list[str]:
        return [
            "/usr/bin/musl-gcc",
            "-std=c11",
            "-fPIC",
            "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB",
            "-DMI_SHARED_LIB_EXPORT",
            "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
            "-I",
            "<pinned-mimalloc-source>/include",
            "-I",
            "<pinned-mimalloc-source>/src",
            "-O3",
            "-DNDEBUG",
            "-DMI_BUILD_RELEASE=1",
            "-DMI_DEBUG=0",
            "-DMI_STAT=0",
            "-DMI_SECURE=0",
            "-DMI_GUARDED=0",
            "/workspace/compat/allocator/x86_64_startup_regular_arena_oracle.c",
            *(f"<pinned-mimalloc-source>/{source}" for source in EVIDENCE.C_LINK_SOURCES),
            "-pthread",
            "-o",
            "<startup-regular-arena-oracle-binary>",
        ]

    def complete_report(self) -> dict[str, object]:
        source = self.source_snapshot()
        c_runs = {
            scenario: {
                "command": ["<startup-regular-arena-oracle-binary>", scenario],
                "status": 0,
                "stdout_sha256": self.digest("d"),
                "stderr_sha256": self.digest("e"),
            }
            for scenario in EVIDENCE.SCENARIOS
        }
        c_oracle = {
            "binary": {
                "path": EVIDENCE.C_ORACLE_BINARY,
                "sha256": self.digest("f"),
                "bytes": 1,
            },
            "build": {
                "command": self.c_command(),
                "status": 0,
                "stdout_sha256": self.digest("1"),
                "stderr_sha256": self.digest("2"),
            },
            "fixture": {
                "path": EVIDENCE.relative(EVIDENCE.FIXTURE),
                "sha256": self.digest("3"),
            },
            "runs": c_runs,
            "source_files": [
                {"path": path, "sha256": self.digest("4"), "bytes": 1}
                for path in sorted(EVIDENCE.C_SOURCE_FILES)
            ],
            "traces": copy.deepcopy(EVIDENCE.C_EXPECTED),
            "upstream": copy.deepcopy(EVIDENCE.PINNED_UPSTREAM),
        }
        rust = {
            "cargo_command": [
                "/usr/bin/cargo",
                "test",
                "--locked",
                "--target",
                EVIDENCE.TARGET,
                "--target-dir",
                "<isolated-temporary-target-dir>",
                "-p",
                "crabc-mimalloc",
                "--test",
                EVIDENCE.RUST_TARGET,
                "--features",
                "native-runtime-test-audit",
                EVIDENCE.RUST_FILTER,
                "--",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ],
            "observed": {
                "passed": 1,
                "failed": 0,
                "ignored": 0,
                "measured": 0,
                "filtered_out": 0,
            },
            "source_test": f"{EVIDENCE.RUST_TARGET}::{EVIDENCE.RUST_FILTER}",
            "stdout_sha256": self.digest("5"),
            "trace": copy.deepcopy(EVIDENCE.RUST_EXPECTED),
        }
        return {
            "format": 1,
            "kind": "mimalloc-x86_64-startup-regular-arena-evidence",
            "profile": EVIDENCE.PROFILE,
            "status": "passed",
            "target": {
                "architecture": "x86_64",
                "endianness": "little",
                "rust_target": EVIDENCE.TARGET,
                "system": "linux",
            },
            "native_execution_provenance": {
                "execution_mode": "native",
                "host_architecture": "x86_64",
            },
            "toolchain": {
                "cargo": "cargo pinned",
                "rustc_host": EVIDENCE.TARGET,
                "rustc_release": "nightly-pinned",
            },
            "cargo": {
                "locked": True,
                "lockfile": {"path": "Cargo.lock", "sha256": self.digest("6")},
                "target_dir": {
                    "isolated": True,
                    "retained": False,
                    "value": "<isolated-temporary-target-dir>",
                },
            },
            "candidate_source": {
                "before": source,
                "after": copy.deepcopy(source),
                "unchanged_during_execution": True,
            },
            "c_oracle": c_oracle,
            "rust": rust,
            "comparison": EVIDENCE.comparison(c_oracle, rust),
            "scope": copy.deepcopy(EVIDENCE.REPORT_SCOPE),
        }

    def test_complete_receipt_binds_the_four_source_transitions(self) -> None:
        report = self.complete_report()
        EVIDENCE.validate_report(report)
        self.assertEqual(report["comparison"]["matched_value_count"], 28)
        self.assertEqual(
            report["comparison"]["values"]["reuse.client_startup_identity"],
            1,
        )
        self.assertEqual(
            report["comparison"]["values"]["ineligible.client_is_arena_backed"],
            0,
        )

    def test_receipt_rejects_a_changed_source_fallback_or_mismatched_lane(self) -> None:
        report = self.complete_report()
        report["c_oracle"]["traces"]["ineligible"]["client_is_arena_backed"] = 1
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "C source transitions"):
            EVIDENCE.validate_report(report)

        report = self.complete_report()
        report["rust"]["trace"]["reuse"]["arena_size_after_allocation"] = EVIDENCE.LAZY_BYTES
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "Rust source transitions"):
            EVIDENCE.validate_report(report)

    def test_receipt_rejects_weakened_source_or_locked_command_binding(self) -> None:
        report = self.complete_report()
        report["candidate_source"]["unchanged_during_execution"] = 1
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "exact true"):
            EVIDENCE.validate_report(report)

        report = self.complete_report()
        report["cargo"]["locked"] = 1
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "lock mode"):
            EVIDENCE.validate_report(report)

        report = self.complete_report()
        report["c_oracle"]["source_files"].pop()
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "source roster"):
            EVIDENCE.validate_report(report)

        report = self.complete_report()
        report["rust"]["cargo_command"].remove("--locked")
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "Rust command"):
            EVIDENCE.validate_report(report)


if __name__ == "__main__":
    unittest.main()
