#!/usr/bin/env python3
"""Focused no-execution tests for the diagnostic-output evidence reader."""

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
SCRIPT_PATH = ROOT / "compat/allocator/x86_64_diagnostic_output_owner_evidence.py"
SPEC = importlib.util.spec_from_file_location("crabc_diagnostic_output_evidence", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
EVIDENCE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = EVIDENCE
SPEC.loader.exec_module(EVIDENCE)


class RetainedStreamReaderTests(unittest.TestCase):
    C_THREAD_IDENTITY = 0x7F0A_C0DE
    RUST_THREAD_IDENTITY = 0x7F0A_FACE

    @staticmethod
    def raw_record(
        command: list[str], cwd: Path, stdout: str = "", stderr: str = "",
    ) -> dict[str, object]:
        return {
            "command": command,
            "cwd": str(cwd),
            "status": 0,
            "stdout": stdout,
            "stderr": stderr,
        }

    @staticmethod
    def trace_for_thread_identity(identity: int) -> dict[str, list[str]]:
        prefix = f"mimalloc: warning: thread 0x{identity:X}: ".encode("ascii").hex()
        return {
            "release": [],
            "enabled": [prefix, EVIDENCE.SELECTED_BODY],
            "cap": [prefix, EVIDENCE.FIRST, prefix, EVIDENCE.SECOND],
            "verbose": [prefix, EVIDENCE.FIRST, prefix, EVIDENCE.SECOND],
            "delayed": [EVIDENCE.EARLY, EVIDENCE.LATER],
            "null": [EVIDENCE.EARLY],
            "post_init": [EVIDENCE.POST_INIT],
        }

    def complete_report(self) -> dict[str, object]:
        temporary = ROOT / ".work/allocator-x86_64/diagnostic-output-owner/synthetic-receipt"
        source = temporary / "source/mimalloc-3.5.0"
        binary = temporary / "diagnostic-output-owner-c-oracle"
        target = temporary / "rust-target"
        c_trace = self.trace_for_thread_identity(self.C_THREAD_IDENTITY)
        rust_trace = self.trace_for_thread_identity(self.RUST_THREAD_IDENTITY)
        c_runs = {
            scenario: self.raw_record(
                [str(binary), scenario],
                source,
                f"{scenario}={':'.join(c_trace[scenario])}\n"
                f"thread_identity={self.C_THREAD_IDENTITY:x}\n",
                EVIDENCE.EXPECTED_C_STDERR[scenario],
            )
            for scenario in EVIDENCE.SCENARIOS
        }
        c_runs[EVIDENCE.FINAL_STATISTICS_SCENARIO] = self.raw_record(
            [str(binary), EVIDENCE.FINAL_STATISTICS_SCENARIO],
            source,
            f"{EVIDENCE.FINAL_STATISTICS_SCENARIO}="
            f"{':'.join(EVIDENCE.EXPECTED_RUST_FINAL_STATISTICS_TRACE)}\n"
            f"thread_identity={self.C_THREAD_IDENTITY:x}\n",
            EVIDENCE.EXPECTED_C_STDERR[EVIDENCE.FINAL_STATISTICS_SCENARIO],
        )
        rust_stream = "\n".join(
            [EVIDENCE.TRACE_BEGIN]
            + [f"{scenario}={':'.join(rust_trace[scenario])}" for scenario in EVIDENCE.SCENARIOS]
            + [
                EVIDENCE.TRACE_END,
                EVIDENCE.FINAL_STATISTICS_BEGIN,
                f"{EVIDENCE.FINAL_STATISTICS_SCENARIO}="
                f"{':'.join(EVIDENCE.EXPECTED_RUST_FINAL_STATISTICS_TRACE)}",
                EVIDENCE.FINAL_STATISTICS_END,
                EVIDENCE.THREAD_IDENTITIES_BEGIN,
            ]
            + [f"{scenario}={self.RUST_THREAD_IDENTITY:x}" for scenario in EVIDENCE.SCENARIOS]
            + [EVIDENCE.THREAD_IDENTITIES_END, ""]
        )
        default_stderr = "\n".join(
            [EVIDENCE.DEFAULT_STDERR_BEGIN]
            + [
                f"{scenario}={':'.join(EVIDENCE.EXPECTED_DEFAULT_STDERR_TRACE[scenario])}"
                for scenario in EVIDENCE.SCENARIOS
            ]
            + [EVIDENCE.DEFAULT_STDERR_END, ""]
        )
        return {
            "c_oracle": {
                "build": self.raw_record(
                    EVIDENCE.c_compile_command("musl-gcc", source, binary), source,
                ),
                "runs": c_runs,
                "source_files": EVIDENCE.expected_pinned_c_source_records(),
            },
            "cargo_lock": EVIDENCE.current_file_identity(EVIDENCE.LOCKFILE),
            "fixture": EVIDENCE.current_file_identity(EVIDENCE.FIXTURE),
            "format": 2,
            "kind": "mimalloc-x86_64-diagnostic-output-owner-evidence",
            "native_execution_provenance": {"execution_mode": "native", "host_architecture": "x86_64"},
            "profile": EVIDENCE.PROFILE,
            "rust": self.raw_record(
                EVIDENCE.rust_command("cargo", target), ROOT, rust_stream, default_stderr,
            ),
            "rust_build_inputs": EVIDENCE.current_rust_build_input_records(),
            "rust_source_files": EVIDENCE.current_rust_source_records(),
            "scope": EVIDENCE.SCOPE,
            "status": "passed",
            "target": {
                "architecture": "x86_64",
                "endianness": "little",
                "rust_target": EVIDENCE.TARGET,
                "system": "linux",
            },
            "upstream": EVIDENCE.PINNED_UPSTREAM,
        }

    def test_reader_reconstructs_the_trace_from_retained_raw_streams(self) -> None:
        report = self.complete_report()
        EVIDENCE.validate_report(report)
        self.assertIn("stdout", report["c_oracle"]["runs"]["enabled"])
        self.assertIn("stderr", report["rust"])
        self.assertNotIn("stdout_sha256", report["rust"])

    def test_reader_reconstructs_canonical_scenarios_after_the_sorted_json_round_trip(self) -> None:
        report = json.loads(json.dumps(self.complete_report(), sort_keys=True))
        self.assertEqual(
            list(report["c_oracle"]["runs"]),
            sorted(EVIDENCE.C_SCENARIOS),
        )

        EVIDENCE.validate_report(report)

    def test_reader_rejects_missing_or_extra_c_scenarios_after_the_sorted_json_round_trip(self) -> None:
        for name, mutate in {
            "missing": lambda runs: runs.pop("cap"),
            "extra": lambda runs: runs.__setitem__("unexpected", runs["cap"]),
        }.items():
            with self.subTest(case=name):
                report = json.loads(json.dumps(self.complete_report(), sort_keys=True))
                mutate(report["c_oracle"]["runs"])
                with self.assertRaisesRegex(EVIDENCE.EvidenceError, "C scenario roster drifted"):
                    EVIDENCE.validate_report(report)

    def test_reader_accepts_native03_toolchain_prelude_around_the_exact_default_sink_capture(self) -> None:
        report = self.complete_report()
        # native-differential-03 retained this Cargo/rustup prelude before the
        # test-owned line-delimited default-sink capture. It is command stderr,
        # not allocator output. Its candidate is retained under the checkout's
        # ignored evidence root with SHA
        # 2c6b2efca5c127ab1eb24d3756104aadf07a6076c3b2ae26757bb70d7ebed13c.
        prelude = (
            "info: syncing channel updates for nightly-2026-07-24-x86_64-unknown-linux-musl\n"
            "info: latest update on 2026-07-24 for version 1.99.0-nightly (89c61a754 2026-07-23)\n"
            "info: downloading 8 components\n"
        )
        suffix = "info: cargo wrapper completed\n"
        report["rust"]["stderr"] = prelude + report["rust"]["stderr"] + suffix

        EVIDENCE.validate_report(report)
        self.assertEqual(report["rust"]["stderr"], prelude + EVIDENCE.expected_default_stderr_stream() + suffix)

    def test_reader_rejects_duplicate_missing_reordered_or_non_lf_default_sink_markers(self) -> None:
        block = EVIDENCE.expected_default_stderr_stream()
        cases = {
            "duplicate": block + block,
            "missing": block.replace(EVIDENCE.DEFAULT_STDERR_END + "\n", ""),
            "missing_final_lf": block[:-1],
            "reordered": (
                EVIDENCE.DEFAULT_STDERR_END
                + "\n"
                + EVIDENCE.DEFAULT_STDERR_BEGIN
                + "\n"
                + "release=\n"
            ),
            "carriage_return": block.replace(EVIDENCE.DEFAULT_STDERR_BEGIN + "\n", EVIDENCE.DEFAULT_STDERR_BEGIN + "\r\n"),
            "vertical_tab_predecessor": "toolchain\v" + block,
        }
        for name, stderr in cases.items():
            with self.subTest(case=name):
                report = self.complete_report()
                report["rust"]["stderr"] = stderr
                with self.assertRaisesRegex(EVIDENCE.EvidenceError, "default-stderr marker framing drifted"):
                    EVIDENCE.validate_report(report)

    def test_reader_rejects_extra_or_mutated_bytes_inside_the_default_sink_capture(self) -> None:
        for name, stderr in {
            "extra": EVIDENCE.expected_default_stderr_stream().replace("enabled=\n", "enabled=\nextra=\n"),
            "mutated": EVIDENCE.expected_default_stderr_stream().replace("7374646572720a", "77726f6e670a"),
        }.items():
            with self.subTest(case=name):
                report = self.complete_report()
                report["rust"]["stderr"] = stderr
                with self.assertRaisesRegex(EVIDENCE.EvidenceError, "default-stderr framed bytes drifted"):
                    EVIDENCE.validate_report(report)

    def test_reader_requires_the_source_pre_increment_cap_boundary(self) -> None:
        prefix = f"mimalloc: warning: thread 0x{self.C_THREAD_IDENTITY:X}: ".encode("ascii").hex()
        self.assertEqual(
            EVIDENCE.expected_trace_for_thread_identity(self.C_THREAD_IDENTITY)["cap"],
            [prefix, EVIDENCE.FIRST, prefix, EVIDENCE.SECOND],
        )

    def test_reader_rejects_changed_raw_callback_order_without_running_a_process(self) -> None:
        report = self.complete_report()
        prefix, body = self.trace_for_thread_identity(self.C_THREAD_IDENTITY)["enabled"]
        report["c_oracle"]["runs"]["enabled"]["stdout"] = (
            f"enabled={body}:{prefix}\nthread_identity={self.C_THREAD_IDENTITY:x}\n"
        )
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "pinned C diagnostic-output callback trace drifted"):
            EVIDENCE.validate_report(report)

    def test_reader_rejects_unbound_or_mismatched_thread_prefixes_without_running_a_process(self) -> None:
        missing = self.complete_report()
        prefix, body = self.trace_for_thread_identity(self.C_THREAD_IDENTITY)["enabled"]
        missing["c_oracle"]["runs"]["enabled"]["stdout"] = f"enabled={prefix}:{body}\n"
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "callback and thread-identity"):
            EVIDENCE.validate_report(missing)

        mismatched = self.complete_report()
        mismatched["c_oracle"]["runs"]["enabled"]["stdout"] = (
            f"enabled={prefix}:{body}\nthread_identity={self.C_THREAD_IDENTITY + 1:x}\n"
        )
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "pinned C diagnostic-output callback trace drifted"):
            EVIDENCE.validate_report(mismatched)

        rust_mismatched = self.complete_report()
        rust_mismatched["rust"]["stdout"] = rust_mismatched["rust"]["stdout"].replace(
            f"enabled={self.RUST_THREAD_IDENTITY:x}",
            f"enabled={self.RUST_THREAD_IDENTITY + 1:x}",
        )
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "Rust diagnostic-output callback trace drifted"):
            EVIDENCE.validate_report(rust_mismatched)

    def test_reader_rejects_noncanonical_thread_prefix_or_observation_without_running_a_process(self) -> None:
        report = self.complete_report()
        canonical_prefix, body = self.trace_for_thread_identity(self.C_THREAD_IDENTITY)["enabled"]
        lower_prefix = bytes.fromhex(canonical_prefix).replace(b"0x7F0AC0DE", b"0x7f0AC0DE").hex()
        report["c_oracle"]["runs"]["enabled"]["stdout"] = (
            f"enabled={lower_prefix}:{body}\nthread_identity={self.C_THREAD_IDENTITY:x}\n"
        )
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "pinned C diagnostic-output callback trace drifted"):
            EVIDENCE.validate_report(report)

        report = self.complete_report()
        report["c_oracle"]["runs"]["enabled"]["stdout"] = (
            f"enabled={canonical_prefix}:{body}\nthread_identity=0{self.C_THREAD_IDENTITY:x}\n"
        )
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "canonical lower-case minimal hex"):
            EVIDENCE.validate_report(report)

    def test_reader_rejects_missing_rust_stream_marker_without_running_a_process(self) -> None:
        report = copy.deepcopy(self.complete_report())
        report["rust"]["stdout"] = report["rust"]["stdout"].replace(EVIDENCE.TRACE_END, "")
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "trace markers"):
            EVIDENCE.validate_report(report)

        report = self.complete_report()
        report["rust"]["stdout"] = report["rust"]["stdout"].replace(
            EVIDENCE.FINAL_STATISTICS_END,
            f"{EVIDENCE.FINAL_STATISTICS_END}\n{EVIDENCE.FINAL_STATISTICS_END}",
        )
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "final-statistics trace markers"):
            EVIDENCE.validate_report(report)

    def test_reader_rejects_each_changed_authenticated_identity(self) -> None:
        report = self.complete_report()
        mutations = {
            "fixture": lambda value: value["fixture"].__setitem__("sha256", "0" * 64),
            "Cargo.lock": lambda value: value["cargo_lock"].__setitem__("sha256", "0" * 64),
            "pinned C source": lambda value: value["c_oracle"]["source_files"][0].__setitem__("sha256", "0" * 64),
        }
        for index, source in enumerate(report["rust_source_files"]):
            mutations[f"Rust source {source['path']}"] = (
                lambda value, index=index: value["rust_source_files"][index].__setitem__("sha256", "0" * 64)
            )
        for index, source in enumerate(report["rust_build_inputs"]):
            mutations[f"Rust build input {source['path']}"] = (
                lambda value, index=index: value["rust_build_inputs"][index].__setitem__("sha256", "0" * 64)
            )
        for name, mutate in mutations.items():
            with self.subTest(identity=name):
                changed = copy.deepcopy(report)
                mutate(changed)
                with self.assertRaises(EVIDENCE.EvidenceError):
                    EVIDENCE.validate_report(changed)

    def test_rust_source_roster_covers_owner_stats_clock_lock_and_x86_futex_dependency_chain(self) -> None:
        self.assertEqual(
            [record["path"] for record in EVIDENCE.current_rust_source_records()],
            [
                "crabc-mimalloc/src/lib.rs",
                "crabc-mimalloc/src/diagnostic_output.rs",
                "crabc-mimalloc/src/lock.rs",
                "crabc-mimalloc/src/os.rs",
                "crabc-mimalloc/src/statistics.rs",
                "crabc-core/src/lib.rs",
                "crabc-core/src/error.rs",
                "crabc-core/src/thread.rs",
                "crabc-core/src/syscall_x86_64.rs",
            ],
        )

    def test_c_source_roster_binds_the_compiled_thread_identity_header(self) -> None:
        header = "include/mimalloc/prim-tls.h"
        source_paths = [record["path"] for record in EVIDENCE.expected_pinned_c_source_records()]
        self.assertIn(header, source_paths)

        report = self.complete_report()
        index = source_paths.index(header)
        report["c_oracle"]["source_files"][index]["sha256"] = "0" * 64
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "C source identity drifted"):
            EVIDENCE.validate_report(report)

        current_report = self.complete_report()
        current_pin = list(EVIDENCE.PINNED_C_SOURCE_IDENTITIES)
        current_pin[index] = (header, "0" * 64)
        with mock.patch.object(EVIDENCE, "PINNED_C_SOURCE_IDENTITIES", tuple(current_pin)):
            with self.assertRaisesRegex(EVIDENCE.EvidenceError, "C source identity drifted"):
                EVIDENCE.validate_report(current_report)

    def test_c_source_roster_binds_the_warning_counter_fetch_add_header(self) -> None:
        header = "include/mimalloc/atomic.h"
        source_paths = [record["path"] for record in EVIDENCE.expected_pinned_c_source_records()]
        self.assertIn(header, source_paths)

        report = self.complete_report()
        index = source_paths.index(header)
        report["c_oracle"]["source_files"][index]["sha256"] = "0" * 64
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "C source identity drifted"):
            EVIDENCE.validate_report(report)

        current_report = self.complete_report()
        current_pin = list(EVIDENCE.PINNED_C_SOURCE_IDENTITIES)
        current_pin[index] = (header, "0" * 64)
        with mock.patch.object(EVIDENCE, "PINNED_C_SOURCE_IDENTITIES", tuple(current_pin)):
            with self.assertRaisesRegex(EVIDENCE.EvidenceError, "C source identity drifted"):
                EVIDENCE.validate_report(current_report)

    def test_reader_rejects_changed_current_owner_route_and_private_lock_sources(self) -> None:
        report = self.complete_report()
        original_sha256_file = EVIDENCE.sha256_file
        changed_paths = (
            EVIDENCE.RUST_SOURCE_FILES[0],
            EVIDENCE.RUST_SOURCE_FILES[2],
        )
        for changed_path in changed_paths:
            with self.subTest(path=changed_path):
                def changed_sha256_file(path: Path) -> str:
                    if path.resolve() == changed_path.resolve():
                        return "0" * 64
                    return original_sha256_file(path)

                with mock.patch.object(EVIDENCE, "sha256_file", side_effect=changed_sha256_file):
                    with self.assertRaisesRegex(EVIDENCE.EvidenceError, "Rust source closure drifted"):
                        EVIDENCE.validate_report(report)

    def test_reader_rejects_changed_current_cargo_config(self) -> None:
        report = self.complete_report()
        original_sha256_file = EVIDENCE.sha256_file
        cargo_config = ROOT / ".cargo/config.toml"

        def changed_sha256_file(path: Path) -> str:
            if path.resolve() == cargo_config.resolve():
                return "0" * 64
            return original_sha256_file(path)

        with mock.patch.object(EVIDENCE, "sha256_file", side_effect=changed_sha256_file):
            with self.assertRaisesRegex(EVIDENCE.EvidenceError, "Rust build-input closure drifted"):
                EVIDENCE.validate_report(report)

    def test_reader_rejects_changed_c_and_rust_commands(self) -> None:
        changed_c = self.complete_report()
        changed_c["c_oracle"]["build"]["command"][0] = "/wrong/musl-gcc"
        with self.assertRaises(EVIDENCE.EvidenceError):
            EVIDENCE.validate_report(changed_c)

        changed_rust = self.complete_report()
        changed_rust["rust"]["command"][0] = "/wrong/cargo"
        with self.assertRaises(EVIDENCE.EvidenceError):
            EVIDENCE.validate_report(changed_rust)

    def test_reader_rejects_changed_collector_owned_cwds(self) -> None:
        changed_c = self.complete_report()
        changed_c["c_oracle"]["build"]["cwd"] = str(ROOT / ".work/wrong-source")
        with self.assertRaises(EVIDENCE.EvidenceError):
            EVIDENCE.validate_report(changed_c)

        changed_rust = self.complete_report()
        changed_rust["rust"]["cwd"] = str(ROOT / ".work/wrong-rust-cwd")
        with self.assertRaises(EVIDENCE.EvidenceError):
            EVIDENCE.validate_report(changed_rust)

    def test_reader_rejects_changed_default_stderr_bytes(self) -> None:
        report = self.complete_report()
        report["c_oracle"]["runs"]["post_init"]["stderr"] = "wrong default output\n"
        with self.assertRaises(EVIDENCE.EvidenceError):
            EVIDENCE.validate_report(report)

    def test_reader_rejects_reordered_or_mutated_final_statistics_phases(self) -> None:
        report = self.complete_report()
        final = report["c_oracle"]["runs"][EVIDENCE.FINAL_STATISTICS_SCENARIO]
        final["stdout"] = final["stdout"].replace(
            "6d696d616c6c6f633a2070726f6365737320646f6e652039370a",
            "0a",
        )
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "verbose-tail order"):
            EVIDENCE.validate_report(report)

        report = self.complete_report()
        report["rust"]["stdout"] = report["rust"]["stdout"].replace(
            "73756270726f6320370a",
            "73756270726f6320380a",
            1,
        )
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "Rust final-statistics formatter"):
            EVIDENCE.validate_report(report)

    def test_reader_rejects_changed_rust_default_stderr_bytes(self) -> None:
        report = self.complete_report()
        report["rust"]["stderr"] = report["rust"]["stderr"].replace("6561726c790a", "77726f6e670a")
        with self.assertRaises(EVIDENCE.EvidenceError):
            EVIDENCE.validate_report(report)

    def test_collect_retains_unvalidated_candidate_when_semantic_validation_fails(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="diagnostic-output-candidate-test-", dir=ROOT / ".work"
        ) as temporary:
            temporary_path = Path(temporary)
            archive = temporary_path / "mimalloc-3.5.0.tar.gz"
            archive.write_bytes(b"synthetic pinned archive")
            report_path = temporary_path / "diagnostic-output-owner.json"
            fake_source_records = [{"path": member, "sha256": "0" * 64} for member in EVIDENCE.C_SOURCE_FILES]

            class FakeHarness:
                WORK_ROOT = temporary_path / "collector-work"

                @staticmethod
                def require_tool(name: str) -> str:
                    self.assertEqual(name, "musl-gcc")
                    return name

                @staticmethod
                def temporary_directory(prefix: str) -> tempfile.TemporaryDirectory[str]:
                    return tempfile.TemporaryDirectory(prefix=prefix, dir=temporary_path)

                @staticmethod
                def safe_extract(_archive: Path, destination: Path, archive_root: str) -> Path:
                    source = destination / archive_root
                    for member in EVIDENCE.C_SOURCE_FILES:
                        path = source / member
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(member.encode("ascii"))
                    return source

            def fake_command_record(command: list[str], cwd: Path) -> dict[str, object]:
                return self.raw_record(command, cwd)

            pinned_upstream = dict(EVIDENCE.PINNED_UPSTREAM)
            pinned_upstream["archive_sha256"] = EVIDENCE.hashlib.sha256(archive.read_bytes()).hexdigest()
            with (
                mock.patch.object(EVIDENCE, "PINNED_UPSTREAM", pinned_upstream),
                mock.patch.object(EVIDENCE, "require_native_x86_64", return_value={"execution_mode": "native", "host_architecture": "x86_64"}),
                mock.patch.object(EVIDENCE, "load_harness", return_value=FakeHarness),
                mock.patch.object(EVIDENCE, "shutil_which", return_value="cargo"),
                mock.patch.object(EVIDENCE, "source_records", return_value=fake_source_records),
                mock.patch.object(EVIDENCE, "expected_pinned_c_source_records", return_value=fake_source_records),
                mock.patch.object(EVIDENCE, "command_record", side_effect=fake_command_record),
                mock.patch.object(EVIDENCE, "validate_report", side_effect=EVIDENCE.EvidenceError("forced semantic drift")),
            ):
                with self.assertRaisesRegex(EVIDENCE.EvidenceError, "forced semantic drift"):
                    EVIDENCE.collect(archive, report_path)

            candidate_path = EVIDENCE.candidate_report_path(report_path)
            self.assertTrue(candidate_path.is_file())
            self.assertFalse(report_path.exists())
            candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
            self.assertEqual(candidate["status"], "unvalidated")
            self.assertEqual(candidate["c_oracle"]["build"]["command"][0], "musl-gcc")
            self.assertEqual(candidate["c_oracle"]["runs"]["release"]["command"][1], "release")
            self.assertTrue(Path(candidate["c_oracle"]["source_root"]).is_dir())

    def test_collector_owned_paths_cannot_escape_the_checkout_work_tree(self) -> None:
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "must stay under this checkout's .work"):
            EVIDENCE.require_checkout_work_path(Path("/var/empty/report.json"), "evidence report")
