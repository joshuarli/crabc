#!/usr/bin/env python3
"""Compare pinned-C and Rust small-page remote publication/collection races."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import run
from x86_64_regular_small_evidence import (
    EXPECTED_C_ELF, EXPECTED_COMPILE_DEFINITIONS, EXPECTED_UPSTREAM,
)

ROOT = Path(__file__).resolve().parents[2]
C_PROBE = ROOT / "compat/allocator/x86_64_m5_remote_collect_race.c"
RUST_SOURCE = ROOT / "crabc-mimalloc/src/remote_free.rs"
LOOM_SOURCE = ROOT / "crabc-mimalloc/src/remote_free_loom.rs"
REPORT = ROOT / "compat/reports/allocator/x86_64/m5-remote-collect-race.json"
BEGIN = "CRABC_MI_M5_REMOTE_COLLECT_RACE_BEGIN"
END = "CRABC_MI_M5_REMOTE_COLLECT_RACE_END"
RUST_TEST = "remote_free::tests::x86_64_m5_remote_collect_race_matches_pinned_c_protocol"
LOOM_TEST = ("remote_free::publication_collect_race_tests::"
             "small_page_owner_exit_and_arena_reader_collect_each_remote_block_once")
EXPECTED = {
    "producer_count": 3,
    "used_before": 3,
    "used_after": 0,
    "head_owned_empty": 1,
    "collected_count": 3,
}


class EvidenceError(RuntimeError):
    """The source-built race or its physical receipt missed the contract."""


def trace(record: dict, side: str) -> dict[str, int]:
    if record.get("status") != 0 or not isinstance(record.get("stdout"), str):
        raise EvidenceError(f"{side} execution failed")
    try:
        parsed = run.parse_address_independent_trace(
            record["stdout"], begin=BEGIN, end=END, description=side,
        )
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    if parsed != EXPECTED:
        raise EvidenceError(f"{side} trace differs: {parsed}")
    return parsed


def read_report(path: Path) -> dict[str, int]:
    try:
        report = json.loads(path.read_text())
        pin = run.load_pin()
        if report["kind"] != "pinned-c-native-rust-m5-remote-collect-race":
            raise EvidenceError("wrong report kind")
        if report["status"] != "matched":
            raise EvidenceError(f"race execution diverged: {report['reason']}")
        if report["source"] != {
            "revision": pin["revision"], "archive_sha256": pin["sha256"],
            "c_probe_sha256": run.sha256_file(C_PROBE),
            "rust_source_sha256": run.sha256_file(RUST_SOURCE),
            "loom_source_sha256": run.sha256_file(LOOM_SOURCE),
            "lockfile_sha256": run.sha256_file(ROOT / "Cargo.lock"),
        }:
            raise EvidenceError("selected source seal differs")
        if report["c"]["elf"] != EXPECTED_C_ELF:
            raise EvidenceError("C fixture lacks native x86-64 ELF identity")
        if report["c"]["build"]["status"] != 0:
            raise EvidenceError("pinned C build failed")
        if report["rust"]["execution"]["status"] != 0:
            raise EvidenceError("Rust fixture failed")
        if report["c"]["execution"]["stderr"]:
            raise EvidenceError("pinned C emitted a runtime diagnostic")
        rust_output = (report["rust"]["execution"]["stdout"] + "\n"
                       + report["rust"]["execution"]["stderr"])
        if run.parse_rust_test_count(rust_output) != 1:
            raise EvidenceError("the selected Rust test did not pass exactly once")
        loom_execution = report["loom"]["execution"]
        if loom_execution["status"] != 0 or run.parse_rust_test_count(
            loom_execution["stdout"] + "\n" + loom_execution["stderr"]
        ) != 1:
            raise EvidenceError("the selected Loom race did not pass exactly once")
        c_trace = trace(report["c"]["execution"], "pinned C")
        rust_trace = trace(report["rust"]["execution"], "native Rust")
        if c_trace != rust_trace or report["comparison"] != c_trace:
            raise EvidenceError("raw C/Rust records or stored comparison differ")
        return c_trace
    except (OSError, ValueError, KeyError, TypeError, run.HarnessError) as error:
        raise EvidenceError(f"cannot physically reread race receipt: {error}") from error


def run_evidence(path: Path, offline: bool) -> None:
    target = run.require_native_x86_64()
    pin = run.load_pin()
    if pin["revision"] != EXPECTED_UPSTREAM["revision"]:
        raise EvidenceError("pinned mimalloc revision differs")
    archive = run.fetch_archive(pin, offline)
    source_seal = {
        "revision": pin["revision"], "archive_sha256": run.sha256_file(archive),
        "c_probe_sha256": run.sha256_file(C_PROBE),
        "rust_source_sha256": run.sha256_file(RUST_SOURCE),
        "loom_source_sha256": run.sha256_file(LOOM_SOURCE),
        "lockfile_sha256": run.sha256_file(ROOT / "Cargo.lock"),
    }
    with run.temporary_directory("m5-remote-collect-race-") as directory:
        temporary = Path(directory)
        source = run.safe_extract(archive, temporary / "source", pin["archive_root"])
        c_binary = temporary / "pinned-c-race"
        c_command = [
            run.require_tool("musl-gcc"), "-std=c11", "-fPIC",
            "-ftls-model=initial-exec", *EXPECTED_COMPILE_DEFINITIONS,
            "-I", str(source / "include"), "-I", str(source / "src"),
            *run.CONFIGURATION_PROFILES["release"], str(C_PROBE),
            *(str(source / member) for member in run.ORACLE_SOURCES),
            "-pthread", "-o", str(c_binary),
        ]
        c_build = run.command_record(c_command, cwd=source, timeout_seconds=900)
        if c_build["status"] == 0:
            c_header = run.command_record([run.require_tool("readelf"), "-h", str(c_binary)], cwd=source)
            c_elf = run.parse_elf_identity(c_header["stdout"], "x86_64") if c_header["status"] == 0 else None
            c_execution = run.command_record([str(c_binary)], cwd=source, timeout_seconds=30)
        else:
            c_header = None
            c_elf = None
            c_execution = {"status": -1, "stdout": "", "stderr": "C build failed"}

        rust_command = [
            run.require_tool("cargo"), "test", "--locked", "--target",
            "x86_64-unknown-linux-musl", "--target-dir",
            str(run.WORK_ROOT / "target/compat/allocator/x86_64/m5-remote-collect-race"),
            "-p", "crabc-mimalloc", "--lib", "--no-default-features", RUST_TEST,
            "--", "--exact", "--nocapture", "--test-threads=1",
        ]
        environment = os.environ.copy()
        environment["CARGO_INCREMENTAL"] = "0"
        rust_execution = run.command_record(rust_command, cwd=ROOT, env=environment, timeout_seconds=1800)
        loom_command = [
            run.require_tool("cargo"), "test", "--locked", "--target",
            "x86_64-unknown-linux-musl", "--target-dir",
            str(run.WORK_ROOT / "target/compat/allocator/x86_64/m5-remote-collect-race-loom"),
            "-p", "crabc-mimalloc", "--lib", "--features", "loom", LOOM_TEST,
            "--", "--exact", "--test-threads=1",
        ]
        loom_environment = environment.copy()
        loom_environment["CARGO_ENCODED_RUSTFLAGS"] = ""
        loom_execution = run.command_record(
            loom_command, cwd=ROOT, env=loom_environment, timeout_seconds=1800,
        )
        comparison = None
        reason = None
        try:
            c_trace = trace(c_execution, "pinned C")
            rust_trace = trace(rust_execution, "native Rust")
            if c_trace != rust_trace:
                raise EvidenceError("pinned C and native Rust traces differ")
            if loom_execution["status"] != 0 or run.parse_rust_test_count(
                loom_execution["stdout"] + "\n" + loom_execution["stderr"]
            ) != 1:
                raise EvidenceError("the selected Loom race failed")
            comparison = c_trace
        except (EvidenceError, run.HarnessError) as error:
            reason = str(error)
        report = {
            "kind": "pinned-c-native-rust-m5-remote-collect-race",
            "status": "matched" if reason is None else "diverged", "reason": reason,
            "target": target, "source": source_seal,
            "c": {"build": c_build, "header": c_header, "execution": c_execution, "elf": c_elf},
            "rust": {"execution": rust_execution},
            "loom": {"execution": loom_execution},
            "comparison": comparison,
        }
    run.write_json(path, report)
    path.chmod(0o644)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, default=REPORT)
    parser.add_argument("--read-report", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.read_report is None:
            run_evidence(arguments.report, arguments.offline)
        observed = read_report(arguments.read_report or arguments.report)
    except (EvidenceError, run.HarnessError, OSError) as error:
        print(f"M5 remote collection race: FAIL: {error}", file=sys.stderr)
        return 1
    print(f"M5 remote collection race: PASS ({len(observed)} C/Rust values)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
