#!/usr/bin/env python3
"""Build and reread the pinned-C/native bounded remote publication and owner collection trace."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

import run
from x86_64_regular_small_evidence import (
    EXPECTED_C_ELF, EXPECTED_COMPILE_DEFINITIONS, EXPECTED_UPSTREAM,
)

ROOT = Path(__file__).resolve().parents[2]
C_PROBE = ROOT / "compat/allocator/x86_64_m5_remote_owner_collect.c"
RUST_PROBE = ROOT / "compat/allocator/x86_64_m5_remote_owner_collect.rs"
REPORT = ROOT / "compat/reports/allocator/x86_64/m5-remote-owner-collect.json"
BEGIN = "CRABC_MI_M5_REMOTE_OWNER_COLLECT_BEGIN"
END = "CRABC_MI_M5_REMOTE_OWNER_COLLECT_END"
RUST_PACKAGE = "m5-remote-owner-collect-fixture"
RUST_PROTOCOL_TEST = "remote_free::tests::x86_64_m5_remote_owner_collect_preserves_pending_and_collected_membership"
PROTOCOL_BEGIN = "CRABC_MI_M5_REMOTE_OWNER_COLLECT_PROTOCOL_BEGIN"
PROTOCOL_END = "CRABC_MI_M5_REMOTE_OWNER_COLLECT_PROTOCOL_END"
RUST_MANIFEST = (
    '[package]\nname = "' + RUST_PACKAGE + '"\nversion = "0.0.0"\nedition = "2021"\n'
    '[workspace]\n[dependencies]\n'
    f'crabc-mimalloc = {{ path = "{ROOT / "crabc-mimalloc"}", default-features = false, '
    'features = ["native-runtime-test-audit"] }\n'
    '[[bin]]\nname = "' + RUST_PACKAGE + '"\n'
    f'path = "{RUST_PROBE}"\n'
)
PROTOCOL_EXPECTED = {
    "owned_before": 1,
    "pending_count": 3,
    "pending_chain_valid": 1,
    "owned_empty_after": 1,
    "collected_count": 3,
    "collected_chain_valid": 1,
}
EXPECTED_RUST = {
    "producer_count": 3,
    "request": 65536,
    "used_before": 4,
    "mapped_before": 1,
    "used_after": 1,
    "mapped_after": 1,
    "released": 1,
    "still_released": 1,
}
EXPECTED_C = {**EXPECTED_RUST, **PROTOCOL_EXPECTED}


class EvidenceError(RuntimeError):
    """The source-built execution or physical receipt missed its contract."""


def parsed_trace(record: dict, side: str) -> dict[str, int]:
    if record.get("status") != 0 or not isinstance(record.get("stdout"), str):
        raise EvidenceError(f"{side} execution did not complete")
    try:
        return run.parse_address_independent_trace(
            record["stdout"], begin=BEGIN, end=END, description=side,
        )
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def compare(c_trace: dict[str, int], rust_trace: dict[str, int]) -> dict:
    if c_trace != EXPECTED_C:
        raise EvidenceError(f"pinned C source trace differs: {c_trace}")
    if rust_trace != EXPECTED_RUST:
        raise EvidenceError(f"native Rust trace differs: {rust_trace}")
    common = {key: c_trace[key] for key in EXPECTED_RUST}
    if common != rust_trace:
        raise EvidenceError("pinned C and native Rust common observations differ")
    return {"status": "matched", "shared_values": len(common),
            "protocol_values": len(PROTOCOL_EXPECTED), "common": common,
            "protocol": PROTOCOL_EXPECTED}


def protocol_trace(record: dict) -> dict[str, int]:
    if record["status"] != 0:
        raise EvidenceError("the Rust source protocol test failed")
    output = record["stdout"] + "\n" + record["stderr"]
    if run.parse_rust_test_count(output) != 1:
        raise EvidenceError("the selected Rust protocol test did not pass exactly once")
    return run.parse_address_independent_trace(
        output, begin=PROTOCOL_BEGIN, end=PROTOCOL_END,
        description="Rust raw protocol receipt",
    )


def read_report(path: Path) -> dict:
    try:
        report = json.loads(path.read_text())
        if report["kind"] != "pinned-c-native-rust-m5-remote-owner-collect":
            raise EvidenceError("wrong source-built report kind")
        if report["status"] != "matched":
            raise EvidenceError("source-built report is red")
        pin = run.load_pin()
        if report["source"] != {
            "revision": pin["revision"], "archive_sha256": pin["sha256"],
            "c_probe_sha256": run.sha256_file(C_PROBE),
            "rust_probe_sha256": run.sha256_file(RUST_PROBE),
            "rust_protocol_source_sha256": run.sha256_file(ROOT / "crabc-mimalloc/src/remote_free.rs"),
            "lockfile_sha256": run.sha256_file(ROOT / "Cargo.lock"),
        }:
            raise EvidenceError("source or selected fixture seal differs")
        if report["c"]["elf"] != EXPECTED_C_ELF or report["rust"]["elf"] != EXPECTED_C_ELF:
            raise EvidenceError("C or Rust product lacks native x86-64 ELF identity")
        for side in ("c", "rust"):
            build = report[side]["build"]
            execution = report[side]["execution"]
            if build["status"] != 0 or execution["status"] != 0:
                raise EvidenceError(f"{side} build or execution failed")
            if execution["stderr"]:
                raise EvidenceError(f"{side} runtime emitted a source warning or error")
        if str(C_PROBE) not in report["c"]["build"]["command"]:
            raise EvidenceError("pinned C build did not name its selected fixture")
        if (report["rust"]["manifest"] != RUST_MANIFEST
                or "--manifest-path" not in report["rust"]["build"]["command"]):
            raise EvidenceError("native Rust build did not name its selected fixture")
        c_trace = parsed_trace(report["c"]["execution"], "C raw receipt")
        rust_trace = parsed_trace(report["rust"]["execution"], "Rust raw receipt")
        comparison = compare(c_trace, rust_trace)
        protocol = protocol_trace(report["rust_protocol"]["execution"])
        if protocol != {key: c_trace[key] for key in protocol}:
            raise EvidenceError("Rust and pinned C ownership/list transitions differ")
        if (report["c"]["trace"] != c_trace or report["rust"]["trace"] != rust_trace
                or report["rust_protocol"]["trace"] != protocol
                or report["comparison"] != comparison):
            raise EvidenceError("stored comparison differs from raw executions")
        return comparison
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError, run.HarnessError) as error:
        raise EvidenceError(f"cannot physically read remote owner collection receipt: {error}") from error


def run_evidence(report_path: Path, offline: bool) -> dict:
    provenance = run.require_native_x86_64()
    pin = run.load_pin()
    if pin["revision"] != EXPECTED_UPSTREAM["revision"]:
        raise EvidenceError("pinned C revision differs")
    archive = run.fetch_archive(pin, offline)
    source_seal = {
        "revision": pin["revision"], "archive_sha256": run.sha256_file(archive),
        "c_probe_sha256": run.sha256_file(C_PROBE),
        "rust_probe_sha256": run.sha256_file(RUST_PROBE),
        "rust_protocol_source_sha256": run.sha256_file(ROOT / "crabc-mimalloc/src/remote_free.rs"),
        "lockfile_sha256": run.sha256_file(ROOT / "Cargo.lock"),
    }
    with run.temporary_directory("m5-remote-owner-collect-") as directory:
        temporary = Path(directory)
        source = run.safe_extract(archive, temporary / "source", pin["archive_root"])
        c_binary = temporary / "source-oracle"
        c_command = [run.require_tool("musl-gcc"), "-std=c11", "-fPIC",
            "-ftls-model=initial-exec", *EXPECTED_COMPILE_DEFINITIONS,
            "-I", str(source / "include"), "-I", str(source / "src"),
            *run.CONFIGURATION_PROFILES["release"], str(C_PROBE),
            *(str(source / member) for member in run.ORACLE_SOURCES),
            "-pthread", "-o", str(c_binary)]
        c_build = run.command_record(c_command, cwd=source, timeout_seconds=900)
        c_run = run.command_record([str(c_binary)], cwd=source) if c_build["status"] == 0 else {
            "command": [str(c_binary)], "status": -1, "stdout": "", "stderr": "C build failed",
        }
        c_elf = None
        if c_build["status"] == 0:
            c_header = run.command_record([run.require_tool("readelf"), "-h", str(c_binary)], cwd=source)
            run.require_success(c_header, "pinned C ELF header")
            c_elf = run.parse_elf_identity(c_header["stdout"], "x86_64")

        package = temporary / "rust-fixture"
        package.mkdir()
        (package / "Cargo.toml").write_text(RUST_MANIFEST)
        shutil.copyfile(ROOT / "Cargo.lock", package / "Cargo.lock")
        rust_target = run.WORK_ROOT / "target/compat/allocator/x86_64/m5-remote-owner-collect/cargo-target"
        rust_command = [run.require_tool("cargo"), "build", "--offline", "--manifest-path",
            str(package / "Cargo.toml"), "--target", "x86_64-unknown-linux-musl",
            "--target-dir", str(rust_target)]
        env = os.environ.copy()
        env["CARGO_INCREMENTAL"] = "0"
        env["CARGO_HOME"] = str(ROOT / ".work/x86_64/cargo")
        rust_build = run.command_record(rust_command, cwd=ROOT, env=env, timeout_seconds=1800)
        rust_binary = rust_target / "x86_64-unknown-linux-musl/debug" / RUST_PACKAGE
        rust_run = run.command_record([str(rust_binary)], cwd=ROOT) if rust_build["status"] == 0 else {
            "command": [str(rust_binary)], "status": -1, "stdout": "", "stderr": "Rust build failed",
        }
        rust_elf = None
        if rust_build["status"] == 0:
            rust_header = run.command_record([run.require_tool("readelf"), "-h", str(rust_binary)], cwd=ROOT)
            run.require_success(rust_header, "native Rust ELF header")
            rust_elf = run.parse_elf_identity(rust_header["stdout"], "x86_64")
        protocol_command = [run.require_tool("cargo"), "test", "--locked", "--offline",
            "--target", "x86_64-unknown-linux-musl", "--target-dir",
            str(run.WORK_ROOT / "target/compat/allocator/x86_64/m5-remote-owner-collect/protocol-target"),
            "-p", "crabc-mimalloc", "--lib", "--no-default-features", RUST_PROTOCOL_TEST,
            "--", "--exact", "--nocapture", "--test-threads=1"]
        protocol_run = run.command_record(protocol_command, cwd=ROOT, env=env, timeout_seconds=1800)
        c_trace = parsed_trace(c_run, "C") if c_run["status"] == 0 else None
        rust_trace = parsed_trace(rust_run, "Rust") if rust_run["status"] == 0 else None
        try:
            protocol = protocol_trace(protocol_run)
        except (EvidenceError, run.HarnessError):
            protocol = None
        try:
            if c_trace is None or rust_trace is None or protocol is None or c_run["stderr"] or rust_run["stderr"]:
                raise EvidenceError("a source build, execution, or runtime warning failed")
            comparison = compare(c_trace, rust_trace)
            if protocol != {key: c_trace[key] for key in protocol}:
                raise EvidenceError("Rust and pinned C ownership/list transitions differ")
        except EvidenceError as error:
            comparison = {"status": "diverged", "reason": str(error)}
        report = {
            "kind": "pinned-c-native-rust-m5-remote-owner-collect",
            "status": comparison["status"], "target": provenance, "source": source_seal,
            "c": {"build": c_build, "execution": c_run, "elf": c_elf, "trace": c_trace},
            "rust": {"build": rust_build, "execution": rust_run, "elf": rust_elf,
                     "trace": rust_trace, "manifest": RUST_MANIFEST},
            "rust_protocol": {"execution": protocol_run, "trace": protocol},
            "comparison": comparison,
        }
    run.write_json(report_path, report)
    report_path.chmod(0o644)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, default=REPORT)
    parser.add_argument("--read-report", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.read_report is not None:
            comparison = read_report(arguments.read_report)
        else:
            report = run_evidence(arguments.report, arguments.offline)
            if report["status"] != "matched":
                raise EvidenceError(f"{report['comparison']['reason']}; raw report {arguments.report}")
            comparison = read_report(arguments.report)
    except (EvidenceError, run.HarnessError, OSError) as error:
        print(f"remote owner collection differential: FAIL: {error}", file=sys.stderr)
        return 1
    print(f"remote owner collection differential: PASS ({comparison['shared_values']} runtime values, "
          f"{comparison['protocol_values']} C/Rust protocol values)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
