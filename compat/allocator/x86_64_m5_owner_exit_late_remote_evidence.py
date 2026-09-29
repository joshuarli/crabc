#!/usr/bin/env python3
"""Build and reread the pinned-C/native two-publisher owner-exit trace."""

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
C_PROBE = ROOT / "compat/allocator/x86_64_m5_owner_exit_late_remote.c"
RUST_PROBE = ROOT / "compat/allocator/x86_64_m5_owner_exit_late_remote.rs"
REPORT = ROOT / "compat/reports/allocator/x86_64/m5-owner-exit-late-remote.json"
BEGIN = "CRABC_MI_M5_OWNER_EXIT_LATE_REMOTE_BEGIN"
END = "CRABC_MI_M5_OWNER_EXIT_LATE_REMOTE_END"
RUST_PACKAGE = "m5-owner-exit-late-remote-fixture"
RUST_MANIFEST = (
    '[package]\nname = "' + RUST_PACKAGE + '"\nversion = "0.0.0"\nedition = "2021"\n'
    '[workspace]\n[dependencies]\n'
    f'crabc-mimalloc = {{ path = "{ROOT / "crabc-mimalloc"}", default-features = false, '
    'features = ["native-runtime-test-audit"] }\n'
    '[[bin]]\nname = "' + RUST_PACKAGE + '"\n'
    f'path = "{RUST_PROBE}"\n'
)
C_ONLY = {
    "used_before_exit": 3,
    "first_head_nonempty": 1,
    "used_after_exit": 2,
    "abandoned_after_exit": 1,
    "unowned_after_exit": 1,
}
EXPECTED_RUST = {
    "full_retain_negative_one": 1,
    "reclaim_on_free": 1,
    "request": 65536,
    "capacity": 6,
    "setup_valid": 1,
    "first_usable": 81920,
    "first_registered": 1,
    "registered_after_exit": 1,
    "second_usable": 81920,
    "registered_after_second": 1,
    "used_after_second": 1,
    "reclaimed_after_second": 1,
    "registered_before_collect": 1,
    "used_before_collect": 0,
    "retire_expire": 4,
    "released_after_collect": 1,
    "still_released": 1,
    "survivor_usable": 1,
}
EXPECTED_C = {**EXPECTED_RUST, **C_ONLY}


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
            "c_only_values": len(C_ONLY), "common": common, "c_only": C_ONLY}


def read_report(path: Path) -> dict:
    try:
        report = json.loads(path.read_text())
        if report["kind"] != "pinned-c-native-rust-m5-owner-exit-late-remote":
            raise EvidenceError("wrong source-built report kind")
        if report["status"] != "matched":
            raise EvidenceError("source-built report is red")
        pin = run.load_pin()
        if report["source"] != {
            "revision": pin["revision"], "archive_sha256": pin["sha256"],
            "c_probe_sha256": run.sha256_file(C_PROBE),
            "rust_probe_sha256": run.sha256_file(RUST_PROBE),
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
        if (report["c"]["trace"] != c_trace or report["rust"]["trace"] != rust_trace
                or report["comparison"] != comparison):
            raise EvidenceError("stored comparison differs from raw executions")
        return comparison
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError, run.HarnessError) as error:
        raise EvidenceError(f"cannot physically read owner-exit receipt: {error}") from error


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
        "lockfile_sha256": run.sha256_file(ROOT / "Cargo.lock"),
    }
    with run.temporary_directory("m5-owner-exit-late-remote-") as directory:
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
        rust_target = run.WORK_ROOT / "target/compat/allocator/x86_64/m5-owner-exit-late-remote/cargo-target"
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
        c_trace = parsed_trace(c_run, "C") if c_run["status"] == 0 else None
        rust_trace = parsed_trace(rust_run, "Rust") if rust_run["status"] == 0 else None
        try:
            if c_trace is None or rust_trace is None or c_run["stderr"] or rust_run["stderr"]:
                raise EvidenceError("a source build, execution, or runtime warning failed")
            comparison = compare(c_trace, rust_trace)
        except EvidenceError as error:
            comparison = {"status": "diverged", "reason": str(error)}
        report = {
            "kind": "pinned-c-native-rust-m5-owner-exit-late-remote",
            "status": comparison["status"], "target": provenance, "source": source_seal,
            "c": {"build": c_build, "execution": c_run, "elf": c_elf, "trace": c_trace},
            "rust": {"build": rust_build, "execution": rust_run, "elf": rust_elf,
                     "trace": rust_trace, "manifest": RUST_MANIFEST},
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
        print(f"owner-exit late-remote differential: FAIL: {error}", file=sys.stderr)
        return 1
    print(f"owner-exit late-remote differential: PASS ({comparison['shared_values']} matched values, "
          f"{comparison['c_only_values']} pinned-C internal observations)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
