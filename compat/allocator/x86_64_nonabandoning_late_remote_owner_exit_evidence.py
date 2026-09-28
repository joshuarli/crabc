#!/usr/bin/env python3
"""Compare pinned C and native Rust late remote owner exit on x86-64."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "compat/allocator/x86_64_nonabandoning_late_remote_owner_exit.c"
RUST_SOURCE = ROOT / "crabc-mimalloc/src/runtime_lifecycle.rs"
REPORT = ROOT / "compat/reports/allocator/x86_64/nonabandoning-late-remote-owner-exit.json"
BASE = ROOT / "compat/allocator/x86_64_regular_small_evidence.py"
spec = importlib.util.spec_from_file_location("regular_small_base", BASE)
assert spec is not None and spec.loader is not None
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
run = base.run

TRACE_BEGIN = "CRABC_MI_LATE_REMOTE_OWNER_EXIT_BEGIN"
TRACE_END = "CRABC_MI_LATE_REMOTE_OWNER_EXIT_END"
RUST_FILTER = (
    "runtime_lifecycle::tests::"
    "native_owner_exit_active_survivor_reclaims_late_remote_full_medium"
)
EXPECTED_TRACE = {
    "full_retain": -1,
    "medium_capacity": 6,
    "medium_full_before_exit": 1,
    "medium_registered_after_exit": 1,
    "medium_used_after_exit": 6,
    "medium_abandoned_after_exit": 1,
    "medium_unowned_after_exit": 1,
    "medium_queue_detached_after_exit": 1,
    "singleton_registered_after_exit": 1,
    "medium_reclaimed_after_late_free": 1,
    "medium_used_after_late_free": 5,
    "singleton_released": 1,
    "medium_retired_used": 0,
    "medium_retired_expire": 4,
    "medium_registered_before_collect": 1,
    "medium_released_after_collect": 1,
    "survivor_usable": 1,
}
SOURCE_ANCHORS = (
    ("src/free.c", 44, 56, "de6d94667e1d6b127947a347660b35b4eaf1480751da492154de4a1e48f43e13"),
    ("src/free.c", 63, 95, "657217f8cfaae0c13e78e2aaaeaae1563134d895019367ff457ca9d6b2bd885a"),
    ("src/free.c", 428, 478, "f54217a78fa99275146f84371befd7fa8c57301a4b3403d6ec68ed93e4c0e778"),
    ("src/free.c", 480, 512, "f4e336858be00bf3a186ea6e4ce0e4df0856bc8f4092005b1b79b9bc6d80852f"),
    ("src/page.c", 424, 457, "70a97877d51e5ca85aee8e74e61e293ebddd7676e214035abb83f5a30608078c"),
    ("src/page.c", 291, 306, "0c6988279400c93848945d1b35f204622bd6a6f35ff0dc8a5171c33614f6d5cc"),
    ("src/page.c", 460, 518, "9e0c373ed5a817f9e9998319442aaf7b5870509e4821a57686179b54ff6428af"),
    ("src/theap.c", 123, 165, "a84d17ad1b74eb93e79bb3b756f099fd60fe611eda6279c17db283c44cccc1bb"),
    ("src/theap.c", 228, 232, "16c0e73a20b9a94bf994c4e83836c976f5683e3c6e8b18935782a934405adba0"),
)


class EvidenceError(RuntimeError):
    """The bounded source comparison did not establish its trace contract."""


def render_trace(trace: dict[str, int]) -> str:
    return "\n".join((TRACE_BEGIN, *(f"{key}={value}" for key, value in trace.items()), TRACE_END))


def parse_trace(output: str, description: str) -> dict[str, int]:
    if output.count(TRACE_BEGIN) != 1 or output.count(TRACE_END) != 1:
        raise EvidenceError(f"{description} trace markers are missing or duplicated")
    body = output.split(TRACE_BEGIN, 1)[1].split(TRACE_END, 1)[0]
    trace = {}
    for line in body.strip().splitlines():
        if line.count("=") != 1:
            raise EvidenceError(f"{description} trace has an unparseable line")
        key, value = line.split("=", 1)
        if key in trace:
            raise EvidenceError(f"{description} trace has duplicate {key}")
        if not key.replace("_", "").isalnum() or not value.lstrip("-").isdigit():
            raise EvidenceError(f"{description} trace has a noninteger or address value")
        trace[key] = int(value)
    missing = set(EXPECTED_TRACE) - set(trace)
    unexpected = set(trace) - set(EXPECTED_TRACE)
    if missing or unexpected:
        raise EvidenceError(f"{description} trace missing {sorted(missing)}; unexpected {sorted(unexpected)}")
    return trace


def compare_traces(c_trace: dict[str, int], rust_trace: dict[str, int]) -> dict[str, int]:
    for description, trace in (("C", c_trace), ("Rust", rust_trace)):
        if set(trace) != set(EXPECTED_TRACE):
            raise EvidenceError(f"{description} trace missing or unexpected keys")
        for key, expected in EXPECTED_TRACE.items():
            if type(trace[key]) is not int or trace[key] != expected:
                raise EvidenceError(f"{description} {key}: expected {expected}, observed {trace[key]}")
    if c_trace != rust_trace:
        raise EvidenceError("C and Rust owner-exit traces differ")
    return c_trace


def checked_command(command: list[str], *, cwd: Path, description: str, env=None) -> dict:
    record = run.command_record(command, cwd=cwd, env=env)
    try:
        run.require_success(record, description)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    return record


def run_evidence(report_path: Path, *, offline: bool) -> dict:
    provenance = run.require_native_x86_64()
    pin = run.load_pin()
    if pin["sha256"] != base.EXPECTED_ARCHIVE_SHA256 or pin["revision"] != base.EXPECTED_UPSTREAM["revision"]:
        raise EvidenceError("pinned mimalloc source identity drifted")
    archive = run.fetch_archive(pin, offline)
    before_lock = base.sha256_file(ROOT / "Cargo.lock")
    with run.temporary_directory("late-remote-owner-exit-") as name:
        temporary = Path(name)
        source = run.safe_extract(archive, temporary / "source", pin["archive_root"])
        anchors = []
        for member, first, last, expected in SOURCE_ANCHORS:
            digest = base.sha256_bytes(base.source_range((source / member).read_bytes(), first, last))
            if digest != expected:
                raise EvidenceError(f"pinned source branch drifted: {member}:{first}-{last}")
            anchors.append({"member": member, "first": first, "last": last, "sha256": digest})
        compiler = run.require_tool("musl-gcc")
        cargo = run.require_tool("cargo")
        c_binary = temporary / "late-remote-owner-exit-c"
        c_command = [compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            *base.EXPECTED_COMPILE_DEFINITIONS, "-I", str(source / "include"),
            "-I", str(source / "src"), *run.CONFIGURATION_PROFILES["release"],
            str(PROBE), *(str(source / member) for member in run.ORACLE_SOURCES),
            "-pthread", "-o", str(c_binary)]
        c_build = checked_command(c_command, cwd=source, description="pinned C late-remote owner-exit build")
        elf_record = checked_command([run.require_tool("readelf"), "-h", str(c_binary)],
            cwd=source, description="pinned C ELF identity")
        elf = run.parse_elf_identity(str(elf_record["stdout"]), "x86_64")
        if elf != base.EXPECTED_C_ELF:
            raise EvidenceError("pinned C product is not the native x86-64 ELF")
        c_run = checked_command([str(c_binary)], cwd=source, description="pinned C late-remote owner-exit execution")
        c_trace = parse_trace(str(c_run["stdout"]), "C")
        rust_target = run.WORK_ROOT / "target"
        rust_command = [cargo, "test", "--locked", "--target", base.TARGET,
            "--target-dir", str(rust_target), "-p", "crabc-mimalloc",
            "--lib", "--no-default-features", RUST_FILTER,
            "--", "--exact", "--nocapture", "--test-threads=1"]
        env = os.environ.copy()
        env["CARGO_INCREMENTAL"] = "0"
        rust_run = checked_command(rust_command, cwd=ROOT, env=env,
            description="native Rust late-remote owner-exit execution")
        if run.parse_rust_test_count(str(rust_run["stdout"]) + "\n" + str(rust_run["stderr"])) != 1:
            raise EvidenceError("native Rust fixture did not run exactly once")
        rust_trace = parse_trace(str(rust_run["stdout"]) + "\n" + str(rust_run["stderr"]), "Rust")
        try:
            trace = compare_traces(c_trace, rust_trace)
            comparison = {"status": "matched", "values": len(trace), "trace": trace}
        except EvidenceError as error:
            comparison = {"status": "diverged", "reason": str(error),
                "values": len(set(c_trace) & set(rust_trace))}
        report = {
            "kind": "pinned-c-native-rust-nonabandoning-late-remote-owner-exit",
            "status": comparison["status"], "target": provenance,
            "source": {"archive_sha256": base.sha256_file(archive), "revision": pin["revision"],
                "anchors": anchors},
            "probe": {"path": base.relative(PROBE), "sha256": base.sha256_file(PROBE),
                "rust_source": base.relative(RUST_SOURCE), "rust_sha256": base.sha256_file(RUST_SOURCE),
                "lockfile_sha256": before_lock},
            "c": {"build_command": base.normalize_command(c_command, temporary, source),
                "build": c_build, "elf": elf, "execution": c_run, "trace": c_trace},
            "rust": {"command": base.normalize_command(rust_command, temporary, None),
                "execution": rust_run, "trace": rust_trace},
            "comparison": comparison,
        }
    if base.sha256_file(ROOT / "Cargo.lock") != before_lock:
        raise EvidenceError("Cargo.lock changed during locked Rust execution")
    run.write_json(report_path, report)
    report_path.chmod(0o644)
    return report


def validate_report(report: dict) -> dict[str, int]:
    """Reread source identity and both raw executions after build cleanup."""
    try:
        if report["kind"] != "pinned-c-native-rust-nonabandoning-late-remote-owner-exit":
            raise EvidenceError("late-remote report kind differs")
        if report["status"] != "matched":
            raise EvidenceError("late-remote report did not match")
        source = report["source"]
        pin = run.load_pin()
        if source["archive_sha256"] != base.EXPECTED_ARCHIVE_SHA256 or source["revision"] != pin["revision"]:
            raise EvidenceError("late-remote source archive identity differs")
        expected_anchors = [
            {"member": member, "first": first, "last": last, "sha256": digest}
            for member, first, last, digest in SOURCE_ANCHORS
        ]
        if source["anchors"] != expected_anchors:
            raise EvidenceError("late-remote source branch anchors differ")
        probe = report["probe"]
        if probe != {
            "path": base.relative(PROBE), "sha256": base.sha256_file(PROBE),
            "rust_source": base.relative(RUST_SOURCE), "rust_sha256": base.sha256_file(RUST_SOURCE),
            "lockfile_sha256": base.sha256_file(ROOT / "Cargo.lock"),
        }:
            raise EvidenceError("late-remote selected source seal differs")
        c = report["c"]
        rust = report["rust"]
        if c["elf"] != base.EXPECTED_C_ELF:
            raise EvidenceError("late-remote C ELF identity differs")
        if (not any(part.endswith("/" + base.relative(PROBE)) for part in c["build_command"])
                or RUST_FILTER not in rust["command"]):
            raise EvidenceError("late-remote selected commands differ")
        for name, record in (("C build", c["build"]), ("C execution", c["execution"]),
                             ("Rust execution", rust["execution"])):
            if record["status"] != 0 or not isinstance(record["stdout"], str) or not isinstance(record["stderr"], str):
                raise EvidenceError(f"late-remote {name} failed or lacks raw output")
        if c["execution"]["stderr"]:
            raise EvidenceError("late-remote C execution wrote stderr")
        if run.parse_rust_test_count(rust["execution"]["stdout"] + "\n" + rust["execution"]["stderr"]) != 1:
            raise EvidenceError("late-remote Rust test count differs")
        c_trace = parse_trace(c["execution"]["stdout"], "C raw report")
        rust_trace = parse_trace(rust["execution"]["stdout"] + "\n" + rust["execution"]["stderr"], "Rust raw report")
        trace = compare_traces(c_trace, rust_trace)
        if c["trace"] != trace or rust["trace"] != trace or report["comparison"] != {
            "status": "matched", "values": len(trace), "trace": trace,
        }:
            raise EvidenceError("late-remote stored trace differs from raw execution")
        return trace
    except (KeyError, TypeError, ValueError, run.HarnessError) as error:
        raise EvidenceError(f"malformed late-remote report: {error}") from error


def read_report(path: Path) -> dict[str, int]:
    try:
        return validate_report(json.loads(path.read_text()))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read late-remote report: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, default=REPORT)
    parser.add_argument("--read-report", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.read_report is not None:
            trace = read_report(arguments.read_report)
            print(f"late-remote owner-exit receipt: PASS ({len(trace)} source-bound values)")
            return 0
        report = run_evidence(arguments.report, offline=arguments.offline)
        if report["status"] == "matched":
            read_report(arguments.report)
    except (EvidenceError, run.HarnessError, OSError) as error:
        print(f"late-remote owner-exit differential: FAIL: {error}", file=sys.stderr)
        return 1
    if report["status"] != "matched":
        print(f"late-remote owner-exit differential: FAIL: {report['comparison']['reason']}; "
              f"raw report {arguments.report}", file=sys.stderr)
        return 1
    print(f"late-remote owner-exit differential: PASS ({report['comparison']['values']} source-bound values)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
