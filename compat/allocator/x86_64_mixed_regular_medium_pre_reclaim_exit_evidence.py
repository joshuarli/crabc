#!/usr/bin/env python3
"""Compare pinned C and native Rust mixed regular-medium owner exit."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "compat/allocator/x86_64_mixed_regular_medium_pre_reclaim_exit.c"
RUST_SOURCE = ROOT / "crabc-mimalloc/tests/native_mixed_regular_medium_pre_reclaim_exit.rs"
REPORT = ROOT / "compat/reports/allocator/x86_64/mixed-regular-medium-pre-reclaim-exit.json"
BASE = ROOT / "compat/allocator/x86_64_regular_small_evidence.py"
spec = importlib.util.spec_from_file_location("regular_small_base", BASE)
assert spec is not None and spec.loader is not None
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
run = base.run

TRACE_BEGIN = "CRABC_MI_MIXED_MEDIUM_PRE_RECLAIM_BEGIN"
TRACE_END = "CRABC_MI_MIXED_MEDIUM_PRE_RECLAIM_END"
RUST_FILTER = "mixed_regular_medium_pages_reclaim_independently_after_pre_reclaim_remote_frees"
RUST_TEST = "native_mixed_regular_medium_pre_reclaim_exit"
EXPECTED = {
    "request": 49152,
    "block_size": 57344,
    "arena_map_count": 8,
    "os_map_count": 8,
    "arena_slice_count": 8,
    "os_mapping_size": 589824,
    "setup_valid": 1,
    "remote_queue_ready": 1,
    "exit_arena_abandoned": 1,
    "exit_os_abandoned": 1,
    "exit_os_list": 1,
    "exit_arena_bitmap": 0,
    "first_remote_class": 1,
    "arena_reclaimed": 1,
    "arena_reused": 1,
    "arena_map_after_reclaim": 1,
    "os_list_while_arena_reclaimed": 1,
    "os_reclaimed": 1,
    "os_reused": 1,
    "os_map_after_reclaim": 1,
    "os_list_after_reclaim_empty": 1,
    "reexit_arena_bitmap": 1,
    "reexit_os_list": 1,
    "reexit_both_mapped": 1,
    "final_arena_freed": 1,
    "arena_map_clear": 1,
    "os_map_retained": 1,
    "arena_bitmap_final_clear": 1,
    "arena_free_after_final": 8,
    "arena_committed_after_final": 8,
    "arena_purge_after_final": 8,
    "arena_reserved_drop": 0,
    "arena_committed_drop": 0,
    "final_os_freed": 1,
    "os_map_clear": 1,
    "os_list_final_empty": 1,
    "os_reserved_drop": 589824,
    "os_committed_drop": 524288,
    "arena_purge_after_collect": 0,
    "warning_enabled": 0,
}
SOURCE_ANCHORS = (
    ("src/options.c", 302, 316, "76a7223e1d448ddaba2746d524324c7362a1d179454f0e11b77e8bfa490b6efd"),
    ("src/arena.c", 781, 855, "5dfcb6e1533dad8aa3f4305b8bc65c922163d87d3f918fa9594c888b5588a020"),
    ("src/arena.c", 1304, 1428, "337af803bb9ea1b51c6dcfffa8c23421b2aea2e28dbf34f22a7f796971b82764"),
    ("src/arena.c", 1433, 1484, "f9c9e17f05fea72042b4fefa7554f1e5e27b1966b1adb7ae4617e75f45f51c5a"),
    ("src/free.c", 428, 512, "94e598b118523533357088427b68ca7e1bdbb6e2002495185e1d872d73f066d8"),
    ("src/page-map.c", 201, 211, "51aabad4c8f7392826dbe889d5e2502b0ecf68f43dd28856c6d96753e9aa7f25"),
)
SOURCE_PATHS = {
    "runtime": ROOT / "crabc-mimalloc/src/runtime_lifecycle.rs",
    "single_thread": ROOT / "crabc-mimalloc/src/single_thread.rs",
    "abandoned": ROOT / "crabc-mimalloc/src/abandoned.rs",
    "lib": ROOT / "crabc-mimalloc/src/lib.rs",
    "page_map": ROOT / "crabc-mimalloc/src/page_map.rs",
    "arena": ROOT / "crabc-mimalloc/src/arena.rs",
    "process_arena": ROOT / "crabc-mimalloc/src/process_arena.rs",
    "os": ROOT / "crabc-mimalloc/src/os.rs",
    "options": ROOT / "crabc-mimalloc/src/source_options_api.rs",
    "diagnostic_output": ROOT / "crabc-mimalloc/src/diagnostic_output.rs",
    "statistics": ROOT / "crabc-mimalloc/src/statistics.rs",
    "config": ROOT / "crabc-mimalloc/src/config.rs",
    "support": ROOT / "crabc-mimalloc/tests/support/native_runtime.rs",
}


class EvidenceError(RuntimeError):
    """The source-bound mixed owner-exit trace did not establish its contract."""


def render_trace(trace: dict[str, int]) -> str:
    return "\n".join((TRACE_BEGIN, *(f"{key}={value}" for key, value in trace.items()), TRACE_END))


def parse_trace(output: str, description: str) -> dict[str, int]:
    if output.count(TRACE_BEGIN) != 1 or output.count(TRACE_END) != 1:
        raise EvidenceError(f"{description} trace markers are missing or duplicated")
    body = output.split(TRACE_BEGIN, 1)[1].split(TRACE_END, 1)[0]
    trace = {}
    for line in body.strip().splitlines():
        found = re.fullmatch(r"([a-z][a-z_]+)=(-?[0-9]+)", line)
        if found is None or found[1] in trace:
            raise EvidenceError(f"{description} trace has malformed or duplicate values")
        trace[found[1]] = int(found[2])
    if set(trace) != set(EXPECTED):
        raise EvidenceError(f"{description} trace has missing or unexpected values")
    return trace


def compare_traces(c_trace: dict[str, int], rust_trace: dict[str, int]) -> dict[str, int]:
    for name, trace in (("C", c_trace), ("Rust", rust_trace)):
        if set(trace) != set(EXPECTED):
            raise EvidenceError(f"{name} trace is incomplete")
        for key, value in EXPECTED.items():
            if type(trace[key]) is not int or trace[key] != value:
                raise EvidenceError(f"{name} {key}: expected {value}, observed {trace[key]}")
    if c_trace != rust_trace:
        raise EvidenceError("C and Rust mixed owner-exit traces differ")
    return c_trace


def source_seal() -> dict[str, str]:
    paths = {"c": PROBE, "rust": RUST_SOURCE, **SOURCE_PATHS}
    seal = {f"{key}_path": base.relative(path) for key, path in paths.items()}
    seal.update({f"{key}_sha256": base.sha256_file(path) for key, path in paths.items()})
    seal["lockfile_sha256"] = base.sha256_file(ROOT / "Cargo.lock")
    return seal


def command(parts: list[str], *, cwd: Path, description: str) -> dict:
    record = run.command_record(parts, cwd=cwd)
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
    seal = source_seal()
    with run.temporary_directory("mixed-regular-medium-pre-reclaim-exit-") as name:
        temporary = Path(name)
        source = run.safe_extract(archive, temporary / "source", pin["archive_root"])
        anchors = []
        for member, first, last, expected in SOURCE_ANCHORS:
            digest = base.sha256_bytes(base.source_range((source / member).read_bytes(), first, last))
            if digest != expected:
                raise EvidenceError(f"pinned source branch drifted: {member}:{first}-{last}")
            anchors.append({"member": member, "first": first, "last": last, "sha256": digest})
        c_binary = temporary / "mixed-regular-medium-pre-reclaim-exit-c"
        c_command = [run.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            *base.EXPECTED_COMPILE_DEFINITIONS, "-I", str(source / "include"),
            "-I", str(source / "src"), *run.CONFIGURATION_PROFILES["release"],
            str(PROBE), *(str(source / member) for member in run.ORACLE_SOURCES),
            "-pthread", "-o", str(c_binary)]
        c_build = command(c_command, cwd=source, description="pinned C mixed-medium build")
        elf_record = command([run.require_tool("readelf"), "-h", str(c_binary)],
            cwd=source, description="pinned C ELF identity")
        elf = run.parse_elf_identity(str(elf_record["stdout"]), "x86_64")
        if elf != base.EXPECTED_C_ELF:
            raise EvidenceError("pinned C product is not native x86-64 ELF")
        c_run = command([str(c_binary)], cwd=source, description="pinned C mixed-medium execution")
        c_trace = parse_trace(str(c_run["stdout"]), "C")
        rust_command = [run.require_tool("cargo"), "test", "--offline", "--locked", "--target",
            base.TARGET, "--target-dir", str(run.WORK_ROOT / "target"), "-p", "crabc-mimalloc",
            "--test", RUST_TEST, "--no-default-features", "--features",
            "native-runtime-test-audit,native-runtime-test-fault",
            RUST_FILTER, "--", "--exact", "--nocapture", "--test-threads=1"]
        env = os.environ.copy()
        env["CARGO_INCREMENTAL"] = "0"
        rust_run = run.command_record(rust_command, cwd=ROOT, env=env)
        rust_output = str(rust_run["stdout"]) + "\n" + str(rust_run["stderr"])
        rust_trace = None
        if rust_run["status"] == 0 and run.parse_rust_test_count(rust_output) == 1:
            rust_trace = parse_trace(rust_output, "Rust")
            try:
                trace = compare_traces(c_trace, rust_trace)
                comparison = {"status": "matched", "values": len(trace), "trace": trace}
            except EvidenceError as error:
                comparison = {"status": "diverged", "reason": str(error)}
        else:
            comparison = {"status": "execution-failed", "reason": f"Rust status {rust_run['status']} or test count differed"}
        report = {
            "kind": "pinned-c-native-rust-mixed-regular-medium-pre-reclaim-exit",
            "status": comparison["status"], "target": provenance,
            "source": {"archive_sha256": base.sha256_file(archive), "revision": pin["revision"], "anchors": anchors},
            "probe": seal,
            "c": {"build_command": base.normalize_command(c_command, temporary, source),
                  "build": c_build, "elf": elf, "execution": c_run, "trace": c_trace},
            "rust": {"command": base.normalize_command(rust_command, temporary, None),
                     "execution": rust_run, "trace": rust_trace},
            "comparison": comparison,
        }
    if source_seal() != seal:
        raise EvidenceError("source changed during native differential")
    run.write_json(report_path, report)
    report_path.chmod(0o644)
    return report


def validate_report(report: dict) -> dict[str, int]:
    try:
        if report["kind"] != "pinned-c-native-rust-mixed-regular-medium-pre-reclaim-exit" or report["status"] != "matched":
            raise EvidenceError("mixed-medium report kind or status differs")
        source = report["source"]
        if source["archive_sha256"] != base.EXPECTED_ARCHIVE_SHA256 or source["revision"] != run.load_pin()["revision"]:
            raise EvidenceError("mixed-medium source archive differs")
        if source["anchors"] != [
            {"member": member, "first": first, "last": last, "sha256": digest}
            for member, first, last, digest in SOURCE_ANCHORS
        ]:
            raise EvidenceError("mixed-medium source anchors differ")
        if report["probe"] != source_seal():
            raise EvidenceError("mixed-medium source seal differs")
        c, rust = report["c"], report["rust"]
        if c["elf"] != base.EXPECTED_C_ELF:
            raise EvidenceError("mixed-medium C ELF identity differs")
        if (not any(part.endswith("/" + base.relative(PROBE)) for part in c["build_command"])
                or RUST_FILTER not in rust["command"]
                or rust["command"][rust["command"].index("--test") + 1] != RUST_TEST
                or "native-runtime-test-audit,native-runtime-test-fault" not in rust["command"]):
            raise EvidenceError("mixed-medium execution commands differ")
        for name, record in (("C build", c["build"]), ("C execution", c["execution"]),
                             ("Rust execution", rust["execution"])):
            if record["status"] != 0 or not isinstance(record["stdout"], str) or not isinstance(record["stderr"], str):
                raise EvidenceError(f"mixed-medium {name} failed or lacks raw output")
        if c["execution"]["stderr"] != "\n":
            raise EvidenceError("mixed-medium C loader-init stderr or warning differs")
        if "mimalloc: warning:" in rust["execution"]["stdout"] + rust["execution"]["stderr"]:
            raise EvidenceError("mixed-medium Rust allocator warning differs")
        if run.parse_rust_test_count(rust["execution"]["stdout"] + "\n" + rust["execution"]["stderr"]) != 1:
            raise EvidenceError("mixed-medium Rust test count differs")
        c_trace = parse_trace(c["execution"]["stdout"], "C raw report")
        rust_trace = parse_trace(rust["execution"]["stdout"] + "\n" + rust["execution"]["stderr"], "Rust raw report")
        trace = compare_traces(c_trace, rust_trace)
        if c["trace"] != trace or rust["trace"] != trace or report["comparison"] != {
            "status": "matched", "values": len(trace), "trace": trace,
        }:
            raise EvidenceError("mixed-medium stored trace differs from raw execution")
        return trace
    except (KeyError, TypeError, ValueError, run.HarnessError) as error:
        raise EvidenceError(f"malformed mixed-medium report: {error}") from error


def read_report(path: Path) -> dict[str, int]:
    try:
        return validate_report(json.loads(path.read_text()))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read mixed-medium report: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, default=REPORT)
    parser.add_argument("--read-report", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.read_report is not None:
            trace = read_report(arguments.read_report)
            print(f"mixed-medium owner-exit receipt: PASS ({len(trace)} source-bound values)")
            return 0
        report = run_evidence(arguments.report, offline=arguments.offline)
        if report["status"] == "matched":
            read_report(arguments.report)
    except (EvidenceError, run.HarnessError, OSError) as error:
        print(f"mixed-medium owner-exit differential: FAIL: {error}", file=sys.stderr)
        return 1
    if report["status"] != "matched":
        print(f"mixed-medium owner-exit differential: FAIL: {report['comparison']['reason']}; "
              f"raw report {arguments.report}", file=sys.stderr)
        return 1
    print(f"mixed-medium owner-exit differential: PASS ({report['comparison']['values']} source-bound values)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
