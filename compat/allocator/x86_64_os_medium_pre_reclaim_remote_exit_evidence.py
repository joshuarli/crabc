#!/usr/bin/env python3
"""Compare pinned C and native Rust OS-medium pre-reclaim-remote owner exit."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "compat/allocator/x86_64_os_medium_pre_reclaim_remote_exit.c"
RUST_SOURCE = ROOT / "crabc-mimalloc/tests/native_os_medium_pre_reclaim_remote_exit.rs"
RUNTIME_SOURCE = ROOT / "crabc-mimalloc/src/runtime_lifecycle.rs"
SINGLE_THREAD_SOURCE = ROOT / "crabc-mimalloc/src/single_thread.rs"
ABANDONED_SOURCE = ROOT / "crabc-mimalloc/src/abandoned.rs"
LIB_SOURCE = ROOT / "crabc-mimalloc/src/lib.rs"
PAGE_MAP_SOURCE = ROOT / "crabc-mimalloc/src/page_map.rs"
SUPPORT_SOURCE = ROOT / "crabc-mimalloc/tests/support/native_runtime.rs"
REPORT = ROOT / "compat/reports/allocator/x86_64/os-medium-pre-reclaim-remote-exit.json"
BASE = ROOT / "compat/allocator/x86_64_regular_small_evidence.py"
spec = importlib.util.spec_from_file_location("regular_small_base", BASE)
assert spec is not None and spec.loader is not None
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
run = base.run

TRACE_BEGIN = "CRABC_MI_OS_MEDIUM_PRE_RECLAIM_REMOTE_BEGIN"
TRACE_END = "CRABC_MI_OS_MEDIUM_PRE_RECLAIM_REMOTE_END"
C_OS_PREFIX = "CRABC_MI_C_OS_MEDIUM_STATE "
RUST_FILTER = "remote_free_before_reclaim_preserves_abandoned_os_page_for_second_survivor"
EXPECTED = {
    "request": 49152,
    "block_size": 57344,
    "reserved": 9,
    "map_count": 8,
    "owner_setup_valid": 1,
    "two_survivors_ready": 1,
    "abandoned_after_exit": 1,
    "registered_after_exit": 1,
    "remote_queue_blocks_first_reclaim": 1,
    "first_remote_completed": 1,
    "abandoned_after_first_remote": 1,
    "registered_after_first_remote": 1,
    "used_after_first_remote": 8,
    "first_remote_head_cleared": 1,
    "second_reclaimed_on_free": 1,
    "first_reuse_same_page": 1,
    "registered_after_first_reuse": 1,
    "first_used_eight": 1,
    "late_remote_pending": 1,
    "used_before_collect": 8,
    "used_after_collect": 7,
    "second_reuse_same_page": 1,
    "late_remote_head_cleared": 1,
    "abandoned_after_reclaimer_exit": 1,
    "registered_after_reclaimer_exit": 1,
    "live_after_reclaimer_exit": 1,
    "remote_and_final_frees": 1,
    "terminal_map_clear": 1,
    "terminal_region_clear": 1,
}
C_OS_KEYS = (
    "os_list_after_exit", "os_list_after_first_remote",
    "mostly_used_after_first_remote", "os_list_empty_after_reclaim",
    "os_list_after_reclaimer_exit", "os_list_empty_after_final",
)
SOURCE_ANCHORS = (
    ("include/mimalloc/internal.h", 925, 930, "47118b528cc9431598f00c35c7259f3aa22e83ec689ec12d635384edbb595574"),
    ("src/arena.c", 819, 855, "8deb9d795b71ad70a008b538c5be49b15f35371bc2d249aeb69b66f2c29a614d"),
    ("src/arena.c", 1304, 1428, "337af803bb9ea1b51c6dcfffa8c23421b2aea2e28dbf34f22a7f796971b82764"),
    ("src/free.c", 428, 512, "94e598b118523533357088427b68ca7e1bdbb6e2002495185e1d872d73f066d8"),
    ("src/page.c", 291, 318, "9c82540ca4cd5c42767bfdd3793f1714a6ffbd3b46fd6bc149383463796241e9"),
    ("src/page-map.c", 139, 145, "5a9d0a94640b0bd5c436f7e101872c92f73ab47cf7374ad80a0bb5acdf2f5213"),
    ("src/theap.c", 123, 165, "a84d17ad1b74eb93e79bb3b756f099fd60fe611eda6279c17db283c44cccc1bb"),
)


class EvidenceError(RuntimeError):
    """The source-bound owner-exit trace did not establish its contract."""


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


def parse_c_os_state(output: str) -> dict[str, int]:
    lines = [line for line in output.splitlines() if line.startswith(C_OS_PREFIX)]
    if len(lines) != 1:
        raise EvidenceError("C OS state is missing or duplicated")
    fields = lines[0][len(C_OS_PREFIX):].split()
    if len(fields) != len(C_OS_KEYS):
        raise EvidenceError("C OS state has missing or unexpected fields")
    observed = {}
    for field in fields:
        found = re.fullmatch(r"([a-z][a-z_]+)=([01])", field)
        if found is None or found[1] in observed:
            raise EvidenceError("C OS state is malformed or duplicated")
        observed[found[1]] = int(found[2])
    if set(observed) != set(C_OS_KEYS) or any(value != 1 for value in observed.values()):
        raise EvidenceError("C OS state did not complete its source route")
    return observed


def compare_traces(c_trace: dict[str, int], rust_trace: dict[str, int]) -> dict[str, int]:
    for name, trace in (("C", c_trace), ("Rust", rust_trace)):
        if set(trace) != set(EXPECTED):
            raise EvidenceError(f"{name} trace is incomplete")
        for key, value in EXPECTED.items():
            if type(trace[key]) is not int or trace[key] != value:
                raise EvidenceError(f"{name} {key}: expected {value}, observed {trace[key]}")
    if c_trace != rust_trace:
        raise EvidenceError("C and Rust OS-medium owner-exit traces differ")
    return c_trace


def command(command: list[str], *, cwd: Path, description: str, env=None) -> dict:
    record = run.command_record(command, cwd=cwd, env=env)
    try:
        run.require_success(record, description)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    return record


def source_seal() -> dict[str, str]:
    return {
        "c_path": base.relative(PROBE), "c_sha256": base.sha256_file(PROBE),
        "rust_path": base.relative(RUST_SOURCE), "rust_sha256": base.sha256_file(RUST_SOURCE),
        "runtime_path": base.relative(RUNTIME_SOURCE), "runtime_sha256": base.sha256_file(RUNTIME_SOURCE),
        "single_thread_path": base.relative(SINGLE_THREAD_SOURCE),
        "single_thread_sha256": base.sha256_file(SINGLE_THREAD_SOURCE),
        "abandoned_path": base.relative(ABANDONED_SOURCE),
        "abandoned_sha256": base.sha256_file(ABANDONED_SOURCE),
        "lib_path": base.relative(LIB_SOURCE), "lib_sha256": base.sha256_file(LIB_SOURCE),
        "page_map_path": base.relative(PAGE_MAP_SOURCE), "page_map_sha256": base.sha256_file(PAGE_MAP_SOURCE),
        "support_path": base.relative(SUPPORT_SOURCE), "support_sha256": base.sha256_file(SUPPORT_SOURCE),
        "lockfile_sha256": base.sha256_file(ROOT / "Cargo.lock"),
    }


def run_evidence(report_path: Path, *, offline: bool) -> dict:
    provenance = run.require_native_x86_64()
    pin = run.load_pin()
    if pin["sha256"] != base.EXPECTED_ARCHIVE_SHA256 or pin["revision"] != base.EXPECTED_UPSTREAM["revision"]:
        raise EvidenceError("pinned mimalloc source identity drifted")
    archive = run.fetch_archive(pin, offline)
    seal = source_seal()
    with run.temporary_directory("os-medium-pre-reclaim-remote-exit-") as name:
        temporary = Path(name)
        source = run.safe_extract(archive, temporary / "source", pin["archive_root"])
        anchors = []
        for member, first, last, expected in SOURCE_ANCHORS:
            digest = base.sha256_bytes(base.source_range((source / member).read_bytes(), first, last))
            if digest != expected:
                raise EvidenceError(f"pinned source branch drifted: {member}:{first}-{last}")
            anchors.append({"member": member, "first": first, "last": last, "sha256": digest})
        c_binary = temporary / "os-medium-pre-reclaim-remote-exit-c"
        c_command = [run.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            *base.EXPECTED_COMPILE_DEFINITIONS, "-I", str(source / "include"),
            "-I", str(source / "src"), *run.CONFIGURATION_PROFILES["release"],
            str(PROBE), *(str(source / member) for member in run.ORACLE_SOURCES),
            "-pthread", "-o", str(c_binary)]
        c_build = command(c_command, cwd=source, description="pinned C OS-medium owner-exit build")
        elf_record = command([run.require_tool("readelf"), "-h", str(c_binary)],
            cwd=source, description="pinned C ELF identity")
        elf = run.parse_elf_identity(str(elf_record["stdout"]), "x86_64")
        if elf != base.EXPECTED_C_ELF:
            raise EvidenceError("pinned C product is not native x86-64 ELF")
        c_run = command([str(c_binary)], cwd=source, description="pinned C OS-medium owner-exit execution")
        c_os_state = parse_c_os_state(str(c_run["stdout"]))
        c_trace = parse_trace(str(c_run["stdout"]), "C")
        rust_command = [run.require_tool("cargo"), "test", "--offline", "--locked", "--target",
            base.TARGET, "--target-dir", str(run.WORK_ROOT / "target"), "-p", "crabc-mimalloc",
            "--test", "native_os_medium_pre_reclaim_remote_exit",
            "--no-default-features", "--features", "native-runtime-test-audit",
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
            "kind": "pinned-c-native-rust-os-medium-pre-reclaim-remote-exit",
            "status": comparison["status"], "target": provenance,
            "source": {"archive_sha256": base.sha256_file(archive), "revision": pin["revision"], "anchors": anchors},
            "probe": seal,
            "c": {"build_command": base.normalize_command(c_command, temporary, source),
                  "build": c_build, "elf": elf, "execution": c_run,
                  "os_state": c_os_state, "trace": c_trace},
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
        if report["kind"] != "pinned-c-native-rust-os-medium-pre-reclaim-remote-exit" or report["status"] != "matched":
            raise EvidenceError("OS-medium report kind or status differs")
        source = report["source"]
        if source["archive_sha256"] != base.EXPECTED_ARCHIVE_SHA256 or source["revision"] != run.load_pin()["revision"]:
            raise EvidenceError("OS-medium source archive differs")
        if source["anchors"] != [
            {"member": member, "first": first, "last": last, "sha256": digest}
            for member, first, last, digest in SOURCE_ANCHORS
        ]:
            raise EvidenceError("OS-medium source anchors differ")
        if report["probe"] != source_seal():
            raise EvidenceError("OS-medium source seal differs")
        c, rust = report["c"], report["rust"]
        if c["elf"] != base.EXPECTED_C_ELF:
            raise EvidenceError("OS-medium C ELF identity differs")
        if (not any(part.endswith("/" + base.relative(PROBE)) for part in c["build_command"])
                or RUST_FILTER not in rust["command"] or "native-runtime-test-audit" not in rust["command"]
                or rust["command"][rust["command"].index("--test") + 1] != "native_os_medium_pre_reclaim_remote_exit"):
            raise EvidenceError("OS-medium execution commands differ")
        for name, record in (("C build", c["build"]), ("C execution", c["execution"]),
                             ("Rust execution", rust["execution"])):
            if record["status"] != 0 or not isinstance(record["stdout"], str) or not isinstance(record["stderr"], str):
                raise EvidenceError(f"OS-medium {name} failed or lacks raw output")
        if c["execution"]["stderr"]:
            raise EvidenceError("OS-medium C execution wrote stderr")
        if run.parse_rust_test_count(rust["execution"]["stdout"] + "\n" + rust["execution"]["stderr"]) != 1:
            raise EvidenceError("OS-medium Rust test count differs")
        c_os_state = parse_c_os_state(c["execution"]["stdout"])
        if c["os_state"] != c_os_state:
            raise EvidenceError("OS-medium stored C source state differs")
        c_trace = parse_trace(c["execution"]["stdout"], "C raw report")
        rust_trace = parse_trace(rust["execution"]["stdout"] + "\n" + rust["execution"]["stderr"], "Rust raw report")
        trace = compare_traces(c_trace, rust_trace)
        if c["trace"] != trace or rust["trace"] != trace or report["comparison"] != {
            "status": "matched", "values": len(trace), "trace": trace,
        }:
            raise EvidenceError("OS-medium stored trace differs from raw execution")
        return trace
    except (KeyError, TypeError, ValueError, run.HarnessError) as error:
        raise EvidenceError(f"malformed OS-medium report: {error}") from error


def read_report(path: Path) -> dict[str, int]:
    try:
        return validate_report(json.loads(path.read_text()))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read OS-medium report: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, default=REPORT)
    parser.add_argument("--read-report", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.read_report is not None:
            trace = read_report(arguments.read_report)
            print(f"OS-medium pre-reclaim-remote owner-exit receipt: PASS ({len(trace)} source-bound values)")
            return 0
        report = run_evidence(arguments.report, offline=arguments.offline)
        if report["status"] == "matched":
            read_report(arguments.report)
    except (EvidenceError, run.HarnessError, OSError) as error:
        print(f"OS-medium pre-reclaim-remote owner-exit differential: FAIL: {error}", file=sys.stderr)
        return 1
    if report["status"] != "matched":
        print(f"OS-medium pre-reclaim-remote owner-exit differential: FAIL: {report['comparison']['reason']}; "
              f"raw report {arguments.report}", file=sys.stderr)
        return 1
    print(f"OS-medium pre-reclaim-remote owner-exit differential: PASS ({report['comparison']['values']} source-bound values)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
