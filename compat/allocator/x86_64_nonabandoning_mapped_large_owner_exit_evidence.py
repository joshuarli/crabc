#!/usr/bin/env python3
"""Compare pinned C and native Rust mapped-large owner exit on x86-64."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "compat/allocator/x86_64_nonabandoning_mapped_large_owner_exit.c"
RUST_SOURCE = ROOT / "crabc-mimalloc/src/mapped_large_owner_exit.rs"
RUNTIME_SOURCE = ROOT / "crabc-mimalloc/src/runtime_lifecycle.rs"
LIB_SOURCE = ROOT / "crabc-mimalloc/src/lib.rs"
REPORT = ROOT / "compat/reports/allocator/x86_64/nonabandoning-mapped-large-owner-exit.json"
BASE = ROOT / "compat/allocator/x86_64_regular_small_evidence.py"
spec = importlib.util.spec_from_file_location("regular_small_base", BASE)
assert spec is not None and spec.loader is not None
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
run = base.run

TRACE_BEGIN = "CRABC_MI_MAPPED_LARGE_OWNER_EXIT_BEGIN"
TRACE_END = "CRABC_MI_MAPPED_LARGE_OWNER_EXIT_END"
C_SOURCE_STATE = (
    "CRABC_MI_C_SOURCE_MAPPED_STATE large_mapped=1 medium_mapped=1 "
    "large_unowned=1 medium_unowned=1\n"
)
C_LARGE_FIRST_FREE = "CRABC_MI_C_SOURCE_LARGE_FIRST_FREE mapped=1 unowned=1 used=1\n"
C_FINAL_STATE = (
    "CRABC_MI_C_SOURCE_FINAL_STATE large_registered=0 large_used=18446744073709551615 "
    "large_expire=0 medium_registered=1 medium_used=0 medium_expire=4\n"
)
RUST_FILTER = (
    "mapped_large_owner_exit::"
    "nonabandoning_mapped_large_and_medium_reclaim_after_owner_exit"
)
EXPECTED_TRACE = {
    "full_retain": -1,
    "large_request": 152234,
    "medium_request": 65536,
    "large_slice_count": 64,
    "medium_slice_count": 8,
    "owner_queues_valid": 1,
    "large_registered_after_exit": 1,
    "medium_registered_after_exit": 1,
    "large_stays_registered_nonlocal": 1,
    "medium_requeued": 1,
    "large_released_on_final": 1,
    "medium_registered_after_large_final": 1,
    "medium_registered_before_collect": 1,
    "large_released": 1,
    "medium_released": 1,
    "survivor_usable": 1,
}
GEOMETRY_KEYS = {"large_reserved", "medium_reserved",
                 "large_registered_slice_count", "medium_registered_slice_count"}
SOURCE_ANCHORS = (
    ("src/free.c", 428, 478, "f54217a78fa99275146f84371befd7fa8c57301a4b3403d6ec68ed93e4c0e778"),
    ("src/free.c", 480, 512, "f4e336858be00bf3a186ea6e4ce0e4df0856bc8f4092005b1b79b9bc6d80852f"),
    ("src/page-queue.c", 252, 276, "b6fa8adb53af487239dec0f9192950defae89096c207b1beff34e9466ecd4771"),
    ("src/page-map.c", 139, 145, "5a9d0a94640b0bd5c436f7e101872c92f73ab47cf7374ad80a0bb5acdf2f5213"),
    ("src/page.c", 291, 306, "0c6988279400c93848945d1b35f204622bd6a6f35ff0dc8a5171c33614f6d5cc"),
    ("src/page.c", 424, 457, "70a97877d51e5ca85aee8e74e61e293ebddd7676e214035abb83f5a30608078c"),
    ("src/page.c", 460, 518, "9e0c373ed5a817f9e9998319442aaf7b5870509e4821a57686179b54ff6428af"),
    ("src/theap.c", 123, 165, "a84d17ad1b74eb93e79bb3b756f099fd60fe611eda6279c17db283c44cccc1bb"),
    ("src/theap.c", 228, 232, "16c0e73a20b9a94bf994c4e83836c976f5683e3c6e8b18935782a934405adba0"),
)


class EvidenceError(RuntimeError):
    """The bounded source comparison did not establish its trace contract."""


def render_trace(trace: dict[str, int]) -> str:
    return "\n".join((TRACE_BEGIN, *(f"{key}={value}" for key, value in trace.items()), TRACE_END))


def parse_c_source_state(output: str) -> dict[str, int]:
    lines = [line for line in output.splitlines() if line.startswith("CRABC_MI_C_SOURCE_MAPPED_STATE ")]
    if len(lines) != 1:
        raise EvidenceError("C source mapped state is missing or duplicated")
    found = re.fullmatch(
        r"CRABC_MI_C_SOURCE_MAPPED_STATE large_mapped=([01]) medium_mapped=([01]) "
        r"large_unowned=([01]) medium_unowned=([01])", lines[0]
    )
    if found is None:
        raise EvidenceError("C source mapped state is malformed")
    state = dict(zip(("large_mapped", "medium_mapped", "large_unowned", "medium_unowned"),
                     (int(value) for value in found.groups())))
    for key, value in state.items():
        if value != 1:
            raise EvidenceError(f"C source {key} was not observed")
    return state


def parse_c_large_first_free(output: str) -> dict[str, int]:
    lines = [line for line in output.splitlines() if line.startswith("CRABC_MI_C_SOURCE_LARGE_FIRST_FREE ")]
    if len(lines) != 1:
        raise EvidenceError("C large first-free state is missing or duplicated")
    found = re.fullmatch(r"CRABC_MI_C_SOURCE_LARGE_FIRST_FREE mapped=([01]) unowned=([01]) used=([0-9]+)", lines[0])
    if found is None:
        raise EvidenceError("C large first-free state is malformed")
    state = dict(zip(("mapped", "unowned", "used"), (int(value) for value in found.groups())))
    if state != {"mapped": 1, "unowned": 1, "used": 1}:
        raise EvidenceError("C large page did not reabandon after its first free")
    return state


def parse_c_final_state(output: str) -> dict[str, int]:
    lines = [line for line in output.splitlines() if line.startswith("CRABC_MI_C_SOURCE_FINAL_STATE ")]
    if len(lines) != 1:
        raise EvidenceError("C final source state is missing or duplicated")
    found = re.fullmatch(
        r"CRABC_MI_C_SOURCE_FINAL_STATE large_registered=([01]) large_used=([0-9]+) "
        r"large_expire=([0-9]+) medium_registered=([01]) medium_used=([0-9]+) medium_expire=([0-9]+)",
        lines[0],
    )
    if found is None:
        raise EvidenceError("C final source state is malformed")
    names = ("large_registered", "large_used", "large_expire", "medium_registered", "medium_used", "medium_expire")
    state = dict(zip(names, (int(value) for value in found.groups())))
    if (state["large_registered"] != 0 or state["medium_registered"] != 1
            or state["medium_used"] != 0 or state["medium_expire"] != 4):
        raise EvidenceError("C final large release or medium retirement differs")
    return state


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
    required = set(EXPECTED_TRACE) | GEOMETRY_KEYS
    missing = required - set(trace)
    unexpected = set(trace) - required
    if missing or unexpected:
        raise EvidenceError(f"{description} trace missing {sorted(missing)}; unexpected {sorted(unexpected)}")
    return trace


def compare_traces(c_trace: dict[str, int], rust_trace: dict[str, int]) -> dict[str, int]:
    for description, trace in (("C", c_trace), ("Rust", rust_trace)):
        if set(trace) != set(EXPECTED_TRACE) | GEOMETRY_KEYS:
            raise EvidenceError(f"{description} trace missing or unexpected keys")
        for key, expected in EXPECTED_TRACE.items():
            if type(trace[key]) is not int or trace[key] != expected:
                raise EvidenceError(f"{description} {key}: expected {expected}, observed {trace[key]}")
        for key in ("large_reserved", "medium_reserved"):
            if type(trace[key]) is not int or trace[key] <= 2:
                raise EvidenceError(f"{description} {key}: regular page must have spare blocks")
        for kind in ("large", "medium"):
            key = kind + "_registered_slice_count"
            if type(trace[key]) is not int or not 0 < trace[key] <= trace[kind + "_slice_count"]:
                raise EvidenceError(f"{description} {key}: invalid source PageMap prefix")
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
    with run.temporary_directory("mapped-large-owner-exit-") as name:
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
        c_binary = temporary / "mapped-large-owner-exit-c"
        c_command = [compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            *base.EXPECTED_COMPILE_DEFINITIONS, "-I", str(source / "include"),
            "-I", str(source / "src"), *run.CONFIGURATION_PROFILES["release"],
            str(PROBE), *(str(source / member) for member in run.ORACLE_SOURCES),
            "-pthread", "-o", str(c_binary)]
        c_build = checked_command(c_command, cwd=source, description="pinned C mapped-large owner-exit build")
        elf_record = checked_command([run.require_tool("readelf"), "-h", str(c_binary)],
            cwd=source, description="pinned C ELF identity")
        elf = run.parse_elf_identity(str(elf_record["stdout"]), "x86_64")
        if elf != base.EXPECTED_C_ELF:
            raise EvidenceError("pinned C product is not the native x86-64 ELF")
        c_run = checked_command([str(c_binary)], cwd=source, description="pinned C mapped-large owner-exit execution")
        c_source_state = parse_c_source_state(str(c_run["stdout"]))
        c_large_first_free = parse_c_large_first_free(str(c_run["stdout"]))
        c_final_state = parse_c_final_state(str(c_run["stdout"]))
        c_trace = parse_trace(str(c_run["stdout"]), "C")
        rust_target = run.WORK_ROOT / "target"
        rust_command = [cargo, "test", "--locked", "--target", base.TARGET,
            "--target-dir", str(rust_target), "-p", "crabc-mimalloc",
            "--lib", "--no-default-features", "--features", "native-runtime-test-audit", RUST_FILTER,
            "--", "--exact", "--nocapture", "--test-threads=1"]
        env = os.environ.copy()
        env["CARGO_INCREMENTAL"] = "0"
        rust_run = run.command_record(rust_command, cwd=ROOT, env=env)
        rust_output = str(rust_run["stdout"]) + "\n" + str(rust_run["stderr"])
        if rust_run["status"] != 0:
            rust_trace = None
            comparison = {"status": "execution-failed",
                "reason": f"native Rust fixture exited {rust_run['status']}; raw execution retained"}
        else:
            if run.parse_rust_test_count(rust_output) != 1:
                raise EvidenceError("native Rust fixture did not run exactly once")
            rust_trace = parse_trace(rust_output, "Rust")
            try:
                trace = compare_traces(c_trace, rust_trace)
                comparison = {"status": "matched", "values": len(trace), "trace": trace}
            except EvidenceError as error:
                comparison = {"status": "diverged", "reason": str(error),
                    "values": len(set(c_trace) & set(rust_trace))}
        report = {
            "kind": "pinned-c-native-rust-nonabandoning-mapped-large-owner-exit",
            "status": comparison["status"], "target": provenance,
            "source": {"archive_sha256": base.sha256_file(archive), "revision": pin["revision"],
                "anchors": anchors},
            "probe": {"path": base.relative(PROBE), "sha256": base.sha256_file(PROBE),
                "rust_source": base.relative(RUST_SOURCE), "rust_sha256": base.sha256_file(RUST_SOURCE),
                "runtime_source": base.relative(RUNTIME_SOURCE),
                "runtime_sha256": base.sha256_file(RUNTIME_SOURCE),
                "lib_source": base.relative(LIB_SOURCE), "lib_sha256": base.sha256_file(LIB_SOURCE),
                "lockfile_sha256": before_lock},
            "c": {"build_command": base.normalize_command(c_command, temporary, source),
                "build": c_build, "elf": elf, "execution": c_run,
                "source_state": c_source_state, "large_first_free": c_large_first_free,
                "final_state": c_final_state,
                "trace": c_trace},
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
        if report["kind"] != "pinned-c-native-rust-nonabandoning-mapped-large-owner-exit":
            raise EvidenceError("mapped-large report kind differs")
        if report["status"] != "matched":
            raise EvidenceError("mapped-large report did not match")
        source = report["source"]
        pin = run.load_pin()
        if source["archive_sha256"] != base.EXPECTED_ARCHIVE_SHA256 or source["revision"] != pin["revision"]:
            raise EvidenceError("mapped-large source archive identity differs")
        expected_anchors = [
            {"member": member, "first": first, "last": last, "sha256": digest}
            for member, first, last, digest in SOURCE_ANCHORS
        ]
        if source["anchors"] != expected_anchors:
            raise EvidenceError("mapped-large source branch anchors differ")
        probe = report["probe"]
        if probe != {
            "path": base.relative(PROBE), "sha256": base.sha256_file(PROBE),
            "rust_source": base.relative(RUST_SOURCE), "rust_sha256": base.sha256_file(RUST_SOURCE),
            "runtime_source": base.relative(RUNTIME_SOURCE),
            "runtime_sha256": base.sha256_file(RUNTIME_SOURCE),
            "lib_source": base.relative(LIB_SOURCE), "lib_sha256": base.sha256_file(LIB_SOURCE),
            "lockfile_sha256": base.sha256_file(ROOT / "Cargo.lock"),
        }:
            raise EvidenceError("mapped-large selected source seal differs")
        c = report["c"]
        rust = report["rust"]
        if c["elf"] != base.EXPECTED_C_ELF:
            raise EvidenceError("mapped-large C ELF identity differs")
        if (not any(part.endswith("/" + base.relative(PROBE)) for part in c["build_command"])
                or RUST_FILTER not in rust["command"]
                or "native-runtime-test-audit" not in rust["command"]):
            raise EvidenceError("mapped-large selected commands differ")
        for name, record in (("C build", c["build"]), ("C execution", c["execution"]),
                             ("Rust execution", rust["execution"])):
            if record["status"] != 0 or not isinstance(record["stdout"], str) or not isinstance(record["stderr"], str):
                raise EvidenceError(f"mapped-large {name} failed or lacks raw output")
        if c["execution"]["stderr"]:
            raise EvidenceError("mapped-large C execution wrote stderr")
        if run.parse_rust_test_count(rust["execution"]["stdout"] + "\n" + rust["execution"]["stderr"]) != 1:
            raise EvidenceError("mapped-large Rust test count differs")
        c_source_state = parse_c_source_state(c["execution"]["stdout"])
        if c["source_state"] != c_source_state:
            raise EvidenceError("mapped-large C source state differs from raw execution")
        c_large_first_free = parse_c_large_first_free(c["execution"]["stdout"])
        if c["large_first_free"] != c_large_first_free:
            raise EvidenceError("mapped-large C first-free state differs from raw execution")
        c_final_state = parse_c_final_state(c["execution"]["stdout"])
        if c["final_state"] != c_final_state:
            raise EvidenceError("mapped-large C final state differs from raw execution")
        c_trace = parse_trace(c["execution"]["stdout"], "C raw report")
        rust_trace = parse_trace(rust["execution"]["stdout"] + "\n" + rust["execution"]["stderr"], "Rust raw report")
        trace = compare_traces(c_trace, rust_trace)
        if c["trace"] != trace or rust["trace"] != trace or report["comparison"] != {
            "status": "matched", "values": len(trace), "trace": trace,
        }:
            raise EvidenceError("mapped-large stored trace differs from raw execution")
        return trace
    except (KeyError, TypeError, ValueError, run.HarnessError) as error:
        raise EvidenceError(f"malformed mapped-large report: {error}") from error


def read_report(path: Path) -> dict[str, int]:
    try:
        return validate_report(json.loads(path.read_text()))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read mapped-large report: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, default=REPORT)
    parser.add_argument("--read-report", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.read_report is not None:
            trace = read_report(arguments.read_report)
            print(f"mapped-large owner-exit receipt: PASS ({len(trace)} source-bound values)")
            return 0
        report = run_evidence(arguments.report, offline=arguments.offline)
        if report["status"] == "matched":
            read_report(arguments.report)
    except (EvidenceError, run.HarnessError, OSError) as error:
        print(f"mapped-large owner-exit differential: FAIL: {error}", file=sys.stderr)
        return 1
    if report["status"] != "matched":
        print(f"mapped-large owner-exit differential: FAIL: {report['comparison']['reason']}; "
              f"raw report {arguments.report}", file=sys.stderr)
        return 1
    print(f"mapped-large owner-exit differential: PASS ({report['comparison']['values']} source-bound values)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
