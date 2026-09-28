#!/usr/bin/env python3
"""Compare pinned C and native Rust mixed full-page owner exit on x86-64."""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "compat/allocator/x86_64_nonabandoning_mixed_owner_exit.c"
RUST_SOURCE = ROOT / "crabc-mimalloc/src/runtime_lifecycle.rs"
REPORT = ROOT / "compat/reports/allocator/x86_64/nonabandoning-mixed-owner-exit.json"
BASE = ROOT / "compat/allocator/x86_64_regular_small_evidence.py"
spec = importlib.util.spec_from_file_location("regular_small_base", BASE)
assert spec is not None and spec.loader is not None
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
run = base.run

TRACE_BEGIN = "CRABC_MI_MIXED_OWNER_EXIT_BEGIN"
TRACE_END = "CRABC_MI_MIXED_OWNER_EXIT_END"
RUST_FILTER = (
    "runtime_lifecycle::tests::"
    "native_owner_exit_traverses_full_medium_and_os_singleton_before_survivor_frees"
)
EXPECTED_TRACE = {
    "full_retain": -1,
    "medium_capacity": 6,
    "medium_full": 1,
    "singleton_os_full": 1,
    "remote_collected": 1,
    "singleton_live_after_exit": 1,
    "singleton_released": 1,
    "medium_retained": 1,
    "medium_released": 1,
    "survivor_usable": 1,
}
SOURCE_ANCHORS = (
    ("src/free.c", 44, 56, "de6d94667e1d6b127947a347660b35b4eaf1480751da492154de4a1e48f43e13"),
    ("src/free.c", 480, 512, "f4e336858be00bf3a186ea6e4ce0e4df0856bc8f4092005b1b79b9bc6d80852f"),
    ("src/page.c", 424, 457, "70a97877d51e5ca85aee8e74e61e293ebddd7676e214035abb83f5a30608078c"),
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
    with run.temporary_directory("mixed-owner-exit-") as name:
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
        c_binary = temporary / "mixed-owner-exit-c"
        c_command = [compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            *base.EXPECTED_COMPILE_DEFINITIONS, "-I", str(source / "include"),
            "-I", str(source / "src"), *run.CONFIGURATION_PROFILES["release"],
            str(PROBE), *(str(source / member) for member in run.ORACLE_SOURCES),
            "-pthread", "-o", str(c_binary)]
        c_build = checked_command(c_command, cwd=source, description="pinned C mixed owner-exit build")
        elf_record = checked_command([run.require_tool("readelf"), "-h", str(c_binary)],
            cwd=source, description="pinned C ELF identity")
        elf = run.parse_elf_identity(str(elf_record["stdout"]), "x86_64")
        if elf != base.EXPECTED_C_ELF:
            raise EvidenceError("pinned C product is not the native x86-64 ELF")
        c_run = checked_command([str(c_binary)], cwd=source, description="pinned C mixed owner-exit execution")
        c_trace = parse_trace(str(c_run["stdout"]), "C")
        rust_target = run.WORK_ROOT / "target"
        rust_command = [cargo, "test", "--locked", "--target", base.TARGET,
            "--target-dir", str(rust_target), "-p", "crabc-mimalloc",
            "--lib", "--no-default-features", RUST_FILTER,
            "--", "--exact", "--nocapture", "--test-threads=1"]
        env = os.environ.copy()
        env["CARGO_INCREMENTAL"] = "0"
        rust_run = checked_command(rust_command, cwd=ROOT, env=env,
            description="native Rust mixed owner-exit execution")
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
            "kind": "pinned-c-native-rust-nonabandoning-mixed-owner-exit",
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, default=REPORT)
    arguments = parser.parse_args()
    try:
        report = run_evidence(arguments.report, offline=arguments.offline)
    except (EvidenceError, run.HarnessError, OSError) as error:
        print(f"mixed owner-exit differential: FAIL: {error}", file=sys.stderr)
        return 1
    if report["status"] != "matched":
        print(f"mixed owner-exit differential: FAIL: {report['comparison']['reason']}; "
              f"raw report {arguments.report}", file=sys.stderr)
        return 1
    print(f"mixed owner-exit differential: PASS ({report['comparison']['values']} source-bound values)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
