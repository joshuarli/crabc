#!/usr/bin/env python3
"""Compare a source-built worker statistics reset and exit in separate processes."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import os
from pathlib import Path

import run as harness
import perf_engine_x86_64 as engine
from x86_64_m7_gate import parse_options_trace


FIXTURE = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_worker_reset_oracle.c"
BEGIN = "CRABC_MI_M7_STATISTICS_WORKER_RESET_TRACE_BEGIN"
END = "CRABC_MI_M7_STATISTICS_WORKER_RESET_TRACE_END"
REPORT = harness.ARTIFACT_ROOT / "x86_64/m7-statistics-worker-reset/profile.json"
TARGET = "x86_64-unknown-linux-musl"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, args.offline)
    cc = harness.require_tool("musl-gcc")
    cargo = harness.require_tool("cargo")
    with harness.temporary_directory("crabc-m7-statistics-worker-reset-") as temp_name:
        temp = Path(temp_name)
        source = harness.safe_extract(archive, temp / "source", pin["archive_root"])
        flags = ["-DMI_STAT=1" if flag == "-DMI_STAT=0" else flag
                 for flag in harness.CONFIGURATION_PROFILES["release"]]
        common = [cc, "-std=c11", "-O2", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                  *flags, "-I", str(source / "include"), str(FIXTURE)]
        c_driver = temp / "worker-reset-c"
        c_build = harness.command_record([*common, str(source / "src/static.c"),
                                          "-pthread", "-o", str(c_driver)], cwd=source)
        harness.require_success(c_build, "pinned worker statistics build")
        target_dir = temp / "cargo-target"
        rust_build = harness.command_record([
            cargo, "build", "--locked", "--offline", "--release", "--target", TARGET,
            "-p", "crabc-mimalloc-native-mi-adapter", "--no-default-features",
            "--features", "crabc-mimalloc/mi-stat-1", "--target-dir", str(target_dir),
        ], cwd=harness.ROOT, env=dict(os.environ), timeout_seconds=3600)
        harness.require_success(rust_build, "native worker statistics adapter build")
        rust_driver = temp / "worker-reset-rust"
        library = target_dir / TARGET / "release" / "libcrabc_mimalloc_native_mi_adapter.a"
        rust_link = harness.command_record([*common, str(library), "-pthread", "-o", str(rust_driver)],
                                           cwd=source)
        harness.require_success(rust_link, "native worker statistics driver link")
        stages = ("allocated", "reset", "freed", "exited")
        expected_keys = {"profile.level", "allocation.usable", "allocation.second_usable"}
        expected_keys.update(f"{stage}.{field}" for stage in stages
                             for field in ("normal", "threads", "heaps", "theaps", "normal_count"))
        expected_keys.update(("worker.live_owner", "worker.reset_owner", "worker.freed_owner",
                              "process.exited_owner"))
        expected_keys.update(f"worker.{state}_{field}" for state in ("live", "reset", "freed")
                             for field in ("binned", "total"))
        expected_keys.update(("process.exited_binned", "process.exited_total"))
        traces = {}
        executions = {}
        for side, driver in (("c", c_driver), ("rust", rust_driver)):
            execution = harness.command_record([str(driver)], cwd=source, env={}, timeout_seconds=60)
            harness.require_success(execution, f"{side} worker statistics process")
            trace = parse_options_trace(str(execution["stdout"]), side, BEGIN, END)
            if set(trace) != expected_keys or trace["profile.level"] != "1":
                raise harness.HarnessError(f"{side} omitted worker reset observations")
            for stage in stages:
                for field in ("normal", "threads", "heaps", "theaps"):
                    if len(trace[f"{stage}.{field}"].split(",")) != 3:
                        raise harness.HarnessError(f"{side} malformed {stage}.{field}")
            for key in expected_keys:
                if key.startswith(("worker.", "process.")):
                    if trace[key] == "absent":
                        if key not in ("worker.reset_binned", "worker.reset_total",
                                       "worker.freed_binned", "worker.freed_total"):
                            raise harness.HarnessError(f"{side} omitted {key}")
                        continue
                    try:
                        bytes.fromhex(trace[key])
                    except ValueError as error:
                        raise harness.HarnessError(f"{side} malformed {key}") from error
            traces[side] = trace
            executions[side] = execution["command"]
        source_expected = {
            "profile.level": "1", "allocation.usable": "64", "allocation.second_usable": "64",
            "allocated.normal": "64,64,64", "reset.normal": "128,128,128",
            "freed.normal": "0,128,128", "exited.normal": "0,128,128",
            "allocated.threads": "1,1,1", "reset.threads": "1,1,1",
            "freed.threads": "1,1,1", "exited.threads": "0,1,1",
            "allocated.theaps": "1,1,1", "reset.theaps": "1,1,1",
            "freed.theaps": "1,1,1", "exited.theaps": "0,1,1",
            "worker.reset_binned": "absent", "worker.reset_total": "absent",
            "worker.freed_binned": "absent", "worker.freed_total": "absent",
        }
        source_expected.update({f"{stage}.heaps": "0,0,0" for stage in stages})
        source_expected.update({f"{stage}.normal_count": "0" for stage in stages})
        if any(traces["c"][key] != value for key, value in source_expected.items()):
            raise harness.HarnessError("pinned C lost the worker reset and exit observations")
        if not (bytes.fromhex(traces["c"]["worker.live_owner"]).startswith(b"heap ")
                and traces["c"]["worker.live_owner"] == traces["c"]["worker.reset_owner"]
                and traces["c"]["worker.live_owner"] == traces["c"]["worker.freed_owner"]
                and bytes.fromhex(traces["c"]["process.exited_owner"]).startswith(b"subproc ")
                and b"not all freed" in bytes.fromhex(traces["c"]["worker.live_binned"])
                and b"64" in bytes.fromhex(traces["c"]["worker.live_total"])
                and b"ok" in bytes.fromhex(traces["c"]["process.exited_binned"])
                and b"ok" in bytes.fromhex(traces["c"]["process.exited_total"])):
            raise harness.HarnessError("pinned C lost the worker/process output sections")
        mismatch = sorted(key for key in traces["c"] if traces["c"][key] != traces["rust"][key])
        level_two_flags = ["-DMI_STAT=2" if flag == "-DMI_STAT=0" else flag
                           for flag in harness.CONFIGURATION_PROFILES["release"]]
        level_two_common = [cc, "-std=c11", "-O2", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                            "-DCRABC_WORKER_STAT_LEVEL=2", *level_two_flags,
                            "-I", str(source / "include"), str(FIXTURE)]
        level_two_c_driver = temp / "worker-reset-level-two-c"
        level_two_c_build = harness.command_record([
            *level_two_common, str(source / "src/static.c"), "-pthread", "-o", str(level_two_c_driver),
        ], cwd=source)
        harness.require_success(level_two_c_build, "pinned level-two worker statistics build")
        level_two_target = temp / "cargo-target-level-two"
        level_two_rust_build = harness.command_record([
            cargo, "build", "--locked", "--offline", "--release", "--target", TARGET,
            "-p", "crabc-mimalloc-native-mi-adapter", "--no-default-features",
            "--features", "crabc-mimalloc/mi-stat-2", "--target-dir", str(level_two_target),
        ], cwd=harness.ROOT, env=dict(os.environ), timeout_seconds=3600)
        harness.require_success(level_two_rust_build, "native level-two worker statistics adapter build")
        level_two_rust_driver = temp / "worker-reset-level-two-rust"
        level_two_library = level_two_target / TARGET / "release" / "libcrabc_mimalloc_native_mi_adapter.a"
        level_two_rust_link = harness.command_record([
            *level_two_common, str(level_two_library), "-pthread", "-o", str(level_two_rust_driver),
        ], cwd=source)
        harness.require_success(level_two_rust_link, "native level-two worker statistics driver link")
        level_two_keys = expected_keys | {"allocation.first_bin", "allocation.second_bin"}
        level_two_keys.update(f"{stage}.{field}" for stage in stages for field in (
            "requested", "first_bin", "second_bin", "first_page_bin", "second_page_bin"))
        level_two_keys.update(("worker.live_first_bin", "worker.live_requested",
                               "worker.reset_second_bin", "process.exited_first_bin",
                               "process.exited_second_bin", "process.exited_requested"))
        raw_output_keys = {"worker.live_full", "worker.reset_full", "worker.freed_full",
                           "process.exited_full"}
        level_two_keys.update(raw_output_keys)
        snapshot_stages = ("preworker", "first_allocation", "reset", "exit")
        snapshot_count_fields = ("reserved", "committed", "theaps", "threads")
        snapshot_scalar_fields = ("mmap_calls", "commit_calls", "arena_count", "current_rss",
                                  "peak_rss", "elapsed", "faults")
        snapshot_pair_fields = ("process_commit",)
        level_two_keys.update(f"snapshot.{stage}.{field}" for stage in snapshot_stages
                              for field in (*snapshot_count_fields, *snapshot_scalar_fields,
                                            *snapshot_pair_fields))
        variable_snapshot_keys = {f"snapshot.{stage}.{field}" for stage in snapshot_stages
                                  for field in ("elapsed", "faults", "peak_rss")}
        level_two_traces = {}
        level_two_executions = {}
        for side, driver in (("c", level_two_c_driver), ("rust", level_two_rust_driver)):
            execution = harness.command_record([str(driver)], cwd=source, env={}, timeout_seconds=60)
            harness.require_success(execution, f"{side} level-two worker statistics process")
            trace = parse_options_trace(str(execution["stdout"]), f"{side} level two", BEGIN, END)
            if set(trace) != level_two_keys or trace["profile.level"] != "2":
                raise harness.HarnessError(f"{side} omitted level-two worker reset observations")
            for stage in stages:
                for field in ("normal", "threads", "heaps", "theaps", "requested", "first_bin",
                              "second_bin", "first_page_bin", "second_page_bin"):
                    if len(trace[f"{stage}.{field}"].split(",")) != 3:
                        raise harness.HarnessError(f"{side} malformed {stage}.{field}")
            for stage in snapshot_stages:
                for field in snapshot_count_fields:
                    if len(trace[f"snapshot.{stage}.{field}"].split(",")) != 3:
                        raise harness.HarnessError(f"{side} malformed snapshot.{stage}.{field}")
                for field in snapshot_pair_fields:
                    if len(trace[f"snapshot.{stage}.{field}"].split(",")) != 2:
                        raise harness.HarnessError(f"{side} malformed snapshot.{stage}.{field}")
            for key in level_two_keys:
                if key.startswith(("worker.", "process.")) and trace[key] != "absent":
                    try:
                        bytes.fromhex(trace[key])
                    except ValueError as error:
                        raise harness.HarnessError(f"{side} malformed {key}") from error
            level_two_traces[side] = trace
            level_two_executions[side] = execution["command"]
        level_two_source_expected = {
            "profile.level": "2", "allocation.usable": "64", "allocation.second_usable": "32768",
            "allocation.first_bin": "8", "allocation.second_bin": "44",
            "allocated.normal": "64,64,64", "reset.normal": "32832,32832,32832",
            "freed.normal": "0,32832,32832", "exited.normal": "0,32832,32832",
            "allocated.requested": "64,64,64", "reset.requested": "32832,32832,32832",
            "freed.requested": "32832,32832,32832", "exited.requested": "32832,32832,32832",
            "allocated.normal_count": "1", "reset.normal_count": "2",
            "freed.normal_count": "2", "exited.normal_count": "2",
            "allocated.first_bin": "1,1,1", "reset.first_bin": "1,1,1",
            "freed.first_bin": "0,1,1", "exited.first_bin": "0,1,1",
            "allocated.second_bin": "0,0,0", "reset.second_bin": "1,1,1",
            "freed.second_bin": "0,1,1", "exited.second_bin": "0,1,1",
            "allocated.first_page_bin": "1,1,1", "reset.first_page_bin": "1,1,1",
            "freed.first_page_bin": "1,1,1", "exited.first_page_bin": "0,1,1",
            "allocated.second_page_bin": "0,0,0", "reset.second_page_bin": "1,1,1",
            "freed.second_page_bin": "1,1,1", "exited.second_page_bin": "0,1,1",
        }
        level_two_source_expected.update({f"{stage}.heaps": "0,0,0" for stage in stages})
        level_two_source_expected.update({
            f"{stage}.threads": "0,1,1" if stage == "exited" else "1,1,1"
            for stage in stages})
        level_two_source_expected.update({
            f"{stage}.theaps": "0,1,1" if stage == "exited" else "1,1,1"
            for stage in stages})
        if any(level_two_traces["c"][key] != value
               for key, value in level_two_source_expected.items()):
            raise harness.HarnessError("pinned C lost level-two worker reset accounting")
        level_two_c = level_two_traces["c"]
        source_theaps = {"preworker": "1,1,1", "first_allocation": "2,2,2",
                         "reset": "2,2,2", "exit": "1,2,2"}
        if any(level_two_c[f"snapshot.{stage}.theaps"] != expected
               for stage, expected in source_theaps.items()):
            raise harness.HarnessError("pinned C lost static and worker Theap publication")
        if not (level_two_c["worker.live_owner"] == level_two_c["worker.reset_owner"]
                == level_two_c["worker.freed_owner"]
                and bytes.fromhex(level_two_c["worker.live_owner"]).startswith(b"heap ")
                and bytes.fromhex(level_two_c["process.exited_owner"]).startswith(b"subproc ")
                and b"not all freed" in bytes.fromhex(level_two_c["worker.live_first_bin"])
                and b"64" in bytes.fromhex(level_two_c["worker.live_requested"])
                and level_two_c["worker.reset_second_bin"] == "absent"
                and b"ok" in bytes.fromhex(level_two_c["process.exited_first_bin"])
                and b"ok" in bytes.fromhex(level_two_c["process.exited_second_bin"])
                and b"32.1 KiB" in bytes.fromhex(level_two_c["process.exited_requested"])):
            raise harness.HarnessError("pinned C lost level-two worker/process output")
        level_two_mismatch = sorted(key for key in level_two_traces["c"].keys()
                                    - raw_output_keys - variable_snapshot_keys
                                    if level_two_traces["c"][key] != level_two_traces["rust"][key])
        variable_snapshot_mismatch = sorted(key for key in variable_snapshot_keys
                                            if level_two_traces["c"][key] != level_two_traces["rust"][key])
        first_deterministic_snapshot_difference = next((
            {"stage": stage, "field": field, "c": level_two_c[f"snapshot.{stage}.{field}"],
             "rust": level_two_traces["rust"][f"snapshot.{stage}.{field}"]}
            for stage in snapshot_stages
            for field in (*snapshot_count_fields, "process_commit", "current_rss",
                          "mmap_calls", "commit_calls", "arena_count")
            if level_two_c[f"snapshot.{stage}.{field}"]
            != level_two_traces["rust"][f"snapshot.{stage}.{field}"]
        ), None)
        raw_output_mismatch = sorted(key for key in raw_output_keys
                                     if level_two_traces["c"][key] != level_two_traces["rust"][key])
        raw_output_diffs = {
            key: list(difflib.unified_diff(
                bytes.fromhex(level_two_traces["c"][key]).decode().splitlines(),
                bytes.fromhex(level_two_traces["rust"][key]).decode().splitlines(),
                fromfile="pinned-c", tofile="rust", lineterm=""))
            for key in raw_output_mismatch
        }
        report = {
            "status": ("red" if mismatch or level_two_mismatch else
                       "partial" if raw_output_mismatch else "passed"),
            "git": engine.git_provenance(),
            "pin": {key: pin[key] for key in ("tag", "sha256", "revision")},
            "source_files": harness.source_file_records(source, (
                "include/mimalloc-stats.h", "src/stats.c", "src/init.c", "src/heap.c",
                "src/theap.c", "src/alloc.c", "src/free.c", "src/page.c", "src/os.c",
                "src/prim/unix/prim.c", "src/static.c")),
            "fixture_sha256": hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
            "reader_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "rust_source_sha256": {
                path: hashlib.sha256((harness.ROOT / path).read_bytes()).hexdigest()
                for path in ("crabc-mimalloc/src/statistics.rs", "crabc-mimalloc/src/runtime_lifecycle.rs",
                             "crabc-mimalloc/src/main_theap.rs",
                             "crabc-mimalloc/src/single_thread.rs", "crabc-mimalloc/src/diagnostic_output.rs",
                             "crabc-mimalloc/src/os.rs", "crabc-mimalloc/src/subproc_main_heaps.rs",
                             "compat/allocator/native-mi-adapter/src/lib.rs", "Cargo.lock")},
            "c_build_command": c_build["command"], "rust_build_command": rust_build["command"],
            "rust_link_command": rust_link["command"], "executions": executions,
            "traces": traces, "mismatch_keys": mismatch,
            "level_two_c_build_command": level_two_c_build["command"],
            "level_two_rust_build_command": level_two_rust_build["command"],
            "level_two_rust_link_command": level_two_rust_link["command"],
            "level_two_executions": level_two_executions,
            "level_two_traces": level_two_traces, "level_two_mismatch_keys": level_two_mismatch,
            "level_two_variable_snapshot_mismatch_keys": variable_snapshot_mismatch,
            "first_deterministic_snapshot_difference": first_deterministic_snapshot_difference,
            "level_two_raw_output_mismatch_keys": raw_output_mismatch,
            "level_two_raw_output_status": "unproved" if raw_output_mismatch else "matched",
            "level_two_raw_output_diffs": raw_output_diffs,
        }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    harness.write_json(REPORT, report)
    print("worker reset level one: " + ("RED " + ",".join(mismatch) if mismatch else "matched"))
    print("worker reset level two: " + ("RED " + ",".join(level_two_mismatch)
                                        if level_two_mismatch else "matched"))
    print("worker reset level two full output: " + report["level_two_raw_output_status"])
    print(f"report: {harness.relative(REPORT)}")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except harness.HarnessError as error:
        print(f"ERROR: {error}")
        raise SystemExit(2)
