#!/usr/bin/env python3
"""Compare a source-built worker statistics reset and exit in separate processes."""

from __future__ import annotations

import argparse
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
        report = {
            "status": "red" if mismatch else "passed", "git": engine.git_provenance(),
            "pin": {key: pin[key] for key in ("tag", "sha256", "revision")},
            "source_files": harness.source_file_records(source, (
                "include/mimalloc-stats.h", "src/stats.c", "src/init.c", "src/heap.c",
                "src/theap.c", "src/static.c")),
            "fixture_sha256": hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
            "reader_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "rust_source_sha256": {
                path: hashlib.sha256((harness.ROOT / path).read_bytes()).hexdigest()
                for path in ("crabc-mimalloc/src/statistics.rs", "crabc-mimalloc/src/runtime_lifecycle.rs",
                             "crabc-mimalloc/src/single_thread.rs", "crabc-mimalloc/src/diagnostic_output.rs",
                             "compat/allocator/native-mi-adapter/src/lib.rs", "Cargo.lock")},
            "c_build_command": c_build["command"], "rust_build_command": rust_build["command"],
            "rust_link_command": rust_link["command"], "executions": executions,
            "traces": traces, "mismatch_keys": mismatch,
        }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    harness.write_json(REPORT, report)
    print("worker reset: " + ("RED " + ",".join(mismatch) if mismatch else "matched"))
    print(f"report: {harness.relative(REPORT)}")
    return 1 if mismatch else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except harness.HarnessError as error:
        print(f"ERROR: {error}")
        raise SystemExit(2)
