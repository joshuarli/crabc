#!/usr/bin/env python3
"""Compare a pinned debug-padding regular page with the native Rust adapter."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path

import perf_engine_x86_64 as engine
import run as harness
from x86_64_m7_gate import parse_options_trace


FIXTURE = harness.ALLOCATOR_ROOT / "x86_64_m7_debug_padding_page_oracle.c"
BEGIN = "CRABC_MI_M7_DEBUG_PADDING_PAGE_TRACE_BEGIN"
END = "CRABC_MI_M7_DEBUG_PADDING_PAGE_TRACE_END"
REPORT = harness.ARTIFACT_ROOT / "x86_64/m7-debug-padding/page.json"
TARGET = "x86_64-unknown-linux-musl"
STATICLIB = "libcrabc_mimalloc_native_mi_adapter.a"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    arguments = parser.parse_args()
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, arguments.offline)
    compiler = harness.require_tool("musl-gcc")
    cargo = harness.require_tool("cargo")
    with harness.temporary_directory("crabc-mimalloc-x86_64-m7-debug-padding-page-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        profile = [flag for flag in harness.CONFIGURATION_PROFILES["release"]
                   if not flag.startswith(("-DMI_DEBUG=", "-DMI_STAT="))]
        profile.extend(("-DMI_DEBUG=1", "-DMI_PADDING=1", "-DMI_STAT=2"))
        common = [compiler, "-std=c11", "-O2", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                  *profile, "-I", str(source / "include"), str(FIXTURE)]
        c_binary = temporary / "debug-padding-page-c"
        c_build = harness.command_record([
            *common, str(source / "src/static.c"), "-pthread", "-o", str(c_binary),
        ], cwd=source)
        harness.require_success(c_build, "pinned debug-padding page C build")
        target = harness.WORK_ROOT / "cargo-target/m7-debug-padding-page"
        rust_build = harness.command_record([
            cargo, "build", "--locked", "--offline", "--release", "--target", TARGET,
            "-p", "crabc-mimalloc-native-mi-adapter", "--no-default-features",
            "--features", "crabc-mimalloc/mi-debug-1", "--target-dir", str(target),
        ], cwd=harness.ROOT, env=dict(os.environ), timeout_seconds=3600)
        harness.require_success(rust_build, "native debug-padding page adapter build")
        rust_binary = temporary / "debug-padding-page-rust"
        rust_link = harness.command_record([
            *common, str(target / TARGET / "release" / STATICLIB),
            "-pthread", "-o", str(rust_binary),
        ], cwd=source)
        harness.require_success(rust_link, "native debug-padding page driver link")
        traces = {}
        executions = {}
        expected_keys = {
            "case", "usable", "good_size", "debug_uninit_fill_bytes", "same_page",
            "owned.live", "owned.after_first_free", "errors.after_first_free",
            "error_code.after_first_free", "diagnostic.overflow", "diagnostic.offset_17",
        }
        expected_keys.update(f"{stage}.{field}" for stage in ("live", "after_first_free", "terminal")
                             for field in ("normal", "requested", "pages", "page_bin", "malloc_bin",
                                           "pages_retire"))
        for side, binary in (("c", c_binary), ("rust", rust_binary)):
            for case in ("clean", "corrupt"):
                execution = harness.command_record([str(binary), case], cwd=source, env={}, timeout_seconds=60)
                harness.require_success(execution, f"{side} {case} debug-padding page process")
                trace = parse_options_trace(str(execution["stdout"]), f"{side} {case}", BEGIN, END)
                if trace.get("case") != case or set(trace) != expected_keys:
                    raise harness.HarnessError(f"{side} {case} omitted debug-padding page observations")
                traces[f"{side}.{case}"] = trace
                executions[f"{side}.{case}"] = execution
        expected_common = {
            "usable": "17", "good_size": "32", "debug_uninit_fill_bytes": "17",
            "same_page": "1", "owned.live": "1", "owned.after_first_free": "1",
            "live.normal": "48,48,48", "live.requested": "34,34,34",
            "live.pages": "1,1,1", "live.page_bin": "1,1,1", "live.malloc_bin": "2,2,2",
            "live.pages_retire": "0",
        }
        for case, expected in (
            ("clean", {
                "errors.after_first_free": "0", "error_code.after_first_free": "0",
                "diagnostic.overflow": "0", "diagnostic.offset_17": "0",
                "after_first_free.normal": "24,48,48", "after_first_free.malloc_bin": "1,2,2",
                "terminal.normal": "0,48,48", "terminal.pages": "0,1,1",
                "terminal.page_bin": "0,1,1", "terminal.malloc_bin": "0,2,2",
                "terminal.pages_retire": "1",
            }),
            ("corrupt", {
                "errors.after_first_free": "1", "error_code.after_first_free": "14",
                "diagnostic.overflow": "1", "diagnostic.offset_17": "1",
                "after_first_free.normal": "48,48,48", "after_first_free.malloc_bin": "2,2,2",
                "terminal.normal": "24,48,48", "terminal.pages": "1,1,1",
                "terminal.page_bin": "1,1,1", "terminal.malloc_bin": "1,2,2",
                "terminal.pages_retire": "0",
            }),
        ):
            for key, value in {**expected_common, **expected}.items():
                if traces[f"c.{case}"].get(key) != value:
                    raise harness.HarnessError(f"pinned C {case} {key} lost its source behavior")
        keys = set(traces["c.clean"])
        if any(set(trace) != keys for trace in traces.values()):
            raise harness.HarnessError("C/Rust page trace key sets differ")
        mismatch = {case: sorted(key for key in keys if traces[f"c.{case}"][key] != traces[f"rust.{case}"][key])
                    for case in ("clean", "corrupt")}
        report = {
            "status": "red" if any(mismatch.values()) else "passed",
            "git": engine.git_provenance(),
            "pin": {key: pin[key] for key in ("tag", "sha256", "revision")},
            "source_files": harness.source_file_records(source, (
                "include/mimalloc/types.h", "include/mimalloc-stats.h", "src/alloc.c",
                "src/free.c", "src/page.c", "src/heap.c", "src/static.c",
            )),
            "fixture_sha256": hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
            "reader_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "rust_source_sha256": {
                path: hashlib.sha256((harness.ROOT / path).read_bytes()).hexdigest()
                for path in (
                    "crabc-mimalloc/Cargo.toml", "crabc-mimalloc/src/config.rs",
                    "crabc-mimalloc/src/page.rs", "crabc-mimalloc/src/alloc.rs",
                    "crabc-mimalloc/src/free_list.rs", "crabc-mimalloc/src/types.rs",
                    "crabc-mimalloc/src/local_fast_path.rs", "crabc-mimalloc/src/runtime_lifecycle.rs",
                    "crabc-mimalloc/src/size_class.rs", "crabc-mimalloc/src/single_thread.rs",
                    "compat/allocator/native-mi-adapter/src/lib.rs",
                    "Cargo.lock",
                )
            },
            "c_build_command": c_build["command"], "rust_build_command": rust_build["command"],
            "rust_link_command": rust_link["command"], "executions": executions,
            "traces": traces, "mismatch_keys": mismatch,
        }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    harness.write_json(REPORT, report)
    for case, values in mismatch.items():
        print(f"{case}: {'matched' if not values else 'RED ' + ','.join(values)}")
    print(f"report: {harness.relative(REPORT)}")
    return 1 if report["status"] == "red" else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except harness.HarnessError as error:
        print(f"ERROR: {error}")
        raise SystemExit(2)
