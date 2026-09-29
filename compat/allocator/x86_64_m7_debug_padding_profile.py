#!/usr/bin/env python3
"""Source-built bounded debug-padding C/Rust probe in fresh processes."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path

import run as harness
import perf_engine_x86_64 as engine
from x86_64_m7_gate import parse_options_trace


FIXTURE = harness.ALLOCATOR_ROOT / "x86_64_m7_debug_padding_oracle.c"
BEGIN = "CRABC_MI_DEBUG_PADDING_TRACE_BEGIN"
END = "CRABC_MI_DEBUG_PADDING_TRACE_END"
RUST_TARGET = "x86_64-unknown-linux-musl"
ADAPTER = "crabc-mimalloc-native-mi-adapter"
STATICLIB = "libcrabc_mimalloc_native_mi_adapter.a"
REPORT = harness.ARTIFACT_ROOT / "x86_64/m7-debug-padding/profile.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    arguments = parser.parse_args()
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, arguments.offline)
    compiler = harness.require_tool("musl-gcc")
    cargo = harness.require_tool("cargo")
    with harness.temporary_directory("crabc-mimalloc-x86_64-m7-debug-padding-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        profile = [flag for flag in harness.CONFIGURATION_PROFILES["release"]
                   if not flag.startswith(("-DMI_DEBUG=", "-DMI_STAT="))]
        profile.extend(("-DMI_DEBUG=1", "-DMI_PADDING=1"))
        common = [compiler, "-std=c11", "-O2", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                  *profile, "-I", str(source / "include"), str(FIXTURE)]
        c_binary = temporary / "debug-padding-c"
        c_build = harness.command_record([
            *common, str(source / "src/static.c"), "-pthread", "-o", str(c_binary),
        ], cwd=source)
        harness.require_success(c_build, "pinned debug-padding C build")
        target = harness.WORK_ROOT / "cargo-target/m7-debug-padding-profile"
        rust_build = harness.command_record([
            cargo, "build", "--locked", "--offline", "--release", "--target", RUST_TARGET,
            "-p", ADAPTER, "--no-default-features", "--features", "crabc-mimalloc/mi-debug-1",
            "--target-dir", str(target),
        ], cwd=harness.ROOT, env=dict(os.environ), timeout_seconds=3600)
        harness.require_success(rust_build, "native debug-padding adapter build")
        rust_binary = temporary / "debug-padding-rust"
        rust_link = harness.command_record([
            *common, str(target / RUST_TARGET / "release" / STATICLIB),
            "-pthread", "-o", str(rust_binary),
        ], cwd=source)
        harness.require_success(rust_link, "native debug-padding driver link")
        traces = {}
        executions = {}
        expected_keys = {
            "case", "show_errors", "usable", "debug_uninit_fill", "error_count",
            "error_code", "overflow_diagnostic", "offset_17_diagnostic",
        }
        for side, binary in (("c", c_binary), ("rust", rust_binary)):
            for case in ("clean", "corrupt"):
                execution = harness.command_record([str(binary), case], cwd=source, env={}, timeout_seconds=60)
                harness.require_success(execution, f"{side} {case} debug-padding process")
                trace = parse_options_trace(str(execution["stdout"]), f"{side} {case}", BEGIN, END)
                if set(trace) != expected_keys or trace["case"] != case:
                    raise harness.HarnessError(f"{side} {case} omitted debug-padding observations")
                traces[f"{side}.{case}"] = trace
                executions[f"{side}.{case}"] = execution["command"]
        common_expected = {"show_errors": "1", "usable": "17", "debug_uninit_fill": "1"}
        for case, expected in (
            ("clean", {"error_count": "0", "error_code": "0", "overflow_diagnostic": "0",
                       "offset_17_diagnostic": "0"}),
            ("corrupt", {"error_count": "1", "error_code": "14", "overflow_diagnostic": "1",
                         "offset_17_diagnostic": "1"}),
        ):
            if any(traces[f"c.{case}"][key] != value for key, value in {**common_expected, **expected}.items()):
                raise harness.HarnessError(f"pinned C {case} lost its debug-padding source behavior")
        mismatch = {
            case: sorted(key for key in expected_keys
                         if traces[f"c.{case}"][key] != traces[f"rust.{case}"][key])
            for case in ("clean", "corrupt")
        }
        source_files = harness.source_file_records(source, (
            "include/mimalloc/types.h", "src/alloc.c", "src/free.c", "src/options.c", "src/static.c",
        ))
        report = {
            "status": "red" if any(mismatch.values()) else "passed",
            "git": engine.git_provenance(),
            "pin": {key: pin[key] for key in ("tag", "sha256", "revision")},
            "source_files": source_files,
            "fixture_sha256": hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
            "reader_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "rust_source_sha256": {
                path: hashlib.sha256((harness.ROOT / path).read_bytes()).hexdigest()
                for path in (
                    "crabc-mimalloc/Cargo.toml", "crabc-mimalloc/src/config.rs",
                    "crabc-mimalloc/src/size_class.rs", "crabc-mimalloc/src/alloc.rs",
                    "crabc-mimalloc/src/free_list.rs", "crabc-mimalloc/src/page.rs",
                    "crabc-mimalloc/src/local_fast_path.rs", "crabc-mimalloc/src/runtime_lifecycle.rs",
                    "crabc-mimalloc/src/types.rs", "crabc-mimalloc/src/single_thread.rs",
                    "crabc-mimalloc/src/source_api.rs", "crabc-mimalloc/src/diagnostic_output.rs",
                    "compat/allocator/native-mi-adapter/src/lib.rs", "Cargo.lock",
                )
            },
            "c_build_command": c_build["command"], "rust_build_command": rust_build["command"],
            "rust_link_command": rust_link["command"], "executions": executions,
            "traces": traces, "mismatch_keys": mismatch,
        }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    harness.write_json(REPORT, report)
    for case, keys in mismatch.items():
        print(f"{case}: {'matched' if not keys else 'RED ' + ','.join(keys)}")
    print(f"report: {harness.relative(REPORT)}")
    return 1 if report["status"] == "red" else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except harness.HarnessError as error:
        print(f"ERROR: {error}")
        raise SystemExit(2)
