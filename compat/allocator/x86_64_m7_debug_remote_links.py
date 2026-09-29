#!/usr/bin/env python3
"""Compare source-built C and Rust debug remote-free collection."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path

import run as harness
import perf_engine_x86_64 as engine
from x86_64_m7_gate import parse_options_trace


FIXTURE = harness.ALLOCATOR_ROOT / "x86_64_m7_debug_remote_links_oracle.c"
BEGIN = "CRABC_MI_DEBUG_REMOTE_TRACE_BEGIN"
END = "CRABC_MI_DEBUG_REMOTE_TRACE_END"
TARGET = "x86_64-unknown-linux-musl"
REPORT = harness.ARTIFACT_ROOT / "x86_64/m7-debug-remote-links/profile.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    arguments = parser.parse_args()
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, arguments.offline)
    compiler = harness.require_tool("musl-gcc")
    cargo = harness.require_tool("cargo")
    with harness.temporary_directory("crabc-mimalloc-x86_64-m7-debug-remote-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        profile = [flag for flag in harness.CONFIGURATION_PROFILES["release"]
                   if not flag.startswith(("-DMI_DEBUG=", "-DMI_STAT="))]
        profile.extend(("-DMI_DEBUG=1", "-DMI_PADDING=1"))
        common = [compiler, "-std=c11", "-O2", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                  *profile, "-I", str(source / "include"), str(FIXTURE)]
        c_binary = temporary / "remote-c"
        c_build = harness.command_record([*common, str(source / "src/static.c"), "-pthread", "-o", str(c_binary)], cwd=source)
        harness.require_success(c_build, "pinned debug remote C build")
        target = harness.WORK_ROOT / "cargo-target/m7-debug-remote-links"
        rust_build = harness.command_record([
            cargo, "build", "--locked", "--offline", "--release", "--target", TARGET,
            "-p", "crabc-mimalloc-native-mi-adapter", "--no-default-features",
            "--features", "crabc-mimalloc/mi-debug-1", "--target-dir", str(target),
        ], cwd=harness.ROOT, env=dict(os.environ), timeout_seconds=3600)
        harness.require_success(rust_build, "native debug remote adapter build")
        rust_binary = temporary / "remote-rust"
        rust_link = harness.command_record([
            *common, str(target / TARGET / "release" / "libcrabc_mimalloc_native_mi_adapter.a"),
            "-pthread", "-o", str(rust_binary),
        ], cwd=source)
        harness.require_success(rust_link, "native debug remote driver link")
        executions = {}
        traces = {}
        keys = {"usable", "other_usable", "survivor", "first_fill", "second_fill", "reused_remote"}
        for side, binary in (("c", c_binary), ("rust", rust_binary)):
            execution = harness.command_record([str(binary)], cwd=source, env={}, timeout_seconds=60)
            executions[side] = execution
            if execution["status"] == 0:
                traces[side] = parse_options_trace(str(execution["stdout"]), side, BEGIN, END)
            else:
                traces[side] = {}
        if (set(traces["c"]) != keys or traces["c"]["usable"] != "17"
                or traces["c"]["survivor"] != "51" or traces["c"]["reused_remote"] != "2"):
            raise harness.HarnessError("pinned C debug remote behavior changed")
        mismatch = sorted(key for key in keys if traces["c"].get(key) != traces["rust"].get(key))
        report = {
            "status": "red" if mismatch else "passed",
            "git": engine.git_provenance(),
            "pin": {key: pin[key] for key in ("tag", "sha256", "revision")},
            "source_files": harness.source_file_records(source, (
                "include/mimalloc/internal.h", "include/mimalloc/types.h", "src/free.c", "src/page.c", "src/static.c",
            )),
            "fixture_sha256": hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
            "reader_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "rust_source_sha256": {
                path: hashlib.sha256((harness.ROOT / path).read_bytes()).hexdigest()
                for path in ("crabc-mimalloc/src/free_list.rs", "crabc-mimalloc/src/remote_free.rs", "crabc-mimalloc/src/types.rs")
            },
            "c_build_command": c_build["command"],
            "rust_build_command": rust_build["command"],
            "rust_link_command": rust_link["command"],
            "executions": executions,
            "traces": traces,
            "mismatch_keys": mismatch,
        }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    harness.write_json(REPORT, report)
    print(f"debug remote links: {'RED ' + ','.join(mismatch) if mismatch else 'matched'}")
    print(f"report: {harness.relative(REPORT)}")
    return 1 if mismatch else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except harness.HarnessError as error:
        print(f"ERROR: {error}")
        raise SystemExit(2)
