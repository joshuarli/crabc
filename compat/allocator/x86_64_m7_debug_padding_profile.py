#!/usr/bin/env python3
"""Source-built bounded debug-padding C/Rust probe in fresh processes."""

from __future__ import annotations

import argparse
import contextlib
import json
import hashlib
import os
import subprocess
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
CASES = [(case,) for case in ("clean", "corrupt")] + [
    (case, shape, operation, route)
    for case in ("clean", "corrupt") for shape in ("small", "arena", "os", "os-small")
    for operation in ("malloc", "calloc", "realloc", "rezalloc", "record")
    for route in ("local", "remote", "owner-exit") if shape != "small" or operation != "record"
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--replay", action="store_true")
    arguments = parser.parse_args()
    harness.require_native_x86_64()
    pin = harness.load_pin()
    if arguments.replay:
        report = json.loads(REPORT.read_text())
        if report["git"] != engine.git_provenance() or not report["git"].get("clean"):
            raise harness.HarnessError("debug-padding replay requires its exact clean source")
        for path, record in report["files"].items():
            if engine.file_record(harness.ROOT / path) != record:
                raise harness.HarnessError(f"debug-padding retained input differs: {path}")
        if any(hashlib.sha256((harness.ROOT / path).read_bytes()).hexdigest() != digest
               for path, digest in report["rust_source_sha256"].items()):
            raise harness.HarnessError("debug-padding retained Rust source differs")
        source = REPORT.parent / "profile/source" / pin["archive_root"]
        if engine.tree_digest((source / "src", source / "include")) != report["source_tree"]:
            raise harness.HarnessError("debug-padding retained C source differs")
        expected = {f"{side}.{'.'.join(case)}" for side in ("c", "rust") for case in CASES}
        if set(report["executions"]) != expected:
            raise harness.HarnessError("debug-padding receipt omits selected cases")
        for side in ("c", "rust"):
            binary = REPORT.parent / "profile" / f"debug-padding-{side}"
            for case in CASES:
                name = f"{side}.{'.'.join(case)}"
                execution = subprocess.run([str(binary), *case], cwd=binary.parent, env={},
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
                if execution.returncode != report["executions"][name]["status"]:
                    raise harness.HarnessError(f"debug-padding retained execution status differs: {name}")
                trace = parse_options_trace(execution.stdout.decode("ascii"), name, BEGIN, END)
                if trace != report["traces"][name]:
                    raise harness.HarnessError(f"debug-padding retained observations differ: {name}")
        mismatch = {".".join(case): sorted(
            key for key in set(report["traces"][f"c.{'.'.join(case)}"]) | set(report["traces"][f"rust.{'.'.join(case)}"])
            if report["traces"][f"c.{'.'.join(case)}"].get(key) != report["traces"][f"rust.{'.'.join(case)}"].get(key))
            for case in CASES}
        if mismatch != report["mismatch_keys"] or report["status"] != ("red" if any(mismatch.values()) else "passed"):
            raise harness.HarnessError("debug-padding retained verdict differs from executable observations")
        print("debug-padding retained physical observations matched")
        return int(report["status"] != "passed")
    archive = harness.fetch_archive(pin, arguments.offline)
    source_git = engine.git_provenance()
    source_before = engine.tree_digest((harness.ROOT / "crabc-mimalloc/src",
                                       harness.ROOT / "compat/allocator/native-mi-adapter/src"))
    fixture_before = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    reader_before = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    compiler = harness.require_tool("musl-gcc")
    cargo = harness.require_tool("cargo")
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.nullcontext(REPORT.parent / "profile") as name:
        temporary = Path(name)
        temporary.mkdir(parents=True, exist_ok=True)
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
        aligned_keys = {"case", "shape", "operation", "route", "usable", "request", "aligned",
                        "initial", "preserved", "growth_fill", "error_count", "error_code",
                        "overflow_diagnostic", "owned_after_collect"}
        for side, binary in (("c", c_binary), ("rust", rust_binary)):
            for arguments in CASES:
                case = ".".join(arguments)
                execution = harness.command_record([str(binary), *arguments], cwd=source, env={}, timeout_seconds=60)
                for stream in ("stdout", "stderr"):
                    (temporary / f"{side}.{case}.{stream}").write_text(str(execution[stream]))
                executions[f"{side}.{case}"] = execution
                if execution["status"] != 0:
                    traces[f"{side}.{case}"] = {}
                    continue
                trace = parse_options_trace(str(execution["stdout"]), f"{side} {case}", BEGIN, END)
                if set(trace) != (expected_keys if len(arguments) == 1 else aligned_keys) or trace["case"] != arguments[0]:
                    raise harness.HarnessError(f"{side} {case} omitted debug-padding observations")
                traces[f"{side}.{case}"] = trace
        common_expected = {"show_errors": "1", "usable": "17", "debug_uninit_fill": "1"}
        for case, expected in (
            ("clean", {"error_count": "0", "error_code": "0", "overflow_diagnostic": "0",
                       "offset_17_diagnostic": "0"}),
            ("corrupt", {"error_count": "1", "error_code": "14", "overflow_diagnostic": "1",
                         "offset_17_diagnostic": "1"}),
        ):
            if any(traces[f"c.{case}"][key] != value for key, value in {**common_expected, **expected}.items()):
                raise harness.HarnessError(f"pinned C {case} lost its debug-padding source behavior")
        mismatch = {}
        for arguments in CASES:
            case = ".".join(arguments)
            c, rust = traces[f"c.{case}"], traces[f"rust.{case}"]
            mismatch[case] = sorted(key for key in set(c) | set(rust) if c.get(key) != rust.get(key))
            if not c or not rust:
                mismatch[case].append("execution")
            if len(arguments) > 1 and c:
                if any(c[key] != "1" for key in ("aligned", "initial", "preserved", "growth_fill")):
                    raise harness.HarnessError(f"pinned C {case} lost its allocation/zero/reallocation contract")
                corrupt, shape, operation, _ = arguments
                detected = corrupt == "corrupt" and (shape == "small" or operation == "record")
                for key, value in {"error_count": str(int(detected)), "error_code": "14" if detected else "0",
                                   "overflow_diagnostic": str(int(detected)),
                                   "owned_after_collect": str(int(detected))}.items():
                    if c[key] != value:
                        raise harness.HarnessError(f"pinned C {case} lost its {key} corruption/retention behavior")
        source_files = harness.source_file_records(source, (
            "include/mimalloc/types.h", "src/alloc.c", "src/free.c", "src/options.c", "src/static.c",
        ))
        if (source_git != engine.git_provenance()
                or source_before != engine.tree_digest((harness.ROOT / "crabc-mimalloc/src",
                                                       harness.ROOT / "compat/allocator/native-mi-adapter/src"))
                or fixture_before != hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
                or reader_before != hashlib.sha256(Path(__file__).read_bytes()).hexdigest()):
            raise harness.HarnessError("debug-padding source changed while its evidence executed")
        report = {
            "status": "red" if any(mismatch.values()) else "passed",
            "git": source_git,
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
            "source_tree": engine.tree_digest((source / "src", source / "include")),
            "files": {harness.relative(path): engine.file_record(path) for path in (
                FIXTURE, Path(__file__), c_binary, rust_binary,
                target / RUST_TARGET / "release" / STATICLIB,
                *(temporary / f"{side}.{'.'.join(case)}.{stream}" for side in ("c", "rust")
                  for case in CASES for stream in ("stdout", "stderr")),
            )},
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
