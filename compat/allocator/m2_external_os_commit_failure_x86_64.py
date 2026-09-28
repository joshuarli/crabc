#!/usr/bin/env python3
"""Compare failed mixed external OS commit and retry with pinned C."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import run as harness
from x86_64_lifecycle_evidence import RUNTIME_THP_CONFIGURATION_C_ORACLE_LINK_SOURCES


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "compat/allocator/m2_external_os_commit_failure_x86_64.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m2-external-os-commit-failure"
TEST = "os::tests::emit_m2_external_os_commit_failure_process_trace"
FIELDS = (
    "mapping_length", "already_committed", "attempts", "first_exact",
    "retry_exact", "first_primitive_result", "retry_primitive_result",
    "first_source_committed", "retry_source_committed", "calls_after_failure",
    "current_after_failure", "total_after_failure", "warning_calls",
    "warning_after_call", "warning_before_charge", "warning_exact",
    "first_retained", "mapping_live_after_failure", "calls_after_retry",
    "current_after_retry", "total_after_retry", "reserved_delta",
    "second_writable", "terminal_unmap_calls", "terminal_unmap_exact",
    "caller_released",
)


def trace(output: str, language: str) -> dict[str, int]:
    begin = f"CRABC_M2_EXTERNAL_OS_COMMIT_FAILURE_{language}_TRACE_BEGIN"
    end = f"CRABC_M2_EXTERNAL_OS_COMMIT_FAILURE_{language}_TRACE_END"
    if output.count(begin) != 1 or output.count(end) != 1:
        raise RuntimeError(f"{language} external commit failure trace markers are not unique")
    values: dict[str, int] = {}
    for line in output.split(begin, 1)[1].split(end, 1)[0].splitlines():
        if not line.strip():
            continue
        key, separator, raw = line.strip().partition("=")
        if not separator or key in values:
            raise RuntimeError(f"{language} external commit failure trace is malformed")
        values[key] = int(raw)
    if set(values) != set(FIELDS):
        raise RuntimeError(f"{language} external commit failure fields differ: {sorted(values)}")
    return values


def c_oracle(*, offline: bool) -> tuple[dict[str, int], dict[str, Any]]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline=offline)
    compiler = harness.require_tool("musl-gcc")
    with harness.temporary_directory(prefix="crabc-mimalloc-m2-external-commit-failure-") as temporary:
        source = harness.safe_extract(archive, Path(temporary), pin["archive_root"])
        binary = ARTIFACTS / "pinned-c-external-os-commit-failure"
        command = [
            compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"),
            *harness.CONFIGURATION_PROFILES["release"], str(FIXTURE),
            *(str(source / name) for name in RUNTIME_THP_CONFIGURATION_C_ORACLE_LINK_SOURCES),
            "-Wl,--wrap=mprotect", "-Wl,--wrap=munmap", "-pthread",
            "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C external commit failure build")
        execution = harness.command_record([str(binary)], cwd=source, env={}, timeout_seconds=120)
        harness.require_success(execution, "pinned C external commit failure")
        return trace(str(execution["stdout"]), "C"), {
            "build_status": build["status"], "run_status": execution["status"],
            "stderr": str(execution["stderr"]),
        }


def rust_receiver() -> tuple[dict[str, int], dict[str, Any]]:
    command = [
        "cargo", "test", "--locked", "--target", "x86_64-unknown-linux-musl",
        "-p", "crabc-mimalloc", "--lib", "--no-default-features", "--no-run",
        "--message-format=json",
    ]
    build = harness.command_record(command, cwd=ROOT, timeout_seconds=3600)
    harness.require_success(build, "Rust external commit failure build")
    candidates: list[Path] = []
    for line in str(build["stdout"]).splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        target = event.get("target", {})
        profile = event.get("profile", {})
        if (event.get("reason") == "compiler-artifact" and target.get("name") == "crabc_mimalloc"
                and target.get("kind") == ["lib"] and profile.get("test") is True
                and isinstance(event.get("executable"), str)):
            candidates.append(Path(event["executable"]))
    if len(candidates) != 1:
        raise RuntimeError(f"expected one Rust library test binary, found {len(candidates)}")
    execution = harness.command_record(
        [str(candidates[0]), TEST, "--exact", "--nocapture", "--test-threads=1"],
        cwd=ROOT, env={}, timeout_seconds=120,
    )
    harness.require_success(execution, "Rust external commit failure receiver")
    if "test result: ok. 1 passed; 0 failed" not in str(execution["stdout"]):
        raise RuntimeError("Rust external commit failure receiver did not execute once")
    return trace(str(execution["stdout"]), "RUST"), {
        "build_status": build["status"], "run_status": execution["status"],
        "stderr": str(execution["stderr"]),
    }


def run(*, offline: bool) -> dict[str, Any]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    c, c_commands = c_oracle(offline=offline)
    rust, rust_commands = rust_receiver()
    expected = {
        "mapping_length": 8192, "already_committed": 4096, "attempts": 2,
        "first_exact": 1, "retry_exact": 1,
        "first_primitive_result": -1, "retry_primitive_result": 0,
        "first_source_committed": 0, "retry_source_committed": 1,
        "calls_after_failure": 1, "current_after_failure": 0,
        "total_after_failure": 0, "warning_calls": 1,
        "warning_after_call": 1, "warning_before_charge": 1,
        "warning_exact": 1, "first_retained": 1,
        "mapping_live_after_failure": 1, "calls_after_retry": 2,
        "current_after_retry": 4096, "total_after_retry": 4096,
        "reserved_delta": 0, "second_writable": 1,
        "terminal_unmap_calls": 1, "terminal_unmap_exact": 1,
        "caller_released": 1,
    }
    mismatches = [field for field in FIELDS if c[field] != rust[field]]
    for language, values in (("c", c), ("rust", rust)):
        mismatches.extend(f"{language}.{field}" for field, value in expected.items() if values[field] != value)
    if c_commands["stderr"] or rust_commands["stderr"]:
        mismatches.append("unrouted_diagnostics")
    report = {
        "status": "matched" if not mismatches else "red",
        "c": c, "rust": rust, "mismatches": mismatches,
        "c_commands": c_commands, "rust_commands": rust_commands,
        "scope": "fresh process; failed mixed external mprotect and one explicit successful retry; warning-time commit call and no-charge state; terminal caller munmap",
    }
    (ARTIFACTS / "evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"external OS commit failure {report['status'].upper()} ({len(FIELDS)} exact relations)")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    arguments = parser.parse_args()
    raise SystemExit(0 if run(offline=arguments.offline)["status"] == "matched" else 1)
