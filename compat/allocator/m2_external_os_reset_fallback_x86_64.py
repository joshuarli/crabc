#!/usr/bin/env python3
"""Compare the cached external reset advice fallback with pinned C."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import run as harness
from x86_64_lifecycle_evidence import RUNTIME_THP_CONFIGURATION_C_ORACLE_LINK_SOURCES


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "compat/allocator/m2_external_os_reset_fallback_x86_64.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m2-external-os-reset-fallback"
TEST = "os::tests::emit_m2_external_os_reset_fallback_process_trace"
FIELDS = (
    "purge_delay_raw", "purge_decommits_raw", "mapping_length", "raw_purge_length",
    "advice_calls", "first_exact", "fallback_exact", "cached_exact",
    "first_result", "fallback_result", "cached_result",
    "first_needs_recommit", "second_needs_recommit",
    "first_purge_calls_delta", "first_purged_delta",
    "first_reset_calls_delta", "first_reset_delta",
    "purge_calls_delta", "purged_delta", "reset_calls_delta", "reset_delta",
    "reserved_delta", "committed_delta", "warning_calls",
    "writable_after_first", "neighbors_retained", "writable_after_second",
    "mapping_live", "terminal_unmap_calls", "terminal_unmap_exact", "caller_released",
)


def trace(output: str, language: str) -> dict[str, int]:
    begin = f"CRABC_M2_EXTERNAL_OS_RESET_FALLBACK_{language}_TRACE_BEGIN"
    end = f"CRABC_M2_EXTERNAL_OS_RESET_FALLBACK_{language}_TRACE_END"
    if output.count(begin) != 1 or output.count(end) != 1:
        raise RuntimeError(f"{language} fallback trace markers are not unique")
    values: dict[str, int] = {}
    for line in output.split(begin, 1)[1].split(end, 1)[0].splitlines():
        if not line.strip():
            continue
        key, separator, raw = line.strip().partition("=")
        if not separator or key in values:
            raise RuntimeError(f"{language} fallback trace has a malformed field")
        values[key] = int(raw)
    if set(values) != set(FIELDS):
        raise RuntimeError(f"{language} fallback trace fields differ: {sorted(values)}")
    return values


def c_oracle(*, offline: bool) -> tuple[dict[str, int], dict[str, Any]]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline=offline)
    compiler = harness.require_tool("musl-gcc")
    with harness.temporary_directory(prefix="crabc-mimalloc-m2-external-reset-fallback-") as temporary:
        source = harness.safe_extract(archive, Path(temporary), pin["archive_root"])
        binary = ARTIFACTS / "pinned-c-external-os-reset-fallback"
        command = [
            compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"),
            *harness.CONFIGURATION_PROFILES["release"], str(FIXTURE),
            *(str(source / name) for name in RUNTIME_THP_CONFIGURATION_C_ORACLE_LINK_SOURCES),
            "-Wl,--wrap=madvise", "-Wl,--wrap=munmap", "-pthread",
            "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C external reset fallback build")
        execution = harness.command_record([str(binary)], cwd=source, env={}, timeout_seconds=120)
        harness.require_success(execution, "pinned C external reset fallback")
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
    harness.require_success(build, "Rust external reset fallback receiver build")
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
    harness.require_success(execution, "Rust external reset fallback receiver")
    if "test result: ok. 1 passed; 0 failed" not in str(execution["stdout"]):
        raise RuntimeError("Rust external reset fallback receiver did not execute once")
    return trace(str(execution["stdout"]), "RUST"), {
        "build_status": build["status"], "run_status": execution["status"],
        "stderr": str(execution["stderr"]),
    }


def run(*, offline: bool) -> dict[str, Any]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    c, c_commands = c_oracle(offline=offline)
    rust, rust_commands = rust_receiver()
    expected = {
        "purge_delay_raw": 0, "purge_decommits_raw": 0,
        "mapping_length": 3 * 4096, "raw_purge_length": 3 * 4096 - 2,
        "advice_calls": 3, "first_exact": 1, "fallback_exact": 1,
        "cached_exact": 1, "first_result": -1,
        "fallback_result": 0, "cached_result": 0,
        "first_needs_recommit": 0, "second_needs_recommit": 0,
        "first_purge_calls_delta": 1,
        "first_purged_delta": 3 * 4096 - 2,
        "first_reset_calls_delta": 1, "first_reset_delta": 4096,
        "purge_calls_delta": 2, "purged_delta": 2 * (3 * 4096 - 2),
        "reset_calls_delta": 2, "reset_delta": 2 * 4096,
        "reserved_delta": 0, "committed_delta": 0,
        "warning_calls": 0, "writable_after_first": 1,
        "neighbors_retained": 1, "writable_after_second": 1,
        "mapping_live": 1, "terminal_unmap_calls": 1,
        "terminal_unmap_exact": 1, "caller_released": 1,
    }
    mismatches = [field for field in FIELDS if c[field] != rust[field]]
    for language, values in (("c", c), ("rust", rust)):
        mismatches.extend(f"{language}.{field}" for field, value in expected.items()
                          if values[field] != value)
    if c_commands["stderr"] or rust_commands["stderr"]:
        mismatches.append("unrouted_diagnostics")
    report = {
        "status": "matched" if not mismatches else "red",
        "c": c, "rust": rust, "mismatches": mismatches,
        "c_commands": c_commands, "rust_commands": rust_commands,
        "scope": "fresh process, caller-owned external mapping; first MADV_FREE EINVAL, immediate MADV_DONTNEED fallback, cached MADV_DONTNEED on later purge; exact contained advice, stats, warning absence and caller terminal munmap",
    }
    (ARTIFACTS / "evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"external OS reset fallback {report['status'].upper()} ({len(FIELDS)} exact relations)")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    arguments = parser.parse_args()
    raise SystemExit(0 if run(offline=arguments.offline)["status"] == "matched" else 1)
