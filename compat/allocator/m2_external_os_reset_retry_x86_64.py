#!/usr/bin/env python3
"""Compare caller-owned external reset retries with pinned C."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import run as harness
from x86_64_lifecycle_evidence import RUNTIME_THP_CONFIGURATION_C_ORACLE_LINK_SOURCES

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "compat/allocator/m2_external_os_reset_retry_x86_64.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m2-external-os-reset-retry"
TEST = "os::tests::emit_m2_external_os_reset_retry_process_trace"
PROFILES = ("one-eagain", "two-eagain")
FIELDS = (
    "profile", "purge_delay_raw", "purge_decommits_raw", "mapping_length",
    "raw_purge_length", "advice_calls",
    *(f"advice{index}_{suffix}" for index in (1, 2, 3)
      for suffix in ("exact", "result", "errno")),
    "needs_recommit", "purge_calls_delta", "purged_delta", "reset_calls_delta",
    "reset_delta", "reserved_delta", "committed_delta", "warning_calls",
    "neighbors_retained", "mapping_writable", "mapping_live",
    "terminal_unmap_calls", "terminal_unmap_exact", "caller_released",
)


def trace(output: str, language: str) -> dict[str, int]:
    begin = f"CRABC_M2_EXTERNAL_OS_RESET_RETRY_{language}_TRACE_BEGIN"
    end = f"CRABC_M2_EXTERNAL_OS_RESET_RETRY_{language}_TRACE_END"
    if output.count(begin) != 1 or output.count(end) != 1:
        raise RuntimeError(f"{language} reset retry trace markers are not unique")
    values: dict[str, int] = {}
    for line in output.split(begin, 1)[1].split(end, 1)[0].splitlines():
        if not line.strip():
            continue
        key, separator, raw = line.strip().partition("=")
        if not separator or key in values:
            raise RuntimeError(f"{language} reset retry trace has a malformed field")
        values[key] = int(raw)
    if set(values) != set(FIELDS):
        raise RuntimeError(f"{language} reset retry trace fields differ: {sorted(values)}")
    return values


def expected(profile: str) -> dict[str, int]:
    failures = 1 if profile == "one-eagain" else 2
    result = {
        "profile": failures, "purge_delay_raw": 0, "purge_decommits_raw": 0,
        "mapping_length": 3 * 4096, "raw_purge_length": 3 * 4096 - 2,
        "advice_calls": failures + 1, "needs_recommit": 0,
        "purge_calls_delta": 1, "purged_delta": 3 * 4096 - 2,
        "reset_calls_delta": 1, "reset_delta": 4096,
        "reserved_delta": 0, "committed_delta": 0, "warning_calls": 0,
        "neighbors_retained": 1, "mapping_writable": 1, "mapping_live": 1,
        "terminal_unmap_calls": 1, "terminal_unmap_exact": 1,
        "caller_released": 1,
    }
    for index in (1, 2, 3):
        attempted = index <= failures + 1
        result[f"advice{index}_exact"] = int(attempted)
        result[f"advice{index}_result"] = -1 if index <= failures else 0
        result[f"advice{index}_errno"] = 11 if index <= failures else 0
    return result


def c_oracle(*, offline: bool) -> tuple[dict[str, dict[str, int]], dict[str, Any]]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline=offline)
    compiler = harness.require_tool("musl-gcc")
    with harness.temporary_directory(prefix="crabc-mimalloc-m2-external-reset-retry-") as temporary:
        source = harness.safe_extract(archive, Path(temporary), pin["archive_root"])
        binary = ARTIFACTS / "pinned-c-external-os-reset-retry"
        command = [
            compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE),
            *(str(source / name) for name in RUNTIME_THP_CONFIGURATION_C_ORACLE_LINK_SOURCES),
            "-Wl,--wrap=madvise", "-Wl,--wrap=munmap", "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C external reset retry build")
        rows: dict[str, dict[str, int]] = {}
        runs = {}
        for profile in PROFILES:
            execution = harness.command_record([str(binary), profile], cwd=source, env={}, timeout_seconds=120)
            harness.require_success(execution, f"pinned C external reset retry {profile}")
            rows[profile] = trace(str(execution["stdout"]), "C")
            runs[profile] = {"status": execution["status"], "stderr": execution["stderr"]}
        return rows, {"build_status": build["status"], "runs": runs}


def rust_receiver() -> tuple[dict[str, dict[str, int]], dict[str, Any]]:
    command = [
        "cargo", "test", "--locked", "--target", "x86_64-unknown-linux-musl",
        "-p", "crabc-mimalloc", "--lib", "--no-default-features", "--no-run",
        "--message-format=json",
    ]
    build = harness.command_record(command, cwd=ROOT, timeout_seconds=3600)
    harness.require_success(build, "Rust external reset retry receiver build")
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
    rows: dict[str, dict[str, int]] = {}
    runs = {}
    for profile in PROFILES:
        execution = harness.command_record(
            [str(candidates[0]), TEST, "--exact", "--nocapture", "--test-threads=1"],
            cwd=ROOT, env={"CRABC_M2_EXTERNAL_RESET_RETRY_PROFILE": profile}, timeout_seconds=120,
        )
        harness.require_success(execution, f"Rust external reset retry {profile}")
        if "test result: ok. 1 passed; 0 failed" not in str(execution["stdout"]):
            raise RuntimeError(f"Rust external reset retry {profile} did not execute once")
        rows[profile] = trace(str(execution["stdout"]), "RUST")
        runs[profile] = {"status": execution["status"], "stderr": execution["stderr"]}
    return rows, {"build_status": build["status"], "runs": runs}


def run(*, offline: bool, c_only: bool) -> dict[str, Any]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    c, c_commands = c_oracle(offline=offline)
    rust, rust_commands = ({}, {}) if c_only else rust_receiver()
    mismatches = []
    for profile in PROFILES:
        for language, rows in (("c", c), ("rust", rust)):
            if language == "rust" and c_only:
                continue
            mismatches.extend(f"{language}.{profile}.{field}" for field in FIELDS
                              if rows[profile][field] != expected(profile)[field])
        if not c_only:
            mismatches.extend(f"differential.{profile}.{field}" for field in FIELDS
                              if c[profile][field] != rust[profile][field])
    if any(run["stderr"] for run in c_commands["runs"].values()):
        mismatches.append("c.unrouted_diagnostics")
    if not c_only and any(run["stderr"] for run in rust_commands["runs"].values()):
        mismatches.append("rust.unrouted_diagnostics")
    report = {
        "status": "matched" if not mismatches else "red", "c": c, "rust": rust,
        "mismatches": mismatches, "c_commands": c_commands,
        "rust_commands": rust_commands,
        "scope": "fresh caller-owned external mapping; one or two MADV_FREE EAGAIN retries to success, no EINVAL fallback, source accounting and caller terminal unmap",
    }
    (ARTIFACTS / "evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"external OS reset retry {report['status'].upper()} ({len(PROFILES)} profiles, {len(FIELDS)} fields each)")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--c-only", action="store_true")
    arguments = parser.parse_args()
    raise SystemExit(0 if run(offline=arguments.offline, c_only=arguments.c_only)["status"] == "matched" else 1)
