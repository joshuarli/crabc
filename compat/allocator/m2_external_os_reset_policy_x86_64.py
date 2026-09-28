#!/usr/bin/env python3
"""Compare caller-owned external reset advice success and failure with pinned C."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import run as harness
from x86_64_lifecycle_evidence import RUNTIME_THP_CONFIGURATION_C_ORACLE_LINK_SOURCES


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "compat/allocator/m2_external_os_reset_policy_x86_64.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m2-external-os-reset-policy"
TEST = "os::tests::emit_m2_external_os_reset_policy_process_trace"
CASES = ("success", "failure")
FIELDS = (
    "case_failure", "purge_delay_raw", "purge_decommits_raw",
    "external_mapping_length", "raw_purge_length", "advice_calls",
    "advice_exact", "advice_result", "needs_recommit",
    "purge_calls_delta", "purged_delta", "reset_calls_delta", "reset_delta",
    "reserved_delta", "committed_delta", "warning_calls",
    "warning_after_purge", "warning_after_reset", "warning_exact",
    "neighbors_retained", "mapping_writable", "mapping_live",
    "terminal_unmap_calls", "terminal_unmap_exact", "caller_released",
)


def trace(output: str, language: str) -> dict[str, int]:
    begin = f"CRABC_M2_EXTERNAL_OS_RESET_{language}_TRACE_BEGIN"
    end = f"CRABC_M2_EXTERNAL_OS_RESET_{language}_TRACE_END"
    if output.count(begin) != 1 or output.count(end) != 1:
        raise RuntimeError(f"{language} external reset trace markers are not unique")
    values: dict[str, int] = {}
    for line in output.split(begin, 1)[1].split(end, 1)[0].splitlines():
        if not line.strip():
            continue
        key, separator, raw = line.strip().partition("=")
        if not separator or key in values:
            raise RuntimeError(f"{language} external reset trace has a malformed field")
        values[key] = int(raw)
    if set(values) != set(FIELDS):
        raise RuntimeError(f"{language} external reset fields differ: {sorted(values)}")
    return values


def c_oracle(*, offline: bool) -> tuple[dict[str, dict[str, int]], dict[str, Any]]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline=offline)
    compiler = harness.require_tool("musl-gcc")
    with harness.temporary_directory(prefix="crabc-mimalloc-m2-external-reset-") as temporary:
        source = harness.safe_extract(archive, Path(temporary), pin["archive_root"])
        binary = ARTIFACTS / "pinned-c-external-os-reset"
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
        harness.require_success(build, "pinned C external reset build")
        values: dict[str, dict[str, int]] = {}
        commands: dict[str, Any] = {"build_status": build["status"]}
        for case in CASES:
            execution = harness.command_record([str(binary), case], cwd=source, env={}, timeout_seconds=120)
            harness.require_success(execution, f"pinned C external reset {case}")
            values[case] = trace(str(execution["stdout"]), "C")
            commands[case] = {"run_status": execution["status"], "stderr": str(execution["stderr"])}
        return values, commands


def rust_receiver() -> tuple[dict[str, dict[str, int]], dict[str, Any]]:
    command = [
        "cargo", "test", "--locked", "--target", "x86_64-unknown-linux-musl",
        "-p", "crabc-mimalloc", "--lib", "--no-default-features", "--no-run",
        "--message-format=json",
    ]
    build = harness.command_record(command, cwd=ROOT, timeout_seconds=3600)
    harness.require_success(build, "Rust external reset receiver build")
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
    values: dict[str, dict[str, int]] = {}
    commands: dict[str, Any] = {"build_status": build["status"]}
    for case in CASES:
        execution = harness.command_record(
            [str(candidates[0]), TEST, "--exact", "--nocapture", "--test-threads=1"],
            cwd=ROOT, env={"CRABC_M2_EXTERNAL_RESET_CASE": case}, timeout_seconds=120,
        )
        harness.require_success(execution, f"Rust external reset receiver {case}")
        if "test result: ok. 1 passed; 0 failed" not in str(execution["stdout"]):
            raise RuntimeError(f"Rust external reset receiver {case} did not execute once")
        values[case] = trace(str(execution["stdout"]), "RUST")
        commands[case] = {"run_status": execution["status"], "stderr": str(execution["stderr"])}
    return values, commands


def run(*, offline: bool) -> dict[str, Any]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    c, c_commands = c_oracle(offline=offline)
    rust, rust_commands = rust_receiver()
    mismatches: list[str] = []
    for case in CASES:
        mismatches.extend(f"{case}.{field}" for field in FIELDS if c[case][field] != rust[case][field])
        expected = {
            "case_failure": int(case == "failure"),
            "purge_delay_raw": 0, "purge_decommits_raw": 0,
            "external_mapping_length": 3 * 4096, "raw_purge_length": 3 * 4096 - 2,
            "advice_calls": 1, "advice_exact": 1,
            "advice_result": -1 if case == "failure" else 0,
            "needs_recommit": 0, "purge_calls_delta": 1,
            "purged_delta": 3 * 4096 - 2,
            "reset_calls_delta": 1, "reset_delta": 4096,
            "reserved_delta": 0, "committed_delta": 0,
            "warning_calls": int(case == "failure"),
            "warning_after_purge": int(case == "failure"),
            "warning_after_reset": int(case == "failure"),
            "warning_exact": int(case == "failure"),
            "neighbors_retained": 1, "mapping_writable": 1,
            "mapping_live": 1, "terminal_unmap_calls": 1,
            "terminal_unmap_exact": 1, "caller_released": 1,
        }
        for language, values in (("c", c[case]), ("rust", rust[case])):
            mismatches.extend(f"{case}.{language}.{field}" for field, value in expected.items()
                              if values[field] != value)
        if c_commands[case]["stderr"] or rust_commands[case]["stderr"]:
            mismatches.append(f"{case}.unrouted_diagnostics")
    report = {
        "status": "matched" if not mismatches else "red",
        "c": c, "rust": rust, "mismatches": mismatches,
        "c_commands": c_commands, "rust_commands": rust_commands,
        "scope": "fresh process per side and case; non-owning external span; contained MADV_FREE success/EIO failure, purge/reset statistics and warning order; terminal caller munmap",
    }
    (ARTIFACTS / "evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"external OS reset policy {report['status'].upper()} ({len(FIELDS) * len(CASES)} exact relations)")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    arguments = parser.parse_args()
    raise SystemExit(0 if run(offline=arguments.offline)["status"] == "matched" else 1)
