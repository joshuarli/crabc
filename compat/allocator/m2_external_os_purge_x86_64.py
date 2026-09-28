#!/usr/bin/env python3
"""Compare caller-owned external purge success and failure with pinned C."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import run as harness
from x86_64_lifecycle_evidence import RUNTIME_THP_CONFIGURATION_C_ORACLE_LINK_SOURCES


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "compat/allocator/m2_external_os_purge_x86_64.c"
COMMIT_FIXTURE = ROOT / "compat/allocator/m2_external_os_commit_x86_64.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m2-external-os-purge"
TEST = "os::tests::emit_m2_external_os_purge_process_trace"
CASES = ("success", "failure")
FIELDS = (
    "case_failure", "purge_delay_raw", "purge_decommits_raw",
    "external_mapping_length", "raw_purge_length", "advice_calls",
    "advice_exact", "advice_result", "needs_recommit",
    "purge_calls_delta", "purged_delta", "reset_calls_delta",
    "reserved_delta", "committed_delta", "warning_calls",
    "warning_after_purge", "warning_exact", "middle_byte",
    "neighbors_retained", "mapping_writable", "mapping_live",
    "terminal_unmap_calls", "terminal_unmap_exact",
    "terminal_unmap_result", "caller_released",
)
COMMIT_FIELDS = (
    "mapping_length", "already_committed", "commit_attempts", "commit_exact",
    "commit_result", "source_committed", "commit_calls_delta",
    "committed_current_delta", "committed_total_delta", "reserved_delta",
    "first_retained", "second_writable", "mapping_live",
    "terminal_unmap_calls", "terminal_unmap_exact", "caller_released",
)


def trace(output: str, language: str, *, operation: str = "PURGE") -> dict[str, int]:
    begin = f"CRABC_M2_EXTERNAL_OS_{operation}_{language}_TRACE_BEGIN"
    end = f"CRABC_M2_EXTERNAL_OS_{operation}_{language}_TRACE_END"
    if output.count(begin) != 1 or output.count(end) != 1:
        raise RuntimeError(f"{language} purge trace markers are not unique")
    body = output.split(begin, 1)[1].split(end, 1)[0]
    values: dict[str, int] = {}
    for line in body.splitlines():
        if not line.strip():
            continue
        key, separator, raw = line.strip().partition("=")
        if not separator or key in values:
            raise RuntimeError(f"{language} purge trace has a malformed field")
        values[key] = int(raw)
    fields = FIELDS if operation == "PURGE" else COMMIT_FIELDS
    if set(values) != set(fields):
        raise RuntimeError(f"{language} purge trace has unexpected fields: {sorted(values)}")
    return values


def c_oracle(*, offline: bool) -> tuple[dict[str, dict[str, int]], dict[str, Any]]:
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline=offline)
    compiler = harness.require_tool("musl-gcc")
    with harness.temporary_directory(prefix="crabc-mimalloc-m2-external-purge-source-") as temporary:
        source = harness.safe_extract(archive, Path(temporary), pin["archive_root"])
        binary = ARTIFACTS / "pinned-c-external-os-purge"
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
        harness.require_success(build, "pinned C external purge build")
        values: dict[str, dict[str, int]] = {}
        commands: dict[str, Any] = {"build_status": build["status"]}
        for case in CASES:
            execution = harness.command_record([str(binary), case], cwd=source, env={}, timeout_seconds=120)
            harness.require_success(execution, f"pinned C external purge {case}")
            values[case] = trace(str(execution["stdout"]), "C")
            commands[case] = {"run_status": execution["status"], "stderr": str(execution["stderr"])}
        return values, commands


def rust_receiver() -> tuple[dict[str, dict[str, int]], dict[str, Any], Path]:
    command = [
        "cargo", "test", "--locked", "--target", "x86_64-unknown-linux-musl",
        "-p", "crabc-mimalloc", "--lib", "--no-default-features", "--no-run",
        "--message-format=json",
    ]
    build = harness.command_record(command, cwd=ROOT, timeout_seconds=3600)
    harness.require_success(build, "Rust external purge receiver build")
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
            cwd=ROOT, env={"CRABC_M2_EXTERNAL_PURGE_CASE": case}, timeout_seconds=120,
        )
        harness.require_success(execution, f"Rust external purge receiver {case}")
        if "test result: ok. 1 passed; 0 failed" not in str(execution["stdout"]):
            raise RuntimeError(f"Rust external purge receiver {case} did not execute once")
        values[case] = trace(str(execution["stdout"]), "RUST")
        commands[case] = {"run_status": execution["status"], "stderr": str(execution["stderr"])}
    return values, commands, candidates[0]


def commit_c_oracle(*, offline: bool) -> tuple[dict[str, int], dict[str, Any]]:
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline=offline)
    compiler = harness.require_tool("musl-gcc")
    with harness.temporary_directory(prefix="crabc-mimalloc-m2-external-commit-source-") as temporary:
        source = harness.safe_extract(archive, Path(temporary), pin["archive_root"])
        binary = ARTIFACTS / "pinned-c-external-os-commit"
        command = [
            compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"),
            *harness.CONFIGURATION_PROFILES["release"], str(COMMIT_FIXTURE),
            *(str(source / name) for name in RUNTIME_THP_CONFIGURATION_C_ORACLE_LINK_SOURCES),
            "-Wl,--wrap=mprotect", "-Wl,--wrap=munmap", "-pthread",
            "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C external mixed commit build")
        execution = harness.command_record([str(binary)], cwd=source, env={}, timeout_seconds=120)
        harness.require_success(execution, "pinned C external mixed commit")
        return trace(str(execution["stdout"]), "C", operation="COMMIT"), {
            "build_status": build["status"], "run_status": execution["status"],
            "stderr": str(execution["stderr"]),
        }


def commit_rust_receiver(binary: Path) -> tuple[dict[str, int], dict[str, Any]]:
    execution = harness.command_record(
        [str(binary), "os::tests::emit_m2_external_os_commit_process_trace",
         "--exact", "--nocapture", "--test-threads=1"],
        cwd=ROOT, env={}, timeout_seconds=120,
    )
    harness.require_success(execution, "Rust external mixed commit receiver")
    if "test result: ok. 1 passed; 0 failed" not in str(execution["stdout"]):
        raise RuntimeError("Rust external mixed commit receiver did not execute once")
    return trace(str(execution["stdout"]), "RUST", operation="COMMIT"), {
        "run_status": execution["status"], "stderr": str(execution["stderr"]),
    }


def run(*, offline: bool) -> dict[str, Any]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    c, c_commands = c_oracle(offline=offline)
    rust, rust_commands, rust_binary = rust_receiver()
    commit_c, commit_c_commands = commit_c_oracle(offline=offline)
    commit_rust, commit_rust_commands = commit_rust_receiver(rust_binary)
    mismatches: list[str] = []
    for case in CASES:
        mismatches.extend(f"{case}.{field}" for field in FIELDS if c[case][field] != rust[case][field])
        expected = {
            "case_failure": int(case == "failure"),
            "purge_delay_raw": 0,
            "purge_decommits_raw": 1,
            "external_mapping_length": 3 * 4096,
            "raw_purge_length": 3 * 4096 - 2,
            "advice_calls": 1,
            "advice_exact": 1,
            "advice_result": -1 if case == "failure" else 0,
            "needs_recommit": 0,
            "purge_calls_delta": 1,
            "purged_delta": 3 * 4096 - 2,
            "reset_calls_delta": 0,
            "reserved_delta": 0,
            "committed_delta": 0,
            "warning_calls": int(case == "failure"),
            "warning_after_purge": int(case == "failure"),
            "warning_exact": int(case == "failure"),
            "middle_byte": 0x5a if case == "failure" else 0,
            "neighbors_retained": 1,
            "mapping_writable": 1,
            "mapping_live": 1,
            "terminal_unmap_calls": 1,
            "terminal_unmap_exact": 1,
            "terminal_unmap_result": 0,
            "caller_released": 1,
        }
        for language, values in (("c", c[case]), ("rust", rust[case])):
            mismatches.extend(f"{case}.{language}.{field}" for field, value in expected.items() if values[field] != value)
        if c_commands[case]["stderr"] or rust_commands[case]["stderr"]:
            mismatches.append(f"{case}.unrouted_diagnostics")
    mismatches.extend(f"commit.{field}" for field in COMMIT_FIELDS if commit_c[field] != commit_rust[field])
    commit_expected = {
        "mapping_length": 2 * 4096, "already_committed": 4096,
        "commit_attempts": 1, "commit_exact": 1, "commit_result": 0,
        "source_committed": 1, "commit_calls_delta": 1,
        "committed_current_delta": 4096, "committed_total_delta": 4096,
        "reserved_delta": 0, "first_retained": 1, "second_writable": 1,
        "mapping_live": 1, "terminal_unmap_calls": 1,
        "terminal_unmap_exact": 1, "caller_released": 1,
    }
    for language, values in (("c", commit_c), ("rust", commit_rust)):
        mismatches.extend(f"commit.{language}.{field}" for field, value in commit_expected.items()
                          if values[field] != value)
    if commit_c_commands["stderr"] or commit_rust_commands["stderr"]:
        mismatches.append("commit.unrouted_diagnostics")
    report = {
        "status": "matched" if not mismatches else "red",
        "c": c, "rust": rust, "mismatches": mismatches,
        "c_commands": c_commands, "rust_commands": rust_commands,
        "commit_c": commit_c, "commit_rust": commit_rust,
        "commit_c_commands": commit_c_commands, "commit_rust_commands": commit_rust_commands,
        "scope": "fresh process per side and case; external contained MADV_DONTNEED success/EIO failure and mixed commit accounting; source warning and statistics order; terminal caller munmap",
    }
    (ARTIFACTS / "evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"external OS purge and commit {report['status'].upper()} ({len(FIELDS) * len(CASES) + len(COMMIT_FIELDS)} exact relations)")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    arguments = parser.parse_args()
    raise SystemExit(0 if run(offline=arguments.offline)["status"] == "matched" else 1)
