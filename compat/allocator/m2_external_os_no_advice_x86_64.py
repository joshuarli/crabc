#!/usr/bin/env python3
"""Compare external no-advice purge policies and one contained control with pinned C."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import run as harness
from x86_64_lifecycle_evidence import RUNTIME_THP_CONFIGURATION_C_ORACLE_LINK_SOURCES


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "compat/allocator/m2_external_os_no_advice_x86_64.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m2-external-os-no-advice"
TEST = "os::tests::emit_m2_external_os_no_advice_process_trace"
PROFILES = (
    "negative-delay", "reset-forbidden", "decommit-empty",
    "reset-empty", "contained-control",
)
FIELDS = (
    "profile", "purge_delay_raw", "purge_decommits_raw", "allow_reset",
    "mapping_length", "raw_purge_length", "advice_calls", "advice_exact",
    "advice_kind", "needs_recommit", "purge_calls_delta", "purged_delta",
    "reset_calls_delta", "reset_delta", "reserved_delta", "committed_delta",
    "warning_calls", "middle_byte", "neighbors_retained", "mapping_writable",
    "mapping_live", "terminal_unmap_calls", "terminal_unmap_exact",
    "caller_released",
)


def trace(output: str, language: str) -> dict[str, int]:
    begin = f"CRABC_M2_EXTERNAL_OS_NO_ADVICE_{language}_TRACE_BEGIN"
    end = f"CRABC_M2_EXTERNAL_OS_NO_ADVICE_{language}_TRACE_END"
    if output.count(begin) != 1 or output.count(end) != 1:
        raise RuntimeError(f"{language} no-advice trace markers are not unique")
    values: dict[str, int] = {}
    for line in output.split(begin, 1)[1].split(end, 1)[0].splitlines():
        if not line.strip():
            continue
        key, separator, raw = line.strip().partition("=")
        if not separator or key in values:
            raise RuntimeError(f"{language} no-advice trace has a malformed field")
        values[key] = int(raw)
    if set(values) != set(FIELDS):
        raise RuntimeError(f"{language} no-advice fields differ: {sorted(values)}")
    return values


def c_oracle(*, offline: bool) -> tuple[dict[str, dict[str, int]], dict[str, Any]]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline=offline)
    compiler = harness.require_tool("musl-gcc")
    with harness.temporary_directory(prefix="crabc-mimalloc-m2-external-no-advice-") as temporary:
        source = harness.safe_extract(archive, Path(temporary), pin["archive_root"])
        binary = ARTIFACTS / "pinned-c-external-os-no-advice"
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
        harness.require_success(build, "pinned C external no-advice build")
        values: dict[str, dict[str, int]] = {}
        commands: dict[str, Any] = {"build_status": build["status"]}
        for profile in PROFILES:
            execution = harness.command_record([str(binary), profile], cwd=source, env={}, timeout_seconds=120)
            harness.require_success(execution, f"pinned C external {profile}")
            values[profile] = trace(str(execution["stdout"]), "C")
            commands[profile] = {"run_status": execution["status"], "stderr": str(execution["stderr"])}
        return values, commands


def rust_receiver() -> tuple[dict[str, dict[str, int]], dict[str, Any]]:
    command = [
        "cargo", "test", "--locked", "--target", "x86_64-unknown-linux-musl",
        "-p", "crabc-mimalloc", "--lib", "--no-default-features", "--no-run",
        "--message-format=json",
    ]
    build = harness.command_record(command, cwd=ROOT, timeout_seconds=3600)
    harness.require_success(build, "Rust external no-advice receiver build")
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
    for profile in PROFILES:
        execution = harness.command_record(
            [str(candidates[0]), TEST, "--exact", "--nocapture", "--test-threads=1"],
            cwd=ROOT, env={"CRABC_M2_EXTERNAL_NO_ADVICE_PROFILE": profile}, timeout_seconds=120,
        )
        harness.require_success(execution, f"Rust external {profile} receiver")
        if "test result: ok. 1 passed; 0 failed" not in str(execution["stdout"]):
            raise RuntimeError(f"Rust external {profile} receiver did not execute once")
        values[profile] = trace(str(execution["stdout"]), "RUST")
        commands[profile] = {"run_status": execution["status"], "stderr": str(execution["stderr"])}
    return values, commands


def run(*, offline: bool) -> dict[str, Any]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    c, c_commands = c_oracle(offline=offline)
    rust, rust_commands = rust_receiver()
    mismatches: list[str] = []
    for index, profile in enumerate(PROFILES):
        mismatches.extend(f"{profile}.{field}" for field in FIELDS if c[profile][field] != rust[profile][field])
        raw_length = 4094 if profile.endswith("empty") else 12286
        purge_selected = profile != "negative-delay"
        control = profile == "contained-control"
        expected = {
            "profile": index, "purge_delay_raw": -1 if index == 0 else 0,
            "purge_decommits_raw": int(profile in ("negative-delay", "decommit-empty", "contained-control")),
            "allow_reset": int(profile != "reset-forbidden"),
            "mapping_length": 12288, "raw_purge_length": raw_length,
            "advice_calls": int(control), "advice_exact": int(control),
            "advice_kind": 4 if control else 0,
            "needs_recommit": int(profile == "decommit-empty"),
            "purge_calls_delta": int(purge_selected),
            "purged_delta": raw_length if purge_selected else 0,
            "reset_calls_delta": 0, "reset_delta": 0,
            "reserved_delta": 0, "committed_delta": 0,
            "warning_calls": 0, "middle_byte": 0 if control else 0x5a,
            "neighbors_retained": 1, "mapping_writable": 1,
            "mapping_live": 1, "terminal_unmap_calls": 1,
            "terminal_unmap_exact": 1, "caller_released": 1,
        }
        for language, values in (("c", c[profile]), ("rust", rust[profile])):
            mismatches.extend(f"{profile}.{language}.{field}" for field, value in expected.items()
                              if values[field] != value)
        if c_commands[profile]["stderr"] or rust_commands[profile]["stderr"]:
            mismatches.append(f"{profile}.unrouted_diagnostics")
    report = {
        "status": "matched" if not mismatches else "red",
        "c": c, "rust": rust, "mismatches": mismatches,
        "c_commands": c_commands, "rust_commands": rust_commands,
        "scope": "fresh process per policy; negative delay, forbidden reset, conservative empty decommit/reset, and contained decommit control; exact source counters, advice absence or selected range, retained caller-owned map and terminal caller unmap",
    }
    (ARTIFACTS / "evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"external OS no-advice policy {report['status'].upper()} ({len(FIELDS) * len(PROFILES)} exact relations)")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    arguments = parser.parse_args()
    raise SystemExit(0 if run(offline=arguments.offline)["status"] == "matched" else 1)
