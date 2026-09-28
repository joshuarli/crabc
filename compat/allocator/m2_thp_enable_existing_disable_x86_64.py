#!/usr/bin/env python3
"""Compare process-owned THP advice with inherited disable through pinned C and Rust owners."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import run as harness
from x86_64_lifecycle_evidence import RUNTIME_THP_CONFIGURATION_C_ORACLE_LINK_SOURCES


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "compat/allocator/m2_thp_enable_existing_disable_x86_64.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m2-thp-enable-existing-disable"
TEST = "os::tests::emit_m2_thp_enable_existing_disable_process_trace"
COMMON = (
    "selected_allow_thp_raw",
    "selected_allow_large_os_pages_raw",
    "config_has_transparent_huge_pages",
    "process_ready",
    "thp_prctl_count",
    "thp_disabled_before",
    "thp_disabled_after",
    "mapping_owned",
    "mapping_length",
    "advice_count",
    "advice_address_is_mapping",
    "advice_length",
    "advice_kind",
    "advice_succeeded",
    "vmflags_hg",
    "mapping_survived",
    "mmap_calls_delta",
    "reserved_live_delta",
    "committed_live_delta",
    "release_count",
    "release_exact_range",
    "release_result",
    "reserved_after_release_delta",
    "committed_after_release_delta",
)


def trace(output: str, language: str) -> dict[str, int]:
    begin = f"CRABC_M2_THP_ENABLE_EXISTING_DISABLE_{language}_TRACE_BEGIN"
    end = f"CRABC_M2_THP_ENABLE_EXISTING_DISABLE_{language}_TRACE_END"
    if output.count(begin) != 1 or output.count(end) != 1:
        raise RuntimeError(f"{language} process trace markers are not unique")
    body = output.split(begin, 1)[1].split(end, 1)[0]
    values: dict[str, int] = {}
    for line in body.splitlines():
        if not line.strip():
            continue
        key, separator, raw = line.strip().partition("=")
        if not separator or key in values:
            raise RuntimeError(f"{language} process trace has a malformed field")
        values[key] = int(raw)
    if set(values) != set(COMMON) | ({"advice_result"} if language == "C" else set()):
        raise RuntimeError(f"{language} process trace has unexpected fields: {sorted(values)}")
    return values


def c_oracle(*, offline: bool) -> tuple[dict[str, int], dict[str, Any]]:
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline=offline)
    compiler = harness.require_tool("musl-gcc")
    with harness.temporary_directory(prefix="crabc-mimalloc-m2-thp-inherited-disable-source-") as temporary:
        source = harness.safe_extract(archive, Path(temporary), pin["archive_root"])
        binary = ARTIFACTS / "pinned-c-thp-enable-existing-disable"
        command = [
            compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"),
            *harness.CONFIGURATION_PROFILES["release"], str(FIXTURE),
            *(str(source / name) for name in RUNTIME_THP_CONFIGURATION_C_ORACLE_LINK_SOURCES),
            "-Wl,--wrap=prctl", "-Wl,--wrap=madvise", "-Wl,--wrap=munmap", "-pthread",
            "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C process THP inherited disable advice build")
        execution = harness.command_record([str(binary)], cwd=source, env={}, timeout_seconds=120)
        harness.require_success(execution, "pinned C process THP inherited disable advice")
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
    harness.require_success(build, "Rust process THP inherited disable advice test build")
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
    harness.require_success(execution, "Rust process THP inherited disable advice receiver")
    if "test result: ok. 1 passed; 0 failed" not in str(execution["stdout"]):
        raise RuntimeError("Rust process THP inherited disable advice receiver did not execute once")
    return trace(str(execution["stdout"]), "RUST"), {
        "build_status": build["status"], "run_status": execution["status"],
        "stderr": str(execution["stderr"]),
    }


def run(*, offline: bool) -> dict[str, Any]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    c, c_commands = c_oracle(offline=offline)
    rust, rust_commands = rust_receiver()
    mismatches = [key for key in COMMON if c[key] != rust[key]]
    expected = {
        "selected_allow_thp_raw": 1,
        "selected_allow_large_os_pages_raw": 0,
        "process_ready": 1,
        "thp_prctl_count": 0,
        "thp_disabled_before": 1,
        "thp_disabled_after": 1,
        "mapping_owned": 1,
        "mapping_length": 2 * 1024 * 1024,
        "advice_count": 1,
        "advice_address_is_mapping": 1,
        "advice_length": 2 * 1024 * 1024,
        "advice_kind": 14,
        "advice_succeeded": 1,
        "vmflags_hg": 1,
        "mapping_survived": 1,
        "mmap_calls_delta": 1,
        "reserved_live_delta": 2 * 1024 * 1024,
        "committed_live_delta": 2 * 1024 * 1024,
        "release_count": 1,
        "release_exact_range": 1,
        "release_result": 0,
        "reserved_after_release_delta": 0,
        "committed_after_release_delta": 0,
    }
    mismatches.extend(f"c.{key}" for key, value in expected.items() if c[key] != value)
    mismatches.extend(f"rust.{key}" for key, value in expected.items() if rust[key] != value)
    if c["advice_result"] != 0:
        mismatches.append("c.advice_result")
    if c["config_has_transparent_huge_pages"] not in (0, 1):
        mismatches.append("c.config_has_transparent_huge_pages")
    if c_commands["stderr"] or rust_commands["stderr"]:
        mismatches.append("diagnostics")
    report = {
        "status": "matched" if not mismatches else "red",
        "c": c, "rust": rust, "mismatches": mismatches,
        "c_commands": c_commands, "rust_commands": rust_commands,
        "scope": "one fresh process per side, inherited THP process disable remains set under allow_thp=1 while the selected regular map receives explicit MADV_HUGEPAGE; no physical huge-page residency claim",
    }
    (ARTIFACTS / "evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"THP inherited disable advice {report['status'].upper()} ({len(COMMON)} exact relations)")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    arguments = parser.parse_args()
    raise SystemExit(0 if run(offline=arguments.offline)["status"] == "matched" else 1)
