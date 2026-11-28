#!/usr/bin/env python3
"""Compare arena page abandonment, reabandon and terminal unabandon against pinned C."""

from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path
from typing import Any, Mapping

import run as harness


FIXTURE = Path(__file__).with_suffix(".c")
ARCH = harness.native_evidence_architecture()
RUST_TEST_TARGET = "native_arena_abandonment"
TARGET = "arena_abandonment_transitions_match_the_pinned_source"
PREFIX = "m2.arena_abandon."
LINE = re.compile(r"^m2\.arena_abandon\.([a-z][a-z0-9_.]*)=(-?[0-9]+)$")


def parse_trace(output: str, source: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in output.splitlines():
        candidate = line.rsplit(" ... ", 1)[-1]
        match = LINE.fullmatch(candidate)
        if match is None:
            if candidate.startswith(PREFIX):
                raise harness.HarnessError(f"{source} has malformed trace line: {candidate}")
            continue
        field, raw = match.groups()
        if field in values:
            raise harness.HarnessError(f"{source} repeats {field}")
        values[field] = int(raw)
    if not values:
        raise harness.HarnessError(f"{source} emitted no arena abandonment trace")
    return values


def rust_executable(artifacts: Path) -> Path:
    command = [
        "cargo", "test", "--locked", "--target", f"{ARCH}-unknown-linux-musl",
        "-p", "crabc-mimalloc", "--no-default-features", "--features", "native-runtime-test-audit",
        "--test", RUST_TEST_TARGET, "--no-run", "--message-format=json",
    ]
    build = harness.command_record(command, cwd=harness.ROOT, timeout_seconds=3600)
    harness.write_json(artifacts / "rust-build.json", build)
    harness.require_success(build, "Rust arena abandonment test build")
    executables = []
    for line in str(build["stdout"]).splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        target = event.get("target") if isinstance(event, Mapping) else None
        if (isinstance(event, Mapping) and event.get("reason") == "compiler-artifact"
                and isinstance(target, Mapping) and target.get("name") == RUST_TEST_TARGET
                and target.get("kind") == ["test"] and isinstance(event.get("executable"), str)):
            executables.append(Path(event["executable"]))
    if len(executables) != 1 or not executables[0].is_file():
        raise harness.HarnessError("Rust arena abandonment build did not name one test executable")
    binary = artifacts / "rust-test"
    shutil.copy2(executables[0], binary)
    return binary


def run(offline: bool) -> Path:
    harness.require_native_evidence(ARCH)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / ARCH / "m2-arena-abandonment"
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "pinned-c-oracle"
    with harness.temporary_directory(prefix="m2-arena-abandonment-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C arena abandonment oracle build")
        c_run = harness.command_record([str(binary)], cwd=source, env={}, timeout_seconds=120)
    (artifacts / "pinned-c.stdout").write_text(str(c_run["stdout"]), encoding="utf-8")
    (artifacts / "pinned-c.stderr").write_text(str(c_run["stderr"]), encoding="utf-8")
    harness.require_success(c_run, "pinned C arena abandonment oracle")
    c_trace = parse_trace(str(c_run["stdout"]), "pinned C")

    executable = rust_executable(artifacts)
    rust = harness.command_record(
        [str(executable), TARGET, "--exact", "--nocapture", "--test-threads=1"],
        cwd=harness.ROOT, env={}, timeout_seconds=300,
    )
    (artifacts / "rust.stdout").write_text(str(rust["stdout"]), encoding="utf-8")
    (artifacts / "rust.stderr").write_text(str(rust["stderr"]), encoding="utf-8")
    harness.require_success(rust, "Rust arena abandonment receiver")
    if harness.parse_rust_test_count(str(rust["stdout"])) != 1:
        raise harness.HarnessError("Rust arena abandonment receiver did not run one passing test")
    rust_trace = parse_trace(str(rust["stdout"]), "Rust")
    if c_trace != rust_trace:
        differences = [f"{field}: C={c_trace.get(field)} Rust={rust_trace.get(field)}"
                       for field in sorted(set(c_trace) | set(rust_trace))
                       if c_trace.get(field) != rust_trace.get(field)]
        raise harness.HarnessError("arena abandonment differs: " + "; ".join(differences))
    evidence: dict[str, Any] = {
        "status": "passed", "pinned_revision": pin["revision"],
        "fixture": harness.artifact_record(FIXTURE),
        "c_executable": harness.artifact_record(binary),
        "rust_test": f"{RUST_TEST_TARGET}::{TARGET}", "trace": c_trace,
    }
    path = artifacts / "evidence.json"
    harness.write_json(path, evidence)
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    try:
        print(run(args.offline))
    except (harness.HarnessError, ValueError) as error:
        parser.exit(1, f"ERROR: {error}\n")
