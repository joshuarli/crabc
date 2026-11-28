#!/usr/bin/env python3
"""Compare arena page abandonment, reabandon and terminal unabandon against pinned C."""

from __future__ import annotations

import argparse
import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import run as harness


ARCH = harness.native_evidence_architecture()


@dataclass(frozen=True)
class Receiver:
    """One pinned-C fixture compared with one `native_*` integration test."""

    fixture: Path
    rust_test_target: str
    target: str
    prefix: str
    artifact: str
    description: str


ABANDONMENT = Receiver(
    fixture=Path(__file__).with_suffix(".c"),
    rust_test_target="native_arena_abandonment",
    target="arena_abandonment_transitions_match_the_pinned_source",
    prefix="m2.arena_abandon.",
    artifact="m2-arena-abandonment",
    description="arena abandonment",
)


def parse_trace(output: str, source: str, receiver: Receiver) -> dict[str, int]:
    line = re.compile("^" + re.escape(receiver.prefix) + r"([a-z][a-z0-9_.]*)=(-?[0-9]+)$")
    values: dict[str, int] = {}
    for text in output.splitlines():
        candidate = text.rsplit(" ... ", 1)[-1]
        match = line.fullmatch(candidate)
        if match is None:
            if candidate.startswith(receiver.prefix):
                raise harness.HarnessError(f"{source} has malformed trace line: {candidate}")
            continue
        field, raw = match.groups()
        if field in values:
            raise harness.HarnessError(f"{source} repeats {field}")
        values[field] = int(raw)
    if not values:
        raise harness.HarnessError(f"{source} emitted no {receiver.description} trace")
    return values


def rust_executable(artifacts: Path, receiver: Receiver) -> Path:
    command = [
        "cargo", "test", "--locked", "--target", f"{ARCH}-unknown-linux-musl",
        "-p", "crabc-mimalloc", "--no-default-features", "--features", "native-runtime-test-audit",
        "--test", receiver.rust_test_target, "--no-run", "--message-format=json",
    ]
    build = harness.command_record(command, cwd=harness.ROOT, timeout_seconds=3600)
    harness.write_json(artifacts / "rust-build.json", build)
    harness.require_success(build, f"Rust {receiver.description} test build")
    executables = []
    for line in str(build["stdout"]).splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        target = event.get("target") if isinstance(event, Mapping) else None
        if (isinstance(event, Mapping) and event.get("reason") == "compiler-artifact"
                and isinstance(target, Mapping) and target.get("name") == receiver.rust_test_target
                and target.get("kind") == ["test"] and isinstance(event.get("executable"), str)):
            executables.append(Path(event["executable"]))
    if len(executables) != 1 or not executables[0].is_file():
        raise harness.HarnessError(f"Rust {receiver.description} build did not name one test executable")
    binary = artifacts / "rust-test"
    shutil.copy2(executables[0], binary)
    return binary


def run(offline: bool, receiver: Receiver = ABANDONMENT) -> Path:
    harness.require_native_evidence(ARCH)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / ARCH / receiver.artifact
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "pinned-c-oracle"
    with harness.temporary_directory(prefix=f"{receiver.artifact}-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(receiver.fixture), "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, f"pinned C {receiver.description} oracle build")
        c_run = harness.command_record([str(binary)], cwd=source, env={}, timeout_seconds=120)
    (artifacts / "pinned-c.stdout").write_text(str(c_run["stdout"]), encoding="utf-8")
    (artifacts / "pinned-c.stderr").write_text(str(c_run["stderr"]), encoding="utf-8")
    harness.require_success(c_run, f"pinned C {receiver.description} oracle")
    c_trace = parse_trace(str(c_run["stdout"]), "pinned C", receiver)

    executable = rust_executable(artifacts, receiver)
    rust = harness.command_record(
        [str(executable), receiver.target, "--exact", "--nocapture", "--test-threads=1"],
        cwd=harness.ROOT, env={}, timeout_seconds=300,
    )
    (artifacts / "rust.stdout").write_text(str(rust["stdout"]), encoding="utf-8")
    (artifacts / "rust.stderr").write_text(str(rust["stderr"]), encoding="utf-8")
    harness.require_success(rust, f"Rust {receiver.description} receiver")
    if harness.parse_rust_test_count(str(rust["stdout"])) != 1:
        raise harness.HarnessError(f"Rust {receiver.description} receiver did not run one passing test")
    rust_trace = parse_trace(str(rust["stdout"]), "Rust", receiver)
    if c_trace != rust_trace:
        differences = [f"{field}: C={c_trace.get(field)} Rust={rust_trace.get(field)}"
                       for field in sorted(set(c_trace) | set(rust_trace))
                       if c_trace.get(field) != rust_trace.get(field)]
        raise harness.HarnessError(f"{receiver.description} differs: " + "; ".join(differences))
    evidence: dict[str, Any] = {
        "status": "passed", "pinned_revision": pin["revision"],
        "fixture": harness.artifact_record(receiver.fixture),
        "c_executable": harness.artifact_record(binary),
        "rust_test": f"{receiver.rust_test_target}::{receiver.target}", "trace": c_trace,
    }
    path = artifacts / "evidence.json"
    harness.write_json(path, evidence)
    return path


def main(description: str, receiver: Receiver) -> None:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    try:
        print(run(args.offline, receiver))
    except (harness.HarnessError, ValueError) as error:
        parser.exit(1, f"ERROR: {error}\n")


if __name__ == "__main__":
    main(__doc__, ABANDONMENT)
