#!/usr/bin/env python3
"""Differentially observe source-start regular-arena consumption on x86-64.

This focused private lane builds one direct-include mimalloc v3.5.0 C oracle
and one ordinary-dependency Rust runtime test. It covers the finite
``init.c`` startup-regular outcomes used by ticket zero: a published 64-MiB
reservation, the source's ignored too-small reservation failure, an absent
option, and the `disallow_arena_alloc` direct-OS fallback. It is not a public
allocator API, huge-page, physical-NUMA, metadata-destruction, or campaign
qualification claim.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "compat/allocator/run.py"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/startup-regular-arena.json"
LOCKFILE = ROOT / "Cargo.lock"
TARGET = "x86_64-unknown-linux-musl"
FIXTURE = ROOT / "compat/allocator/x86_64_startup_regular_arena_oracle.c"
RUST_TEST = ROOT / "crabc-mimalloc/tests/native_runtime_startup_regular_arena.rs"
RUST_TARGET = "native_runtime_startup_regular_arena"
RUST_FILTER = "runtime_ticket_zero_uses_source_startup_regular_arena_and_source_fallbacks"
C_TRACE_BEGIN = "CRABC_MI_STARTUP_REGULAR_ARENA_TRACE_BEGIN"
C_TRACE_END = "CRABC_MI_STARTUP_REGULAR_ARENA_TRACE_END"
RUST_TRACE_BEGIN = "CRABC_MI_RUNTIME_STARTUP_REGULAR_ARENA_TRACE_BEGIN"
RUST_TRACE_END = "CRABC_MI_RUNTIME_STARTUP_REGULAR_ARENA_TRACE_END"
PROFILE = "linux-x86_64-private-ticket-zero-startup-regular-arena"
PINNED_UPSTREAM = {
    "archive_sha256": "1e432f0559a4ab512143b9bff7a700541a2c8d4712b26a72de3e0222790da305",
    "revision": "18b08671c9302247bfb682286e6bf3cc1773f801",
}
C_ORACLE_BINARY = (
    ".work/allocator-x86_64/target/compat/allocator/x86_64/"
    "startup-regular-arena/startup-regular-arena-oracle"
)

C_LINK_SOURCES = (
    "src/alloc.c",
    "src/alloc-aligned.c",
    "src/alloc-posix.c",
    "src/arena.c",
    "src/bitmap.c",
    "src/heap.c",
    "src/libc.c",
    "src/options.c",
    "src/os.c",
    "src/page-map.c",
    "src/page.c",
    "src/random.c",
    "src/stats.c",
    "src/subproc.c",
    "src/theap.c",
    "src/threadlocal.c",
    "src/prim/prim.c",
    "src/prim/prim-tls.c",
)
C_SOURCE_FILES = (
    "include/mimalloc.h",
    "include/mimalloc/internal.h",
    "include/mimalloc/prim.h",
    "src/init.c",
    *C_LINK_SOURCES,
    "src/prim/unix/prim.c",
)
C_TRACE_FIELDS = (
    "registry_after_init",
    "client_is_arena_backed",
    "client_startup_identity",
    "registry_after_allocation",
    "arena_size_after_allocation",
    "arena_initially_committed",
    "registry_after_free",
)
RUST_TRACE_FIELDS = (
    "startup_outcome",
    "registry_after_init",
    "client_is_arena_backed",
    "client_startup_identity",
    "sidecar_vm_reservations",
    "registry_after_allocation",
    "arena_size_after_allocation",
    "arena_initially_committed",
    "registry_after_free",
    "page_map_entries_after_free",
)
SCENARIOS = ("reuse", "failed", "absent", "ineligible")
STARTUP_BYTES = 64 * 1024 * 1024
LAZY_BYTES = 128 * 1024 * 1024
REPORT_SCOPE = {
    "boundary": "four child-isolated ticket-zero source-start regular-arena transitions only",
    "public_runtime_support": False,
    "claims": [
        "published startup regular arena is searched before a lazy first-arena mapping",
        "too-small ignored startup failure and absent option use the ordinary fresh-arena fallback",
        "disallow_arena_alloc keeps its published startup parent and uses the existing direct-OS fallback",
    ],
    "exclusions": [
        "allocator metadata backing or publication ownership",
        "arena destruction or general multi-arena routing",
        "dynamic/later-TLD allocation",
        "huge-page success or host NUMA placement",
        "public mi API or libc runtime qualification",
    ],
}

# The source input roster includes the complete private allocator Rust tree,
# the exact C input closure, the fixed test/producer, and toolchain/runner
# inputs. It identifies the candidate measured by this report; validation of a
# historical receipt remains structural/self-consistency only and never
# authenticates a later checkout by itself.
CANDIDATE_INPUT_ROOTS = (
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain.toml",
    "crabc-mimalloc/Cargo.toml",
    "crabc-mimalloc/src",
    "crabc-mimalloc/tests/native_runtime_startup_regular_arena.rs",
    "compat/allocator/run-x86_64.sh",
    "compat/allocator/run.py",
    "compat/allocator/x86_64_startup_regular_arena_oracle.c",
    "compat/allocator/x86_64_startup_regular_arena_evidence.py",
    "compat/allocator/tests/test_x86_64_startup_regular_arena_evidence.py",
)

C_EXPECTED: Mapping[str, Mapping[str, int]] = {
    "reuse": {
        "registry_after_init": 1,
        "client_is_arena_backed": 1,
        "client_startup_identity": 1,
        "registry_after_allocation": 1,
        "arena_size_after_allocation": STARTUP_BYTES,
        "arena_initially_committed": 1,
        "registry_after_free": 1,
    },
    "failed": {
        "registry_after_init": 0,
        "client_is_arena_backed": 1,
        "client_startup_identity": 2,
        "registry_after_allocation": 1,
        "arena_size_after_allocation": LAZY_BYTES,
        "arena_initially_committed": 1,
        "registry_after_free": 1,
    },
    "absent": {
        "registry_after_init": 0,
        "client_is_arena_backed": 1,
        "client_startup_identity": 2,
        "registry_after_allocation": 1,
        "arena_size_after_allocation": LAZY_BYTES,
        "arena_initially_committed": 1,
        "registry_after_free": 1,
    },
    "ineligible": {
        "registry_after_init": 1,
        "client_is_arena_backed": 0,
        "client_startup_identity": 2,
        "registry_after_allocation": 1,
        "arena_size_after_allocation": STARTUP_BYTES,
        "arena_initially_committed": 1,
        "registry_after_free": 1,
    },
}
RUST_EXPECTED: Mapping[str, Mapping[str, int]] = {
    scenario: {
        "startup_outcome": {"reuse": 1, "failed": 2, "absent": 0, "ineligible": 1}[scenario],
        **C_EXPECTED[scenario],
        "sidecar_vm_reservations": 0 if scenario in {"reuse", "ineligible"} else 1,
        "page_map_entries_after_free": 0,
    }
    for scenario in SCENARIOS
}
COMMON_FIELDS = C_TRACE_FIELDS
TEST_RESULT = re.compile(
    r"test result: (?P<status>ok|FAILED)\. "
    r"(?P<passed>\d+) passed; (?P<failed>\d+) failed; "
    r"(?P<ignored>\d+) ignored; (?P<measured>\d+) measured; "
    r"(?P<filtered>\d+) filtered out;"
)
RUSTC_HOST = re.compile(r"^host: (?P<target>\S+)$", re.MULTILINE)
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
GIT_OBJECT = re.compile(r"[0-9a-f]{40}\Z")


class EvidenceError(RuntimeError):
    """One fixed source-start regular-arena evidence precondition failed."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    if not path.is_file():
        raise EvidenceError(f"required evidence input is missing: {relative(path)}")
    return sha256_bytes(path.read_bytes())


def relative(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError as error:
        raise EvidenceError(f"evidence path escapes the checkout: {path}") from error


def exactly_matches(actual: object, expected: object) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        assert isinstance(actual, dict)
        return set(actual) == set(expected) and all(
            exactly_matches(actual[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        assert isinstance(actual, list)
        return len(actual) == len(expected) and all(
            exactly_matches(item, wanted) for item, wanted in zip(actual, expected)
        )
    return actual == expected


def require_native_x86_64() -> dict[str, str]:
    mode = os.environ.get("CRABC_EXECUTION_MODE")
    host = os.environ.get("CRABC_HOST_ARCH")
    if mode != "native" or host not in {"x86_64", "amd64"}:
        raise EvidenceError("requires canonical native x86-64 dispatcher provenance")
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise EvidenceError("requires the native Linux/x86-64 pinned image")
    return {"execution_mode": "native", "host_architecture": host}


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise EvidenceError(f"required pinned-image tool is unavailable: {name}")
    return path


def run_text(command: Sequence[str], *, cwd: Path | None = None, env: Mapping[str, str] | None = None) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd or ROOT,
        env=dict(env) if env is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    output = f"{completed.stdout}{completed.stderr}"
    if completed.returncode != 0:
        raise EvidenceError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n{output.strip()}"
        )
    return output


def toolchain_record(cargo: str, rustc: str) -> dict[str, str]:
    rustc_version = run_text([rustc, "-vV"])
    match = RUSTC_HOST.search(rustc_version)
    if match is None or match.group("target") != TARGET:
        observed = match.group("target") if match is not None else "<missing>"
        raise EvidenceError(f"requires rustc host {TARGET}, observed {observed}")
    release = next(
        (line.removeprefix("release: ") for line in rustc_version.splitlines() if line.startswith("release: ")),
        "<missing>",
    )
    return {
        "cargo": run_text([cargo, "--version"]).strip(),
        "rustc_host": TARGET,
        "rustc_release": release,
    }


def load_harness() -> Any:
    spec = importlib.util.spec_from_file_location("crabc_startup_regular_allocator_harness", RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise EvidenceError("pinned allocator source harness is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        raise EvidenceError("pinned allocator source harness could not load") from error
    return module


def parse_scalar_trace(output: str, *, begin: str, end: str, fields: Sequence[str], source: str) -> dict[str, int]:
    lines = output.splitlines()
    begins = [index for index, line in enumerate(lines) if line == begin]
    ends = [index for index, line in enumerate(lines) if line == end]
    if len(begins) != 1 or len(ends) != 1 or begins[0] >= ends[0]:
        raise EvidenceError(f"{source} did not emit one ordered scalar trace")
    values: dict[str, int] = {}
    for line in lines[begins[0] + 1 : ends[0]]:
        name, separator, value = line.partition("=")
        if not separator or not name or not value.isdecimal() or name in values:
            raise EvidenceError(f"{source} emitted an invalid scalar trace row: {line!r}")
        values[name] = int(value)
    if set(values) != set(fields):
        raise EvidenceError(
            f"{source} scalar trace keys drifted: missing {sorted(set(fields) - set(values))}; "
            f"unexpected {sorted(set(values) - set(fields))}"
        )
    return values


def source_input_paths() -> tuple[Path, ...]:
    paths: list[Path] = []
    for item in CANDIDATE_INPUT_ROOTS:
        path = ROOT / item
        if path.is_dir():
            paths.extend(sorted(candidate for candidate in path.rglob("*") if candidate.is_file()))
        else:
            paths.append(path)
    if len(set(paths)) != len(paths):
        raise EvidenceError("candidate source input roster has duplicate paths")
    return tuple(paths)


def git_text(arguments: Sequence[str]) -> str:
    environment = dict(os.environ)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    completed = subprocess.run(
        ["git", *arguments], cwd=ROOT, env=environment,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    if completed.returncode != 0:
        raise EvidenceError(
            f"Git source observation failed: {' '.join(arguments)}: {completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def source_snapshot() -> dict[str, Any]:
    files = [
        {"path": relative(path), "sha256": sha256_file(path)}
        for path in source_input_paths()
    ]
    return {
        "git_revision": git_text(["rev-parse", "HEAD"]),
        "git_tree": git_text(["rev-parse", "HEAD^{tree}"]),
        "git_status_porcelain": git_text(["status", "--porcelain=v1", "--untracked-files=all"]),
        "files": files,
    }


def candidate_attestation(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    if not exactly_matches(before, after):
        raise EvidenceError("candidate source changed while the evidence producer ran")
    return {
        "before": dict(before),
        "after": dict(after),
        "unchanged_during_execution": True,
    }


def normalize_c_command(command: Sequence[str], source: Path, binary: Path) -> list[str]:
    result: list[str] = []
    for argument in command:
        if argument == str(binary):
            result.append("<startup-regular-arena-oracle-binary>")
        elif argument.startswith(f"{source}/"):
            result.append(f"<pinned-mimalloc-source>/{Path(argument).relative_to(source).as_posix()}")
        else:
            result.append(argument)
    return result


def source_file_records(harness: Any, source: Path) -> list[dict[str, str]]:
    try:
        return harness.source_file_records(source, C_SOURCE_FILES)
    except harness.HarnessError as error:
        raise EvidenceError(f"pinned C source roster failed: {error}") from error


def run_c_oracle(harness: Any) -> dict[str, Any]:
    try:
        pin = harness.load_pin()
        archive = harness.fetch_archive(pin, offline=True)
        compiler = harness.require_tool("musl-gcc")
        artifacts = harness.ARTIFACT_ROOT / "x86_64/startup-regular-arena"
        artifacts.mkdir(parents=True, exist_ok=True)
        binary = artifacts / "startup-regular-arena-oracle"
        with harness.temporary_directory(prefix="crabc-mimalloc-x86_64-startup-regular-source-") as temporary:
            source = harness.safe_extract(archive, Path(temporary), pin["archive_root"])
            command = [
                compiler,
                "-std=c11",
                "-fPIC",
                "-ftls-model=initial-exec",
                "-DMI_SHARED_LIB",
                "-DMI_SHARED_LIB_EXPORT",
                "-DMI_LIBC_MUSL=1",
                "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
                "-I", str(source / "include"),
                "-I", str(source / "src"),
                *harness.CONFIGURATION_PROFILES["release"],
                str(FIXTURE),
                *(str(source / item) for item in C_LINK_SOURCES),
                "-pthread",
                "-o", str(binary),
            ]
            build = harness.command_record(command, cwd=source, timeout_seconds=300)
            harness.require_success(build, "pinned C startup-regular oracle build")
            traces: dict[str, dict[str, int]] = {}
            runs: dict[str, dict[str, Any]] = {}
            for scenario in SCENARIOS:
                record = harness.command_record([str(binary), scenario], cwd=source, timeout_seconds=120, env={})
                harness.require_success(record, f"pinned C startup-regular oracle {scenario}")
                trace = parse_scalar_trace(
                    str(record["stdout"]), begin=C_TRACE_BEGIN, end=C_TRACE_END,
                    fields=C_TRACE_FIELDS, source=f"pinned C {scenario} startup-regular oracle",
                )
                if trace != C_EXPECTED[scenario]:
                    raise EvidenceError(f"pinned C {scenario} source transition drifted: {trace}")
                traces[scenario] = trace
                runs[scenario] = {
                    "command": ["<startup-regular-arena-oracle-binary>", scenario],
                    "status": record["status"],
                    "stdout_sha256": sha256_bytes(str(record["stdout"]).encode("utf-8")),
                    "stderr_sha256": sha256_bytes(str(record["stderr"]).encode("utf-8")),
                }
            roster = source_file_records(harness, source)
            normalized_compile = normalize_c_command(command, source, binary)
    except harness.HarnessError as error:
        raise EvidenceError(f"pinned C startup-regular oracle failed: {error}") from error
    if not binary.is_file():
        raise EvidenceError("pinned C startup-regular oracle binary was not retained")
    return {
        "binary": harness.artifact_record(binary),
        "build": {
            "command": normalized_compile,
            "status": build["status"],
            "stdout_sha256": sha256_bytes(str(build["stdout"]).encode("utf-8")),
            "stderr_sha256": sha256_bytes(str(build["stderr"]).encode("utf-8")),
        },
        "fixture": {"path": relative(FIXTURE), "sha256": sha256_file(FIXTURE)},
        "runs": runs,
        "source_files": roster,
        "traces": traces,
        "upstream": {"archive_sha256": pin["sha256"], "revision": pin["revision"]},
    }


def cargo_command(cargo: str, target_dir: Path) -> list[str]:
    return [
        cargo, "test", "--locked", "--target", TARGET, "--target-dir", str(target_dir),
        "-p", "crabc-mimalloc", "--test", RUST_TARGET,
        "--features", "native-runtime-test-audit", RUST_FILTER,
        "--", "--exact", "--nocapture", "--test-threads=1",
    ]


def parse_test_result(output: str) -> dict[str, int]:
    matches = list(TEST_RESULT.finditer(output))
    if len(matches) != 1:
        raise EvidenceError(f"Rust startup-regular test produced {len(matches)} summaries, expected one")
    match = matches[0]
    result = {
        "passed": int(match.group("passed")),
        "failed": int(match.group("failed")),
        "ignored": int(match.group("ignored")),
        "measured": int(match.group("measured")),
        "filtered_out": int(match.group("filtered")),
    }
    if match.group("status") != "ok" or result != {
        "passed": 1, "failed": 0, "ignored": 0, "measured": 0,
        "filtered_out": result["filtered_out"],
    }:
        raise EvidenceError(f"Rust startup-regular test did not produce one clean pass: {result}")
    return result


def parse_rust_trace(output: str) -> dict[str, dict[str, int]]:
    fields = tuple(f"{scenario}_{field}" for scenario in SCENARIOS for field in RUST_TRACE_FIELDS)
    flat = parse_scalar_trace(
        output, begin=RUST_TRACE_BEGIN, end=RUST_TRACE_END, fields=fields,
        source="Rust runtime startup-regular witness",
    )
    traces = {
        scenario: {field: flat[f"{scenario}_{field}"] for field in RUST_TRACE_FIELDS}
        for scenario in SCENARIOS
    }
    for scenario, trace in traces.items():
        if trace != RUST_EXPECTED[scenario]:
            raise EvidenceError(f"Rust {scenario} source transition drifted: {trace}")
    return traces


def run_rust_witness(cargo: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86_64-startup-regular-rust-") as directory:
        target_dir = Path(directory) / "target"
        command = cargo_command(cargo, target_dir)
        output = run_text(command)
    result = parse_test_result(output)
    traces = parse_rust_trace(output)
    normalized = ["<isolated-temporary-target-dir>" if part == str(target_dir) else part for part in command]
    return {
        "cargo_command": normalized,
        "observed": result,
        "source_test": f"{RUST_TARGET}::{RUST_FILTER}",
        "trace": traces,
        "stdout_sha256": sha256_bytes(output.encode("utf-8")),
    }


def comparison(c_oracle: Mapping[str, Any], rust: Mapping[str, Any]) -> dict[str, Any]:
    c_traces = c_oracle.get("traces")
    rust_traces = rust.get("trace")
    if not isinstance(c_traces, Mapping) or not isinstance(rust_traces, Mapping):
        raise EvidenceError("C/Rust source-start comparison is missing a trace")
    matched: dict[str, int] = {}
    for scenario in SCENARIOS:
        c_trace = c_traces.get(scenario)
        rust_trace = rust_traces.get(scenario)
        if not isinstance(c_trace, Mapping) or not isinstance(rust_trace, Mapping):
            raise EvidenceError(f"C/Rust {scenario} trace is malformed")
        for field in COMMON_FIELDS:
            if type(c_trace.get(field)) is not int or type(rust_trace.get(field)) is not int:
                raise EvidenceError(f"C/Rust {scenario} {field} is not an exact integer")
            if c_trace[field] != rust_trace[field]:
                raise EvidenceError(f"C/Rust {scenario} {field} differs")
            matched[f"{scenario}.{field}"] = c_trace[field]
    return {"matched_value_count": len(matched), "values": matched, "status": "matched-source-transitions"}


def require_sha256(value: object, description: str) -> None:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise EvidenceError(f"{description} must be one lowercase SHA-256 digest")


def require_file_record(record: object, description: str, *, path: str | None = None) -> None:
    if not isinstance(record, Mapping) or set(record) != {"bytes", "path", "sha256"}:
        raise EvidenceError(f"{description} record drifted")
    if type(record["bytes"]) is not int or record["bytes"] < 0:
        raise EvidenceError(f"{description} byte count drifted")
    if not isinstance(record["path"], str) or not record["path"]:
        raise EvidenceError(f"{description} path drifted")
    if path is not None and record["path"] != path:
        raise EvidenceError(f"{description} path drifted")
    require_sha256(record["sha256"], f"{description} SHA-256")


def validate_source_snapshot(snapshot: object) -> None:
    if not isinstance(snapshot, Mapping) or set(snapshot) != {
        "files", "git_revision", "git_status_porcelain", "git_tree",
    }:
        raise EvidenceError("startup-regular candidate snapshot schema drifted")
    for field in ("git_revision", "git_tree"):
        value = snapshot[field]
        if not isinstance(value, str) or GIT_OBJECT.fullmatch(value) is None:
            raise EvidenceError(f"startup-regular candidate {field} drifted")
    if not isinstance(snapshot["git_status_porcelain"], str):
        raise EvidenceError("startup-regular candidate status record drifted")
    files = snapshot["files"]
    if not isinstance(files, list):
        raise EvidenceError("startup-regular candidate input roster drifted")
    expected_paths = [relative(path) for path in source_input_paths()]
    paths: list[str] = []
    for record in files:
        if not isinstance(record, Mapping) or set(record) != {"path", "sha256"}:
            raise EvidenceError("startup-regular candidate input record drifted")
        path = record["path"]
        if not isinstance(path, str):
            raise EvidenceError("startup-regular candidate input path drifted")
        require_sha256(record["sha256"], "startup-regular candidate input")
        paths.append(path)
    if paths != expected_paths:
        raise EvidenceError("startup-regular candidate input roster drifted")


def validate_c_compile_command(command: object) -> None:
    if not isinstance(command, list) or not all(isinstance(part, str) for part in command):
        raise EvidenceError("startup-regular C compile command drifted")
    expected_prefix = [
        "-std=c11",
        "-fPIC",
        "-ftls-model=initial-exec",
        "-DMI_SHARED_LIB",
        "-DMI_SHARED_LIB_EXPORT",
        "-DMI_LIBC_MUSL=1",
        "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
        "-I",
        "<pinned-mimalloc-source>/include",
        "-I",
        "<pinned-mimalloc-source>/src",
        "-O3",
        "-DNDEBUG",
        "-DMI_BUILD_RELEASE=1",
        "-DMI_DEBUG=0",
        "-DMI_STAT=0",
        "-DMI_SECURE=0",
        "-DMI_GUARDED=0",
    ]
    if len(command) < 1 + len(expected_prefix) + 1 + len(C_LINK_SOURCES) + 3:
        raise EvidenceError("startup-regular C compile command is incomplete")
    if Path(command[0]).name != "musl-gcc" or command[1 : 1 + len(expected_prefix)] != expected_prefix:
        raise EvidenceError("startup-regular C release command drifted")
    cursor = 1 + len(expected_prefix)
    fixture = command[cursor]
    if not fixture.endswith(relative(FIXTURE)):
        raise EvidenceError("startup-regular C fixture command drifted")
    cursor += 1
    expected_sources = [f"<pinned-mimalloc-source>/{source}" for source in C_LINK_SOURCES]
    if command[cursor : cursor + len(expected_sources)] != expected_sources:
        raise EvidenceError("startup-regular C source selection drifted")
    cursor += len(expected_sources)
    if command[cursor:] != ["-pthread", "-o", "<startup-regular-arena-oracle-binary>"]:
        raise EvidenceError("startup-regular C output command drifted")


def validate_c_oracle(record: object) -> Mapping[str, Any]:
    if not isinstance(record, Mapping) or set(record) != {
        "binary", "build", "fixture", "runs", "source_files", "traces", "upstream",
    }:
        raise EvidenceError("startup-regular C oracle schema drifted")
    require_file_record(record["binary"], "startup-regular C binary", path=C_ORACLE_BINARY)
    build = record["build"]
    if not isinstance(build, Mapping) or set(build) != {
        "command", "status", "stderr_sha256", "stdout_sha256",
    }:
        raise EvidenceError("startup-regular C build record drifted")
    if type(build["status"]) is not int or build["status"] != 0:
        raise EvidenceError("startup-regular C build status drifted")
    validate_c_compile_command(build["command"])
    require_sha256(build["stderr_sha256"], "startup-regular C build stderr")
    require_sha256(build["stdout_sha256"], "startup-regular C build stdout")
    fixture = record["fixture"]
    if not isinstance(fixture, Mapping) or set(fixture) != {"path", "sha256"} or fixture["path"] != relative(FIXTURE):
        raise EvidenceError("startup-regular C fixture record drifted")
    require_sha256(fixture["sha256"], "startup-regular C fixture")
    if not exactly_matches(record["upstream"], PINNED_UPSTREAM):
        raise EvidenceError("startup-regular C upstream pin drifted")
    source_files = record["source_files"]
    if not isinstance(source_files, list) or [
        source.get("path") if isinstance(source, Mapping) else None for source in source_files
    ] != sorted(C_SOURCE_FILES):
        raise EvidenceError("startup-regular C source roster drifted")
    for source in source_files:
        require_file_record(source, "startup-regular C source")
    runs = record["runs"]
    if not isinstance(runs, Mapping) or set(runs) != set(SCENARIOS):
        raise EvidenceError("startup-regular C run roster drifted")
    for scenario in SCENARIOS:
        run = runs[scenario]
        if not isinstance(run, Mapping) or set(run) != {
            "command", "status", "stderr_sha256", "stdout_sha256",
        }:
            raise EvidenceError(f"startup-regular C {scenario} run record drifted")
        if run["command"] != ["<startup-regular-arena-oracle-binary>", scenario] or type(run["status"]) is not int or run["status"] != 0:
            raise EvidenceError(f"startup-regular C {scenario} invocation drifted")
        require_sha256(run["stderr_sha256"], f"startup-regular C {scenario} stderr")
        require_sha256(run["stdout_sha256"], f"startup-regular C {scenario} stdout")
    if not exactly_matches(record["traces"], C_EXPECTED):
        raise EvidenceError("startup-regular C source transitions drifted")
    return record


def validate_rust_witness(record: object) -> Mapping[str, Any]:
    if not isinstance(record, Mapping) or set(record) != {
        "cargo_command", "observed", "source_test", "stdout_sha256", "trace",
    }:
        raise EvidenceError("startup-regular Rust witness schema drifted")
    command = record["cargo_command"]
    if not isinstance(command, list) or not all(isinstance(part, str) for part in command):
        raise EvidenceError("startup-regular Rust command drifted")
    expected = [
        "test", "--locked", "--target", TARGET, "--target-dir", "<isolated-temporary-target-dir>",
        "-p", "crabc-mimalloc", "--test", RUST_TARGET, "--features", "native-runtime-test-audit",
        RUST_FILTER, "--", "--exact", "--nocapture", "--test-threads=1",
    ]
    if len(command) != len(expected) + 1 or command[1:] != expected:
        raise EvidenceError("startup-regular Rust command drifted")
    if record["source_test"] != f"{RUST_TARGET}::{RUST_FILTER}":
        raise EvidenceError("startup-regular Rust test selection drifted")
    if not exactly_matches(record["observed"], {
        "passed": 1, "failed": 0, "ignored": 0, "measured": 0, "filtered_out": 0,
    }):
        raise EvidenceError("startup-regular Rust observed result drifted")
    require_sha256(record["stdout_sha256"], "startup-regular Rust stdout")
    if not exactly_matches(record["trace"], RUST_EXPECTED):
        raise EvidenceError("startup-regular Rust source transitions drifted")
    return record


def validate_report(report: Mapping[str, Any]) -> None:
    required = {
        "candidate_source", "c_oracle", "cargo", "comparison", "format", "kind",
        "native_execution_provenance", "profile", "rust", "scope", "status", "target", "toolchain",
    }
    if set(report) != required:
        raise EvidenceError("startup-regular report schema drifted")
    if type(report.get("format")) is not int or report.get("format") != 1:
        raise EvidenceError("startup-regular report format must be exact integer one")
    if report.get("kind") != "mimalloc-x86_64-startup-regular-arena-evidence" or report.get("status") != "passed":
        raise EvidenceError("startup-regular report identity drifted")
    if report.get("profile") != PROFILE or not exactly_matches(report.get("scope"), REPORT_SCOPE):
        raise EvidenceError("startup-regular report private boundary drifted")
    if report.get("target") != {
        "architecture": "x86_64", "endianness": "little", "rust_target": TARGET, "system": "linux",
    }:
        raise EvidenceError("startup-regular report target drifted")
    if report.get("native_execution_provenance") not in (
        {"execution_mode": "native", "host_architecture": "x86_64"},
        {"execution_mode": "native", "host_architecture": "amd64"},
    ):
        raise EvidenceError("startup-regular report lacks native provenance")
    candidate = report.get("candidate_source")
    if not isinstance(candidate, Mapping) or set(candidate) != {"after", "before", "unchanged_during_execution"}:
        raise EvidenceError("startup-regular candidate source receipt drifted")
    if type(candidate.get("unchanged_during_execution")) is not bool or candidate["unchanged_during_execution"] is not True:
        raise EvidenceError("startup-regular candidate source receipt is not exact true")
    before = candidate.get("before")
    after = candidate.get("after")
    validate_source_snapshot(before)
    validate_source_snapshot(after)
    if not exactly_matches(before, after):
        raise EvidenceError("startup-regular candidate source bytes changed")
    toolchain = report.get("toolchain")
    if not isinstance(toolchain, Mapping) or set(toolchain) != {"cargo", "rustc_host", "rustc_release"}:
        raise EvidenceError("startup-regular toolchain record drifted")
    if toolchain["rustc_host"] != TARGET or not all(
        isinstance(toolchain[field], str) and toolchain[field]
        for field in ("cargo", "rustc_release")
    ):
        raise EvidenceError("startup-regular toolchain identity drifted")
    cargo = report.get("cargo")
    if not isinstance(cargo, Mapping) or set(cargo) != {"locked", "lockfile", "target_dir"}:
        raise EvidenceError("startup-regular Cargo record drifted")
    if type(cargo["locked"]) is not bool or cargo["locked"] is not True:
        raise EvidenceError("startup-regular Cargo lock mode drifted")
    lockfile = cargo["lockfile"]
    if not isinstance(lockfile, Mapping) or set(lockfile) != {"path", "sha256"} or lockfile["path"] != relative(LOCKFILE):
        raise EvidenceError("startup-regular Cargo lockfile drifted")
    require_sha256(lockfile["sha256"], "startup-regular Cargo lockfile")
    if not exactly_matches(cargo["target_dir"], {
        "isolated": True, "retained": False, "value": "<isolated-temporary-target-dir>",
    }):
        raise EvidenceError("startup-regular Cargo target directory drifted")
    c_oracle = validate_c_oracle(report.get("c_oracle"))
    rust = validate_rust_witness(report.get("rust"))
    expected = comparison(c_oracle, rust)
    if report.get("comparison") != expected:
        raise EvidenceError("startup-regular C/Rust comparison drifted")


def atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        path.chmod(0o644)
        temporary = None
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def run_evidence(report_path: Path) -> dict[str, Any]:
    before = source_snapshot()
    provenance = require_native_x86_64()
    cargo = require_tool("cargo")
    rustc = require_tool("rustc")
    toolchain = toolchain_record(cargo, rustc)
    lock_before = sha256_file(LOCKFILE)
    harness = load_harness()
    c_oracle = run_c_oracle(harness)
    rust = run_rust_witness(cargo)
    lock_after = sha256_file(LOCKFILE)
    if lock_before != lock_after:
        raise EvidenceError("Cargo.lock changed despite --locked Rust evidence")
    report: dict[str, Any] = {
        "format": 1,
        "kind": "mimalloc-x86_64-startup-regular-arena-evidence",
        "profile": PROFILE,
        "status": "passed",
        "target": {
            "architecture": "x86_64", "endianness": "little", "rust_target": TARGET, "system": "linux",
        },
        "native_execution_provenance": provenance,
        "toolchain": toolchain,
        "cargo": {
            "lockfile": {"path": relative(LOCKFILE), "sha256": lock_before},
            "locked": True,
            "target_dir": {"isolated": True, "retained": False, "value": "<isolated-temporary-target-dir>"},
        },
        "candidate_source": candidate_attestation(before, source_snapshot()),
        "c_oracle": c_oracle,
        "rust": rust,
        "comparison": comparison(c_oracle, rust),
        "scope": REPORT_SCOPE,
    }
    validate_report(report)
    atomic_write_json(report_path, report)
    return report


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=REPORT_DEFAULT)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        report = run_evidence(arguments.report)
    except EvidenceError as error:
        print(f"allocator x86-64 startup regular arena: FAIL: {error}", file=sys.stderr)
        return 1
    print(
        "allocator x86-64 startup regular arena: PASS "
        f"({report['comparison']['matched_value_count']} matched C/Rust values)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
