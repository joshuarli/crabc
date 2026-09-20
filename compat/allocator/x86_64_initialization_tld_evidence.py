#!/usr/bin/env python3
"""Native x86-64 evidence for three fixed mimalloc initialization TLD arms.

This private producer compiles the pinned C direct fixtures for the detached
static preimage, direct normal TLD initialization, and first-main static TLD
creation.  It compares each complete address-independent record with the
existing Rust emitter, then embeds the current native init-recursion receipt.
The selected branch matrix is intentionally finite: generic/later TLD creation,
automatic teardown, metadata publication, and allocator-recursion completion
remain outside this initialization admission.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "compat/allocator/run.py"
RECURSION_PATH = ROOT / "compat/allocator/x86_64_init_recursion_evidence.py"
FRAGMENT_PATH = ROOT / "compat/allocator/m2-initialization-x86_64-v3.5.0.fragment.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/initialization-tld-matrix.json"
TARGET = "x86_64-unknown-linux-musl"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"
EVIDENCE_KIND = "mimalloc-x86_64-initialization-three-fixed-tld-arms-and-explicit-worker-recovery-evidence"
EVIDENCE_PROFILE = "release-initial-exec-direct-tld-static-normal-first-main-and-explicit-worker-recovery"
TEMPORARY_PREFIX = "crabc-mimalloc-x86-initialization-tld-"

INITIALIZATION_TLD_BRANCH_IDS = (
    "detached-static-preimage",
    "normal-direct-tld-init",
    "first-main-static-tld-create",
)
BRANCH_TARGETS = (
    "types::tests::emit_m2_detached_tld_static_preimage_c_rust_trace",
    "subproc::tests::emit_m2_normal_tld_direct_c_rust_trace",
    "main_theap::tests::emit_m2_static_first_tld_create_c_rust_trace",
)
BRANCH_RUST_SOURCES = (
    "crabc-mimalloc/src/types.rs",
    "crabc-mimalloc/src/subproc.rs",
    "crabc-mimalloc/src/main_theap.rs",
)
BRANCH_C_SOURCE_FILE_RECORDS = (
    (
        {"path": "include/mimalloc.h", "bytes": 49389, "sha256": "af34f215cb6fe9e4e97bf08d78bfda877ab4cdd63c9222640c483d7d6a4488a5"},
        {"path": "include/mimalloc/atomic.h", "bytes": 24497, "sha256": "106b267e98ccc5e01b48252c9742584cd5c914f309e7f4a4413ad85e65063d41"},
        {"path": "include/mimalloc/internal.h", "bytes": 60106, "sha256": "4fd7b1dd450989b1a8a5b4cb54e163a36d932bbf7e341abcd882763251252852"},
        {"path": "include/mimalloc/types.h", "bytes": 40624, "sha256": "6a81148760be95f8fc8a2b7694f29e0f1f153b4c871ddd808e63cb0bbb9c3bae"},
        {"path": "src/init.c", "bytes": 25096, "sha256": "e22486042ba132e002822315ccd4b24738fc3a151fc14172e5e45426e8add299"},
        {"path": "src/prim/prim.c", "bytes": 2449, "sha256": "241b1087a0e22609de71b2deba6c771135dd37e756ea89ba79b5900165b4f229"},
    ),
    (
        {"path": "include/mimalloc.h", "bytes": 49389, "sha256": "af34f215cb6fe9e4e97bf08d78bfda877ab4cdd63c9222640c483d7d6a4488a5"},
        {"path": "include/mimalloc/atomic.h", "bytes": 24497, "sha256": "106b267e98ccc5e01b48252c9742584cd5c914f309e7f4a4413ad85e65063d41"},
        {"path": "include/mimalloc/internal.h", "bytes": 60106, "sha256": "4fd7b1dd450989b1a8a5b4cb54e163a36d932bbf7e341abcd882763251252852"},
        {"path": "include/mimalloc/prim-tls.h", "bytes": 19214, "sha256": "46d871923b38c9463da985c54503cd5cb64bb2c91008f3d35bcbaae2a11c31c2"},
        {"path": "include/mimalloc/prim.h", "bytes": 6403, "sha256": "1987e8e2eedc07bb181bf2a11a27bec80a5309c32cfa66a56900fb4cbb64b172"},
        {"path": "include/mimalloc/types.h", "bytes": 40624, "sha256": "6a81148760be95f8fc8a2b7694f29e0f1f153b4c871ddd808e63cb0bbb9c3bae"},
        {"path": "src/init.c", "bytes": 25096, "sha256": "e22486042ba132e002822315ccd4b24738fc3a151fc14172e5e45426e8add299"},
        {"path": "src/os.c", "bytes": 39093, "sha256": "8410b04c2d5b37e59fff1854364fed1fba873133b064cfe02083277038388548"},
        {"path": "src/prim/prim-tls.c", "bytes": 10103, "sha256": "4970ab233c499a1080db2fa77386439cd35a029a9be7ce25eef817e281ad8d70"},
        {"path": "src/prim/prim.c", "bytes": 2449, "sha256": "241b1087a0e22609de71b2deba6c771135dd37e756ea89ba79b5900165b4f229"},
        {"path": "src/prim/unix/prim.c", "bytes": 36822, "sha256": "8efeac14a9952aa7c3117ce2d9d801f93692bda6cd80e09a51ddca398d7ac774"},
    ),
    (
        {"path": "include/mimalloc.h", "bytes": 49389, "sha256": "af34f215cb6fe9e4e97bf08d78bfda877ab4cdd63c9222640c483d7d6a4488a5"},
        {"path": "include/mimalloc/atomic.h", "bytes": 24497, "sha256": "106b267e98ccc5e01b48252c9742584cd5c914f309e7f4a4413ad85e65063d41"},
        {"path": "include/mimalloc/internal.h", "bytes": 60106, "sha256": "4fd7b1dd450989b1a8a5b4cb54e163a36d932bbf7e341abcd882763251252852"},
        {"path": "include/mimalloc/prim-tls.h", "bytes": 19214, "sha256": "46d871923b38c9463da985c54503cd5cb64bb2c91008f3d35bcbaae2a11c31c2"},
        {"path": "include/mimalloc/prim.h", "bytes": 6403, "sha256": "1987e8e2eedc07bb181bf2a11a27bec80a5309c32cfa66a56900fb4cbb64b172"},
        {"path": "include/mimalloc/types.h", "bytes": 40624, "sha256": "6a81148760be95f8fc8a2b7694f29e0f1f153b4c871ddd808e63cb0bbb9c3bae"},
        {"path": "src/init.c", "bytes": 25096, "sha256": "e22486042ba132e002822315ccd4b24738fc3a151fc14172e5e45426e8add299"},
        {"path": "src/os.c", "bytes": 39093, "sha256": "8410b04c2d5b37e59fff1854364fed1fba873133b064cfe02083277038388548"},
        {"path": "src/prim/prim-tls.c", "bytes": 10103, "sha256": "4970ab233c499a1080db2fa77386439cd35a029a9be7ce25eef817e281ad8d70"},
        {"path": "src/prim/prim.c", "bytes": 2449, "sha256": "241b1087a0e22609de71b2deba6c771135dd37e756ea89ba79b5900165b4f229"},
        {"path": "src/prim/unix/prim.c", "bytes": 36822, "sha256": "8efeac14a9952aa7c3117ce2d9d801f93692bda6cd80e09a51ddca398d7ac774"},
        {"path": "src/subproc.c", "bytes": 11458, "sha256": "39ab44c15b0dd91a53268fd52590d681e3c62e1930144b9392db0fde44439054"},
    ),
)
EXPECTED_ANCHORS = (
    ("src/init.c", 192, 192, "a91cd5dc5550b774d82d31c371386cec7bc67cdafd9fe643af3b8c57c796f3d1"),
    ("src/init.c", 236, 250, "25b55becf855281d82750d46dcd93ab6e8786453295b7eb34b4648ace45fc455"),
    ("src/init.c", 253, 272, "077d0451e7d7a572cdb1cfd6ff9b95bd43e06c22345679faf1c8e7e16f70b9d8"),
)
EXPECTED_REQUIRED_DEFINITIONS = (
    ("mi_tld_detached.memid = memid_static",),
    (
        "static mi_tld_t* mi_tld_init",
        "mi_lock_init(&tld->theaps_lock)",
        "mi_atomic_increment_relaxed(&tld->subproc->thread_count)",
    ),
    (
        "static mi_tld_t* mi_tld_create",
        "mi_atomic_increment_relaxed(&subproc->thread_total_count)",
        "return mi_tld_init(tld,tseq,subproc)",
    ),
)
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "allocator_recursion_completion_claimed": False,
    "automatic_pthread_destructor_claimed": False,
    "generic_or_later_tld_create_claimed": False,
    "metadata_or_os_aligned_publication_claimed": False,
    "native_linux_x86_64_required": True,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "rust_failure_rows_c_fault_equivalence_claimed": False,
}

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)
recursion_spec = importlib.util.spec_from_file_location("crabc_init_recursion", RECURSION_PATH)
assert recursion_spec is not None and recursion_spec.loader is not None
recursion = importlib.util.module_from_spec(recursion_spec)
recursion_spec.loader.exec_module(recursion)


BRANCH_C_PROBE_NAMES = (
    "m2-detached-tld-static-preimage-trace-probe",
    "m2-normal-tld-direct-trace-probe",
    "m2-static-first-tld-create-trace-probe",
)
# Each direct fixture includes `src/init.c` itself, so the compile closure
# deliberately omits it while the retained source-file inventory includes it.
BRANCH_C_ORACLE_SOURCES = (
    tuple(run.M2_DETACHED_TLD_STATIC_PREIMAGE_ORACLE_SOURCES),
    tuple(run.M2_NORMAL_TLD_DIRECT_ORACLE_SOURCES),
    tuple(run.M2_STATIC_FIRST_TLD_CREATE_ORACLE_SOURCES),
)
BRANCH_C_SOURCE_FILES = (
    tuple(sorted((
        "include/mimalloc.h", "include/mimalloc/atomic.h", "include/mimalloc/internal.h",
        "include/mimalloc/types.h", "src/init.c", "src/prim/prim.c",
    ))),
    tuple(sorted((
        "include/mimalloc.h", "include/mimalloc/atomic.h", "include/mimalloc/internal.h",
        "include/mimalloc/prim.h", "include/mimalloc/prim-tls.h", "include/mimalloc/types.h",
        "src/init.c", "src/os.c", "src/prim/prim-tls.c", "src/prim/prim.c", "src/prim/unix/prim.c",
    ))),
    tuple(sorted((
        "include/mimalloc.h", "include/mimalloc/atomic.h", "include/mimalloc/internal.h",
        "include/mimalloc/prim.h", "include/mimalloc/prim-tls.h", "include/mimalloc/types.h",
        "src/init.c", "src/os.c", "src/prim/prim-tls.c", "src/prim/prim.c", "src/prim/unix/prim.c",
        "src/subproc.c",
    ))),
)
class EvidenceError(RuntimeError):
    """The bounded initialization evidence cannot establish its fixed claim."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    if not path.is_file():
        raise EvidenceError(f"required evidence input is missing: {relative(path)}")
    return sha256_bytes(path.read_bytes())


def relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def exactly_matches(observed: object, expected: object) -> bool:
    if type(observed) is not type(expected):
        return False
    if isinstance(expected, dict):
        assert isinstance(observed, dict)
        return set(observed) == set(expected) and all(
            exactly_matches(observed[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        assert isinstance(observed, list)
        return len(observed) == len(expected) and all(
            exactly_matches(value, expected_value)
            for value, expected_value in zip(observed, expected)
        )
    return observed == expected


def source_range(contents: bytes, start_line: int, end_line: int) -> bytes:
    lines = contents.splitlines(keepends=True)
    if start_line < 1 or end_line < start_line or end_line > len(lines):
        raise EvidenceError("initialization source anchor is outside its pinned member")
    return b"".join(lines[start_line - 1 : end_line])


def validate_source_anchors(source: Path) -> list[dict[str, Any]]:
    anchors: list[dict[str, Any]] = []
    for member, start_line, end_line, expected_sha256 in EXPECTED_ANCHORS:
        path = source / member
        if not path.is_file():
            raise EvidenceError(f"pinned source anchor is absent: {member}")
        observed = sha256_bytes(source_range(path.read_bytes(), start_line, end_line))
        if observed != expected_sha256:
            raise EvidenceError(f"pinned initialization source anchor drifted: {member}:{start_line}-{end_line}")
        anchors.append({
            "member": member,
            "start_line": start_line,
            "end_line": end_line,
            "sha256": expected_sha256,
        })
    return anchors


def branch_index(branch_id: str) -> int:
    try:
        return INITIALIZATION_TLD_BRANCH_IDS.index(branch_id)
    except ValueError as error:
        raise EvidenceError(f"unknown fixed initialization TLD branch: {branch_id}") from error


def branch_c_fixture(branch_id: str) -> str:
    index = branch_index(branch_id)
    if index == 0:
        return run.M2_DETACHED_TLD_STATIC_PREIMAGE_TRACE_PROBE
    if index == 1:
        return run.M2_NORMAL_TLD_DIRECT_TRACE_PROBE
    return run.M2_STATIC_FIRST_TLD_CREATE_TRACE_PROBE


def branch_trace_keys(branch_id: str) -> tuple[str, ...]:
    index = branch_index(branch_id)
    if index == 0:
        return tuple(run.M2_DETACHED_TLD_STATIC_PREIMAGE_TRACE_KEYS)
    if index == 1:
        return tuple(run.M2_NORMAL_TLD_DIRECT_TRACE_KEYS)
    return tuple(run.M2_STATIC_FIRST_TLD_CREATE_TRACE_KEYS)


def parse_branch_trace(branch_id: str, output: str, *, source: str) -> dict[str, int]:
    index = branch_index(branch_id)
    try:
        if index == 0:
            return run.parse_m2_detached_tld_static_preimage_trace(output, source=source)
        if index == 1:
            return run.parse_m2_normal_tld_direct_trace(output, source=source)
        return run.parse_m2_static_first_tld_create_trace(output, source=source)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def validate_branch_trace(branch_id: str, trace: Mapping[str, int], *, source: str) -> None:
    index = branch_index(branch_id)
    try:
        if index == 0:
            run.validate_m2_detached_tld_static_preimage_trace(trace, source=source)
        elif index == 1:
            run.validate_m2_normal_tld_direct_trace(trace, source=source)
        else:
            run.validate_m2_static_first_tld_create_trace(trace, source=source)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def compare_branch_trace(branch_id: str, c_trace: Mapping[str, int], rust_trace: Mapping[str, int]) -> dict[str, Any]:
    validate_branch_trace(branch_id, c_trace, source="pinned C")
    validate_branch_trace(branch_id, rust_trace, source="Rust")
    if dict(c_trace) != dict(rust_trace):
        raise EvidenceError(f"pinned C and Rust initialization TLD records differ: {branch_id}")
    return {"compared_value_count": len(branch_trace_keys(branch_id)), "status": "matched"}


def validate_initialization_tld_branch_rows(rows: object) -> None:
    """Require the fixed three schemas, values, order, and exact C/Rust parity."""

    if not isinstance(rows, list) or len(rows) != len(INITIALIZATION_TLD_BRANCH_IDS):
        raise EvidenceError("initialization TLD branch row count changed")
    for expected_id, row in zip(INITIALIZATION_TLD_BRANCH_IDS, rows):
        if not isinstance(row, Mapping) or set(row) != {"id", "c_trace", "rust_trace", "comparison"}:
            raise EvidenceError("initialization TLD branch row schema changed")
        if row.get("id") != expected_id:
            raise EvidenceError("initialization TLD branch roster/order changed")
        c_trace = row.get("c_trace")
        rust_trace = row.get("rust_trace")
        comparison = row.get("comparison")
        if not isinstance(c_trace, Mapping) or not isinstance(rust_trace, Mapping):
            raise EvidenceError("initialization TLD branch trace is absent")
        validate_branch_trace(expected_id, c_trace, source="pinned C")
        validate_branch_trace(expected_id, rust_trace, source="Rust")
        if dict(c_trace) != dict(rust_trace):
            raise EvidenceError("initialization TLD C/Rust row no longer matches")
        if comparison != {
            "compared_value_count": len(branch_trace_keys(expected_id)),
            "status": "matched",
        }:
            raise EvidenceError("initialization TLD comparison record changed")


def validate_c_probe(branch_id: str, probe: object) -> None:
    """Bind one retained C row to its direct include fixture and source closure."""

    index = branch_index(branch_id)
    if not isinstance(probe, Mapping) or set(probe) != {
        "branch", "command", "compiled_source_closure", "fixture", "source_files"
    }:
        raise EvidenceError("initialization C probe schema changed")
    command = probe.get("command")
    if not isinstance(command, list) or not command or Path(command[0]).name != "musl-gcc":
        raise EvidenceError("initialization C compiler changed")
    probe_name = BRANCH_C_PROBE_NAMES[index]
    expected = [
        "-std=c11", "-fPIC", "-ftls-model=initial-exec",
        "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1", "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
        "-I", f"{NORMALIZED_PINNED_SOURCE}/include", "-I", f"{NORMALIZED_PINNED_SOURCE}/src",
        *run.CONFIGURATION_PROFILES["release"],
        f"{NORMALIZED_EVIDENCE_ROOT}/c/{branch_id}/{probe_name}.c",
        *(f"{NORMALIZED_PINNED_SOURCE}/{member}" for member in BRANCH_C_ORACLE_SOURCES[index]),
        "-pthread", "-o", f"{NORMALIZED_EVIDENCE_ROOT}/c/{branch_id}/{probe_name}",
    ]
    if command[1:] != expected:
        raise EvidenceError("initialization C direct fixture command or source closure changed")
    fixture = probe.get("fixture")
    expected_fixture = branch_c_fixture(branch_id).encode("utf-8")
    if fixture != {
        "bytes": len(expected_fixture),
        "path": f"{NORMALIZED_EVIDENCE_ROOT}/c/{branch_id}/{probe_name}.c",
        "sha256": sha256_bytes(expected_fixture),
    }:
        raise EvidenceError("initialization C generated fixture provenance changed")
    if probe.get("compiled_source_closure") != {
        "direct_fixture_includes": ["src/init.c"],
        "translation_units": list(BRANCH_C_ORACLE_SOURCES[index]),
    }:
        raise EvidenceError("initialization C compiled source closure changed")
    source_files = probe.get("source_files")
    if source_files != list(BRANCH_C_SOURCE_FILE_RECORDS[index]):
        raise EvidenceError("initialization C direct source-file provenance changed")


def validate_rust_probe(branch_id: str, probe: object) -> None:
    """Bind one retained Rust row to its exact private target/filter command."""

    index = branch_index(branch_id)
    if not isinstance(probe, Mapping) or set(probe) != {"branch", "command", "passed_test_count", "source"}:
        raise EvidenceError("initialization Rust probe schema changed")
    command = probe.get("command")
    if not isinstance(command, list) or not command or Path(command[0]).name != "cargo":
        raise EvidenceError("initialization Rust compiler changed")
    expected = [
        "test", "--locked", "--target", TARGET, "--target-dir", f"{NORMALIZED_EVIDENCE_ROOT}/rust-target",
        "-p", "crabc-mimalloc", "--lib", "--no-default-features", BRANCH_TARGETS[index],
        "--", "--exact", "--nocapture", "--test-threads=1",
    ]
    if command[1:] != expected or probe.get("passed_test_count") != 1:
        raise EvidenceError("initialization Rust target/filter command changed")
    if probe.get("source") != {
        "path": BRANCH_RUST_SOURCES[index],
        "sha256": sha256_file(ROOT / BRANCH_RUST_SOURCES[index]),
    }:
        raise EvidenceError("initialization Rust trace source changed")

def normalized_command(command: Sequence[str], temporary: Path, source: Path | None) -> list[str]:
    normalized: list[str] = []
    temporary_text = str(temporary)
    source_text = str(source) if source is not None else None
    for part in command:
        if source_text is not None and (part == source_text or part.startswith(source_text + "/")):
            normalized.append(NORMALIZED_PINNED_SOURCE + part[len(source_text):])
        elif part == temporary_text or part.startswith(temporary_text + "/"):
            normalized.append(NORMALIZED_EVIDENCE_ROOT + part[len(temporary_text):])
        else:
            normalized.append(part)
    return normalized


def rust_test_command(cargo: str, target_dir: Path, branch_id: str) -> list[str]:
    index = branch_index(branch_id)
    return [
        cargo, "test", "--locked", "--target", TARGET, "--target-dir", str(target_dir),
        "-p", "crabc-mimalloc", "--lib", "--no-default-features", BRANCH_TARGETS[index],
        "--", "--exact", "--nocapture", "--test-threads=1",
    ]


def run_rust_branch(cargo: str, target_dir: Path, branch_id: str) -> tuple[list[str], dict[str, int]]:
    command = rust_test_command(cargo, target_dir, branch_id)
    environment = os.environ.copy()
    environment["CARGO_INCREMENTAL"] = "0"
    try:
        execution = run.command_record(command, cwd=ROOT, env=environment)
        run.require_success(execution, f"Rust initialization TLD check {branch_id}")
        output = str(execution["stdout"]) + "\n" + str(execution["stderr"])
        if run.parse_rust_test_count(output) != 1:
            raise EvidenceError(f"Rust initialization TLD check did not pass exactly one test: {branch_id}")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    trace = parse_branch_trace(branch_id, output, source="Rust")
    validate_branch_trace(branch_id, trace, source="Rust")
    return command, trace


def build_c_branch(compiler: str, source: Path, temporary: Path, branch_id: str) -> dict[str, Any]:
    index = branch_index(branch_id)
    profile_dir = temporary / "c" / branch_id
    profile = run.CONFIGURATION_PROFILES["release"]
    try:
        if index == 0:
            built = run.build_m2_detached_tld_static_preimage_trace(compiler, source, profile_dir, profile)
        elif index == 1:
            built = run.build_m2_normal_tld_direct_trace(compiler, source, profile_dir, profile)
        else:
            built = run.build_m2_static_first_tld_create_trace(compiler, source, profile_dir, profile)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    c_trace = built.get("record")
    if not isinstance(c_trace, Mapping):
        raise EvidenceError(f"pinned C initialization TLD trace is absent: {branch_id}")
    validate_branch_trace(branch_id, c_trace, source="pinned C")
    fixture = branch_c_fixture(branch_id).encode("utf-8")
    probe_name = BRANCH_C_PROBE_NAMES[index]
    return {
        "command": normalized_command(built["command"], temporary, source),
        "compiled_source_closure": {
            "direct_fixture_includes": ["src/init.c"],
            "translation_units": list(BRANCH_C_ORACLE_SOURCES[index]),
        },
        "fixture": {
            "bytes": len(fixture),
            "path": f"{NORMALIZED_EVIDENCE_ROOT}/c/{branch_id}/{probe_name}.c",
            "sha256": sha256_bytes(fixture),
        },
        "source_files": list(built["source_files"]),
        "trace": dict(c_trace),
    }


def source_input_records() -> list[dict[str, str]]:
    """Freeze all local inputs shared by this matrix and its embedded receipt."""

    paths = {
        "Cargo.lock",
        "compat/allocator/run.py",
        "compat/allocator/m2-initialization-x86_64-v3.5.0.fragment.json",
        "compat/allocator/x86_64_initialization_tld_evidence.py",
        "compat/allocator/x86_64_init_recursion_evidence.py",
        "compat/allocator/x86_64-init-recursion-evidence-v3.5.0.json",
        "compat/upstreams.toml",
        *BRANCH_RUST_SOURCES,
        relative(recursion.RUST_TRACE_SOURCE),
        *(str(check["source"]) for check in recursion.EXPECTED_LIFECYCLE_CHECKS),
    }
    return [
        {"path": path, "sha256": sha256_file(ROOT / path)}
        for path in sorted(paths)
    ]


def source_state() -> dict[str, Any]:
    environment = dict(os.environ)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    try:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, env=environment, text=True,
            capture_output=True, check=True,
        ).stdout.strip()
        status_output = subprocess.run(
            ["git", "status", "--porcelain=v1", "-z"], cwd=ROOT, env=environment,
            capture_output=True, check=True,
        ).stdout
        status = status_output if isinstance(status_output, bytes) else str(status_output).encode()
    except (OSError, subprocess.CalledProcessError) as error:
        raise EvidenceError("cannot attest initialization evidence source state") from error
    return {
        "revision": revision,
        "status": {"bytes": len(status), "hex": status.hex(), "sha256": sha256_bytes(status)},
    }


def validate_source_state(state: object) -> None:
    if not isinstance(state, Mapping) or set(state) != {"revision", "status"}:
        raise EvidenceError("initialization evidence source-state schema changed")
    status = state.get("status")
    if (
        not isinstance(state.get("revision"), str)
        or len(str(state["revision"])) != 40
        or not isinstance(status, Mapping)
        or set(status) != {"bytes", "hex", "sha256"}
    ):
        raise EvidenceError("initialization evidence source-state is invalid")
    try:
        payload = bytes.fromhex(str(status["hex"]))
    except ValueError as error:
        raise EvidenceError("initialization evidence source-state encoding is invalid") from error
    if (
        type(status.get("bytes")) is not int
        or status["bytes"] != len(payload)
        or status.get("sha256") != sha256_bytes(payload)
        or payload
    ):
        raise EvidenceError("initialization evidence was not collected from a clean source revision")


def load_fragment(path: Path = FRAGMENT_PATH) -> dict[str, Any]:
    try:
        fragment = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read initialization M2 evidence fragment") from error
    if not isinstance(fragment, dict) or set(fragment) != {"component", "format", "schema", "target", "upstream"}:
        raise EvidenceError("initialization M2 fragment schema changed")
    if fragment.get("schema") != "crabc-mimalloc-x86_64-m2-component-evidence" or fragment.get("format") != 1:
        raise EvidenceError("initialization M2 fragment identity changed")
    if fragment.get("target") != {
        "architecture": "x86_64", "endianness": "little", "kernel_baseline": "5.10",
        "os": "linux", "rust_target": TARGET,
    }:
        raise EvidenceError("initialization M2 fragment target changed")
    pin = run.load_pin()
    if fragment.get("upstream") != {"archive_sha256": pin["sha256"], "revision": pin["revision"], "version": pin["version"]}:
        raise EvidenceError("initialization M2 fragment upstream changed")
    component = fragment.get("component")
    expected_component = {
        "branch_matrix", "bounded_source_definitions", "checks", "completion_status", "id",
        "remaining_conditions", "source_map_records", "source_units", "unqualified_failure_matrix",
    }
    if not isinstance(component, Mapping) or set(component) != expected_component:
        raise EvidenceError("initialization M2 component fragment schema changed")
    if component.get("id") != "initialization" or component.get("completion_status") != "partial":
        raise EvidenceError("initialization M2 component state changed")
    if component.get("source_units") != ["src/init.c", "src/prim/prim.c", "src/prim/prim-tls.c"]:
        raise EvidenceError("initialization M2 source-unit roster changed")
    if component.get("source_map_records") != [
        {"required_status": "partial", "unit_id": "process-and-thread-initialization"},
        {"required_status": "partial", "unit_id": "c-support-and-once"},
        {"required_status": "partial", "unit_id": "tls-interface-and-thread-identity"},
    ]:
        raise EvidenceError("initialization M2 source-map roster changed")
    expected_checks = (
        ("initialization-tld-direct-source-matrix", "c-rust-initialization-tld-source-matrix", "x86_64_initialization_tld_evidence::three_fixed_direct_tld_branches", 3),
        ("initialization-explicit-worker-recovery-lifecycle", "c-rust-init-recursion-lifecycle", "main_heap_thread::tests::emit_x86_64_init_recursion_teardown_c_rust_trace", 1),
    )
    checks = component.get("checks")
    if not isinstance(checks, list) or [
        (item.get("id"), item.get("kind"), item.get("target"), item.get("expected_passed_test_count"))
        for item in checks if isinstance(item, Mapping)
    ] != list(expected_checks):
        raise EvidenceError("initialization M2 fixed check roster changed")
    anchors = component.get("bounded_source_definitions")
    if not isinstance(anchors, list) or [
        (item.get("source_anchor", {}).get("member"), item.get("source_anchor", {}).get("start_line"), item.get("source_anchor", {}).get("end_line"), item.get("source_anchor", {}).get("sha256"), tuple(item.get("required_definitions", ())))
        for item in anchors if isinstance(item, Mapping)
    ] != [(*anchor, required_definitions) for anchor, required_definitions in zip(EXPECTED_ANCHORS, EXPECTED_REQUIRED_DEFINITIONS)]:
        raise EvidenceError("initialization M2 source anchors changed")
    branches = component.get("branch_matrix")
    expected_branch_anchors = (
        (EXPECTED_ANCHORS[0], EXPECTED_ANCHORS[1]),
        (EXPECTED_ANCHORS[1],),
        (EXPECTED_ANCHORS[2],),
    )
    if not isinstance(branches, list) or len(branches) != len(INITIALIZATION_TLD_BRANCH_IDS):
        raise EvidenceError("initialization M2 branch matrix changed")
    for branch_id, anchors_for_branch, branch in zip(
        INITIALIZATION_TLD_BRANCH_IDS, expected_branch_anchors, branches
    ):
        if not isinstance(branch, Mapping) or set(branch) != {
            "disposition", "evidence_check_ids", "id", "missing_conditions", "source_anchors", "source_scope"
        } or branch.get("id") != branch_id or branch.get("disposition") != "bounded-direct-source-differential":
            raise EvidenceError("initialization M2 branch roster changed")
        anchors = branch.get("source_anchors")
        expected_anchor_records = [
            {"member": member, "start_line": start, "end_line": end, "sha256": digest}
            for member, start, end, digest in anchors_for_branch
        ]
        if anchors != expected_anchor_records or branch.get("evidence_check_ids") != ["initialization-tld-direct-source-matrix"]:
            raise EvidenceError("initialization M2 branch anchor/check binding changed")
        if not isinstance(branch.get("source_scope"), str) or not branch["source_scope"] or not isinstance(branch.get("missing_conditions"), list) or not branch["missing_conditions"]:
            raise EvidenceError("initialization M2 branch scope changed")
    return fragment


def report_from_results(
    *, provenance: Mapping[str, str], before: Mapping[str, Any], after: Mapping[str, Any],
    anchors: Sequence[Mapping[str, Any]], rows: Sequence[Mapping[str, Any]],
    c_probes: Sequence[Mapping[str, Any]], rust_probes: Sequence[Mapping[str, Any]],
    init_recursion: Mapping[str, Any],
) -> dict[str, Any]:
    pin = run.load_pin()
    report = {
        "branch_rows": [dict(row) for row in rows],
        "c_probes": [dict(probe) for probe in c_probes],
        "format": 1,
        "init_recursion": dict(init_recursion),
        "init_recursion_binding": {
            "source_input_paths": [record["path"] for record in source_input_records()],
            "source_state_after": dict(after),
            "source_state_before": dict(before),
        },
        "kind": EVIDENCE_KIND,
        "profile": EVIDENCE_PROFILE,
        "provenance": dict(provenance),
        "rust_probes": [dict(probe) for probe in rust_probes],
        "scope": EXPECTED_SCOPE,
        "source": {
            "anchors": [dict(anchor) for anchor in anchors],
            "archive_sha256": pin["sha256"],
            "compile_definitions": ["-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1", "-DMI_PRIM_HAS_PROCESS_ATTACH=1"],
            "fragment": {"path": relative(FRAGMENT_PATH), "sha256": sha256_file(FRAGMENT_PATH)},
            "inputs": source_input_records(),
            "release_flags": list(run.CONFIGURATION_PROFILES["release"]),
        },
        "source_state_after": dict(after),
        "source_state_before": dict(before),
        "status": "passed",
        "target": {"architecture": "x86_64", "endianness": "little", "os": "linux", "rust_target": TARGET},
        "upstream": {"archive_sha256": pin["sha256"], "revision": pin["revision"], "version": pin["version"]},
    }
    validate_report(report)
    return report


def validate_report(report: Mapping[str, Any]) -> None:
    expected = {
        "branch_rows", "c_probes", "format", "init_recursion", "init_recursion_binding", "kind", "profile", "provenance",
        "rust_probes", "scope", "source", "source_state_after", "source_state_before", "status", "target", "upstream",
    }
    if not isinstance(report, Mapping) or set(report) != expected or report.get("format") != 1 or report.get("status") != "passed":
        raise EvidenceError("initialization evidence report schema changed")
    if report.get("kind") != EVIDENCE_KIND or report.get("profile") != EVIDENCE_PROFILE:
        raise EvidenceError("initialization evidence identity changed")
    if report.get("scope") != EXPECTED_SCOPE:
        raise EvidenceError("initialization evidence scope changed")
    if report.get("target") != {"architecture": "x86_64", "endianness": "little", "os": "linux", "rust_target": TARGET}:
        raise EvidenceError("initialization evidence target changed")
    if report.get("provenance") not in (
        {"execution_mode": "native", "host_architecture": "x86_64"},
        {"execution_mode": "native", "host_architecture": "amd64"},
    ):
        raise EvidenceError("initialization evidence lacks native x86-64 provenance")
    pin = run.load_pin()
    if report.get("upstream") != {"archive_sha256": pin["sha256"], "revision": pin["revision"], "version": pin["version"]}:
        raise EvidenceError("initialization evidence upstream changed")
    validate_source_state(report.get("source_state_before"))
    validate_source_state(report.get("source_state_after"))
    if report["source_state_before"] != report["source_state_after"]:
        raise EvidenceError("initialization evidence source revision changed during collection")
    validate_initialization_tld_branch_rows(report.get("branch_rows"))
    c_probes = report.get("c_probes")
    rust_probes = report.get("rust_probes")
    if not isinstance(c_probes, list) or not isinstance(rust_probes, list) or len(c_probes) != 3 or len(rust_probes) != 3:
        raise EvidenceError("initialization evidence probe inventory changed")
    for index, branch_id in enumerate(INITIALIZATION_TLD_BRANCH_IDS):
        row = report["branch_rows"][index]
        c_probe = c_probes[index]
        rust_probe = rust_probes[index]
        if (
            not isinstance(c_probe, Mapping)
            or not isinstance(rust_probe, Mapping)
            or c_probe.get("branch") != branch_id
            or rust_probe.get("branch") != branch_id
        ):
            raise EvidenceError("initialization evidence probe branch changed")
        validate_c_probe(branch_id, c_probe)
        validate_rust_probe(branch_id, rust_probe)
    source = report.get("source")
    if not isinstance(source, Mapping) or set(source) != {"anchors", "archive_sha256", "compile_definitions", "fragment", "inputs", "release_flags"}:
        raise EvidenceError("initialization evidence source record changed")
    expected_anchors = [
        {"member": member, "start_line": start, "end_line": end, "sha256": digest}
        for member, start, end, digest in EXPECTED_ANCHORS
    ]
    if (
        source.get("anchors") != expected_anchors
        or source.get("archive_sha256") != pin["sha256"]
        or source.get("compile_definitions") != ["-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1", "-DMI_PRIM_HAS_PROCESS_ATTACH=1"]
        or source.get("release_flags") != list(run.CONFIGURATION_PROFILES["release"])
        or source.get("fragment") != {"path": relative(FRAGMENT_PATH), "sha256": sha256_file(FRAGMENT_PATH)}
        or source.get("inputs") != source_input_records()
    ):
        raise EvidenceError("initialization evidence source provenance changed")
    load_fragment()
    recursion.validate_report(report["init_recursion"])
    binding = report.get("init_recursion_binding")
    expected_input_paths = [record["path"] for record in source_input_records()]
    if binding != {
        "source_input_paths": expected_input_paths,
        "source_state_after": report["source_state_after"],
        "source_state_before": report["source_state_before"],
    }:
        raise EvidenceError("embedded init-recursion source-input binding changed")
    recursion_sources = {
        relative(recursion.RUST_TRACE_SOURCE),
        *(str(check["source"]) for check in recursion.EXPECTED_LIFECYCLE_CHECKS),
    }
    if not recursion_sources.issubset(set(expected_input_paths)):
        raise EvidenceError("embedded init-recursion inputs are not in the current source binding")


def bounded_temporary_directory() -> tempfile.TemporaryDirectory[str]:
    root = Path(os.environ.get("TMPDIR", ROOT / ".work/allocator-x86_64/tmp"))
    root.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(prefix=TEMPORARY_PREFIX, dir=root)


def require_native_x86_64() -> dict[str, str]:
    try:
        return run.require_native_x86_64()
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def run_evidence(*, offline: bool, report_path: Path) -> dict[str, Any]:
    """Collect the one fixed direct-TLD matrix and retained worker receipt."""

    load_fragment()
    before = source_state()
    provenance = require_native_x86_64()
    try:
        pin = run.load_pin()
        archive = run.fetch_archive(pin, offline)
        compiler = run.require_tool("musl-gcc")
        cargo = run.require_tool("cargo")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    with bounded_temporary_directory() as temporary_name:
        temporary = Path(temporary_name)
        try:
            source = run.safe_extract(archive, temporary / "source", pin["archive_root"])
        except run.HarnessError as error:
            raise EvidenceError(str(error)) from error
        anchors = validate_source_anchors(source)
        rows: list[dict[str, Any]] = []
        c_probes: list[dict[str, Any]] = []
        rust_probes: list[dict[str, Any]] = []
        rust_target = temporary / "rust-target"
        for index, branch_id in enumerate(INITIALIZATION_TLD_BRANCH_IDS):
            c_result = build_c_branch(compiler, source, temporary, branch_id)
            rust_command, rust_trace = run_rust_branch(cargo, rust_target, branch_id)
            comparison = compare_branch_trace(branch_id, c_result["trace"], rust_trace)
            rows.append({"id": branch_id, "c_trace": c_result["trace"], "rust_trace": rust_trace, "comparison": comparison})
            c_probes.append({
                "branch": branch_id,
                "command": c_result["command"],
                "compiled_source_closure": c_result["compiled_source_closure"],
                "fixture": c_result["fixture"],
                "source_files": c_result["source_files"],
            })
            rust_probes.append({
                "branch": branch_id,
                "command": normalized_command(rust_command, temporary, None),
                "passed_test_count": 1,
                "source": {"path": BRANCH_RUST_SOURCES[index], "sha256": sha256_file(ROOT / BRANCH_RUST_SOURCES[index])},
            })
        init_recursion = recursion.run_evidence(offline=offline, report_path=temporary / "init-recursion.json")
        after = source_state()
        report = report_from_results(
            provenance=provenance, before=before, after=after, anchors=anchors, rows=rows,
            c_probes=c_probes, rust_probes=rust_probes, init_recursion=init_recursion,
        )
    run.write_json(report_path, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, default=REPORT_DEFAULT)
    arguments = parser.parse_args()
    try:
        report = run_evidence(offline=arguments.offline, report_path=arguments.report)
    except (EvidenceError, OSError, json.JSONDecodeError) as error:
        print(f"allocator x86-64 initialization TLD evidence: FAIL: {error}", file=os.sys.stderr)
        return 1
    compared = sum(row["comparison"]["compared_value_count"] for row in report["branch_rows"])
    print(
        "allocator x86-64 initialization TLD evidence: PASS "
        f"({len(report['branch_rows'])} direct C/Rust rows; {compared} values; "
        f"{len(report['init_recursion']['lifecycle_checks'])} retained lifecycle checks; "
        f"report: {relative(arguments.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
