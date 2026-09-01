#!/usr/bin/env python3
"""Compare the ordinary and native-shadow libc malloc-family artifacts.

The matrix is intentionally narrow. It snapshots the ordinary C-backed
``libc.so`` before the ``native-mimalloc-shadow`` feature rebuild, attests the
ordinary public ``free`` route, machine-checks the selected debug shadow's
``free``/``realloc``/``malloc_usable_size`` native pointer-first boundary, and
runs one deterministic initial-thread C trace through each artifact. Two
separately named nonlocal ``realloc`` cases may
only become accepted after their source-faithful fixtures run against pinned
musl and the selected shadow artifact with exactly matching streams. It is
neither a runtime selector nor an allocator promotion gate. General lifecycle,
cross-owner, DSO, and allocator-layout claims stay with their separately
bounded evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[3]
CONTRACT_PATH = ROOT / "compat/allocator/shadow-abi-matrix-v1.json"
FIXTURE_PATH = ROOT / "tests/fixtures/native_mimalloc_shadow_backend_matrix_test.c"
TARGET_DIR = ROOT / "target/debug"
SNAPSHOT_ROOT = ROOT / "target/compat/allocator/shadow-abi-matrix"
LEGACY_LIBC = SNAPSHOT_ROOT / "ordinary-c-mimalloc/libc.so"
LEGACY_ATTESTATION = SNAPSHOT_ROOT / "ordinary-c-mimalloc/attestation.json"
OUTPUT_ROOT = SNAPSHOT_ROOT / "runs"
REPORT_PATH = ROOT / "compat/reports/allocator/shadow-abi-matrix/latest.json"
CANONICAL_LOADER = Path("/lib/ld-crabc-aarch64.so.1")
SELECTED_LIBC_LINK_FLAG = "-l:libc.so"
LINKER_TRACE_FLAG = "-Wl,--trace"
OWNED_BUILTINS_RELATIVE_PATH = Path("usr/lib/libcrabc-builtins.a")
MUSL_ORACLE_COMPILER = "musl-gcc"
MUSL_ORACLE_VERSION = "1.2.6"
MUSL_ORACLE_LIBRARY_ROOT = Path("/opt/musl-1.2.6/lib")
AARCH64_ELF_IDENTITY = {
    "class": "ELF64",
    "data": "little-endian",
    "type": "DYN",
    "machine": "AArch64",
}
NATIVE_DEBUG_GUARD_EXPORTS: tuple[dict[str, object], ...] = (
    {
        "symbol": "free",
        "binding": "GLOBAL",
        "visibility": "DEFAULT",
        "entry_source_path": "libc/src/allocator_native_mimalloc.rs",
        "native_dwarf_name": "native_free",
        "native_dwarf_source_path": "crabc-mimalloc/src/runtime_lifecycle.rs",
        "pointer_first_dwarf_provenance": [
            "native_free_pointer_first_local",
            "native_free_pointer_first_nonlocal",
        ],
    },
    {
        "symbol": "realloc",
        "binding": "GLOBAL",
        "visibility": "DEFAULT",
        "entry_source_path": "libc/src/allocator_native_mimalloc.rs",
        "native_dwarf_name": "native_reallocate",
        "native_dwarf_source_path": "crabc-mimalloc/src/runtime_lifecycle.rs",
        "pointer_first_dwarf_provenance": [
            "native_reallocate_pointer_first_local",
            "native_reallocate_pointer_first_nonlocal",
        ],
    },
    {
        "symbol": "malloc_usable_size",
        "binding": "GLOBAL",
        "visibility": "DEFAULT",
        "entry_source_path": "libc/src/program_utils_exports.rs",
        "native_dwarf_name": "native_usable_size",
        "native_dwarf_source_path": "crabc-mimalloc/src/runtime_lifecycle.rs",
        "pointer_first_dwarf_provenance": ["lookup_live_allocation"],
    },
)


# These are the only nonlocal realloc cases that may enter this ABI matrix.
# Their source fixtures are being converted by the paired core/C-test work;
# until their manifest activation flips to ``required``, the runner refuses to
# publish a successful matrix report.  Keeping the expected source digest and
# normal success stream here prevents a later manifest-only edit from relabeling
# a candidate-only refusal witness as a musl differential.
EXPECTED_MUSL_DIFFERENTIAL_CASES: tuple[dict[str, object], ...] = (
    {
        "id": "foreign-worker-realloc",
        "fixture_path": "tests/fixtures/native_mimalloc_shadow_foreign_realloc_test.c",
        "fixture_sha256": "21de25f80f6743c3422c68fc09d452eed24e23b74b00aa49adf9f57c91fe414a",
        "expected_stdout": "native mimalloc shadow foreign realloc ok\n",
    },
    {
        "id": "post-owner-exit-realloc",
        "fixture_path": "tests/fixtures/native_mimalloc_owner_exit_realloc_test.c",
        "fixture_sha256": "9e65b7bfaa7689ed4d8fffecebc9ea6d8bcff5935bad4eca82e24f6d581f83ee",
        "expected_stdout": "native mimalloc owner exit realloc ok\n",
    },
)


class MatrixError(RuntimeError):
    """A checked artifact or observable comparison contradicted the contract."""


class DeferredMuslDifferentialError(MatrixError):
    """A required source-faithful row has no runtime evidence yet."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def relative_path(path: Path) -> str:
    resolved = path.expanduser().resolve()
    try:
        return str(resolved.relative_to(ROOT))
    except ValueError:
        return str(resolved)


def file_record(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise MatrixError(f"required file is absent: {relative_path(path)}")
    return {
        "bytes": path.stat().st_size,
        "path": relative_path(path),
        "sha256": sha256_file(path),
    }


def bytes_record(value: bytes) -> dict[str, Any]:
    return {
        "bytes": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
        "hex": value.hex(),
    }


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        staged = Path(stream.name)
    os.replace(staged, path)


def read_json(path: Path, subject: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise MatrixError(f"cannot read {subject}: {relative_path(path)}") from error
    if not isinstance(value, dict):
        raise MatrixError(f"{subject} must be a JSON object")
    return value


def require_exact_keys(value: Mapping[str, Any], expected: set[str], subject: str) -> None:
    if set(value) != expected:
        raise MatrixError(f"{subject} fields drifted")


def require_string(value: object, subject: str) -> str:
    if not isinstance(value, str) or not value:
        raise MatrixError(f"{subject} must be a non-empty string")
    return value


def load_contract() -> dict[str, Any]:
    """Validate the small checked-in matrix before touching any artifact."""

    contract = read_json(CONTRACT_PATH, "shadow ABI matrix contract")
    require_exact_keys(
        contract,
        {
            "format",
            "schema",
            "scope",
            "fixture",
            "backends",
            "semantic_cases",
            "musl_differential_required_cases",
            "intentionally_blocked_cases",
            "execution",
            "report",
        },
        "shadow ABI matrix contract",
    )
    if contract["format"] != 1 or contract["schema"] != "crabc-libc-native-mimalloc-shadow-abi-matrix":
        raise MatrixError("shadow ABI matrix contract identity drifted")

    scope = contract["scope"]
    if not isinstance(scope, dict):
        raise MatrixError("shadow ABI matrix scope is invalid")
    require_exact_keys(
        scope,
        {
            "claim",
            "target",
            "kernel_baseline",
            "not_a_promotion_gate",
            "not_a_runtime_selector",
            "not_a_general_lifecycle_claim",
            "nonlocal_musl_differentials_are_required",
            "purpose",
        },
        "shadow ABI matrix scope",
    )
    if (
        scope["target"] != "linux-aarch64-little-endian"
        or scope["kernel_baseline"] != "5.10"
        or scope["not_a_promotion_gate"] is not True
        or scope["not_a_runtime_selector"] is not True
        or scope["not_a_general_lifecycle_claim"] is not True
        or scope["nonlocal_musl_differentials_are_required"] is not True
    ):
        raise MatrixError("shadow ABI matrix scope drifted")
    require_string(scope["claim"], "shadow ABI matrix scope claim")
    require_string(scope["purpose"], "shadow ABI matrix scope purpose")

    fixture = contract["fixture"]
    if not isinstance(fixture, dict):
        raise MatrixError("shadow ABI matrix fixture is invalid")
    require_exact_keys(
        fixture,
        {"path", "sha256", "language", "compile_flags", "link_flags", "link_libraries"},
        "shadow ABI matrix fixture",
    )
    if (
        fixture["path"] != "tests/fixtures/native_mimalloc_shadow_backend_matrix_test.c"
        or fixture["language"] != "C11"
        or fixture["compile_flags"] != ["-fPIE", "-pie", "-fno-builtin"]
        or fixture["link_flags"] != ["-Wl,--allow-shlib-undefined"]
        or fixture["link_libraries"] != [SELECTED_LIBC_LINK_FLAG]
        or fixture["sha256"] != sha256_file(FIXTURE_PATH)
    ):
        raise MatrixError("shadow ABI matrix fixture contract drifted")

    backends = contract["backends"]
    if not isinstance(backends, list) or len(backends) != 2:
        raise MatrixError("shadow ABI matrix requires exactly two backends")
    expected_backends = {
        "ordinary-c-mimalloc": ["default"],
        "native-rust-mimalloc-shadow": ["default", "native-mimalloc-shadow"],
    }
    seen_backends: set[str] = set()
    for backend in backends:
        if not isinstance(backend, dict):
            raise MatrixError("shadow ABI matrix backend is invalid")
        backend_id = require_string(backend["id"], "shadow ABI matrix backend id")
        expected = expected_backends.get(backend_id)
        if expected is None or backend_id in seen_backends:
            raise MatrixError("shadow ABI matrix backend inventory drifted")
        seen_backends.add(backend_id)
        if backend["cargo_features"] != expected or backend["fallback"] is not False:
            raise MatrixError("shadow ABI matrix backend selection drifted")
        require_string(backend["selection"], "shadow ABI matrix backend selection")
        if backend_id == "ordinary-c-mimalloc":
            require_exact_keys(
                backend,
                {"id", "cargo_features", "selection", "fallback", "exported_free_route"},
                "shadow ABI matrix ordinary backend",
            )
            route = backend["exported_free_route"]
            if not isinstance(route, dict):
                raise MatrixError("shadow ABI matrix ordinary free route is invalid")
            require_exact_keys(
                route,
                {"symbol", "required_callee_suffix", "forbidden_callee_suffix"},
                "shadow ABI matrix ordinary free route",
            )
            if (
                route["symbol"] != "free"
                or route["required_callee_suffix"] != "mi_free>"
                or route["forbidden_callee_suffix"] != "native_free>"
            ):
                raise MatrixError("shadow ABI matrix ordinary free route drifted")
            continue

        require_exact_keys(
            backend,
            {"id", "cargo_features", "selection", "fallback", "native_pointer_first_guard"},
            "shadow ABI matrix native backend",
        )
        native_pointer_first_guard = backend["native_pointer_first_guard"]
        if not isinstance(native_pointer_first_guard, dict):
            raise MatrixError("shadow ABI matrix native pointer-first guard is invalid")
        require_exact_keys(
            native_pointer_first_guard,
            {
                "required_elf_identity",
                "required_debug_sections",
                "forbidden_c_backend_symbol_prefix",
                "exports",
            },
            "shadow ABI matrix native pointer-first guard",
        )
        if (
            native_pointer_first_guard["required_elf_identity"] != AARCH64_ELF_IDENTITY
            or native_pointer_first_guard["required_debug_sections"] != [".debug_info", ".debug_line"]
            or native_pointer_first_guard["forbidden_c_backend_symbol_prefix"] != "mi_"
            or native_pointer_first_guard["exports"] != list(NATIVE_DEBUG_GUARD_EXPORTS)
        ):
            raise MatrixError("shadow ABI matrix native pointer-first guard drifted")

    semantic_cases = contract["semantic_cases"]
    expected_cases = [
        ("free-null-preserves-errno", ["free"], "pass", "pass", "match"),
        ("malloc-local-content-and-errno", ["malloc"], "pass", "pass", "match"),
        (
            "realloc-grow-preserves-prefix-and-errno",
            ["realloc"],
            "pass",
            "pass",
            "match",
        ),
        (
            "realloc-shrink-preserves-prefix-and-errno",
            ["realloc"],
            "pass",
            "pass",
            "match",
        ),
        (
            "realloc-null-zero-result",
            ["realloc"],
            "freeable-misaligned-preserves-errno",
            "freeable-aligned-preserves-errno",
            "known-red",
        ),
        (
            "realloc-zero-result",
            ["realloc"],
            "distinct-aligned-preserves-errno",
            "distinct-aligned-preserves-errno",
            "match",
        ),
        (
            "realloc-failure-preserves-source-and-sets-enomem",
            ["realloc"],
            "pass",
            "pass",
            "match",
        ),
        ("free-local-preserves-errno", ["free"], "pass", "pass", "match"),
    ]
    if not isinstance(semantic_cases, list) or len(semantic_cases) != len(expected_cases):
        raise MatrixError("shadow ABI matrix semantic case count drifted")
    for case, (expected_id, expected_operations, ordinary, native, comparison) in zip(
        semantic_cases, expected_cases
    ):
        if not isinstance(case, dict):
            raise MatrixError("shadow ABI matrix semantic case is invalid")
        expected_keys = {"id", "operations", "expected", "comparison"}
        if comparison == "known-red":
            expected_keys.add("reason")
        require_exact_keys(case, expected_keys, "shadow ABI matrix semantic case")
        if case["id"] != expected_id:
            raise MatrixError("shadow ABI matrix semantic case order drifted")
        operations = case["operations"]
        if operations != expected_operations:
            raise MatrixError("shadow ABI matrix semantic case operations drifted")
        if case["expected"] != {
            "ordinary-c-mimalloc": ordinary,
            "native-rust-mimalloc-shadow": native,
        } or case["comparison"] != comparison:
            raise MatrixError("shadow ABI matrix semantic case expectation drifted")
        if comparison == "known-red":
            require_string(case["reason"], "shadow ABI matrix known-red reason")

    musl_differential_cases = contract["musl_differential_required_cases"]
    if (
        not isinstance(musl_differential_cases, list)
        or len(musl_differential_cases) != len(EXPECTED_MUSL_DIFFERENTIAL_CASES)
    ):
        raise MatrixError("shadow ABI matrix musl differential case count drifted")
    seen_musl_differential_cases: set[str] = set()
    for case, expected_case in zip(musl_differential_cases, EXPECTED_MUSL_DIFFERENTIAL_CASES):
        if not isinstance(case, dict):
            raise MatrixError("shadow ABI matrix musl differential case is invalid")
        require_exact_keys(
            case,
            {"id", "fixture", "operations", "classification", "activation", "expected", "reason"},
            "shadow ABI matrix musl differential case",
        )
        case_id = require_string(case["id"], "shadow ABI matrix musl differential case id")
        expected_id = str(expected_case["id"])
        if case_id != expected_id or case_id in seen_musl_differential_cases:
            raise MatrixError("shadow ABI matrix musl differential case inventory drifted")
        seen_musl_differential_cases.add(case_id)
        if case["operations"] != ["realloc"]:
            raise MatrixError("shadow ABI matrix musl differential operations drifted")
        if case["classification"] != "musl-differential-required":
            raise MatrixError("shadow ABI matrix musl differential classification drifted")
        if case["activation"] not in {"deferred", "required"}:
            raise MatrixError("shadow ABI matrix musl differential activation drifted")
        require_string(case["reason"], "shadow ABI matrix musl differential reason")

        fixture = case["fixture"]
        if not isinstance(fixture, dict):
            raise MatrixError("shadow ABI matrix musl differential fixture is invalid")
        require_exact_keys(
            fixture,
            {
                "path",
                "sha256",
                "language",
                "compile_flags",
                "selected_link_flags",
                "selected_link_libraries",
                "musl_link_flags",
                "musl_link_libraries",
            },
            "shadow ABI matrix musl differential fixture",
        )
        if (
            fixture["path"] != expected_case["fixture_path"]
            or fixture["sha256"] != expected_case["fixture_sha256"]
            or fixture["language"] != "C11"
            or fixture["compile_flags"] != ["-fPIE", "-pie", "-fno-builtin"]
            or fixture["selected_link_flags"] != ["-Wl,--allow-shlib-undefined"]
            or fixture["selected_link_libraries"] != [SELECTED_LIBC_LINK_FLAG]
            or fixture["musl_link_flags"] != []
            or fixture["musl_link_libraries"] != ["-lc"]
        ):
            raise MatrixError("shadow ABI matrix musl differential fixture provenance drifted")
        source = ROOT / str(fixture["path"])
        if not source.is_file():
            raise MatrixError("shadow ABI matrix musl differential fixture is absent")
        if case["activation"] == "required" and sha256_file(source) != fixture["sha256"]:
            raise MatrixError("shadow ABI matrix musl differential fixture provenance drifted")

        expected_streams = case["expected"]
        if not isinstance(expected_streams, dict):
            raise MatrixError("shadow ABI matrix musl differential expected streams are invalid")
        require_exact_keys(
            expected_streams,
            {"status", "stdout", "stderr"},
            "shadow ABI matrix musl differential expected streams",
        )
        if expected_streams != {
            "status": 0,
            "stdout": expected_case["expected_stdout"],
            "stderr": "",
        }:
            raise MatrixError("shadow ABI matrix musl differential expected stream drifted")

    blocked = contract["intentionally_blocked_cases"]
    expected_blocked = {
        "foreign-worker-free-routing",
        "owner-exit-routing-outside-selected-realloc",
        "dso-interposition-and-static-linking",
        "address-reuse-usable-size-and-page-layout",
    }
    if not isinstance(blocked, list) or len(blocked) != len(expected_blocked):
        raise MatrixError("shadow ABI matrix blocked case count drifted")
    observed_blocked: set[str] = set()
    for case in blocked:
        if not isinstance(case, dict):
            raise MatrixError("shadow ABI matrix blocked case is invalid")
        require_exact_keys(case, {"id", "status", "reason"}, "shadow ABI matrix blocked case")
        case_id = require_string(case["id"], "shadow ABI matrix blocked case id")
        if case_id not in expected_blocked or case_id in observed_blocked or case["status"] != "blocked":
            raise MatrixError("shadow ABI matrix blocked case inventory drifted")
        if case_id in seen_musl_differential_cases:
            raise MatrixError("shadow ABI matrix required musl differential was classified as blocked")
        observed_blocked.add(case_id)
        require_string(case["reason"], "shadow ABI matrix blocked case reason")

    execution = contract["execution"]
    if not isinstance(execution, dict):
        raise MatrixError("shadow ABI matrix execution is invalid")
    require_exact_keys(
        execution,
        {
            "compiler",
            "canonical_loader",
            "owned_test_launcher",
            "expected_dynamic_dependencies",
            "process_attempts_per_backend",
            "watchdog_seconds",
            "runtime_library_selection",
            "pinned_musl_oracle",
            "link_provenance",
            "artifact_snapshot",
        },
        "shadow ABI matrix execution",
    )
    if (
        execution["compiler"] != "crabc-cc from the installed owned crabc sysroot"
        or execution["canonical_loader"] != str(CANONICAL_LOADER)
        or execution["owned_test_launcher"] != "scripts/run_owned_test_suite.py"
        or execution["expected_dynamic_dependencies"] != ["libc.so"]
        or execution["process_attempts_per_backend"] != 1
        or execution["watchdog_seconds"] != 15
    ):
        raise MatrixError("shadow ABI matrix execution contract drifted")
    require_string(execution["runtime_library_selection"], "shadow ABI matrix runtime selection")
    musl_oracle = execution["pinned_musl_oracle"]
    if not isinstance(musl_oracle, dict):
        raise MatrixError("shadow ABI matrix musl oracle is invalid")
    require_exact_keys(
        musl_oracle,
        {"compiler", "version", "library_root", "provenance"},
        "shadow ABI matrix musl oracle",
    )
    if (
        musl_oracle["compiler"] != MUSL_ORACLE_COMPILER
        or musl_oracle["version"] != MUSL_ORACLE_VERSION
        or musl_oracle["library_root"] != str(MUSL_ORACLE_LIBRARY_ROOT)
    ):
        raise MatrixError("shadow ABI matrix musl oracle contract drifted")
    require_string(musl_oracle["provenance"], "shadow ABI matrix musl oracle provenance")
    link_provenance = execution["link_provenance"]
    if not isinstance(link_provenance, dict):
        raise MatrixError("shadow ABI matrix link provenance is invalid")
    require_exact_keys(
        link_provenance,
        {
            "driver_default_libraries",
            "driver_opt_out",
            "selected_library_flag",
            "linker_trace_flag",
            "owned_builtins_path",
            "reason",
        },
        "shadow ABI matrix link provenance",
    )
    if (
        link_provenance["driver_default_libraries"] != []
        or link_provenance["driver_opt_out"] != "-nodefaultlibs"
        or link_provenance["selected_library_flag"] != SELECTED_LIBC_LINK_FLAG
        or link_provenance["linker_trace_flag"] != LINKER_TRACE_FLAG
        or link_provenance["owned_builtins_path"] != str(OWNED_BUILTINS_RELATIVE_PATH)
    ):
        raise MatrixError("shadow ABI matrix link provenance contract drifted")
    require_string(link_provenance["reason"], "shadow ABI matrix link provenance reason")
    require_string(execution["artifact_snapshot"], "shadow ABI matrix artifact snapshot")

    report = contract["report"]
    if not isinstance(report, dict):
        raise MatrixError("shadow ABI matrix report is invalid")
    require_exact_keys(
        report,
        {"format", "schema", "path", "atomic_publish", "file_artifact_record_fields", "byte_stream_record_fields"},
        "shadow ABI matrix report",
    )
    if (
        report["format"] != 1
        or report["schema"] != "crabc-libc-native-mimalloc-shadow-abi-matrix-report"
        or report["path"] != "compat/reports/allocator/shadow-abi-matrix/latest.json"
        or report["atomic_publish"] is not True
        or report["file_artifact_record_fields"] != ["path", "bytes", "sha256"]
        or report["byte_stream_record_fields"] != ["bytes", "sha256", "hex"]
    ):
        raise MatrixError("shadow ABI matrix report contract drifted")

    return contract


def musl_differential_required_cases(contract: Mapping[str, Any]) -> list[dict[str, Any]]:
    cases = contract["musl_differential_required_cases"]
    assert isinstance(cases, list)
    return [dict(case) for case in cases if isinstance(case, dict)]


def active_musl_differential_cases(contract: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Refuse a passing report while a required nonlocal case remains deferred."""

    cases = musl_differential_required_cases(contract)
    deferred = [str(case["id"]) for case in cases if case["activation"] == "deferred"]
    if deferred:
        raise DeferredMuslDifferentialError(
            "musl differential required cases are deferred pending source-faithful siblings: "
            + ", ".join(deferred)
        )
    return cases


def command_record(
    command: Sequence[str], *, env: Mapping[str, str] | None = None, timeout_seconds: int | None = None
) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            list(command),
            cwd=ROOT,
            env=None if env is None else dict(env),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as error:
        raise MatrixError(f"required command is unavailable: {command[0]}") from error
    except subprocess.TimeoutExpired as error:
        return {
            "kind": "timeout",
            "seconds": timeout_seconds,
            "stdout": bytes_record(error.stdout or b""),
            "stderr": bytes_record(error.stderr or b""),
        }
    return {
        "kind": "process",
        "status": completed.returncode,
        "stdout": bytes_record(completed.stdout),
        "stderr": bytes_record(completed.stderr),
    }


def command_text(record: Mapping[str, Any], subject: str) -> str:
    if record.get("kind") != "process" or record.get("status") != 0:
        raise MatrixError(f"{subject} failed")
    stderr = record.get("stderr")
    stdout = record.get("stdout")
    if not isinstance(stderr, dict) or not isinstance(stdout, dict) or stderr.get("bytes") != 0:
        raise MatrixError(f"{subject} produced diagnostics")
    try:
        return bytes.fromhex(str(stdout["hex"])).decode("utf-8", errors="strict")
    except (KeyError, ValueError, UnicodeDecodeError) as error:
        raise MatrixError(f"{subject} did not produce UTF-8 text") from error


def command_stream_bytes(record: Mapping[str, Any], stream_name: str, subject: str) -> bytes:
    stream = record.get(stream_name)
    if not isinstance(stream, dict):
        raise MatrixError(f"{subject} lacks {stream_name}")
    try:
        return bytes.fromhex(str(stream["hex"]))
    except (KeyError, ValueError) as error:
        raise MatrixError(f"{subject} has malformed {stream_name}") from error


def validate_musl_differential_execution(
    case: Mapping[str, Any], oracle: Mapping[str, Any], selected: Mapping[str, Any]
) -> dict[str, Any]:
    """Require the pinned musl and selected-shadow executions to agree exactly."""

    expected = case["expected"]
    assert isinstance(expected, dict)
    expected_status = expected["status"]
    expected_stdout = str(expected["stdout"]).encode("utf-8")
    expected_stderr = str(expected["stderr"]).encode("utf-8")

    if oracle.get("kind") != "process" or oracle.get("status") != expected_status:
        raise MatrixError("pinned musl oracle status differs from the required result")
    oracle_stdout = command_stream_bytes(oracle, "stdout", "pinned musl oracle")
    oracle_stderr = command_stream_bytes(oracle, "stderr", "pinned musl oracle")
    if oracle_stdout != expected_stdout or oracle_stderr != expected_stderr:
        raise MatrixError("pinned musl oracle stream differs from the required result")

    if selected.get("kind") != "process" or selected.get("status") != oracle.get("status"):
        raise MatrixError("selected shadow status diverges from pinned musl")
    selected_stdout = command_stream_bytes(selected, "stdout", "selected shadow")
    selected_stderr = command_stream_bytes(selected, "stderr", "selected shadow")
    if selected_stdout != oracle_stdout or selected_stderr != oracle_stderr:
        raise MatrixError("selected stream diverges from pinned musl")

    return {
        "id": case["id"],
        "classification": case["classification"],
        "expected_status": expected_status,
        "expected_stdout": expected["stdout"],
        "expected_stderr": expected["stderr"],
    }


def cargo_fingerprint_features(path: Path) -> list[str]:
    value = read_json(path, "crabc-libc Cargo fingerprint")
    raw_features = value.get("features")
    if not isinstance(raw_features, str):
        raise MatrixError("crabc-libc Cargo fingerprint omits enabled features")
    try:
        features = json.loads(raw_features)
    except json.JSONDecodeError as error:
        raise MatrixError("crabc-libc Cargo fingerprint has malformed features") from error
    if (
        not isinstance(features, list)
        or not all(isinstance(feature, str) and feature for feature in features)
        or len(features) != len(set(features))
    ):
        raise MatrixError("crabc-libc Cargo fingerprint features are invalid")
    return features


def backend_contract(contract: Mapping[str, Any], backend_id: str) -> dict[str, Any]:
    backends = contract["backends"]
    assert isinstance(backends, list)
    matches = [backend for backend in backends if isinstance(backend, dict) and backend.get("id") == backend_id]
    if len(matches) != 1:
        raise MatrixError("shadow ABI matrix backend is missing")
    return dict(matches[0])


def matching_cargo_fingerprints(target_dir: Path, backend: Mapping[str, Any]) -> list[tuple[Path, list[str]]]:
    """Return every retained Cargo identity for the selected feature set.

    Cargo intentionally retains historical fingerprint directories in a shared
    target tree. The public-artifact route attestation below binds the actual
    ``libc.so``; requiring one cache entry would make that sound check depend
    on cache garbage collection rather than the selected artifact.
    """

    expected_features = backend["cargo_features"]
    assert isinstance(expected_features, list)
    candidates = sorted((target_dir / ".fingerprint").glob("crabc-libc-*/lib-c.json"))
    matches: list[tuple[Path, list[str]]] = []
    for candidate in candidates:
        try:
            features = cargo_fingerprint_features(candidate)
        except MatrixError:
            continue
        if sorted(features) == sorted(expected_features):
            matches.append((candidate, features))
    if not matches:
        raise MatrixError(f"crabc-libc Cargo has no fingerprint for {backend['id']}")
    return matches


def defined_dynamic_function_symbols(symbols: str, symbol: str) -> list[dict[str, Any]]:
    """Return every defined dynamic function export with this public spelling."""

    definitions: list[dict[str, Any]] = []
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) < 8 or fields[3] != "FUNC" or fields[6] == "UND":
            continue
        if fields[-1].split("@", 1)[0] != symbol:
            continue
        try:
            address = int(fields[1], 16)
            size = int(fields[2])
        except ValueError as error:
            raise MatrixError(f"dynamic {symbol} symbol has an invalid address or size") from error
        definitions.append(
            {
                "address": address,
                "binding": fields[4],
                "section": fields[6],
                "size": size,
                "visibility": fields[5],
            }
        )
    return definitions


def parse_elf_identity(header: str) -> dict[str, str]:
    """Normalize the ELF facts needed by the selected debug-artifact gate."""

    fields: dict[str, str] = {}
    for line in header.splitlines():
        if ":" not in line:
            continue
        key, value = line.strip().split(":", 1)
        fields[key] = value.strip()
    return {
        "class": fields.get("Class", ""),
        "data": "little-endian" if "little endian" in fields.get("Data", "") else fields.get("Data", ""),
        "type": fields.get("Type", "").split(maxsplit=1)[0],
        "machine": fields.get("Machine", ""),
    }


def elf_section_names(output: str) -> set[str]:
    """Extract section names without assigning meaning to their numeric indices."""

    names: set[str] = set()
    for line in output.splitlines():
        match = re.match(r"\s*\[\s*\d+\]\s+(\S+)", line)
        if match is not None:
            names.add(match.group(1))
    return names


def decoded_line_locations(output: str) -> list[dict[str, Any]]:
    """Read address-bearing decoded DWARF lines with their compilation source."""

    current_source: str | None = None
    locations: list[dict[str, Any]] = []
    row = re.compile(r"^(\S+)\s+(-|\d+)\s+(0x[0-9A-Fa-f]+)(?:\s+.*)?$")
    for line in output.splitlines():
        if line and not line[0].isspace() and line.endswith(":") and "/" in line:
            current_source = line[:-1]
            continue
        match = row.match(line)
        if match is None or current_source is None:
            continue
        line_number = None if match.group(2) == "-" else int(match.group(2))
        locations.append(
            {
                "address": int(match.group(3), 16),
                "line": line_number,
                "source_path": current_source,
            }
        )
    return locations


def locations_in_symbol_range(
    locations: Sequence[Mapping[str, Any]], address: int, size: int
) -> list[dict[str, Any]]:
    """Keep only source locations owned by one defined dynamic export."""

    if address <= 0 or size <= 0:
        raise MatrixError("selected native export has an empty code range")
    end = address + size
    return [
        dict(location)
        for location in locations
        if isinstance(location.get("address"), int) and address <= location["address"] < end
    ]


_DIRECT_AARCH64_BRANCH = re.compile(
    r"^\s*[0-9A-Fa-f]+:\s+[0-9A-Fa-f]+\s+(?:b|bl)\s+([0-9A-Fa-f]+)\s+<([^>]+)>",
    re.MULTILINE,
)


def direct_aarch64_branch_targets(disassembly: str) -> list[dict[str, Any]]:
    """Return named direct branches; indirect calls stay relocation-audited separately."""

    observed: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for match in _DIRECT_AARCH64_BRANCH.finditer(disassembly):
        target = (int(match.group(1), 16), match.group(2))
        if target in seen:
            continue
        seen.add(target)
        observed.append({"address": target[0], "label": target[1]})
    return observed


def mimalloc_transfer_labels(
    targets: Sequence[Mapping[str, Any]], forbidden_prefix: str
) -> list[str]:
    """Record direct C-backend transfers without requiring any Rust symbol label."""

    return sorted(
        {
            str(target["label"])
            for target in targets
            if isinstance(target.get("label"), str)
            and str(target["label"]).split("@", 1)[0].startswith(forbidden_prefix)
        }
    )


def mimalloc_relocation_symbols(relocations: str, forbidden_prefix: str) -> list[str]:
    """Find symbol-bearing relocation records that could transfer into C mimalloc."""

    pattern = re.compile(rf"(?<![A-Za-z0-9_])({re.escape(forbidden_prefix)}[A-Za-z0-9_.$@]+)")
    return sorted(set(pattern.findall(relocations)))


_DWARF_SUBPROGRAM = re.compile(r"(?m)^(0x[0-9A-Fa-f]+):\s+DW_TAG_subprogram\s*$")
_DWARF_DIE = re.compile(r"(?m)^0x[0-9A-Fa-f]+:\s+DW_TAG_[A-Za-z_]+\s*$")
_DWARF_HEX_ATTRIBUTE = re.compile(r"DW_AT_(low_pc|high_pc)\s+\(0x([0-9A-Fa-f]+)\)")
_DWARF_NAME = re.compile(r'DW_AT_name\s+\("([^"]+)"\)')
_DWARF_DECL_FILE = re.compile(r'DW_AT_decl_file\s+\("([^"]+)"\)')
_DWARF_ORIGIN = re.compile(r"DW_AT_(?:abstract_origin|specification)\s+\((0x[0-9A-Fa-f]+)")


def dwarf_subprogram_records(output: str) -> dict[int, dict[str, Any]]:
    """Collect top-level subprogram attributes, including their DWARF origin."""

    records: dict[int, dict[str, Any]] = {}
    for match in _DWARF_SUBPROGRAM.finditer(output):
        next_die = _DWARF_DIE.search(output, match.end())
        end = next_die.start() if next_die is not None else len(output)
        attributes = output[match.end() : end]
        values = {name: int(value, 16) for name, value in _DWARF_HEX_ATTRIBUTE.findall(attributes)}
        name = _DWARF_NAME.search(attributes)
        source = _DWARF_DECL_FILE.search(attributes)
        origin = _DWARF_ORIGIN.search(attributes)
        records[int(match.group(1), 16)] = {
            "end_address": values.get("high_pc"),
            "name": None if name is None else name.group(1),
            "origin": None if origin is None else int(origin.group(1), 16),
            "source_path": None if source is None else source.group(1),
            "start_address": values.get("low_pc"),
        }
    return records


def dwarf_subprogram_provenance(
    records: Mapping[int, Mapping[str, Any]], record: Mapping[str, Any]
) -> tuple[str, str] | None:
    """Resolve a concrete subprogram's name/file through its DWARF origin.

    Rust LLVM may emit an outlined concrete instance with only
    ``DW_AT_abstract_origin`` while its named declaration carries the source
    file and ``DW_AT_name``. This remains debug provenance, not an ELF-symbol
    spelling: follow only the explicit DWARF reference and reject cycles or a
    missing named source declaration.
    """

    name = record.get("name")
    source_path = record.get("source_path")
    origin = record.get("origin")
    seen: set[int] = set()
    while isinstance(origin, int):
        if origin in seen:
            return None
        seen.add(origin)
        parent = records.get(origin)
        if parent is None:
            return None
        if name is None:
            name = parent.get("name")
        if source_path is None:
            source_path = parent.get("source_path")
        origin = parent.get("origin")
    if not isinstance(name, str) or not isinstance(source_path, str):
        return None
    return name, source_path


def dwarf_function_at_address(output: str, address: int) -> dict[str, Any] | None:
    """Resolve an address through DWARF rather than an optimizer-chosen ELF label."""

    records = dwarf_subprogram_records(output)
    for record in records.values():
        low_pc = record["start_address"]
        high_pc = record["end_address"]
        if low_pc is None or high_pc is None or not low_pc <= address < high_pc:
            continue
        provenance = dwarf_subprogram_provenance(records, record)
        if provenance is None:
            continue
        name, source_path = provenance
        return {
            "address": address,
            "end_address": high_pc,
            "name": name,
            "source_path": source_path,
            "start_address": low_pc,
        }
    return None


def dwarf_lookup_function(llvm_dwarfdump: str, libc: Path, address: int) -> dict[str, Any] | None:
    output = command_text(
        command_record((llvm_dwarfdump, f"--lookup=0x{address:x}", str(libc))),
        "selected native DWARF address lookup",
    )
    return dwarf_function_at_address(output, address)


def dwarf_named_function_at_address(
    llvm_dwarfdump: str,
    libc: Path,
    address: int,
    expected_name: str,
    expected_source_path: str,
) -> dict[str, Any] | None:
    """Resolve one target through the named declaration's complete DWARF view.

    ``llvm-dwarfdump --lookup`` deliberately elides the declaration DIE behind
    an outlined Rust instance. The named query is still a DWARF query, and
    includes that declaration so ``dwarf_function_at_address`` can follow its
    explicit abstract-origin reference without consulting an ELF symbol label.
    """

    return require_native_dwarf_function(
        dwarf_function_at_address(dwarf_subtree(llvm_dwarfdump, libc, expected_name), address),
        expected_name,
        expected_source_path,
    )


def dwarf_subtree(llvm_dwarfdump: str, libc: Path, name: str) -> str:
    """Inspect one debug-only Rust function definition and its inline children."""

    return command_text(
        command_record(
            (llvm_dwarfdump, f"--name={name}", "--show-children", "--recurse-depth=8", str(libc))
        ),
        f"selected native {name} DWARF inline provenance inspection",
    )


def dwarf_name_observed(output: str, name: str) -> bool:
    """Match a semantic DWARF name or linkage fragment, never a required ELF label."""

    return re.search(rf'DW_AT_(?:name|linkage_name|abstract_origin).*{re.escape(name)}', output) is not None


def require_native_dwarf_function(
    function: Mapping[str, Any] | None, expected_name: str, expected_source_path: str
) -> dict[str, Any] | None:
    if function is None:
        return None
    if function.get("name") != expected_name:
        return None
    source_path = function.get("source_path")
    if not isinstance(source_path, str) or not source_path.endswith(expected_source_path):
        return None
    return dict(function)


def native_pointer_first_export_attestation(
    libc: Path,
    dynamic_symbols: str,
    decoded_lines: Sequence[Mapping[str, Any]],
    objdump: str,
    llvm_dwarfdump: str,
    export: Mapping[str, Any],
    forbidden_prefix: str,
) -> dict[str, Any]:
    """Bind one public export to a native Rust dispatch using debug provenance.

    The selected artifact is deliberately a debug artifact. Its direct branch
    is resolved by destination address through DWARF, and the native function's
    DWARF subtree supplies the pointer-first inline provenance. No mangled or
    private ELF symbol spelling is a production ABI condition.
    """

    symbol = str(export["symbol"])
    definitions = defined_dynamic_function_symbols(dynamic_symbols, symbol)
    if len(definitions) != 1:
        raise MatrixError(f"selected native artifact has wrong dynamic {symbol} definition count")
    definition = definitions[0]
    if (
        definition["binding"] != export["binding"]
        or definition["visibility"] != export["visibility"]
    ):
        raise MatrixError(f"selected native {symbol} dynamic binding or visibility drifted")

    symbol_locations = locations_in_symbol_range(
        decoded_lines, int(definition["address"]), int(definition["size"])
    )
    entry_source_path = str(export["entry_source_path"])
    if not any(
        isinstance(location.get("source_path"), str)
        and str(location["source_path"]).endswith(entry_source_path)
        for location in symbol_locations
    ):
        raise MatrixError(f"selected native {symbol} lacks its Rust entry DWARF provenance")

    disassembly = command_text(
        command_record((objdump, "-d", f"--disassemble={symbol}", str(libc))),
        f"selected native {symbol} transfer inspection",
    )
    public_targets = direct_aarch64_branch_targets(disassembly)
    forbidden_public = mimalloc_transfer_labels(public_targets, forbidden_prefix)
    if forbidden_public:
        raise MatrixError(f"selected native {symbol} transfers directly to C mimalloc")

    expected_name = str(export["native_dwarf_name"])
    expected_source_path = str(export["native_dwarf_source_path"])
    native_dispatch: dict[str, Any] | None = None
    checked_public_targets: list[dict[str, Any]] = []
    for target in public_targets:
        function = dwarf_lookup_function(llvm_dwarfdump, libc, int(target["address"]))
        accepted = require_native_dwarf_function(function, expected_name, expected_source_path)
        if accepted is None:
            accepted = dwarf_named_function_at_address(
                llvm_dwarfdump,
                libc,
                int(target["address"]),
                expected_name,
                expected_source_path,
            )
        if accepted is not None:
            function = accepted
        checked_public_targets.append(
            {
                "address": f"0x{int(target['address']):x}",
                "dwarf_name": None if function is None else function["name"],
            }
        )
        if accepted is not None:
            native_dispatch = accepted
            break

    if native_dispatch is None:
        raise MatrixError(f"selected native {symbol} lacks its named Rust dispatch provenance")

    target_disassembly = command_text(
        command_record(
            (
                objdump,
                "-d",
                f"--start-address=0x{int(native_dispatch['start_address']):x}",
                f"--stop-address=0x{int(native_dispatch['end_address']):x}",
                str(libc),
            )
        ),
        f"selected native {symbol} Rust dispatch transfer inspection",
    )
    dispatch_targets = direct_aarch64_branch_targets(target_disassembly)
    forbidden_dispatch = mimalloc_transfer_labels(dispatch_targets, forbidden_prefix)
    if forbidden_dispatch:
        raise MatrixError(f"selected native {symbol} Rust dispatch transfers directly to C mimalloc")

    dispatch_target_names: set[str] = set()
    for target in dispatch_targets:
        function = dwarf_lookup_function(llvm_dwarfdump, libc, int(target["address"]))
        if function is not None:
            dispatch_target_names.add(str(function["name"]))
    inline_provenance = dwarf_subtree(llvm_dwarfdump, libc, expected_name)
    pointer_first_provenance = [str(name) for name in export["pointer_first_dwarf_provenance"]]
    for provenance_name in pointer_first_provenance:
        if provenance_name in dispatch_target_names or dwarf_name_observed(
            inline_provenance, provenance_name
        ):
            continue
        for target in dispatch_targets:
            matched = dwarf_named_function_at_address(
                llvm_dwarfdump,
                libc,
                int(target["address"]),
                provenance_name,
                expected_source_path,
            )
            if matched is not None:
                dispatch_target_names.add(provenance_name)
                break
    missing_provenance = [
        name
        for name in pointer_first_provenance
        if name not in dispatch_target_names and not dwarf_name_observed(inline_provenance, name)
    ]
    if missing_provenance:
        raise MatrixError(f"selected native {symbol} lacks pointer-first DWARF provenance")

    return {
        "dynamic_symbol": {
            "address": f"0x{int(definition['address']):x}",
            "binding": definition["binding"],
            "size": definition["size"],
            "visibility": definition["visibility"],
        },
        "entry_source_path": entry_source_path,
        "native_dispatch": {
            "address": f"0x{int(native_dispatch['start_address']):x}",
            "kind": "direct-dwarf",
            "name": expected_name,
            "source_path": expected_source_path,
        },
        "pointer_first_dwarf_provenance": pointer_first_provenance,
        "public_direct_transfer_count": len(public_targets),
        "public_direct_targets": checked_public_targets,
        "public_direct_mimalloc_transfers": forbidden_public,
        "dispatch_direct_mimalloc_transfers": forbidden_dispatch,
    }


def attest_native_pointer_first_guard(
    libc: Path,
    target_dir: Path,
    backend: Mapping[str, Any],
    fingerprints: Sequence[tuple[Path, list[str]]],
) -> dict[str, Any]:
    """Fail closed unless the selected debug artifact proves all three Rust routes."""

    guard = backend["native_pointer_first_guard"]
    assert isinstance(guard, dict)
    expected_artifact = target_dir / "libc.so"
    if libc.expanduser().resolve() != expected_artifact.expanduser().resolve():
        raise MatrixError("selected native pointer-first guard requires target-dir libc.so")
    readelf = shutil.which("readelf")
    objdump = shutil.which("objdump")
    llvm_dwarfdump = shutil.which("llvm-dwarfdump")
    if readelf is None or objdump is None or llvm_dwarfdump is None:
        raise MatrixError("readelf, objdump, and llvm-dwarfdump are required for the native pointer-first guard")

    header = command_text(
        command_record((readelf, "-W", "--file-header", str(libc))),
        "selected native ELF identity inspection",
    )
    identity = parse_elf_identity(header)
    if identity != guard["required_elf_identity"]:
        raise MatrixError("selected native artifact ELF identity drifted")
    sections = elf_section_names(
        command_text(
            command_record((readelf, "-W", "--sections", str(libc))),
            "selected native debug-section inspection",
        )
    )
    required_sections = guard["required_debug_sections"]
    assert isinstance(required_sections, list)
    if not set(required_sections).issubset(sections):
        raise MatrixError("selected native artifact lacks required DWARF sections")

    dynamic_symbols = command_text(
        command_record((readelf, "-W", "--dyn-syms", str(libc))),
        "selected native dynamic-symbol inspection",
    )
    relocations = command_text(
        command_record((readelf, "-W", "--relocs", str(libc))),
        "selected native relocation inspection",
    )
    forbidden_prefix = str(guard["forbidden_c_backend_symbol_prefix"])
    mimalloc_relocations = mimalloc_relocation_symbols(relocations, forbidden_prefix)
    if mimalloc_relocations:
        raise MatrixError("selected native artifact retains a C mimalloc relocation")
    decoded_lines = decoded_line_locations(
        command_text(
            command_record((readelf, "--debug-dump=decodedline", str(libc))),
            "selected native DWARF line inspection",
        )
    )
    if not decoded_lines:
        raise MatrixError("selected native artifact has no decoded DWARF line evidence")

    exports = guard["exports"]
    assert isinstance(exports, list)
    return {
        "artifact": file_record(libc),
        "cargo_features": list(fingerprints[0][1]),
        "cargo_fingerprints": [file_record(fingerprint) for fingerprint, _ in fingerprints],
        "elf_identity": identity,
        "required_debug_sections": list(required_sections),
        "forbidden_c_backend_symbol_prefix": forbidden_prefix,
        "mimalloc_relocations": mimalloc_relocations,
        "public_exports": [
            native_pointer_first_export_attestation(
                libc,
                dynamic_symbols,
                decoded_lines,
                objdump,
                llvm_dwarfdump,
                export,
                forbidden_prefix,
            )
            for export in exports
            if isinstance(export, dict)
        ],
        "status": "passed",
    }


def attest_ordinary_free_route(
    libc: Path,
    backend: Mapping[str, Any],
    fingerprints: Sequence[tuple[Path, list[str]]],
) -> dict[str, Any]:
    """Preserve the ordinary C-backed snapshot check unchanged."""

    readelf = shutil.which("readelf")
    objdump = shutil.which("objdump")
    if readelf is None or objdump is None:
        raise MatrixError("readelf and objdump are required for backend attestation")
    route = backend["exported_free_route"]
    assert isinstance(route, dict)
    symbol = str(route["symbol"])
    symbols = command_text(
        command_record((readelf, "-W", "--dyn-syms", str(libc))),
        f"{backend['id']} dynamic symbol inspection",
    )
    if not any(
        len(fields := line.split()) >= 8
        and fields[-1].split("@@", 1)[0] == symbol
        and fields[3] == "FUNC"
        and fields[4] in {"GLOBAL", "WEAK"}
        and fields[5] == "DEFAULT"
        and fields[6] != "UND"
        for line in symbols.splitlines()
    ):
        raise MatrixError(f"{backend['id']} does not define dynamic {symbol}")
    disassembly = command_text(
        command_record((objdump, "-d", f"--disassemble={symbol}", str(libc))),
        f"{backend['id']} free route inspection",
    )
    branch = r"\b(?:b|bl)\s+[^<]*<[^>]*{}"
    required = str(route["required_callee_suffix"])
    forbidden = str(route["forbidden_callee_suffix"])
    if not re.search(branch.format(re.escape(required)), disassembly):
        raise MatrixError(f"{backend['id']} free does not branch to <{required}")
    if re.search(branch.format(re.escape(forbidden)), disassembly):
        raise MatrixError(f"{backend['id']} free branches to forbidden <{forbidden}")
    return {
        "backend": backend["id"],
        "cargo_features": fingerprints[0][1],
        "cargo_fingerprints": [file_record(fingerprint) for fingerprint, _ in fingerprints],
        "exported_free": {
            "symbol": symbol,
            "required_callee_suffix": required,
            "forbidden_callee_suffix": forbidden,
            "disassembly_sha256": hashlib.sha256(disassembly.encode("utf-8")).hexdigest(),
        },
        "status": "passed",
    }


def attest_backend(libc: Path, target_dir: Path, backend: Mapping[str, Any]) -> dict[str, Any]:
    """Attest the ordinary snapshot or the selected native debug boundary."""

    fingerprints = matching_cargo_fingerprints(target_dir, backend)
    if backend["id"] == "native-rust-mimalloc-shadow":
        native_guard = attest_native_pointer_first_guard(libc, target_dir, backend, fingerprints)
        return {
            "backend": backend["id"],
            "cargo_features": native_guard["cargo_features"],
            "cargo_fingerprints": native_guard["cargo_fingerprints"],
            "native_pointer_first_guard": native_guard,
            "status": "passed",
        }
    return attest_ordinary_free_route(libc, backend, fingerprints)


def snapshot_ordinary_backend(contract: Mapping[str, Any], target_dir: Path, source: Path, destination: Path) -> dict[str, Any]:
    backend = backend_contract(contract, "ordinary-c-mimalloc")
    attestation = attest_backend(source, target_dir, backend)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as input_stream, tempfile.NamedTemporaryFile(
        mode="wb", dir=destination.parent, prefix=f".{destination.name}.", delete=False
    ) as output_stream:
        shutil.copyfileobj(input_stream, output_stream)
        staged = Path(output_stream.name)
    os.replace(staged, destination)
    snapshot = {
        "format": 1,
        "schema": "crabc-libc-native-mimalloc-shadow-abi-matrix-ordinary-snapshot",
        "backend": backend["id"],
        "source": file_record(source),
        "snapshot": file_record(destination),
        "attestation": attestation,
    }
    write_json(destination.parent / "attestation.json", snapshot)
    return snapshot


def load_ordinary_snapshot(contract: Mapping[str, Any], path: Path) -> dict[str, Any]:
    snapshot = read_json(path.parent / "attestation.json", "ordinary libc snapshot attestation")
    require_exact_keys(snapshot, {"format", "schema", "backend", "source", "snapshot", "attestation"}, "ordinary libc snapshot")
    if (
        snapshot["format"] != 1
        or snapshot["schema"] != "crabc-libc-native-mimalloc-shadow-abi-matrix-ordinary-snapshot"
        or snapshot["backend"] != "ordinary-c-mimalloc"
    ):
        raise MatrixError("ordinary libc snapshot identity drifted")
    artifact = snapshot["snapshot"]
    if not isinstance(artifact, dict) or artifact != file_record(path):
        raise MatrixError("ordinary libc snapshot does not match its attestation")
    attestation = snapshot["attestation"]
    if not isinstance(attestation, dict) or attestation.get("backend") != "ordinary-c-mimalloc":
        raise MatrixError("ordinary libc snapshot lacks its backend attestation")
    expected = backend_contract(contract, "ordinary-c-mimalloc")
    if attestation.get("cargo_features") != expected["cargo_features"] or attestation.get("status") != "passed":
        raise MatrixError("ordinary libc snapshot selected the wrong Cargo features")
    return snapshot


def require_runtime_inputs() -> tuple[Path, Path, Path]:
    raw_sysroot = os.environ.get("CRABC_TEST_SYSROOT")
    if not raw_sysroot:
        raise MatrixError(
            "shadow ABI matrix requires CRABC_TEST_SYSROOT from scripts/run_owned_test_suite.py"
        )
    sysroot = Path(raw_sysroot).expanduser().resolve()
    compiler = sysroot / "bin/crabc-cc"
    manifest = sysroot / "share/crabc/manifest.json"
    builtins = sysroot / OWNED_BUILTINS_RELATIVE_PATH
    if not compiler.is_file() or not manifest.is_file() or not builtins.is_file():
        raise MatrixError("shadow ABI matrix requires a complete owned crabc sysroot")
    if not CANONICAL_LOADER.is_file() or CANONICAL_LOADER.is_symlink():
        raise MatrixError("shadow ABI matrix requires the staged canonical owned loader")
    return sysroot, compiler, builtins


def require_pinned_musl_oracle(contract: Mapping[str, Any]) -> tuple[Path, Path]:
    """Return only the Docker-pinned musl 1.2.6 compiler and library root."""

    execution = contract["execution"]
    assert isinstance(execution, dict)
    oracle = execution["pinned_musl_oracle"]
    assert isinstance(oracle, dict)
    compiler_name = str(oracle["compiler"])
    compiler = shutil.which(compiler_name)
    if compiler is None:
        raise MatrixError(f"shadow ABI matrix requires the pinned musl oracle compiler: {compiler_name}")
    configured_library_root = Path(str(oracle["library_root"])).resolve()
    observed_library_root = os.environ.get("MUSL_REFERENCE_LIBDIR")
    if observed_library_root is None or Path(observed_library_root).resolve() != configured_library_root:
        raise MatrixError("shadow ABI matrix requires the pinned musl 1.2.6 library root")
    return Path(compiler).resolve(), configured_library_root


def matrix_link_command(
    contract: Mapping[str, Any], compiler: Path, libc: Path, builtins: Path, binary: Path
) -> list[str]:
    """Build one fixture through an explicitly selected dynamic libc input.

    The sealed driver normally owns its library search root and appends ``-lc``.
    That is correct for ordinary applications but intentionally unsuitable for a
    paired-artifact test: an application ``-L`` cannot precede that owned root.
    ``-nodefaultlibs`` makes the opt-out explicit; the only remaining library
    root is the selected artifact directory, and the exact-name input retains
    the public ``DT_NEEDED=libc.so`` spelling even though these test artifacts
    do not carry a DSO SONAME. The owned builtins archive remains explicit and
    follows libc, while CRT/interpreter ownership stays with ``crabc-cc``.
    """

    fixture = contract["fixture"]
    execution = contract["execution"]
    assert isinstance(fixture, dict) and isinstance(execution, dict)
    provenance = execution["link_provenance"]
    assert isinstance(provenance, dict)
    return [
        str(compiler),
        "-std=c11",
        *[str(flag) for flag in fixture["compile_flags"]],
        str(provenance["driver_opt_out"]),
        "-I",
        str(ROOT / "include"),
        "-L",
        str(libc.parent),
        *[str(flag) for flag in fixture["link_flags"]],
        str(FIXTURE_PATH),
        *[str(library) for library in fixture["link_libraries"]],
        str(builtins),
        str(provenance["linker_trace_flag"]),
        "-o",
        str(binary),
    ]


def case_fixture_path(case: Mapping[str, Any]) -> Path:
    fixture = case["fixture"]
    assert isinstance(fixture, dict)
    return ROOT / str(fixture["path"])


def musl_differential_selected_link_command(
    case: Mapping[str, Any], compiler: Path, libc: Path, builtins: Path, binary: Path
) -> list[str]:
    """Build one required case through the attested selected-shadow libc."""

    fixture = case["fixture"]
    assert isinstance(fixture, dict)
    source = case_fixture_path(case)
    return [
        str(compiler),
        "-std=c11",
        *[str(flag) for flag in fixture["compile_flags"]],
        "-nodefaultlibs",
        "-I",
        str(ROOT / "include"),
        "-L",
        str(libc.parent),
        *[str(flag) for flag in fixture["selected_link_flags"]],
        str(source),
        *[str(library) for library in fixture["selected_link_libraries"]],
        str(builtins),
        LINKER_TRACE_FLAG,
        "-o",
        str(binary),
    ]


def musl_differential_oracle_link_command(
    case: Mapping[str, Any], compiler: Path, binary: Path
) -> list[str]:
    """Build the same source with the pinned musl oracle, never crabc headers."""

    fixture = case["fixture"]
    assert isinstance(fixture, dict)
    return [
        str(compiler),
        "-std=c11",
        *[str(flag) for flag in fixture["compile_flags"]],
        *[str(flag) for flag in fixture["musl_link_flags"]],
        str(case_fixture_path(case)),
        *[str(library) for library in fixture["musl_link_libraries"]],
        "-o",
        str(binary),
    ]


def printed_driver_link_plan(compiler: Path, command: Sequence[str]) -> dict[str, Any]:
    record = command_record((str(compiler), "--crabc-print-link-plan", *command[1:]))
    text = command_text(record, "matrix fixture driver link-plan inspection")
    try:
        plan = json.loads(text)
    except json.JSONDecodeError as error:
        raise MatrixError("matrix fixture driver did not emit a JSON link plan") from error
    if not isinstance(plan, dict):
        raise MatrixError("matrix fixture driver link plan is not an object")
    return plan


def link_plan_search_paths(command: Sequence[str]) -> list[str]:
    paths: list[str] = []
    index = 0
    while index < len(command):
        argument = command[index]
        if argument == "-L":
            if index + 1 == len(command):
                raise MatrixError("matrix fixture driver link plan has a dangling -L")
            paths.append(command[index + 1])
            index += 2
            continue
        if argument.startswith("-L") and len(argument) > 2:
            paths.append(argument[2:])
        index += 1
    return paths


def audit_selected_link_plan(
    plan: Mapping[str, Any], sysroot: Path, libc: Path, builtins: Path
) -> dict[str, Any]:
    """Require the sealed driver's plan to preserve exact selected-libc input."""

    command_value = plan.get("command")
    if not isinstance(command_value, list) or not all(isinstance(item, str) for item in command_value):
        raise MatrixError("matrix fixture driver link plan has an invalid command")
    command = list(command_value)
    if plan.get("default_libraries") != []:
        raise MatrixError("matrix fixture driver retained default libraries")
    if plan.get("interpreter") != str(CANONICAL_LOADER):
        raise MatrixError("matrix fixture driver link plan lost the canonical interpreter")
    if command.count("-nodefaultlibs") != 1:
        raise MatrixError("matrix fixture driver link plan lacks exactly one -nodefaultlibs")
    if "-lc" in command:
        raise MatrixError("matrix fixture driver link plan contains generic -lc")
    if command.count(SELECTED_LIBC_LINK_FLAG) != 1:
        raise MatrixError("matrix fixture driver link plan lacks the exact selected libc name")
    if link_plan_search_paths(command) != [str(libc.parent)]:
        raise MatrixError("matrix fixture driver link plan has an ambiguous libc search root")
    if libc.parent.resolve() == (sysroot / "usr/lib").resolve():
        raise MatrixError("matrix fixture selected libc root aliases the owned sysroot libc")
    if command.count(str(builtins)) != 1:
        raise MatrixError("matrix fixture driver link plan lacks exactly one owned builtins archive")
    if command.index(SELECTED_LIBC_LINK_FLAG) >= command.index(str(builtins)):
        raise MatrixError("matrix fixture driver link plan orders builtins before selected libc")
    return {
        "default_libraries": [],
        "driver_opt_out": "-nodefaultlibs",
        "selected_library_root": relative_path(libc.parent),
        "selected_library_flag": SELECTED_LIBC_LINK_FLAG,
        "owned_builtins": file_record(builtins),
        "interpreter": str(CANONICAL_LOADER),
    }


def audit_selected_linker_trace(
    build: Mapping[str, Any], libc: Path, sysroot: Path
) -> dict[str, Any]:
    """Bind the actual lld resolution to the one selected backend artifact."""

    trace = command_stream_bytes(build, "stdout", "matrix fixture linker trace")
    trace += b"\n" + command_stream_bytes(build, "stderr", "matrix fixture linker trace")
    trace_lines = []
    for line in trace.decode("utf-8", errors="replace").splitlines():
        normalized = line.strip()
        if normalized.startswith("ld.lld: "):
            normalized = normalized[len("ld.lld: ") :].strip()
        if normalized:
            trace_lines.append(normalized)
    selected = str(libc.resolve())
    sysroot_libc = str((sysroot / "usr/lib/libc.so").resolve())
    if selected not in trace_lines:
        raise MatrixError("matrix fixture linker trace did not resolve the selected libc artifact")
    if sysroot_libc in trace_lines:
        raise MatrixError("matrix fixture linker trace resolved the owned sysroot libc")
    return {
        "selected_libc": file_record(libc),
        "selected_libc_seen": True,
        "sysroot_libc_seen": False,
    }


def parse_dynamic_dependencies(output: str) -> list[str]:
    dependencies: list[str] = []
    for line in output.splitlines():
        match = re.search(r"Shared library: \[([^\]]+)\]", line)
        if match:
            dependencies.append(match.group(1))
    return dependencies


def parse_dynamic_search_paths(output: str) -> list[str]:
    return re.findall(r"\((?:RPATH|RUNPATH)\).*?\[([^\]]+)\]", output)


def parse_interpreter(output: str) -> str:
    interpreters = re.findall(r"Requesting program interpreter: ([^\]]+)", output)
    if len(interpreters) != 1:
        raise MatrixError("matrix fixture has an ambiguous PT_INTERP")
    return interpreters[0]


def audit_fixture(binary: Path, contract: Mapping[str, Any]) -> dict[str, Any]:
    readelf = shutil.which("readelf")
    if readelf is None:
        raise MatrixError("readelf is required for fixture attestation")
    dynamic = command_text(
        command_record((readelf, "--wide", "--dynamic", str(binary))),
        "matrix fixture DT_NEEDED inspection",
    )
    dependencies = parse_dynamic_dependencies(dynamic)
    search_paths = parse_dynamic_search_paths(dynamic)
    execution = contract["execution"]
    assert isinstance(execution, dict)
    if dependencies != execution["expected_dynamic_dependencies"]:
        raise MatrixError("matrix fixture DT_NEEDED differs from the contract")
    if search_paths:
        raise MatrixError("matrix fixture embeds a dynamic search path")
    program_headers = command_text(
        command_record((readelf, "--wide", "--program-headers", str(binary))),
        "matrix fixture PT_INTERP inspection",
    )
    interpreter = parse_interpreter(program_headers)
    if interpreter != execution["canonical_loader"]:
        raise MatrixError("matrix fixture PT_INTERP differs from the contract")
    return {
        "dynamic_dependencies": dependencies,
        "dynamic_search_paths": search_paths,
        "interpreter": interpreter,
    }


def expected_trace(contract: Mapping[str, Any]) -> list[str]:
    cases = contract["semantic_cases"]
    assert isinstance(cases, list)
    return [str(case["id"]) for case in cases]


def parse_trace(output: bytes, contract: Mapping[str, Any]) -> list[dict[str, str]]:
    try:
        lines = output.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise MatrixError("matrix fixture stdout is not UTF-8") from error
    observed: list[dict[str, str]] = []
    for line in lines:
        match = re.fullmatch(r"case=([a-z0-9-]+) result=([a-z0-9-]+)", line)
        if match is None:
            raise MatrixError("matrix fixture emitted a non-normalized semantic record")
        observed.append({"id": match.group(1), "result": match.group(2)})
    if [record["id"] for record in observed] != expected_trace(contract):
        raise MatrixError("matrix fixture semantic records differ from the contract")
    return observed


def validate_backend_trace(
    contract: Mapping[str, Any], backend: Mapping[str, Any], trace: Sequence[Mapping[str, str]]
) -> None:
    """Reject a changed observed result, including a known red that disappears."""

    cases = contract["semantic_cases"]
    assert isinstance(cases, list)
    if len(trace) != len(cases):
        raise MatrixError(f"{backend['id']} matrix trace is incomplete")
    for case, record in zip(cases, trace):
        assert isinstance(case, dict)
        expected = case["expected"]
        assert isinstance(expected, dict)
        if record.get("id") != case["id"] or record.get("result") != expected[backend["id"]]:
            raise MatrixError(f"{backend['id']} matrix trace differs from its recorded semantics")


def run_backend(
    contract: Mapping[str, Any],
    backend: Mapping[str, Any],
    libc: Path,
    sysroot: Path,
    compiler: Path,
    builtins: Path,
    output_root: Path,
) -> dict[str, Any]:
    execution = contract["execution"]
    assert isinstance(execution, dict)
    backend_root = output_root / str(backend["id"])
    backend_root.mkdir(parents=True, exist_ok=True)
    binary = backend_root / "native-mimalloc-shadow-backend-matrix"
    command = matrix_link_command(contract, compiler, libc, builtins, binary)
    driver_plan = printed_driver_link_plan(compiler, command)
    link_plan = audit_selected_link_plan(driver_plan, sysroot, libc, builtins)
    build = command_record(command)
    if build["kind"] != "process" or build["status"] != 0:
        raise MatrixError(f"{backend['id']} matrix fixture compilation failed")
    linker_trace = audit_selected_linker_trace(build, libc, sysroot)
    elf = audit_fixture(binary, contract)
    environment = dict(os.environ)
    for key in ("LD_AUDIT", "LD_LIBRARY_PATH", "LD_PRELOAD"):
        environment.pop(key, None)
    environment["LD_LIBRARY_PATH"] = str(libc.parent)
    run = command_record(
        (str(binary),), env=environment, timeout_seconds=int(execution["watchdog_seconds"])
    )
    if run["kind"] != "process" or run["status"] != 0:
        raise MatrixError(f"{backend['id']} matrix fixture execution failed")
    stdout = run["stdout"]
    stderr = run["stderr"]
    assert isinstance(stdout, dict) and isinstance(stderr, dict)
    if stderr["bytes"] != 0:
        raise MatrixError(f"{backend['id']} matrix fixture wrote diagnostics")
    trace = parse_trace(bytes.fromhex(str(stdout["hex"])), contract)
    validate_backend_trace(contract, backend, trace)
    return {
        "backend": backend["id"],
        "binary": file_record(binary),
        "build": build,
        "driver_link_plan": driver_plan,
        "elf": elf,
        "link_provenance": {
            "driver_plan": link_plan,
            "linker_trace": linker_trace,
        },
        "run": run,
        "semantic_trace": trace,
        "selected_runtime_library": file_record(libc),
    }


def scrubbed_loader_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for key in ("LD_AUDIT", "LD_LIBRARY_PATH", "LD_PRELOAD"):
        environment.pop(key, None)
    return environment


def run_musl_differential_case(
    contract: Mapping[str, Any],
    case: Mapping[str, Any],
    musl_compiler: Path,
    musl_library_root: Path,
    native_libc: Path,
    sysroot: Path,
    compiler: Path,
    builtins: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Run one activated source-faithful fixture against musl and selected shadow."""

    execution = contract["execution"]
    assert isinstance(execution, dict)
    case_root = output_root / "musl-differentials" / str(case["id"])
    case_root.mkdir(parents=True, exist_ok=True)

    oracle_binary = case_root / "pinned-musl"
    oracle_command = musl_differential_oracle_link_command(case, musl_compiler, oracle_binary)
    oracle_build = command_record(oracle_command)
    if oracle_build["kind"] != "process" or oracle_build["status"] != 0:
        raise MatrixError(f"{case['id']} pinned musl fixture compilation failed")
    oracle_run = command_record(
        (str(oracle_binary),),
        env=scrubbed_loader_environment(),
        timeout_seconds=int(execution["watchdog_seconds"]),
    )
    # Check the oracle against the manifest before an equivalent candidate
    # stream can hide a changed test fixture.
    validate_musl_differential_execution(case, oracle_run, oracle_run)

    selected_binary = case_root / "selected-shadow"
    selected_command = musl_differential_selected_link_command(
        case, compiler, native_libc, builtins, selected_binary
    )
    driver_plan = printed_driver_link_plan(compiler, selected_command)
    link_plan = audit_selected_link_plan(driver_plan, sysroot, native_libc, builtins)
    selected_build = command_record(selected_command)
    if selected_build["kind"] != "process" or selected_build["status"] != 0:
        raise MatrixError(f"{case['id']} selected shadow fixture compilation failed")
    linker_trace = audit_selected_linker_trace(selected_build, native_libc, sysroot)
    selected_elf = audit_fixture(selected_binary, contract)
    selected_environment = scrubbed_loader_environment()
    selected_environment["LD_LIBRARY_PATH"] = str(native_libc.parent)
    selected_run = command_record(
        (str(selected_binary),),
        env=selected_environment,
        timeout_seconds=int(execution["watchdog_seconds"]),
    )
    comparison = validate_musl_differential_execution(case, oracle_run, selected_run)

    return {
        **comparison,
        "fixture": file_record(case_fixture_path(case)),
        "pinned_musl": {
            "compiler": relative_path(musl_compiler),
            "library_root": relative_path(musl_library_root),
            "command": oracle_command,
            "binary": file_record(oracle_binary),
            "build": oracle_build,
            "run": oracle_run,
        },
        "selected_shadow": {
            "command": selected_command,
            "binary": file_record(selected_binary),
            "build": selected_build,
            "driver_link_plan": driver_plan,
            "elf": selected_elf,
            "link_provenance": {
                "driver_plan": link_plan,
                "linker_trace": linker_trace,
            },
            "run": selected_run,
            "runtime_library": file_record(native_libc),
        },
    }


def report_base(contract: Mapping[str, Any]) -> dict[str, Any]:
    report = contract["report"]
    assert isinstance(report, dict)
    return {
        "format": report["format"],
        "schema": report["schema"],
        "status": "failed",
        "contract": file_record(CONTRACT_PATH),
        "fixture": file_record(FIXTURE_PATH),
        "intentionally_blocked_cases": contract["intentionally_blocked_cases"],
        "musl_differential_required_cases": contract["musl_differential_required_cases"],
        "backends": [],
        "semantic_comparisons": [],
        "musl_differential_cases": [],
    }


def execute_matrix(contract: Mapping[str, Any], target_dir: Path, output_root: Path) -> dict[str, Any]:
    musl_differential_cases = active_musl_differential_cases(contract)
    sysroot, compiler, builtins = require_runtime_inputs()
    musl_compiler, musl_library_root = require_pinned_musl_oracle(contract)
    legacy_snapshot = load_ordinary_snapshot(contract, LEGACY_LIBC)
    native_backend = backend_contract(contract, "native-rust-mimalloc-shadow")
    native_libc = target_dir / "libc.so"
    native_attestation = attest_backend(native_libc, target_dir, native_backend)
    legacy_backend = backend_contract(contract, "ordinary-c-mimalloc")
    legacy_run = run_backend(contract, legacy_backend, LEGACY_LIBC, sysroot, compiler, builtins, output_root)
    native_run = run_backend(contract, native_backend, native_libc, sysroot, compiler, builtins, output_root)
    legacy_trace = legacy_run["semantic_trace"]
    native_trace = native_run["semantic_trace"]
    assert isinstance(legacy_trace, list) and isinstance(native_trace, list)
    legacy_results = {str(record["id"]): str(record["result"]) for record in legacy_trace}
    native_results = {str(record["id"]): str(record["result"]) for record in native_trace}
    cases = contract["semantic_cases"]
    assert isinstance(cases, list)
    comparisons: list[dict[str, Any]] = []
    known_red_case_count = 0
    for case in cases:
        assert isinstance(case, dict)
        case_id = str(case["id"])
        comparison = str(case["comparison"])
        ordinary = legacy_results[case_id]
        native = native_results[case_id]
        equal = ordinary == native
        if comparison == "match" and not equal:
            raise MatrixError("a required matching semantic row diverged")
        if comparison == "known-red":
            if equal:
                raise MatrixError("the recorded semantic red unexpectedly collapsed")
            known_red_case_count += 1
        record: dict[str, Any] = {
            "id": case_id,
            "ordinary_c_mimalloc": ordinary,
            "native_rust_mimalloc_shadow": native,
            "equal": equal,
            "classification": comparison,
        }
        if comparison == "known-red":
            record["reason"] = case["reason"]
        comparisons.append(record)
    musl_differentials = [
        run_musl_differential_case(
            contract,
            case,
            musl_compiler,
            musl_library_root,
            native_libc,
            sysroot,
            compiler,
            builtins,
            output_root,
        )
        for case in musl_differential_cases
    ]
    return {
        "runtime": {
            "sysroot": relative_path(sysroot),
            "compiler": relative_path(compiler),
            "canonical_loader": str(CANONICAL_LOADER),
        },
        "artifacts": {
            "ordinary_snapshot": legacy_snapshot,
            "native": {
                "artifact": file_record(native_libc),
                "attestation": native_attestation,
            },
        },
        "backends": [legacy_run, native_run],
        "comparison_summary": {
            "known_red_case_count": known_red_case_count,
            "matched_case_count": len(comparisons) - known_red_case_count,
            "musl_differential_required_case_count": len(musl_differentials),
        },
        "semantic_comparisons": comparisons,
        "musl_differential_cases": musl_differentials,
    }


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("capture", help="snapshot and attest the ordinary libc artifact")
    capture.add_argument("--target-dir", type=Path, default=TARGET_DIR)
    capture.add_argument("--source", type=Path, default=TARGET_DIR / "libc.so")
    capture.add_argument("--destination", type=Path, default=LEGACY_LIBC)
    run = commands.add_parser("run", help="run the paired ABI matrix")
    run.add_argument("--target-dir", type=Path, default=TARGET_DIR)
    run.add_argument("--output-dir", type=Path, default=OUTPUT_ROOT)
    run.add_argument("--report", type=Path, default=REPORT_PATH)
    commands.add_parser("check", help="validate the checked-in contract without runtime execution")
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_arguments(arguments)
    try:
        contract = load_contract()
        if args.command == "check":
            print(
                json.dumps(
                    {
                        "contract": relative_path(CONTRACT_PATH),
                        "fixture": relative_path(FIXTURE_PATH),
                        "status": "contract-valid",
                        "musl_differential_activations": [
                            {
                                "id": case["id"],
                                "activation": case["activation"],
                            }
                            for case in musl_differential_required_cases(contract)
                        ],
                    },
                    sort_keys=True,
                )
            )
            return 0
        if args.command == "capture":
            snapshot = snapshot_ordinary_backend(
                contract,
                args.target_dir.expanduser().resolve(),
                args.source.expanduser().resolve(),
                args.destination.expanduser().resolve(),
            )
            print(json.dumps(snapshot, sort_keys=True))
            return 0
        report = report_base(contract)
        try:
            report.update(
                execute_matrix(
                    contract,
                    args.target_dir.expanduser().resolve(),
                    args.output_dir.expanduser().resolve(),
                )
            )
            report["status"] = "passed"
            report["first_fact"] = {
                "kind": "pass",
                "stage": "semantic-comparison",
                "completed_case_count": len(report["semantic_comparisons"]),
            }
        except MatrixError as error:
            report["first_fact"] = {
                "kind": "first-failure",
                "stage": (
                    "required-musl-differential"
                    if isinstance(error, DeferredMuslDifferentialError)
                    else "harness-or-execution"
                ),
                "message": str(error),
            }
        write_json(args.report, report)
        print(args.report.expanduser().resolve())
        return 0 if report["status"] == "passed" else 1
    except MatrixError as error:
        print(f"shadow-abi-matrix: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
