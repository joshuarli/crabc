#!/usr/bin/env python3
"""Compare the ordinary and native-shadow libc malloc-family artifacts.

The matrix is intentionally narrow. It snapshots the ordinary C-backed
``libc.so`` before the ``native-mimalloc-shadow`` feature rebuild, attests the
two public ``free`` routes, and runs one deterministic initial-thread C trace
through each artifact. It is neither a runtime selector nor an allocator
promotion gate. Lifecycle, cross-owner, DSO, and allocator-layout claims stay
with their separately bounded evidence.
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


class MatrixError(RuntimeError):
    """A checked artifact or observable comparison contradicted the contract."""


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
            "purpose",
        },
        "shadow ABI matrix scope",
    )
    if (
        scope["target"] != "linux-aarch64-little-endian"
        or scope["kernel_baseline"] != "5.10"
        or scope["not_a_promotion_gate"] is not True
        or scope["not_a_runtime_selector"] is not True
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
        or fixture["link_libraries"] != ["-lc"]
        or fixture["sha256"] != sha256_file(FIXTURE_PATH)
    ):
        raise MatrixError("shadow ABI matrix fixture contract drifted")

    backends = contract["backends"]
    if not isinstance(backends, list) or len(backends) != 2:
        raise MatrixError("shadow ABI matrix requires exactly two backends")
    expected_backends = {
        "ordinary-c-mimalloc": {
            "cargo_features": ["default"],
            "required": "mi_free>",
            "forbidden": "native_free>",
        },
        "native-rust-mimalloc-shadow": {
            "cargo_features": ["default", "native-mimalloc-shadow"],
            "required": "native_free>",
            "forbidden": "mi_free>",
        },
    }
    seen_backends: set[str] = set()
    for backend in backends:
        if not isinstance(backend, dict):
            raise MatrixError("shadow ABI matrix backend is invalid")
        require_exact_keys(
            backend,
            {"id", "cargo_features", "selection", "fallback", "exported_free_route"},
            "shadow ABI matrix backend",
        )
        backend_id = require_string(backend["id"], "shadow ABI matrix backend id")
        expected = expected_backends.get(backend_id)
        if expected is None or backend_id in seen_backends:
            raise MatrixError("shadow ABI matrix backend inventory drifted")
        seen_backends.add(backend_id)
        if backend["cargo_features"] != expected["cargo_features"] or backend["fallback"] is not False:
            raise MatrixError("shadow ABI matrix backend selection drifted")
        require_string(backend["selection"], "shadow ABI matrix backend selection")
        route = backend["exported_free_route"]
        if not isinstance(route, dict):
            raise MatrixError("shadow ABI matrix free route is invalid")
        require_exact_keys(route, {"symbol", "required_callee_suffix", "forbidden_callee_suffix"}, "shadow ABI matrix free route")
        if (
            route["symbol"] != "free"
            or route["required_callee_suffix"] != expected["required"]
            or route["forbidden_callee_suffix"] != expected["forbidden"]
        ):
            raise MatrixError("shadow ABI matrix free route drifted")

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
            "distinct-misaligned-preserves-errno",
            "known-red",
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

    blocked = contract["intentionally_blocked_cases"]
    expected_blocked = {
        "foreign-worker-free-or-realloc",
        "owner-exit-and-post-exit-routing",
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


def attest_backend(libc: Path, target_dir: Path, backend: Mapping[str, Any]) -> dict[str, Any]:
    """Prove the exported C ``free`` reaches the selected implementation."""

    fingerprints = matching_cargo_fingerprints(target_dir, backend)
    features = fingerprints[0][1]
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
        "cargo_features": features,
        "cargo_fingerprints": [file_record(fingerprint) for fingerprint, _ in fingerprints],
        "exported_free": {
            "symbol": symbol,
            "required_callee_suffix": required,
            "forbidden_callee_suffix": forbidden,
            "disassembly_sha256": hashlib.sha256(disassembly.encode("utf-8")).hexdigest(),
        },
        "status": "passed",
    }


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


def require_runtime_inputs() -> tuple[Path, Path]:
    raw_sysroot = os.environ.get("CRABC_TEST_SYSROOT")
    if not raw_sysroot:
        raise MatrixError(
            "shadow ABI matrix requires CRABC_TEST_SYSROOT from scripts/run_owned_test_suite.py"
        )
    sysroot = Path(raw_sysroot).expanduser().resolve()
    compiler = sysroot / "bin/crabc-cc"
    manifest = sysroot / "share/crabc/manifest.json"
    if not compiler.is_file() or not manifest.is_file():
        raise MatrixError("shadow ABI matrix requires a complete owned crabc sysroot")
    if not CANONICAL_LOADER.is_file() or CANONICAL_LOADER.is_symlink():
        raise MatrixError("shadow ABI matrix requires the staged canonical owned loader")
    return sysroot, compiler


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
    contract: Mapping[str, Any], backend: Mapping[str, Any], libc: Path, compiler: Path, output_root: Path
) -> dict[str, Any]:
    fixture = contract["fixture"]
    execution = contract["execution"]
    assert isinstance(fixture, dict) and isinstance(execution, dict)
    backend_root = output_root / str(backend["id"])
    backend_root.mkdir(parents=True, exist_ok=True)
    binary = backend_root / "native-mimalloc-shadow-backend-matrix"
    command = [
        str(compiler),
        "-std=c11",
        *[str(flag) for flag in fixture["compile_flags"]],
        "-I",
        str(ROOT / "include"),
        "-L",
        str(libc.parent),
        *[str(flag) for flag in fixture["link_flags"]],
        str(FIXTURE_PATH),
        *[str(library) for library in fixture["link_libraries"]],
        "-o",
        str(binary),
    ]
    build = command_record(command)
    if build["kind"] != "process" or build["status"] != 0:
        raise MatrixError(f"{backend['id']} matrix fixture compilation failed")
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
        "elf": elf,
        "run": run,
        "semantic_trace": trace,
        "selected_runtime_library": file_record(libc),
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
        "backends": [],
        "semantic_comparisons": [],
    }


def execute_matrix(contract: Mapping[str, Any], target_dir: Path, output_root: Path) -> dict[str, Any]:
    sysroot, compiler = require_runtime_inputs()
    legacy_snapshot = load_ordinary_snapshot(contract, LEGACY_LIBC)
    native_backend = backend_contract(contract, "native-rust-mimalloc-shadow")
    native_libc = target_dir / "libc.so"
    native_attestation = attest_backend(native_libc, target_dir, native_backend)
    legacy_backend = backend_contract(contract, "ordinary-c-mimalloc")
    legacy_run = run_backend(contract, legacy_backend, LEGACY_LIBC, compiler, output_root)
    native_run = run_backend(contract, native_backend, native_libc, compiler, output_root)
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
        },
        "semantic_comparisons": comparisons,
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
                        "status": "passed",
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
                "stage": "harness-or-execution",
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
