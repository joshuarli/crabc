#!/usr/bin/env python3
"""Validate the M0 Rustix/Crabc metadata and run isolated backend probes.

The default ``check`` mode only uses Python's standard library.  It validates
the pinned Rustix provenance, correspondence records, and measured dynamic
symbol inventory.  ``compare`` is a deliberately small execution skeleton for
future source fixtures: callers provide one command per backend and each runs
in a fresh temporary directory with the same deterministic environment.

This harness is test infrastructure.  It must not become a dependency of the
production ``crabc-rs`` crate, and it never loads a local Rustix checkout.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
UPSTREAM_PATH = HERE / "upstream.toml"
API_PATH = HERE / "api.toml"
COVERAGE_PATH = ROOT / "compat" / "crabc-rs" / "coverage.toml"

RUSTIX_REVISION = "cf67411d572468d5fc39e8ac8b4e649ae3e5e9ec"
RUSTIX_VERSION = "1.1.4"
TARGET = "aarch64-unknown-linux-musl"
EXPECTED_REFERENCE_SYMBOLS = 1647
EXPECTED_CANDIDATE_SYMBOLS = 1668
EXPECTED_CANDIDATE_ONLY_SYMBOLS = 21
EXPECTED_CANDIDATE_ONLY = (
    "__auxv",
    "__crypt_blowfish",
    "__crypt_md5",
    "__crypt_r",
    "__crypt_sha256",
    "__crypt_sha512",
    "__fork_handler",
    "__funcs_on_exit",
    "__ldso_register_dlclose",
    "__ldso_register_dlerror",
    "__ldso_register_dlopen",
    "__ldso_register_dlsym",
    "__qsort_r",
    "__rc_clone",
    "__rc_create_thread_tls",
    "__rc_tls_base_offset",
    "__rc_tls_block_size",
    "__sigsetjmp_tail",
    "fopen64",
    "rust_eh_personality",
    "tgkill",
)
ALLOWED_API_STATUSES = {
    "missing",
    "implemented",
    "verified",
    "intentional-divergence",
    "not-applicable",
    "deferred",
}
ALLOWED_COVERAGE_CLASSIFICATIONS = {
    "native-safe",
    "native-unsafe",
    "native-higher-level",
    "rust-subsumed",
    "abi-only",
    "internal-runtime",
    "unclassified",
}


class HarnessError(ValueError):
    """A metadata or runner contract violation."""


def load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            value = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise HarnessError(f"cannot load {path}: {error}") from error
    if not isinstance(value, dict):
        raise HarnessError(f"top-level TOML value is not a table: {path}")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HarnessError(message)


def check_no_local_absolute_path(value: Any, location: str = "metadata") -> None:
    """Reject checkout paths while permitting immutable HTTPS provenance URLs."""

    if isinstance(value, Mapping):
        for key, child in value.items():
            check_no_local_absolute_path(child, f"{location}.{key}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            check_no_local_absolute_path(child, f"{location}[{index}]")
        return
    if not isinstance(value, str):
        return
    lowered_location = location.lower()
    if not any(token in lowered_location for token in ("path", "checkout", "source")):
        return
    if value.startswith("/") or value.startswith("~"):
        raise HarnessError(f"{location} must not be a local absolute path: {value!r}")
    if value.startswith("file:"):
        raise HarnessError(f"{location} must not use a file URL: {value!r}")


def validate_upstream(data: Mapping[str, Any]) -> dict[str, Any]:
    require(data.get("schema") == "crabc.rustix-upstream/v1", "bad Rustix upstream schema")
    rustix = data.get("rustix")
    profile = data.get("profile")
    policy = data.get("policy")
    require(isinstance(rustix, Mapping), "upstream.rustix must be a table")
    require(isinstance(profile, Mapping), "upstream.profile must be a table")
    require(isinstance(policy, Mapping), "upstream.policy must be a table")
    require(
        rustix.get("repository") == "https://github.com/bytecodealliance/rustix",
        "Rustix repository is not the pinned upstream repository",
    )
    require(rustix.get("version") == RUSTIX_VERSION, "Rustix version is not 1.1.4")
    require(rustix.get("revision") == RUSTIX_REVISION, "Rustix revision is not pinned")
    require(rustix.get("target") == TARGET, "Rustix target is not AArch64 musl")
    require(profile.get("default_features") is True, "Rustix default features must be enabled")
    expected_features = {
        "event",
        "fs",
        "mm",
        "mount",
        "net",
        "param",
        "pipe",
        "process",
        "pty",
        "rand",
        "shm",
        "stdio",
        "system",
        "termios",
        "thread",
        "time",
    }
    require(set(profile.get("features", ())) == expected_features, "Rustix feature profile changed")
    require(set(profile.get("excluded_features", ())) == {"runtime", "io_uring"}, "Rustix exclusions changed")
    require(policy.get("production_dependency") is False, "Rustix cannot be a production dependency")
    check_no_local_absolute_path(data)
    return {
        "version": rustix["version"],
        "revision": rustix["revision"],
        "target": rustix["target"],
        "features": sorted(expected_features),
        "excluded_features": ["io_uring", "runtime"],
    }


def validate_api(data: Mapping[str, Any], upstream: Mapping[str, Any]) -> dict[str, Any]:
    require(data.get("schema") == "crabc.rustix-api/v1", "bad Rustix API schema")
    require(data.get("target") == TARGET, "Rustix API target is not AArch64 musl")
    reference = data.get("reference")
    policy = data.get("policy")
    entries = data.get("api")
    require(isinstance(reference, Mapping), "api.reference must be a table")
    require(isinstance(policy, Mapping), "api.policy must be a table")
    require(isinstance(entries, list) and entries, "api.api must contain entries")
    require(reference.get("version") == upstream["version"], "API/upstream version mismatch")
    require(reference.get("revision") == upstream["revision"], "API/upstream revision mismatch")
    require(policy.get("production_dependency") is False, "API permits a production Rustix dependency")
    require(policy.get("direct_c_abi_errno_roundtrip") is False, "native facade may not round-trip through C errno")
    require(policy.get("representative_operation") == "fs::openat", "representative operation hook changed")
    require(policy.get("representative_fixture"), "representative fixture hook is missing")
    fixture = ROOT / str(policy["representative_fixture"])
    require(fixture.is_file(), "representative fixture does not exist")
    require(policy.get("representative_backend_boundary") == "direct-crabc-core", "representative backend must use direct crabc-core")
    require(
        set(policy.get("forbidden_backend_layers", ()))
        == {"public libc/POSIX ABI", "TLS errno readback"},
        "direct C-ABI/errno avoidance hook changed",
    )

    ids: set[str] = set()
    rustix_names: set[str] = set()
    status_counts = {status: 0 for status in sorted(ALLOWED_API_STATUSES)}
    for index, entry in enumerate(entries):
        require(isinstance(entry, Mapping), f"api entry {index} is not a table")
        location = f"api[{index}]"
        for key in ("id", "feature", "rustix", "crabc", "status", "compatibility", "tests"):
            require(key in entry, f"{location} is missing {key}")
        identifier = entry["id"]
        rustix_name = entry["rustix"]
        status = entry["status"]
        require(isinstance(identifier, str) and identifier, f"{location}.id is empty")
        require(identifier not in ids, f"duplicate API id: {identifier}")
        require(isinstance(rustix_name, str) and rustix_name, f"{location}.rustix is empty")
        require(rustix_name not in rustix_names, f"duplicate Rustix item: {rustix_name}")
        require(status in ALLOWED_API_STATUSES, f"{location} has unknown status: {status}")
        require(isinstance(entry["tests"], list) and entry["tests"], f"{location}.tests is empty")
        if status in {"intentional-divergence", "not-applicable"}:
            for key in ("reason", "tests", "documentation"):
                require(entry.get(key), f"{location} {status} requires {key}")
        ids.add(identifier)
        rustix_names.add(rustix_name)
        status_counts[status] += 1
    check_no_local_absolute_path(data)
    return {"entry_count": len(entries), "status_counts": status_counts}


def relative_source(path_text: str, *, owner: Path) -> Path:
    require(isinstance(path_text, str) and path_text, "inventory source path is empty")
    source = Path(path_text)
    require(not source.is_absolute(), f"inventory source must be relative: {path_text}")
    resolved = (owner.parent / source).resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError as error:
        raise HarnessError(f"inventory source escapes repository: {path_text}") from error
    require(resolved.is_file(), f"inventory source does not exist: {path_text}")
    return resolved


def symbol_names(path: Path) -> tuple[str, ...]:
    names: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise HarnessError(f"cannot read symbol inventory {path}: {error}") from error
    for line_number, line in enumerate(lines, 1):
        if not line:
            continue
        name = line.split("\t", 1)[0]
        require(name and "\t" in line, f"malformed symbol record {path}:{line_number}")
        names.append(name)
    require(len(names) == len(set(names)), f"duplicate symbol in {path}")
    return tuple(names)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_coverage(data: Mapping[str, Any]) -> dict[str, Any]:
    require(data.get("schema") == "crabc.crabc-rs-coverage/v1", "bad crabc-rs coverage schema")
    require(data.get("target") == TARGET, "coverage target is not AArch64 musl")
    dynamic = data.get("dynamic_exports")
    policy = data.get("policy")
    capabilities = data.get("capability")
    candidate_only_records = data.get("candidate_only")
    require(isinstance(dynamic, Mapping), "coverage.dynamic_exports must be a table")
    require(isinstance(policy, Mapping), "coverage.policy must be a table")
    require(isinstance(capabilities, list) and capabilities, "coverage.capability must contain entries")
    require(isinstance(candidate_only_records, list), "coverage.candidate_only must be a list")
    require(policy.get("production_dependency") is False, "coverage permits a production dependency")
    require(policy.get("public_c_abi_is_native_rust_coverage") is False, "C ABI must not count as native Rust coverage")
    reference_path = relative_source(str(dynamic.get("reference_source", "")), owner=COVERAGE_PATH)
    candidate_path = relative_source(str(dynamic.get("candidate_source", "")), owner=COVERAGE_PATH)
    reference = symbol_names(reference_path)
    candidate = symbol_names(candidate_path)
    embedded = dynamic.get("candidate_symbols")
    candidate_only = dynamic.get("candidate_only_symbols")
    require(isinstance(embedded, list), "coverage candidate_symbols must be an array")
    require(isinstance(candidate_only, list), "coverage candidate_only_symbols must be an array")
    require(tuple(embedded) == candidate, "embedded candidate symbols differ from candidate TSV")
    require(tuple(candidate_only) == EXPECTED_CANDIDATE_ONLY, "candidate-only symbol provenance changed")
    require(len(reference) == EXPECTED_REFERENCE_SYMBOLS, "reference symbol count changed")
    require(len(candidate) == EXPECTED_CANDIDATE_SYMBOLS, "candidate symbol count changed")
    require(len(candidate_only) == EXPECTED_CANDIDATE_ONLY_SYMBOLS, "candidate-only count changed")
    require(set(candidate) - set(candidate_only) == set(reference), "candidate/reference symbol sets differ")
    require(not set(reference) - set(candidate), "candidate is missing a pinned musl symbol")
    require(dynamic.get("reference_count") == EXPECTED_REFERENCE_SYMBOLS, "coverage reference_count changed")
    require(dynamic.get("candidate_count") == EXPECTED_CANDIDATE_SYMBOLS, "coverage candidate_count changed")
    require(dynamic.get("candidate_only_count") == EXPECTED_CANDIDATE_ONLY_SYMBOLS, "coverage candidate_only_count changed")
    require(dynamic.get("missing_from_candidate_count") == 0, "coverage missing symbol count changed")
    require(dynamic.get("metadata_mismatches_count") == 0, "coverage metadata mismatch count changed")
    require(dynamic.get("reference_is_candidate_minus_candidate_only") is True, "coverage set invariant missing")

    record_names: list[str] = []
    for index, record in enumerate(candidate_only_records):
        require(isinstance(record, Mapping), f"candidate_only[{index}] is not a table")
        for key in ("name", "classification", "status", "rationale"):
            require(record.get(key), f"candidate_only[{index}] is missing {key}")
        require(record["classification"] in ALLOWED_COVERAGE_CLASSIFICATIONS, f"unknown candidate-only classification: {record['classification']}")
        require(record["status"] == "inventory", f"candidate-only status is not inventory: {record['name']}")
        record_names.append(record["name"])
    require(tuple(record_names) == EXPECTED_CANDIDATE_ONLY, "candidate-only records do not match symbols")
    for index, capability in enumerate(capabilities):
        require(isinstance(capability, Mapping), f"capability[{index}] is not a table")
        require(capability.get("id"), f"capability[{index}] has no id")
        require(capability.get("classification") in ALLOWED_COVERAGE_CLASSIFICATIONS, f"unknown capability classification: {capability.get('classification')}")
        require(capability.get("status") == "inventory", f"capability[{index}] must remain inventory at M0")
        require(capability.get("rationale"), f"capability[{index}] has no rationale")
    check_no_local_absolute_path(data)
    return {
        "reference_count": len(reference),
        "candidate_count": len(candidate),
        "candidate_only_count": len(candidate_only),
        "missing_from_candidate_count": 0,
        "metadata_mismatches_count": 0,
        "reference_sha256": sha256_file(reference_path),
        "candidate_sha256": sha256_file(candidate_path),
        "unclassified_symbol_count": len(candidate),
    }


def validate_metadata() -> dict[str, Any]:
    upstream = validate_upstream(load_toml(UPSTREAM_PATH))
    api = validate_api(load_toml(API_PATH), upstream)
    coverage = validate_coverage(load_toml(COVERAGE_PATH))
    return {
        "schema": "crabc.rustix-harness/v1",
        "target": TARGET,
        "upstream": upstream,
        "api": api,
        "coverage": coverage,
        "production_dependencies": [],
        "direct_c_abi_errno_roundtrip": False,
        "representative_operation": "fs::openat",
        "representative_backend_boundary": "direct-crabc-core",
    }


@dataclasses.dataclass(frozen=True)
class ProcessResult:
    backend: str
    returncode: int
    stdout: bytes
    stderr: bytes

    def report(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "returncode": self.returncode,
            "stdout_bytes": len(self.stdout),
            "stdout_sha256": hashlib.sha256(self.stdout).hexdigest(),
            "stdout_hex": self.stdout.hex(),
            "stderr_bytes": len(self.stderr),
            "stderr_sha256": hashlib.sha256(self.stderr).hexdigest(),
            "stderr_hex": self.stderr.hex(),
        }


def substitute_command(command: Sequence[str], fixture: Path, workdir: Path) -> list[str]:
    substitutions = {"{fixture}": str(fixture), "{workdir}": str(workdir)}
    rendered: list[str] = []
    for token in command:
        value = str(token)
        for marker, replacement in substitutions.items():
            value = value.replace(marker, replacement)
        rendered.append(value)
    return rendered


def run_backend(
    backend: str,
    command: Sequence[str],
    fixture: Path,
    workdir: Path,
    timeout: float,
) -> ProcessResult:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
        "CRABC_RUSTIX_BACKEND": backend,
        "CRABC_RUSTIX_FIXTURE": str(fixture),
    }
    try:
        result = subprocess.run(
            substitute_command(command, fixture, workdir),
            cwd=workdir,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or b""
        stderr = error.stderr or b""
        return ProcessResult(backend, 124, stdout, stderr + b"\nHARNESS_TIMEOUT\n")
    except OSError as error:
        return ProcessResult(backend, 127, b"", f"HARNESS_EXEC_ERROR:{error.errno}\n".encode())
    return ProcessResult(backend, result.returncode, result.stdout, result.stderr)


def display_fixture(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError:
        return resolved.name


def compare_backends(
    fixture: Path,
    rustix_command: Sequence[str],
    crabc_command: Sequence[str],
    timeout: float,
) -> dict[str, Any]:
    require(timeout > 0, "timeout must be positive")
    fixture = fixture.resolve()
    require(fixture.is_file(), f"fixture does not exist: {fixture}")
    with tempfile.TemporaryDirectory(prefix="crabc-rustix-rustix-") as rustix_dir, tempfile.TemporaryDirectory(prefix="crabc-rustix-crabc-") as crabc_dir:
        rustix = run_backend("rustix", rustix_command, fixture, Path(rustix_dir), timeout)
        crabc = run_backend("crabc-rs", crabc_command, fixture, Path(crabc_dir), timeout)
    comparisons = {
        "returncode_match": rustix.returncode == crabc.returncode,
        "stdout_match": rustix.stdout == crabc.stdout,
        "stderr_match": rustix.stderr == crabc.stderr,
    }
    return {
        "schema": "crabc.rustix-dual-backend/v1",
        "target": TARGET,
        "fixture": display_fixture(fixture),
        "timeout_seconds": timeout,
        "isolated_working_directories": True,
        "passed": all(comparisons.values()),
        "comparisons": comparisons,
        "rustix": rustix.report(),
        "crabc_rs": crabc.report(),
    }


def write_report(path: Path, report: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check", "compare"), nargs="?", default="check")
    parser.add_argument("--check", action="store_true", help="validate all M0 metadata (default)")
    parser.add_argument("--fixture", type=Path, help="fixture path for compare mode")
    parser.add_argument("--rustix-command", help="Rustix fixture command as one shell-style string; use {fixture}/{workdir} markers")
    parser.add_argument("--crabc-command", help="crabc-rs fixture command as one shell-style string; use {fixture}/{workdir} markers")
    parser.add_argument("--timeout", type=float, default=10.0, help="per-backend timeout in seconds")
    parser.add_argument("--report", type=Path, help="optional JSON report destination")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.mode == "check" or args.check:
            report = validate_metadata()
        else:
            require(args.fixture is not None, "compare requires --fixture")
            require(args.rustix_command, "compare requires --rustix-command")
            require(args.crabc_command, "compare requires --crabc-command")
            validate_metadata()
            rustix_command = shlex.split(args.rustix_command)
            crabc_command = shlex.split(args.crabc_command)
            require(rustix_command, "--rustix-command is empty")
            require(crabc_command, "--crabc-command is empty")
            report = compare_backends(args.fixture, rustix_command, crabc_command, args.timeout)
        rendered = json.dumps(report, sort_keys=True, separators=(",", ":"))
        if args.report:
            write_report(args.report, report)
        print(rendered)
    except HarnessError as error:
        print(f"rustix harness: ERROR: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
