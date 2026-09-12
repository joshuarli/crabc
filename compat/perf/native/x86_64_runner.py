#!/usr/bin/env python3
"""Build and retain bounded native x86 Rust-facade benchmark evidence.

This companion deliberately does not use ``compat/perf/native/run.py``.  That
runner is frozen AArch64 infrastructure and creates its workspace beneath
``/tmp``.  This file owns an x86-only, stock-std Rustybench smoke/check path
whose mutable state stays below this checkout's ``.work/x86_64`` boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import selectors
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


SCHEMA = "crabc.perf.native-x86-rust-facade/v1"
PREPARE_SCHEMA = "crabc.perf.native-x86-rust-facade-prepare/v1"
PROFILE_SCHEMA = "crabc.perf.native-x86-rust-facade-profile/v1"
BACKENDS = ("crabc", "rustix")
SMOKE_GEOMETRY = (1, 2, 3)
NORMAL_GEOMETRY = (5, 100, 1000)
RAW_RECORD_KEYS = {
    "name",
    "median_ns",
    "alloc_count",
    "alloc_bytes",
    "max_alloc_count",
    "max_alloc_bytes",
    "sample_count",
    "iter_count",
    "process_resources",
}
RESOURCE_KEYS = {
    "status",
    "memory_status",
    "user_cpu_ns",
    "system_cpu_ns",
    "voluntary_context_switches",
    "involuntary_context_switches",
    "minor_page_faults",
    "major_page_faults",
    "rss_bytes",
    "pss_bytes",
}
NUMERIC_RESOURCE_KEYS = RESOURCE_KEYS - {"status", "memory_status"}

PINNED_IMAGE = "crabc-core-evidence@sha256:5990e55b88db10c7dc82bb57b8087be74282ddb0c50f1dc88f05cec63ce95b8d"
PINNED_TARGET = "x86_64-unknown-linux-musl"
EXPECTED_EXECUTION = {
    "architecture": "x86_64",
    "os": "linux",
    "target": PINNED_TARGET,
    "image": PINNED_IMAGE,
    "stock_std": "image-owned stock x86_64-unknown-linux-musl std measurement infrastructure",
}
EXPECTED_NORMAL_GEOMETRY = {
    "invocations_per_backend": 5,
    "sample_count": 100,
    "sample_size": 1000,
}
EXPECTED_SMOKE_GEOMETRY = {
    "invocations_per_backend": 1,
    "sample_count": 2,
    "sample_size": 3,
}
EXPECTED_ADMISSION = {
    "full_correctness_predecessor": "unavailable",
    "reason": "the fixed complete correctness predecessor reader is not implemented or wired",
}
EXPECTED_FIXTURE = {
    "frozen_source": "compat/perf/native/src/main.rs",
    "frozen_source_sha256": "75dcb476e4108c3eafd7634e68405eb68614d24b6453ef0976f5ee7e884b977f",
    "legacy_manifest": "compat/perf/native/Cargo.toml",
    "legacy_manifest_sha256": "f3dd9870af9e63e7779e60339c14a702b26976cc7059082a3eebf654cd96c947",
    "supplement": "compat/perf/native/x86_64_fixture.rs",
    "supplement_sha256": "9f86753af61eeb931de32f9a339ff6f6dbf485394e0e1466ff570d4a2457e600",
    "manifest_template": "compat/perf/native/x86_64_manifest.toml",
    "manifest_template_sha256": "3d9f4d7e23ada724f6c76296ceb22e4d2736ccf1fec4c2a46ce97d123f1b45b9",
    "lock_template": "compat/perf/native/x86_64_Cargo.lock",
    "lock_template_sha256": "63652897b36d1f399b745823e7a92612b957a8fe850ba7dfa9799ba16aed019b",
    "cargo_config": ".cargo/config.toml",
    "cargo_config_sha256": "169fc613f083a1866a64c4381a17b392e202e5aa77ede11ea21b4c740971bf94",
}
EXPECTED_RUSTYBENCH_INPUT = {
    "canonical_repository": "https://github.com/laputa-systems/rustybench",
    "cargo_repository": "https://github.com/joshuarli/rustybench",
    "revision": "de81e89e2eb2c05b820144412d82a260e7d28cdb",
    "subject": "Add resource and syscall benchmark diagnostics",
    "version": "0.1.0",
    "tree_paths_sha256": "d7f43d76a6df6237a9bc3c34379c1a9374776d503e6fdfaca00f68e3ca2ec379",
    "tree_entries_sha256": "f514c4fb4679ea84ba1f0cd38a79c850eec669cee5aa95b13e72cde398fd4c59",
    "cargo_toml_sha256": "32cdf522d29a13921912ed6faac69cd18282731d74bab072fd1fcc48ffe5fd08",
    "cargo_lock_sha256": "81aec1149c303b950352921a0b7282d92744e9d28e5a8902db70ad72cf1aead4",
    "resolution_sha256": "61b4055a6d98e0542e3daf878e0225915a6584b705c57d8540663f0b3a15708e",
}
EXPECTED_RUSTIX_INPUT = {
    "repository": "https://github.com/bytecodealliance/rustix",
    "version": "1.1.4",
    "revision": "cf67411d572468d5fc39e8ac8b4e649ae3e5e9ec",
    "tree_paths_sha256": "02e56f781155a9232d5683e0a6b4dd724fe3347c2ce682e5f0023a2f6c0ea486",
    "tree_entries_sha256": "bf0c7b8d6cb2ac811e86906edab2f413b0d546ede8fe26ac690a306283cc8aa3",
    "cargo_toml_sha256": "67431c95b50640b666781d6a80778c8e5472b3b61d0baa3868091a4f924343c6",
}
EXPECTED_DEPENDENCY_POLICY = {
    "rustybench_default_features": [],
    "forbidden_active_packages": ["quanta"],
    "active_crabc": [
        "bitflags@2.13.2", "crabc-core@0.3.0", "crabc-perf-native-x86@0.0.0", "crabc-rs@0.3.0",
        "itoa@1.0.18", "lexopt@0.3.2", "mini-internal@0.1.46", "miniserde@0.1.46",
        "proc-macro2@1.0.107", "quote@1.0.47", "regex-lite@0.1.9", "rustybench@0.1.0",
        "rustybench-macros@0.1.0", "syn@3.0.5", "unicode-ident@1.0.24", "zmij@1.0.23",
    ],
    "active_rustix": [
        "bitflags@2.13.2", "crabc-perf-native-x86@0.0.0", "errno@0.3.14", "itoa@1.0.18",
        "lexopt@0.3.2", "libc@0.2.189", "linux-raw-sys@0.12.1", "mini-internal@0.1.46",
        "miniserde@0.1.46", "proc-macro2@1.0.107", "quote@1.0.47", "regex-lite@0.1.9",
        "rustix@1.1.4", "rustybench@0.1.0", "rustybench-macros@0.1.0", "syn@3.0.5",
        "unicode-ident@1.0.24", "zmij@1.0.23",
    ],
}
PATH_DEPENDENCY_SOURCE_KINDS = {
    "crabc-perf-native-x86@0.0.0": "workspace",
    "crabc-rs@0.3.0": "crabc-rs",
    "crabc-core@0.3.0": "crabc-core",
    "rustix@1.1.4": "rustix",
    "rustybench@0.1.0": "rustybench",
    "rustybench-macros@0.1.0": "rustybench",
}
EXPECTED_ROWS = (
    {
        "id": "caller_buffer_readlinkat_raw",
        "benchmark": "native_x86::caller_buffer",
        "source": "supplement",
        "operation": "readlinkat_raw private fixed symlink into a caller-owned MaybeUninit buffer",
    },
    {
        "id": "absent_open_error",
        "benchmark": "native_x86::missing_error",
        "source": "supplement",
        "operation": "open private proven-absent path and require ENOENT",
    },
    {
        "id": "clock_gettime_monotonic",
        "benchmark": "native_x86::frozen::clock_gettime",
        "source": "frozen",
        "operation": "existing frozen CLOCK_MONOTONIC route",
    },
    {
        "id": "getpid",
        "benchmark": "native_x86::frozen::getpid",
        "source": "frozen",
        "operation": "existing frozen getpid route",
    },
    {
        "id": "open_close_dev_null",
        "benchmark": "native_x86::frozen::open_close",
        "source": "frozen",
        "operation": "existing frozen /dev/null open/close route",
    },
)
EXPECTED_CORRECTNESS_OUTPUT = """native_x86
├─ caller_buffer
├─ missing_error
╰─ frozen
   ├─ clock_gettime
   ├─ getpid
   ╰─ open_close

"""
SMOKE_BUILD_ENVIRONMENT_KEYS = {
    "PATH", "HOME", "LC_ALL", "LANG", "TZ", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN",
    "CARGO_HOME", "CARGO_TARGET_DIR", "TMPDIR", "CARGO_ENCODED_RUSTFLAGS", "CARGO_NET_OFFLINE",
}
CLIENT_ENVIRONMENT_KEYS = {"PATH", "HOME", "LC_ALL", "LANG", "TZ"}


class RunnerError(Exception):
    """A contract or retained-evidence failure."""


def repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise RunnerError(f"{label} must be an object")
    return value


def _require_exact_keys(value: object, keys: Iterable[str], label: str) -> Mapping[str, Any]:
    mapping = _require_mapping(value, label)
    expected = set(keys)
    actual = set(mapping)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise RunnerError(f"{label} keys differ; missing={missing!r} unexpected={unexpected!r}")
    return mapping


def _nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RunnerError(f"{label} must be a non-negative integer")
    return value


def _within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _absolute(path: Path | str) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _physical_existing(path: Path, label: str) -> Path:
    try:
        return path.resolve(strict=True)
    except FileNotFoundError as error:
        raise RunnerError(f"{label} is missing: {path}") from error
    except OSError as error:
        raise RunnerError(f"cannot resolve {label}: {path}: {error}") from error


def _work_boundary(root: Path) -> Path:
    root_physical = _physical_existing(root, "repository root")
    boundary = root_physical / ".work/x86_64"
    if not boundary.exists():
        boundary.mkdir(parents=True, exist_ok=True)
    if boundary.is_symlink() or not boundary.is_dir():
        raise RunnerError(f"x86 work boundary must be a real directory: {boundary}")
    return _physical_existing(boundary, "x86 work boundary")


def require_private_work_path(root: Path, path: Path | str) -> Path:
    """Resolve one existing-or-future path without allowing a scratch escape."""

    boundary = _work_boundary(root)
    candidate = _absolute(path)
    if not _within(candidate, boundary):
        raise RunnerError(f"work path must be below {boundary}: {candidate}")

    existing = candidate
    missing: list[str] = []
    while not os.path.lexists(existing):
        if existing == existing.parent:
            raise RunnerError(f"work path has no existing parent: {candidate}")
        missing.append(existing.name)
        existing = existing.parent
    physical_existing = _physical_existing(existing, "work path ancestor")
    if not _within(physical_existing, boundary):
        raise RunnerError(
            f"work path must remain physically below {boundary}: {candidate} -> {physical_existing}"
        )
    if existing.is_symlink():
        raise RunnerError(f"work path may not traverse a symlink: {existing}")
    result = physical_existing.joinpath(*reversed(missing))
    if not _within(result, boundary):
        raise RunnerError(f"work path must remain physically below {boundary}: {candidate}")
    return result


def _ensure_private_directory(root: Path, path: Path | str) -> Path:
    resolved = require_private_work_path(root, path)
    resolved.mkdir(parents=True, exist_ok=True)
    if resolved.is_symlink() or not resolved.is_dir():
        raise RunnerError(f"private work directory is not a real directory: {resolved}")
    return require_private_work_path(root, resolved)


def _work_relative(root: Path, path: Path) -> str:
    physical = require_private_work_path(root, path)
    return physical.relative_to(_physical_existing(root, "repository root")).as_posix()


def _work_path_from_record(root: Path, value: object, label: str) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise RunnerError(f"{label} must be a non-empty root-relative work path")
    return require_private_work_path(root, _physical_existing(root, "repository root") / value)


def _require_execution_path_for_logical(value: object, logical: str, label: str) -> None:
    """Bind an absolute Docker execution path to one retained work path."""

    if not isinstance(value, str) or not value.startswith("/") or not value.endswith(f"/{logical}"):
        raise RunnerError(f"{label} does not name its retained execution path")


def file_identity(path: Path) -> dict[str, Any]:
    try:
        item = path.lstat()
    except OSError as error:
        raise RunnerError(f"cannot stat file input {path}: {error}") from error
    if not stat.S_ISREG(item.st_mode):
        raise RunnerError(f"file input must be a regular file: {path}")
    return {
        "sha256": sha256_file(path),
        "size": item.st_size,
        "mode": stat.S_IMODE(item.st_mode),
    }


def verify_file_identity(path: Path, identity: object, label: str) -> None:
    expected = _require_exact_keys(identity, {"sha256", "size", "mode"}, f"{label} identity")
    actual = file_identity(path)
    if actual["sha256"] != expected["sha256"]:
        raise RunnerError(f"{label} sha256 differs")
    if actual["size"] != expected["size"] or actual["mode"] != expected["mode"]:
        raise RunnerError(f"{label} file metadata differs")


def tree_identity(path: Path) -> dict[str, Any]:
    """Hash a closed regular-file/symlink source tree without its Git metadata."""

    root = _physical_existing(path, "source tree")
    if root.is_symlink() or not root.is_dir():
        raise RunnerError(f"source tree must be a real directory: {path}")
    entries: list[dict[str, Any]] = []
    for current_text, directories, files in os.walk(root, topdown=True, followlinks=False):
        current = Path(current_text)
        directories[:] = sorted(directory for directory in directories if directory != ".git")
        for directory in directories:
            entry = current / directory
            item = entry.lstat()
            if entry.is_symlink() or not stat.S_ISDIR(item.st_mode):
                raise RunnerError(f"source tree contains an unsafe directory entry: {entry}")
            entries.append(
                {
                    "path": entry.relative_to(root).as_posix(),
                    "kind": "directory",
                    "mode": stat.S_IMODE(item.st_mode),
                }
            )
        for filename in sorted(files):
            entry = current / filename
            item = entry.lstat()
            relative = entry.relative_to(root).as_posix()
            if stat.S_ISREG(item.st_mode):
                entries.append(
                    {
                        "path": relative,
                        "kind": "file",
                        "mode": stat.S_IMODE(item.st_mode),
                        "sha256": sha256_file(entry),
                        "size": item.st_size,
                    }
                )
            elif stat.S_ISLNK(item.st_mode):
                target = os.fsencode(os.readlink(entry))
                entries.append(
                    {
                        "path": relative,
                        "kind": "symlink",
                        "mode": stat.S_IMODE(item.st_mode),
                        "target_sha256": _sha256_bytes(target),
                    }
                )
            else:
                raise RunnerError(f"source tree contains a non-file entry: {entry}")
    entries.sort(key=lambda entry: entry["path"])
    return {"entries": entries, "sha256": _sha256_bytes(_canonical_json(entries))}


def verify_tree_identity(path: Path, identity: object, label: str) -> None:
    expected = _require_exact_keys(identity, {"entries", "sha256"}, f"{label} identity")
    actual = tree_identity(path)
    if actual != expected:
        raise RunnerError(f"{label} tree identity differs")


def _write_new_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise RunnerError(f"cannot create retained file {path}: {error}") from error
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _atomic_write_json(root: Path, path: Path, value: Mapping[str, Any]) -> None:
    require_private_work_path(root, path.parent)
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
    finally:
        if temporary.exists():
            temporary.unlink()


def _load_json_file(path: Path, label: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RunnerError(f"{label} is not valid JSON: {path}: {error}") from error


def validate_profile_contract(value: object) -> dict[str, Any]:
    """Accept only the fixed x86 facade workload and provenance contract.

    The profile is intentionally a declarative copy of this runner's durable
    contract, not an open-ended configuration surface.  Checking the complete
    shape here prevents a locally edited profile from silently replacing a
    frozen route, image, source pin, normal geometry, or currently unavailable
    full-mode admission rule.
    """

    profile = _require_exact_keys(
        value,
        {
            "schema", "execution", "normal", "smoke", "admission", "fixture", "inputs",
            "dependency_policy", "rows",
        },
        "x86 native facade profile",
    )
    if profile["schema"] != PROFILE_SCHEMA:
        raise RunnerError("x86 native facade profile schema differs")
    if _require_exact_keys(profile["execution"], EXPECTED_EXECUTION, "profile execution") != EXPECTED_EXECUTION:
        raise RunnerError("profile image or native execution target differs")
    if _require_exact_keys(profile["normal"], EXPECTED_NORMAL_GEOMETRY, "normal profile") != EXPECTED_NORMAL_GEOMETRY:
        raise RunnerError("normal profile geometry differs from 5/100/1000")
    if _require_exact_keys(profile["smoke"], EXPECTED_SMOKE_GEOMETRY, "smoke profile") != EXPECTED_SMOKE_GEOMETRY:
        raise RunnerError("smoke profile geometry differs from the bounded 1/2/3 check")
    if _require_exact_keys(profile["admission"], EXPECTED_ADMISSION, "profile admission") != EXPECTED_ADMISSION:
        raise RunnerError("profile full-mode admission differs")
    if _require_exact_keys(profile["fixture"], EXPECTED_FIXTURE, "profile fixture") != EXPECTED_FIXTURE:
        raise RunnerError("profile fixture contract differs")
    inputs = _require_exact_keys(profile["inputs"], {"rustybench", "rustix"}, "profile inputs")
    if _require_exact_keys(inputs["rustybench"], EXPECTED_RUSTYBENCH_INPUT, "Rustybench profile input") != EXPECTED_RUSTYBENCH_INPUT:
        raise RunnerError("Rustybench profile input differs")
    if _require_exact_keys(inputs["rustix"], EXPECTED_RUSTIX_INPUT, "Rustix profile input") != EXPECTED_RUSTIX_INPUT:
        raise RunnerError("Rustix profile input differs")
    if (
        _require_exact_keys(
            profile["dependency_policy"], EXPECTED_DEPENDENCY_POLICY, "dependency policy"
        )
        != EXPECTED_DEPENDENCY_POLICY
    ):
        raise RunnerError("dependency policy differs")
    rows = profile["rows"]
    if not isinstance(rows, list) or len(rows) != len(EXPECTED_ROWS):
        raise RunnerError("profile row contract differs")
    for index, (row, expected) in enumerate(zip(rows, EXPECTED_ROWS, strict=True)):
        if _require_exact_keys(row, expected, f"profile row {index}") != expected:
            raise RunnerError("profile row contract differs")
    return dict(profile)


def load_profile(root: Path) -> dict[str, Any]:
    path = _physical_existing(root, "repository root") / "compat/perf/native/x86_64_profile.toml"
    try:
        profile = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise RunnerError(f"cannot read x86 native facade profile: {error}") from error
    return validate_profile_contract(profile)


def row_names(profile: Mapping[str, Any]) -> tuple[str, ...]:
    rows = profile["rows"]
    assert isinstance(rows, list)
    return tuple(str(_require_mapping(row, "profile row")["benchmark"]) for row in rows)


def validate_active_dependency_roster(
    profile: Mapping[str, Any], backend: str, records: Iterable[Mapping[str, Any]],
) -> None:
    """Bind Cargo's target-filtered resolved graph to the static lock roster."""

    if backend not in BACKENDS:
        raise RunnerError(f"unknown dependency backend: {backend}")
    policy = _require_mapping(profile.get("dependency_policy"), "dependency policy")
    expected = policy.get(f"active_{backend}")
    if not isinstance(expected, list) or not all(isinstance(value, str) for value in expected):
        raise RunnerError(f"{backend} expected dependency roster is malformed")
    expected_pairs: list[tuple[str, str]] = []
    for index, value in enumerate(expected):
        if value.count("@") != 1:
            raise RunnerError(f"{backend} expected dependency roster entry {index} is malformed")
        name, version = value.rsplit("@", 1)
        if not name or not version:
            raise RunnerError(f"{backend} expected dependency roster entry {index} is malformed")
        expected_pairs.append((name, version))
    observed: list[tuple[str, str]] = []
    for index, record in enumerate(records):
        parsed = _require_mapping(record, f"{backend} dependency record {index}")
        name = parsed.get("name")
        version = parsed.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise RunnerError(f"{backend} dependency record {index} lacks a name/version")
        observed.append((name, version))
    if (
        len(observed) != len(set(observed))
        or expected_pairs != sorted(expected_pairs)
        or observed != expected_pairs
    ):
        raise RunnerError(f"{backend} active dependency roster differs")


def validate_dependency_source_kinds(backend: str, records: Iterable[Mapping[str, Any]]) -> None:
    """Require each locked package to come from its one admitted source root."""

    if backend not in BACKENDS:
        raise RunnerError(f"unknown dependency backend: {backend}")
    for index, record in enumerate(records):
        parsed = _require_mapping(record, f"{backend} dependency record {index}")
        name = parsed.get("name")
        version = parsed.get("version")
        source_kind = parsed.get("source_kind")
        source = parsed.get("source")
        if not isinstance(name, str) or not isinstance(version, str) or not isinstance(source_kind, str):
            raise RunnerError(f"{backend} dependency record {index} lacks source identity")
        expected_kind = PATH_DEPENDENCY_SOURCE_KINDS.get(f"{name}@{version}", "cargo-registry")
        if source_kind != expected_kind:
            raise RunnerError(f"{backend} dependency {name}@{version} source root differs")
        if expected_kind == "cargo-registry":
            if not isinstance(source, str) or not source.startswith("registry+"):
                raise RunnerError(f"{backend} registry dependency {name}@{version} source differs")
        elif source is not None:
            raise RunnerError(f"{backend} path dependency {name}@{version} unexpectedly has a registry source")


def require_admitted_mode(mode: str) -> tuple[int, int, int]:
    """Admit only the implementation smoke until a fixed reader exists."""

    if mode == "smoke":
        return SMOKE_GEOMETRY
    if mode == "full":
        raise RunnerError(
            "full mode is unavailable because the fixed complete correctness predecessor reader is unavailable"
        )
    raise RunnerError(f"unknown native facade mode: {mode}")


def rustybench_invocation_argv(
    artifact: Path,
    *,
    kind: str,
    sample_count: int | None = None,
    sample_size: int | None = None,
) -> list[str]:
    """Construct a direct Rustybench argv with its action made explicit.

    Cargo normally adds ``--bench`` when it invokes a ``harness = false``
    benchmark executable.  The x86 runner deliberately executes the sealed
    artifact directly so that its raw stdout, stderr, PID, affinity proof, and
    ELF identity are one retained record.  Rustybench defaults a direct
    executable invocation to its test action, so the timed form must retain
    that otherwise implicit ``--bench`` selector.
    """

    if kind == "correctness":
        if sample_count is not None or sample_size is not None:
            raise RunnerError("Rustybench correctness invocation may not have timed geometry")
        return [str(artifact), "--test"]
    if kind != "reduced":
        raise RunnerError(f"unknown Rustybench invocation kind: {kind}")
    if sample_count is None or sample_size is None:
        raise RunnerError("reduced Rustybench invocation requires sample geometry")
    sample_count = _nonnegative_int(sample_count, "reduced Rustybench sample_count")
    sample_size = _nonnegative_int(sample_size, "reduced Rustybench sample_size")
    if sample_count <= 0 or sample_size <= 0:
        raise RunnerError("reduced Rustybench sample geometry must be positive")
    return [
        str(artifact), "--bench", "--format", "json", "--sample-count", str(sample_count),
        "--sample-size", str(sample_size),
    ]


def validate_correctness_stdout(text: str) -> None:
    """Require the fixed tool's complete test-action discovery tree.

    The raw timed JSON proves the metric roster.  This separate test-action
    result proves that the same sealed executable found precisely the two x86
    supplement rows plus the three byte-for-byte frozen nested rows.
    """

    if text != EXPECTED_CORRECTNESS_OUTPUT:
        raise RunnerError("Rustybench correctness discovery roster differs")


def validate_benchmark_report(
    raw: object,
    expected_rows: Sequence[str],
    *,
    sample_count: int,
    sample_size: int,
) -> dict[str, int]:
    """Validate Rustybench schema 1 without accepting missing resource data."""

    report = _require_exact_keys(raw, {"schema", "benchmarks"}, "Rustybench raw report")
    if report["schema"] != 1:
        raise RunnerError("Rustybench raw report schema differs from 1")
    benchmarks = report["benchmarks"]
    if not isinstance(benchmarks, list):
        raise RunnerError("Rustybench raw report benchmarks must be a list")
    if len(benchmarks) != len(expected_rows):
        raise RunnerError("Rustybench raw report row count differs")

    totals = {
        "row_count": len(expected_rows),
        "total_median_ns": 0,
        "total_alloc_count": 0,
        "total_alloc_bytes": 0,
        "total_max_alloc_count": 0,
        "total_max_alloc_bytes": 0,
        "total_user_cpu_ns": 0,
        "total_system_cpu_ns": 0,
        "total_voluntary_context_switches": 0,
        "total_involuntary_context_switches": 0,
        "total_minor_page_faults": 0,
        "total_major_page_faults": 0,
        "total_rss_bytes": 0,
        "total_pss_bytes": 0,
    }
    observed_names: list[str] = []
    expected_iterations = sample_count * sample_size
    for index, value in enumerate(benchmarks):
        record = _require_exact_keys(value, RAW_RECORD_KEYS, f"Rustybench row {index}")
        name = record["name"]
        if not isinstance(name, str):
            raise RunnerError(f"Rustybench row {index} name must be a string")
        observed_names.append(name)
        for key in ("median_ns", "alloc_count", "alloc_bytes", "max_alloc_count", "max_alloc_bytes"):
            number = _nonnegative_int(record[key], f"Rustybench row {name} {key}")
            if key == "median_ns":
                totals["total_median_ns"] += number
            elif key == "alloc_count":
                totals["total_alloc_count"] += number
            elif key == "alloc_bytes":
                totals["total_alloc_bytes"] += number
            elif key == "max_alloc_count":
                totals["total_max_alloc_count"] += number
            elif key == "max_alloc_bytes":
                totals["total_max_alloc_bytes"] += number
        if record["sample_count"] != sample_count:
            raise RunnerError(f"Rustybench row {name} sample_count differs")
        if record["iter_count"] != expected_iterations:
            raise RunnerError(f"Rustybench row {name} iter_count differs")
        resources = _require_exact_keys(record["process_resources"], RESOURCE_KEYS, f"Rustybench row {name} resources")
        if resources["status"] != "supported" or resources["memory_status"] != "supported":
            raise RunnerError(f"Rustybench row {name} resources must be supported")
        for key in NUMERIC_RESOURCE_KEYS:
            number = _nonnegative_int(resources[key], f"Rustybench row {name} {key}")
            if key == "user_cpu_ns":
                totals["total_user_cpu_ns"] += number
            elif key == "system_cpu_ns":
                totals["total_system_cpu_ns"] += number
            elif key == "voluntary_context_switches":
                totals["total_voluntary_context_switches"] += number
            elif key == "involuntary_context_switches":
                totals["total_involuntary_context_switches"] += number
            elif key == "minor_page_faults":
                totals["total_minor_page_faults"] += number
            elif key == "major_page_faults":
                totals["total_major_page_faults"] += number
            elif key == "rss_bytes":
                totals["total_rss_bytes"] += number
            elif key == "pss_bytes":
                totals["total_pss_bytes"] += number
    if tuple(observed_names) != tuple(expected_rows):
        if len(set(observed_names)) != len(observed_names):
            raise RunnerError("Rustybench raw report contains a duplicate row")
        raise RunnerError("Rustybench raw report roster is missing, reordered, or unexpected")
    return totals


def _git_stdout(path: Path, arguments: Sequence[str], label: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise RunnerError(f"cannot inspect pinned {label} Git input: {detail}")
    return result.stdout.decode("utf-8", errors="strict")


def _git_hash_stdout(path: Path, arguments: Sequence[str], label: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise RunnerError(f"cannot inspect pinned {label} Git input: {detail}")
    return _sha256_bytes(result.stdout)


def _require_profile_file(path: Path, expected_sha256: object, label: str) -> dict[str, Any]:
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
        raise RunnerError(f"profile lacks a valid {label} sha256")
    identity = file_identity(path)
    if identity["sha256"] != expected_sha256:
        raise RunnerError(f"{label} differs from the profile pin")
    return identity


def _pinned_git_source(path: Path, profile_input: Mapping[str, Any], name: str) -> dict[str, Any]:
    source = _physical_existing(path, f"{name} source")
    if source.is_symlink() or not source.is_dir():
        raise RunnerError(f"{name} source must be a real directory: {path}")
    revision = _git_stdout(source, ["rev-parse", "HEAD"], name).strip()
    if revision != profile_input.get("revision"):
        raise RunnerError(f"{name} revision differs from the profile pin")
    dirty = _git_stdout(source, ["status", "--porcelain", "--untracked-files=all"], name)
    if dirty:
        raise RunnerError(f"{name} source is not clean")
    paths_sha256 = _git_hash_stdout(source, ["ls-tree", "-r", "--name-only", "HEAD"], name)
    entries_sha256 = _git_hash_stdout(source, ["ls-tree", "-r", "HEAD"], name)
    if paths_sha256 != profile_input.get("tree_paths_sha256"):
        raise RunnerError(f"{name} tree path identity differs from the profile pin")
    if entries_sha256 != profile_input.get("tree_entries_sha256"):
        raise RunnerError(f"{name} tree entry identity differs from the profile pin")
    cargo_toml = _require_profile_file(source / "Cargo.toml", profile_input.get("cargo_toml_sha256"), f"{name} Cargo.toml")
    try:
        cargo = tomllib.loads((source / "Cargo.toml").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise RunnerError(f"cannot parse {name} Cargo.toml: {error}") from error
    package = _require_mapping(cargo.get("package"), f"{name} package")
    if package.get("version") != profile_input.get("version"):
        raise RunnerError(f"{name} package version differs from the profile pin")
    expected_repository = profile_input.get("cargo_repository", profile_input.get("repository"))
    if package.get("repository") != expected_repository:
        raise RunnerError(f"{name} Cargo repository spelling differs from the profile pin")
    files: dict[str, Any] = {"Cargo.toml": cargo_toml}
    optional_files = {
        "Cargo.lock": profile_input.get("cargo_lock_sha256"),
        "RESOLUTION.md": profile_input.get("resolution_sha256"),
    }
    for filename, expected_sha256 in optional_files.items():
        if expected_sha256 is not None:
            files[filename] = _require_profile_file(source / filename, expected_sha256, f"{name} {filename}")
    return {
        "revision": revision,
        "tree_paths_sha256": paths_sha256,
        "tree_entries_sha256": entries_sha256,
        "tree": tree_identity(source),
        "files": files,
        "package": {
            "name": package.get("name"),
            "version": package.get("version"),
            "repository": package.get("repository"),
        },
    }


def _profile_file(root: Path, profile: Mapping[str, Any], key: str) -> Path:
    fixture = _require_mapping(profile.get("fixture"), "profile fixture")
    value = fixture.get(key)
    if not isinstance(value, str) or not value:
        raise RunnerError(f"profile fixture {key} must name one source file")
    path = _physical_existing(_physical_existing(root, "repository root") / value, f"profile fixture {key}")
    if not _within(path, _physical_existing(root, "repository root")):
        raise RunnerError(f"profile fixture {key} escapes the repository")
    return path


def capture_source_state(
    root: Path,
    profile: Mapping[str, Any],
    rustybench_source: Path,
    rustix_source: Path,
) -> dict[str, Any]:
    """Bind every local source input before and after the bounded execution."""

    fixture = _require_mapping(profile.get("fixture"), "profile fixture")
    inputs = _require_mapping(profile.get("inputs"), "profile inputs")
    root_physical = _physical_existing(root, "repository root")
    frozen = _profile_file(root_physical, profile, "frozen_source")
    legacy_manifest = _profile_file(root_physical, profile, "legacy_manifest")
    supplement = _profile_file(root_physical, profile, "supplement")
    manifest_template = _profile_file(root_physical, profile, "manifest_template")
    lock_template = _profile_file(root_physical, profile, "lock_template")
    cargo_config = _profile_file(root_physical, profile, "cargo_config")
    profile_path = root_physical / "compat/perf/native/x86_64_profile.toml"
    runner_path = root_physical / "compat/perf/native/x86_64_runner.py"
    frozen_identity = _require_profile_file(
        frozen, fixture.get("frozen_source_sha256"), "frozen native facade source"
    )
    legacy_identity = _require_profile_file(
        legacy_manifest, fixture.get("legacy_manifest_sha256"), "legacy native facade manifest"
    )
    supplement_identity = _require_profile_file(
        supplement, fixture.get("supplement_sha256"), "x86 facade supplement"
    )
    manifest_identity = _require_profile_file(
        manifest_template, fixture.get("manifest_template_sha256"), "x86 facade manifest template"
    )
    lock_identity = _require_profile_file(
        lock_template, fixture.get("lock_template_sha256"), "x86 facade Cargo.lock template"
    )
    cargo_config_identity = _require_profile_file(
        cargo_config, fixture.get("cargo_config_sha256"), "repository Cargo configuration"
    )
    return {
        "profile": file_identity(profile_path),
        "runner": file_identity(runner_path),
        "frozen_source": frozen_identity,
        "legacy_manifest": legacy_identity,
        "supplement": supplement_identity,
        "manifest_template": manifest_identity,
        "lock_template": lock_identity,
        "cargo_config": cargo_config_identity,
        "crabc_rs": tree_identity(root_physical / "crabc-rs"),
        "crabc_core": tree_identity(root_physical / "crabc-core"),
        "rustybench": _pinned_git_source(
            rustybench_source, _require_mapping(inputs.get("rustybench"), "Rustybench profile input"), "Rustybench"
        ),
        "rustix": _pinned_git_source(
            rustix_source, _require_mapping(inputs.get("rustix"), "Rustix profile input"), "Rustix"
        ),
    }


def _require_same(actual: object, expected: object, label: str) -> None:
    if actual != expected:
        raise RunnerError(f"{label} differs")


def _replace_once(template: str, marker: str, replacement: str, label: str) -> str:
    if template.count(marker) != 1:
        raise RunnerError(f"{label} must contain exactly one {marker!r} marker")
    return template.replace(marker, replacement)


def _rust_string(path: Path) -> str:
    # JSON's string grammar is a valid Rust ordinary-string literal for these
    # absolute Linux paths, and it rejects control bytes rather than smuggling
    # source syntax through the renderer.
    return json.dumps(str(path), ensure_ascii=True)


def _prepare_fixture(workspace: Path) -> dict[str, Any]:
    fixture = workspace / "fixture"
    fixture.mkdir(mode=0o700)
    _write_new_bytes(fixture / "fixed-target", b"fixed target fixture\n")
    link = fixture / "fixed-link"
    os.symlink("fixed-target", link)
    absent = fixture / "proven-absent"
    if os.path.lexists(absent):
        raise RunnerError(f"private absent fixture path unexpectedly exists: {absent}")
    link_mode = link.lstat().st_mode
    if not stat.S_ISLNK(link_mode) or os.readlink(link) != "fixed-target":
        raise RunnerError("private caller-buffer fixture symlink differs")
    return {
        "directory": fixture,
        "target": file_identity(fixture / "fixed-target"),
        "link_target": "fixed-target",
        "link_target_sha256": _sha256_bytes(b"fixed-target"),
        "absent_name": "proven-absent",
    }


def _render_workspace(
    root: Path,
    profile: Mapping[str, Any],
    invocation: Path,
    rustybench_source: Path,
    rustix_source: Path,
) -> tuple[Path, dict[str, Any]]:
    workspace = invocation / "workspace"
    source_directory = workspace / "src"
    workspace.mkdir(mode=0o700)
    source_directory.mkdir(mode=0o700)
    root_physical = _physical_existing(root, "repository root")
    manifest_template = _profile_file(root_physical, profile, "manifest_template")
    lock_template = _profile_file(root_physical, profile, "lock_template")
    supplement_template = _profile_file(root_physical, profile, "supplement")
    frozen_source = _profile_file(root_physical, profile, "frozen_source")
    manifest = manifest_template.read_text(encoding="utf-8")
    manifest = _replace_once(manifest, "@RUSTYBENCH_SOURCE@", str(rustybench_source), "x86 manifest")
    manifest = _replace_once(manifest, "@CRABC_RS_SOURCE@", str(root_physical / "crabc-rs"), "x86 manifest")
    manifest = _replace_once(manifest, "@RUSTIX_SOURCE@", str(rustix_source), "x86 manifest")
    manifest = _replace_once(manifest, "@FIXTURE_SOURCE@", str(source_directory / "main.rs"), "x86 manifest")
    source = supplement_template.read_text(encoding="utf-8")
    source = _replace_once(
        source,
        '"@CRABC_NATIVE_FROZEN_SOURCE@"',
        _rust_string(frozen_source),
        "x86 fixture supplement",
    )
    _write_new_bytes(workspace / "Cargo.toml", manifest.encode("utf-8"))
    _write_new_bytes(workspace / "Cargo.lock", lock_template.read_bytes())
    _write_new_bytes(source_directory / "main.rs", source.encode("utf-8"))
    fixture = _prepare_fixture(workspace)
    return workspace, {
        "manifest": file_identity(workspace / "Cargo.toml"),
        "lock": file_identity(workspace / "Cargo.lock"),
        "source": file_identity(source_directory / "main.rs"),
        "fixture_target": fixture["target"],
        "fixture_link_target": fixture["link_target"],
        "fixture_link_target_sha256": fixture["link_target_sha256"],
        "fixture_absent_name": fixture["absent_name"],
    }


def _clean_environments(
    invocation: Path, cargo_home: Path, *, offline: bool
) -> tuple[dict[str, str], dict[str, str], dict[str, Any]]:
    """Create explicit build/client environments instead of inheriting knobs."""

    path = os.environ.get("PATH")
    rustup_home = os.environ.get("RUSTUP_HOME")
    if not path or not rustup_home:
        raise RunnerError("pinned Rust toolchain PATH and RUSTUP_HOME must be available")
    target = invocation / "target"
    temporary = invocation / "tmp"
    home = invocation / "home"
    for directory in (cargo_home, target, temporary, home):
        directory.mkdir(mode=0o700, exist_ok=True)
        if directory.is_symlink() or not directory.is_dir():
            raise RunnerError(f"private environment directory is unsafe: {directory}")
    build = {
        "PATH": path,
        "HOME": str(home),
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
        "RUSTUP_HOME": rustup_home,
        "RUSTUP_TOOLCHAIN": "nightly-2026-07-24",
        "CARGO_HOME": str(cargo_home),
        "CARGO_TARGET_DIR": str(target),
        "TMPDIR": str(temporary),
        # This overrides the repository ancestor's link-dead-code config;
        # the rendered benchmark profile supplies the intended codegen flags.
        "CARGO_ENCODED_RUSTFLAGS": "",
    }
    if offline:
        build["CARGO_NET_OFFLINE"] = "true"
    client = {
        "PATH": path,
        "HOME": str(home),
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
    }
    scrubbed = sorted(
        key for key in os.environ
        if key in {
            "RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
            "RUSTC_BOOTSTRAP", "CARGO_BUILD_TARGET", "CARGO_BUILD_RUSTFLAGS",
            "CARGO_INCREMENTAL", "CARGO_PROFILE_BENCH_OPT_LEVEL", "CARGO_PROFILE_BENCH_LTO",
            "CARGO_PROFILE_BENCH_CODEGEN_UNITS", "CARGO_ENCODED_RUSTFLAGS",
        }
        or key.startswith("RUSTYBENCH_")
        or key.startswith("LD_")
    )
    record = {
        "build": build,
        "client": client,
        "scrubbed_ambient_keys": scrubbed,
    }
    return build, client, record


def _parse_status(raw: bytes, expected_pid: int, expected_cpu: int, label: str) -> None:
    fields: dict[str, str] = {}
    for line in raw.decode("utf-8", errors="replace").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            fields[key] = value.strip()
    if fields.get("Pid") != str(expected_pid):
        raise RunnerError(f"{label} raw status Pid differs")
    cpu_list = fields.get("Cpus_allowed_list")
    if cpu_list != str(expected_cpu):
        raise RunnerError(f"{label} raw status affinity differs")


def _read_affinity_proof(descriptor: int, timeout_seconds: float, label: str) -> bytes:
    selector = selectors.DefaultSelector()
    selector.register(descriptor, selectors.EVENT_READ)
    chunks: list[bytes] = []
    deadline = time.monotonic() + timeout_seconds
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RunnerError(f"{label} did not publish affinity proof before its deadline")
            ready = selector.select(remaining)
            if not ready:
                raise RunnerError(f"{label} did not publish affinity proof before its deadline")
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
            if sum(len(item) for item in chunks) > 128 * 1024:
                raise RunnerError(f"{label} affinity proof is unexpectedly large")
    finally:
        selector.close()
        os.close(descriptor)
    raw = b"".join(chunks)
    if not raw:
        raise RunnerError(f"{label} did not publish an affinity proof")
    return raw


def _run_retained_command(
    invocation: Path,
    *,
    stage: str,
    argv: Sequence[str],
    cwd: Path,
    environment: Mapping[str, str],
    cpu: int,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Run one bounded child with an in-child affinity proof and raw logs."""

    logs = invocation / "logs"
    logs.mkdir(mode=0o700, exist_ok=True)
    stdout_path = logs / f"{stage}.stdout"
    stderr_path = logs / f"{stage}.stderr"
    status_path = logs / f"{stage}.status"
    if any(path.exists() or os.path.lexists(path) for path in (stdout_path, stderr_path, status_path)):
        raise RunnerError(f"retained command log name is already occupied: {stage}")
    read_fd, write_fd = os.pipe()
    os.set_inheritable(write_fd, True)

    def configure_child() -> None:
        os.sched_setaffinity(0, {cpu})
        raw = Path("/proc/self/status").read_bytes()
        os.write(write_fd, raw)
        os.close(write_fd)

    started = time.monotonic_ns()
    try:
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            process = subprocess.Popen(
                list(argv),
                cwd=cwd,
                env=dict(environment),
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                close_fds=True,
                pass_fds=(write_fd,),
                preexec_fn=configure_child,
                start_new_session=True,
            )
    except OSError as error:
        os.close(read_fd)
        os.close(write_fd)
        raise RunnerError(f"cannot start {stage}: {error}") from error
    finally:
        try:
            os.close(write_fd)
        except OSError:
            pass
    try:
        status_raw = _read_affinity_proof(read_fd, min(timeout_seconds, 5.0), stage)
        _parse_status(status_raw, process.pid, cpu, stage)
        _write_new_bytes(status_path, status_raw)
        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as error:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            raise RunnerError(f"{stage} exceeded its {timeout_seconds:g}s deadline") from error
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
    elapsed_wall_ns = time.monotonic_ns() - started
    return {
        "argv": list(argv),
        "cwd": str(cwd),
        "returncode": returncode,
        "child_pid": process.pid,
        "elapsed_wall_ns": elapsed_wall_ns,
        "stdout": file_identity(stdout_path),
        "stderr": file_identity(stderr_path),
        "status": file_identity(status_path),
        "stdout_path": stdout_path,
        "stderr_path": stderr_path,
        "status_path": status_path,
    }


def _tool_path(name: str, environment: Mapping[str, str]) -> Path:
    value = shutil.which(name, path=environment.get("PATH"))
    if value is None:
        raise RunnerError(f"required pinned tool is unavailable: {name}")
    return _physical_existing(Path(value), f"pinned tool {name}")


def _capture_tool_versions(
    invocation: Path,
    environment: Mapping[str, str],
    cpu: int,
) -> dict[str, Any]:
    tools: dict[str, Any] = {}
    for name, arguments in (("rustc", ["-Vv"]), ("cargo", ["-V"]), ("rustup", ["target", "list", "--installed"])):
        path = _tool_path(name, environment)
        command = _run_retained_command(
            invocation,
            stage=f"tool-{name}",
            argv=[name, *arguments],
            cwd=invocation,
            environment=environment,
            cpu=cpu,
            timeout_seconds=20,
        )
        if command["returncode"] != 0:
            raise RunnerError(f"pinned {name} version command failed")
        tools[name] = {
            "path": str(path),
            "file": file_identity(path),
            "command": command,
        }
    rustc_text = Path(tools["rustc"]["command"]["stdout_path"]).read_text(encoding="utf-8")
    required_rustc = {
        "release": "1.99.0-nightly",
        "commit-hash": "89c61a7545da48b06116675b888398d02a4064c7",
        "host": "x86_64-unknown-linux-musl",
    }
    observed_rustc = dict(
        line.split(": ", 1) for line in rustc_text.splitlines() if ": " in line
    )
    for key, expected in required_rustc.items():
        if observed_rustc.get(key) != expected:
            raise RunnerError(f"pinned rustc {key} differs")
    cargo_text = Path(tools["cargo"]["command"]["stdout_path"]).read_text(encoding="utf-8").strip()
    if cargo_text != "cargo 1.99.0-nightly (3efb1f477 2026-07-17)":
        raise RunnerError("pinned cargo identity differs")
    installed_targets = Path(tools["rustup"]["command"]["stdout_path"]).read_text(encoding="utf-8").splitlines()
    if installed_targets != ["x86_64-unknown-linux-musl"]:
        raise RunnerError("pinned Rust target roster differs")
    return tools


def _cpu_diagnostics(invocation: Path, cpu: int, allowed_affinity: Sequence[int]) -> dict[str, Any]:
    logs = invocation / "logs"
    cpuinfo = Path("/proc/cpuinfo").read_bytes()
    cpuinfo_path = logs / "host-cpuinfo.raw"
    _write_new_bytes(cpuinfo_path, cpuinfo)
    frequency = Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_cur_freq")
    frequency_record: dict[str, Any]
    if frequency.is_file():
        raw = frequency.read_bytes()
        frequency_path = logs / "host-cpu-frequency.raw"
        _write_new_bytes(frequency_path, raw)
        frequency_record = {
            "status": "available",
            "path": str(frequency),
            "raw": file_identity(frequency_path),
            "raw_path": frequency_path,
        }
    else:
        frequency_record = {"status": "unavailable"}
    return {
        "client_cpu": cpu,
        "allowed_affinity": list(allowed_affinity),
        "cpuinfo": file_identity(cpuinfo_path),
        "cpuinfo_path": cpuinfo_path,
        # Frequency is intentionally retained but not equality-compared during
        # host replay; it is a volatile diagnostic rather than an input pin.
        "frequency": frequency_record,
    }


def _identity_at(root: Path, path: Path, identity: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {"path": _work_relative(root, path), **(dict(identity) if identity is not None else file_identity(path))}


def _command_record(root: Path, command: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "argv": list(command["argv"]),
        "cwd": _work_relative(root, Path(str(command["cwd"]))),
        "returncode": command["returncode"],
        "child_pid": command["child_pid"],
        "elapsed_wall_ns": command["elapsed_wall_ns"],
        "stdout": _identity_at(root, Path(command["stdout_path"]), command["stdout"]),
        "stderr": _identity_at(root, Path(command["stderr_path"]), command["stderr"]),
        "status": _identity_at(root, Path(command["status_path"]), command["status"]),
    }


def _cargo_artifact(command: Mapping[str, Any], invocation: Path, backend: str) -> Path:
    stdout = Path(command["stdout_path"]).read_text(encoding="utf-8")
    messages: list[Mapping[str, Any]] = []
    for line in stdout.splitlines():
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as error:
            raise RunnerError(f"Cargo {backend} build emitted non-JSON stdout") from error
        messages.append(_require_mapping(parsed, f"Cargo {backend} message"))
    candidates: list[Path] = []
    for message in messages:
        if message.get("reason") != "compiler-artifact":
            continue
        target = message.get("target")
        if not isinstance(target, dict) or target.get("name") != "native_x86":
            continue
        executable = message.get("executable")
        if isinstance(executable, str):
            candidates.append(Path(executable))
    if len(candidates) != 1:
        raise RunnerError(f"Cargo {backend} build must report exactly one native_x86 executable")
    artifact = _physical_existing(candidates[0], f"Cargo {backend} executable")
    target_root = _physical_existing(invocation / "target", "native facade target directory")
    if not _within(artifact, target_root) or not artifact.is_file() or not os.access(artifact, os.X_OK):
        raise RunnerError(f"Cargo {backend} executable escapes its private target directory")
    return artifact


def _lock_registry_checksums(lock_path: Path, metadata: Mapping[str, Any], backend: str) -> None:
    try:
        lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise RunnerError(f"cannot parse rendered Cargo.lock: {error}") from error
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise RunnerError("rendered Cargo.lock lacks package records")
    checksums: dict[tuple[str, str], object] = {}
    for package in packages:
        if isinstance(package, dict) and isinstance(package.get("name"), str) and isinstance(package.get("version"), str):
            checksums[(package["name"], package["version"])] = package.get("checksum")
    metadata_packages = metadata.get("packages")
    if not isinstance(metadata_packages, list):
        raise RunnerError(f"Cargo {backend} metadata lacks packages")
    for package in metadata_packages:
        parsed = _require_mapping(package, f"Cargo {backend} metadata package")
        source = parsed.get("source")
        if isinstance(source, str) and source.startswith("registry+"):
            checksum = checksums.get((parsed.get("name"), parsed.get("version")))
            if not isinstance(checksum, str) or len(checksum) != 64:
                raise RunnerError(f"Cargo {backend} registry package lacks a lock checksum")


def _classify_dependency_path(
    package_root: Path,
    *,
    workspace: Path,
    root: Path,
    rustybench_source: Path,
    rustix_source: Path,
    cargo_home: Path,
) -> tuple[str, str]:
    choices = (
        ("workspace", workspace),
        ("rustybench", rustybench_source),
        ("rustix", rustix_source),
        ("crabc-rs", _physical_existing(root, "repository root") / "crabc-rs"),
        ("crabc-core", _physical_existing(root, "repository root") / "crabc-core"),
        ("cargo-registry", cargo_home / "registry/src"),
    )
    physical = _physical_existing(package_root, "Cargo package source")
    for kind, base in choices:
        if not base.exists():
            continue
        physical_base = _physical_existing(base, f"{kind} source base")
        if _within(physical, physical_base):
            return kind, physical.relative_to(physical_base).as_posix()
    raise RunnerError(f"Cargo package source is outside the admitted source roots: {package_root}")


def _capture_dependency_graph(
    root: Path,
    profile: Mapping[str, Any],
    *,
    invocation: Path,
    workspace: Path,
    cargo_home: Path,
    rustybench_source: Path,
    rustix_source: Path,
    backend: str,
    command: Mapping[str, Any],
) -> dict[str, Any]:
    metadata_path = Path(command["stdout_path"])
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RunnerError(f"Cargo {backend} metadata is malformed: {error}") from error
    metadata_mapping = _require_mapping(metadata, f"Cargo {backend} metadata")
    _lock_registry_checksums(workspace / "Cargo.lock", metadata_mapping, backend)
    packages = metadata_mapping.get("packages")
    resolve = _require_mapping(metadata_mapping.get("resolve"), f"Cargo {backend} resolve")
    nodes = resolve.get("nodes")
    if not isinstance(packages, list) or not isinstance(nodes, list):
        raise RunnerError(f"Cargo {backend} metadata has no resolved package roster")
    package_by_id: dict[str, Mapping[str, Any]] = {}
    for package in packages:
        parsed = _require_mapping(package, f"Cargo {backend} package")
        package_id = parsed.get("id")
        if not isinstance(package_id, str):
            raise RunnerError(f"Cargo {backend} package lacks an id")
        package_by_id[package_id] = parsed
    active_ids: list[str] = []
    policy = _require_mapping(profile.get("dependency_policy"), "dependency policy")
    forbidden = policy.get("forbidden_active_packages")
    if not isinstance(forbidden, list) or not all(isinstance(value, str) for value in forbidden):
        raise RunnerError("dependency policy must list forbidden package names")
    for node in nodes:
        parsed = _require_mapping(node, f"Cargo {backend} resolve node")
        package_id = parsed.get("id")
        if not isinstance(package_id, str) or package_id not in package_by_id:
            raise RunnerError(f"Cargo {backend} resolve node has an unknown package")
        package = package_by_id[package_id]
        if package.get("name") in forbidden:
            raise RunnerError(f"Cargo {backend} selected forbidden package {package.get('name')!r}")
        if package.get("name") == "rustybench" and "quanta-timer" in parsed.get("features", []):
            raise RunnerError("Cargo selected Rustybench's forbidden quanta-timer feature")
        active_ids.append(package_id)
    if len(active_ids) != len(set(active_ids)):
        raise RunnerError(f"Cargo {backend} resolve roster has duplicate package ids")
    required_names = {"rustybench", "rustybench-macros", "regex-lite", "lexopt", "miniserde"}
    active_names = {str(package_by_id[package_id].get("name")) for package_id in active_ids}
    if not required_names <= active_names:
        raise RunnerError(f"Cargo {backend} omits a normal Rustybench dependency")
    records: list[dict[str, Any]] = []
    for package_id in sorted(active_ids):
        package = package_by_id[package_id]
        manifest_text = package.get("manifest_path")
        if not isinstance(manifest_text, str):
            raise RunnerError(f"Cargo {backend} package has no manifest path")
        package_root = _physical_existing(Path(manifest_text).parent, f"Cargo {backend} package root")
        source_kind, relative = _classify_dependency_path(
            package_root,
            workspace=workspace,
            root=root,
            rustybench_source=rustybench_source,
            rustix_source=rustix_source,
            cargo_home=cargo_home,
        )
        records.append(
            {
                "id": package_id,
                "name": package.get("name"),
                "version": package.get("version"),
                "source": package.get("source"),
                "source_kind": source_kind,
                "relative": relative,
                "tree": tree_identity(package_root),
            }
        )
    records.sort(key=lambda record: (str(record["name"]), str(record["version"])))
    validate_active_dependency_roster(profile, backend, records)
    validate_dependency_source_kinds(backend, records)
    return {
        "metadata": file_identity(metadata_path),
        "metadata_path": metadata_path,
        "packages": records,
    }


def _validate_elf_text(value: str, backend: str) -> None:
    required = (
        "Class:                             ELF64",
        "Data:                              2's complement, little endian",
        "Type:                              DYN (Position-Independent Executable file)",
        "Machine:                           Advanced Micro Devices X86-64",
    )
    if any(item not in value for item in required):
        raise RunnerError(f"{backend} benchmark ELF header differs from stock x86 static-PIE expectations")
    if "(NEEDED)" in value or "INTERP" in value:
        raise RunnerError(f"{backend} benchmark ELF unexpectedly has a dynamic runtime dependency")


def _capture_elf(
    invocation: Path,
    *,
    artifact: Path,
    client_environment: Mapping[str, str],
    cpu: int,
    backend: str,
) -> dict[str, Any]:
    command = _run_retained_command(
        invocation,
        stage=f"elf-{backend}",
        argv=["readelf", "-h", "-l", "-d", str(artifact)],
        cwd=artifact.parent,
        environment=client_environment,
        cpu=cpu,
        timeout_seconds=20,
    )
    if command["returncode"] != 0:
        raise RunnerError(f"readelf failed for {backend} benchmark artifact")
    _validate_elf_text(Path(command["stdout_path"]).read_text(encoding="utf-8"), backend)
    return {"file": file_identity(artifact), "readelf": command}


def _run_backend(
    root: Path,
    profile: Mapping[str, Any],
    *,
    invocation: Path,
    workspace: Path,
    cargo_home: Path,
    rustybench_source: Path,
    rustix_source: Path,
    backend: str,
    cpu: int,
    build_environment: Mapping[str, str],
    client_environment: Mapping[str, str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    target = str(_require_mapping(profile.get("execution"), "profile execution")["target"])
    build_command = _run_retained_command(
        invocation,
        stage=f"build-{backend}",
        argv=[
            "cargo", "bench", "--manifest-path", str(workspace / "Cargo.toml"),
            "--bench", "native_x86", "--target", target, "--no-default-features",
            "--features", backend, "--no-run", "--locked", "--offline", "--message-format=json",
        ],
        cwd=workspace,
        environment=build_environment,
        cpu=cpu,
        timeout_seconds=240,
    )
    if build_command["returncode"] != 0:
        raise RunnerError(f"Cargo {backend} build failed; inspect {build_command['stderr_path']}")
    if any(argument.startswith("-Z") or "build-std" in argument for argument in build_command["argv"]):
        raise RunnerError("stock-std build command unexpectedly selected a build-std route")
    artifact = _cargo_artifact(build_command, invocation, backend)
    elf = _capture_elf(
        invocation,
        artifact=artifact,
        client_environment=client_environment,
        cpu=cpu,
        backend=backend,
    )
    metadata_command = _run_retained_command(
        invocation,
        stage=f"metadata-{backend}",
        argv=[
            "cargo", "metadata", "--manifest-path", str(workspace / "Cargo.toml"),
            "--format-version=1", "--locked", "--offline", "--no-default-features",
            "--features", backend, "--filter-platform", target,
        ],
        cwd=workspace,
        environment=build_environment,
        cpu=cpu,
        timeout_seconds=60,
    )
    if metadata_command["returncode"] != 0:
        raise RunnerError(f"Cargo {backend} metadata failed")
    graph = _capture_dependency_graph(
        root,
        profile,
        invocation=invocation,
        workspace=workspace,
        cargo_home=cargo_home,
        rustybench_source=rustybench_source,
        rustix_source=rustix_source,
        backend=backend,
        command=metadata_command,
    )
    correctness = _run_retained_command(
        invocation,
        stage=f"correctness-{backend}",
        argv=rustybench_invocation_argv(artifact, kind="correctness"),
        cwd=workspace,
        environment=client_environment,
        cpu=cpu,
        timeout_seconds=60,
    )
    if correctness["returncode"] != 0:
        raise RunnerError(f"{backend} five-row correctness invocation failed")
    correctness_text = Path(correctness["stdout_path"]).read_text(encoding="utf-8", errors="replace")
    validate_correctness_stdout(correctness_text)
    _, sample_count, sample_size = require_admitted_mode("smoke")
    reduced = _run_retained_command(
        invocation,
        stage=f"reduced-{backend}",
        argv=rustybench_invocation_argv(
            artifact, kind="reduced", sample_count=sample_count, sample_size=sample_size,
        ),
        cwd=workspace,
        environment=client_environment,
        cpu=cpu,
        timeout_seconds=90,
    )
    if reduced["returncode"] != 0:
        raise RunnerError(f"{backend} reduced Rustybench invocation failed")
    raw = _load_json_file(Path(reduced["stdout_path"]), f"{backend} reduced Rustybench stdout")
    summary = validate_benchmark_report(
        raw, row_names(profile), sample_count=sample_count, sample_size=sample_size
    )
    build = {
        "command": build_command,
        "artifact": artifact,
        "elf": elf,
        "metadata_command": metadata_command,
        "dependency_graph": graph,
    }
    invocations = [
        {"backend": backend, "kind": "correctness", "command": correctness},
        {"backend": backend, "kind": "reduced", "command": reduced, "summary": summary},
    ]
    return build, invocations


def _serialise_tool_record(root: Path, value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "path": value["path"],
        "file": value["file"],
        "command": _command_record(root, value["command"]),
    }


def _serialise_build(root: Path, value: Mapping[str, Any]) -> dict[str, Any]:
    graph = _require_mapping(value["dependency_graph"], "dependency graph")
    elf = _require_mapping(value["elf"], "ELF record")
    return {
        "command": _command_record(root, value["command"]),
        "artifact": _identity_at(root, value["artifact"]),
        "elf": {
            "file": elf["file"],
            "readelf": _command_record(root, elf["readelf"]),
        },
        "metadata_command": _command_record(root, value["metadata_command"]),
        "dependency_graph": {
            "metadata": _identity_at(root, graph["metadata_path"], graph["metadata"]),
            "packages": graph["packages"],
        },
    }


def _serialise_invocation(root: Path, value: Mapping[str, Any]) -> dict[str, Any]:
    command = _command_record(root, value["command"])
    raw_argv = command["argv"]
    if not raw_argv or not isinstance(raw_argv[0], str):
        raise RunnerError("retained invocation lacks an executable argv")
    command["logical_argv"] = [_work_relative(root, Path(raw_argv[0])), *raw_argv[1:]]
    result: dict[str, Any] = {
        "backend": value["backend"],
        "kind": value["kind"],
        "command": command,
    }
    if "summary" in value:
        result["summary"] = value["summary"]
    return result


def _execution_environment(profile: Mapping[str, Any]) -> None:
    execution = _require_mapping(profile.get("execution"), "profile execution")
    if sys.platform != "linux" or platform.machine() != "x86_64":
        raise RunnerError(f"requires native Linux/x86_64; found {sys.platform}/{platform.machine()}")
    expected_image = execution.get("image")
    if not isinstance(expected_image, str):
        raise RunnerError("profile lacks a pinned image identity")
    if os.environ.get("CRABC_PERF_X86_IMAGE_ID") != expected_image:
        raise RunnerError("CRABC_PERF_X86_IMAGE_ID must be the dispatcher-derived pinned image identity")


def _require_sources(rustybench_source: Path | None, rustix_source: Path | None) -> tuple[Path, Path]:
    if rustybench_source is None or rustix_source is None:
        raise RunnerError("both --rustybench-source and --rustix-source are required")
    return (
        _physical_existing(rustybench_source, "Rustybench source"),
        _physical_existing(rustix_source, "Rustix source"),
    )


def _check_static_lock_has_no_quanta(lock_path: Path) -> None:
    try:
        lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise RunnerError(f"cannot parse static x86 Cargo.lock: {error}") from error
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise RunnerError("static x86 Cargo.lock lacks packages")
    if any(isinstance(package, dict) and package.get("name") == "quanta" for package in packages):
        raise RunnerError("static x86 Cargo.lock must not admit Rustybench quanta")


def prepare_dependencies(
    root: Path,
    *,
    work_root: Path,
    rustybench_source: Path,
    rustix_source: Path,
) -> Path:
    """Fetch the exact static lock into private Cargo state; run inside pinned Docker."""

    profile = load_profile(root)
    _execution_environment(profile)
    work_root = _ensure_private_directory(root, work_root)
    cargo_home = _ensure_private_directory(root, work_root / "native-facade-x86-cargo-home")
    _check_static_lock_has_no_quanta(_profile_file(root, profile, "lock_template"))
    before = capture_source_state(root, profile, rustybench_source, rustix_source)
    invocation = Path(tempfile.mkdtemp(prefix="native-facade-x86-prepare-", dir=work_root))
    invocation = require_private_work_path(root, invocation)
    workspace, rendered = _render_workspace(root, profile, invocation, rustybench_source, rustix_source)
    allowed_affinity = tuple(sorted(os.sched_getaffinity(0)))
    if not allowed_affinity:
        raise RunnerError("current process has no allowed CPU")
    build_environment, _client_environment, environment_record = _clean_environments(
        invocation, cargo_home, offline=False
    )
    fetch = _run_retained_command(
        invocation,
        stage="cargo-fetch",
        argv=["cargo", "fetch", "--manifest-path", str(workspace / "Cargo.toml"), "--locked"],
        cwd=workspace,
        environment=build_environment,
        cpu=allowed_affinity[0],
        timeout_seconds=180,
    )
    if fetch["returncode"] != 0:
        raise RunnerError(f"Cargo dependency preparation failed; inspect {fetch['stderr_path']}")
    after = capture_source_state(root, profile, rustybench_source, rustix_source)
    _require_same(after, before, "source inputs after dependency preparation")
    report_path = invocation / "prepare.json"
    report: dict[str, Any] = {
        "schema": PREPARE_SCHEMA,
        "status": "prepared",
        "work": {
            "invocation": _work_relative(root, invocation),
            "cargo_home": _work_relative(root, cargo_home),
        },
        "source_before": before,
        "source_after": after,
        "rendered": {
            "workspace": _work_relative(root, workspace),
            **rendered,
            "execution_sources": {
                "rustybench": str(rustybench_source),
                "rustix": str(rustix_source),
                "crabc_rs": str(_physical_existing(root, "repository root") / "crabc-rs"),
            },
        },
        "environment": environment_record,
        "fetch": _command_record(root, fetch),
    }
    _atomic_write_json(root, report_path, report)
    return report_path


def run_smoke(
    root: Path,
    *,
    report_path: Path,
    work_root: Path,
    rustybench_source: Path,
    rustix_source: Path,
) -> dict[str, Any]:
    profile = load_profile(root)
    _execution_environment(profile)
    invocations_per_backend, sample_count, sample_size = require_admitted_mode("smoke")
    work_root = _ensure_private_directory(root, work_root)
    report_path = require_private_work_path(root, report_path)
    cargo_home = _ensure_private_directory(root, work_root / "native-facade-x86-cargo-home")
    _check_static_lock_has_no_quanta(_profile_file(root, profile, "lock_template"))
    before = capture_source_state(root, profile, rustybench_source, rustix_source)
    invocation = Path(tempfile.mkdtemp(prefix="native-facade-x86-smoke-", dir=work_root))
    invocation = require_private_work_path(root, invocation)
    workspace, rendered = _render_workspace(root, profile, invocation, rustybench_source, rustix_source)
    allowed_affinity = tuple(sorted(os.sched_getaffinity(0)))
    if not allowed_affinity:
        raise RunnerError("current process has no allowed CPU")
    cpu = allowed_affinity[0]
    build_environment, client_environment, environment_record = _clean_environments(
        invocation, cargo_home, offline=True
    )
    diagnostics = _cpu_diagnostics(invocation, cpu, allowed_affinity)
    tools = _capture_tool_versions(invocation, build_environment, cpu)
    builds: dict[str, Any] = {}
    invocation_records: list[dict[str, Any]] = []
    for backend in BACKENDS:
        build, backend_invocations = _run_backend(
            root,
            profile,
            invocation=invocation,
            workspace=workspace,
            cargo_home=cargo_home,
            rustybench_source=rustybench_source,
            rustix_source=rustix_source,
            backend=backend,
            cpu=cpu,
            build_environment=build_environment,
            client_environment=client_environment,
        )
        builds[backend] = build
        invocation_records.extend(backend_invocations)
    after = capture_source_state(root, profile, rustybench_source, rustix_source)
    _require_same(after, before, "source inputs after native facade smoke")
    normal = _require_mapping(profile.get("normal"), "normal profile")
    admission = _require_mapping(profile.get("admission"), "profile admission")
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "bounded-implementation-smoke",
        "mode": "smoke",
        "profile": file_identity(_physical_existing(root, "repository root") / "compat/perf/native/x86_64_profile.toml"),
        "work": {
            "work_root": _work_relative(root, work_root),
            "invocation": _work_relative(root, invocation),
            "cargo_home": _work_relative(root, cargo_home),
        },
        "admission": {
            "full_mode": admission.get("full_correctness_predecessor"),
            "reason": admission.get("reason"),
        },
        "plan": {
            "backends": list(BACKENDS),
            "smoke": {
                "invocations_per_backend": invocations_per_backend,
                "sample_count": sample_count,
                "sample_size": sample_size,
                "iter_count": sample_count * sample_size,
            },
            "normal_contract": {
                "invocations_per_backend": normal.get("invocations_per_backend"),
                "sample_count": normal.get("sample_count"),
                "sample_size": normal.get("sample_size"),
                "iter_count": int(normal["sample_count"]) * int(normal["sample_size"]),
            },
        },
        "source_before": before,
        "source_after": after,
        "rendered": {
            "workspace": _work_relative(root, workspace),
            **rendered,
            # These are the locations used when the retained manifest was
            # rendered in Docker. Host replay receives independently mapped
            # physical sources and must not rewrite these execution paths.
            "execution_sources": {
                "rustybench": str(rustybench_source),
                "rustix": str(rustix_source),
                "crabc_rs": str(_physical_existing(root, "repository root") / "crabc-rs"),
                "frozen_source": str(_profile_file(root, profile, "frozen_source")),
            },
        },
        "environment": environment_record,
        "diagnostics": {
            "client_cpu": diagnostics["client_cpu"],
            "allowed_affinity": diagnostics["allowed_affinity"],
            "cpuinfo": _identity_at(root, diagnostics["cpuinfo_path"], diagnostics["cpuinfo"]),
            "frequency": (
                {"status": "unavailable"}
                if diagnostics["frequency"]["status"] == "unavailable"
                else {
                    "status": "available",
                    "path": diagnostics["frequency"]["path"],
                    "raw": _identity_at(
                        root,
                        diagnostics["frequency"]["raw_path"],
                        diagnostics["frequency"]["raw"],
                    ),
                }
            ),
        },
        "tools": {name: _serialise_tool_record(root, value) for name, value in tools.items()},
        "builds": {name: _serialise_build(root, value) for name, value in builds.items()},
        "invocations": [_serialise_invocation(root, value) for value in invocation_records],
    }
    _atomic_write_json(root, report_path, report)
    validate_report(root, report_path, rustybench_source=rustybench_source, rustix_source=rustix_source)
    return report


def _verify_retained_file(root: Path, record: object, label: str) -> Path:
    mapping = _require_exact_keys(record, {"path", "sha256", "size", "mode"}, label)
    path = _work_path_from_record(root, mapping["path"], label)
    verify_file_identity(path, {key: mapping[key] for key in ("sha256", "size", "mode")}, label)
    return path


def _validate_command(root: Path, record: object, *, cpu: int, label: str) -> Mapping[str, Any]:
    mapping = _require_exact_keys(
        record,
        {"argv", "cwd", "returncode", "child_pid", "elapsed_wall_ns", "stdout", "stderr", "status"},
        label,
    )
    argv = mapping["argv"]
    if not isinstance(argv, list) or not argv or not all(isinstance(item, str) for item in argv):
        raise RunnerError(f"{label} argv must be a non-empty string list")
    _work_path_from_record(root, mapping["cwd"], f"{label} cwd")
    if mapping["returncode"] != 0:
        raise RunnerError(f"{label} retained a failing command")
    child_pid = _nonnegative_int(mapping["child_pid"], f"{label} child_pid")
    if child_pid <= 0:
        raise RunnerError(f"{label} child_pid must be positive")
    _nonnegative_int(mapping["elapsed_wall_ns"], f"{label} elapsed_wall_ns")
    _verify_retained_file(root, mapping["stdout"], f"{label} stdout")
    _verify_retained_file(root, mapping["stderr"], f"{label} stderr")
    status_path = _verify_retained_file(root, mapping["status"], f"{label} raw status")
    _parse_status(status_path.read_bytes(), child_pid, cpu, label)
    return mapping


def _validate_tool_record(root: Path, record: object, *, cpu: int, name: str) -> None:
    mapping = _require_exact_keys(record, {"path", "file", "command"}, f"tool {name}")
    if not isinstance(mapping["path"], str) or not mapping["path"].startswith("/"):
        raise RunnerError(f"tool {name} must retain its absolute image path")
    _require_exact_keys(mapping["file"], {"sha256", "size", "mode"}, f"tool {name} file")
    command = _validate_command(root, mapping["command"], cpu=cpu, label=f"tool {name}")
    expected = [name]
    if name == "rustc":
        expected.append("-Vv")
    elif name == "cargo":
        expected.append("-V")
    else:
        expected.extend(["target", "list", "--installed"])
    if command["argv"] != expected:
        raise RunnerError(f"tool {name} invocation differs")


def _validate_rendered_workspace(root: Path, report: Mapping[str, Any]) -> Path:
    rendered = _require_exact_keys(
        report.get("rendered"),
        {
            "workspace", "manifest", "lock", "source", "fixture_target", "fixture_link_target",
            "fixture_link_target_sha256", "fixture_absent_name", "execution_sources",
        },
        "rendered workspace",
    )
    workspace = _work_path_from_record(root, rendered["workspace"], "rendered workspace")
    if workspace.is_symlink() or not workspace.is_dir():
        raise RunnerError("rendered workspace must remain a real directory")
    manifest = _verify_retained_file(
        root, {"path": f"{rendered['workspace']}/Cargo.toml", **_require_mapping(rendered["manifest"], "manifest identity")},
        "rendered manifest",
    )
    _verify_retained_file(
        root, {"path": f"{rendered['workspace']}/Cargo.lock", **_require_mapping(rendered["lock"], "lock identity")},
        "rendered lock",
    )
    _verify_retained_file(
        root, {"path": f"{rendered['workspace']}/src/main.rs", **_require_mapping(rendered["source"], "source identity")},
        "rendered fixture source",
    )
    target = _verify_retained_file(
        root,
        {"path": f"{rendered['workspace']}/fixture/fixed-target", **_require_mapping(rendered["fixture_target"], "fixture target identity")},
        "private fixture target",
    )
    link = target.with_name("fixed-link")
    if not link.is_symlink() or os.readlink(link) != rendered["fixture_link_target"]:
        raise RunnerError("private fixture symlink differs")
    if rendered["fixture_link_target_sha256"] != _sha256_bytes(os.fsencode(os.readlink(link))):
        raise RunnerError("private fixture symlink target identity differs")
    absent_name = rendered["fixture_absent_name"]
    if not isinstance(absent_name, str) or not absent_name or "/" in absent_name:
        raise RunnerError("private absent fixture name differs")
    if os.path.lexists(link.parent / absent_name):
        raise RunnerError("private absent fixture path now exists")
    execution_sources = _require_exact_keys(
        rendered["execution_sources"], {"rustybench", "rustix", "crabc_rs", "frozen_source"}, "execution source locations"
    )
    if not all(isinstance(value, str) and value.startswith("/") for value in execution_sources.values()):
        raise RunnerError("execution source locations must retain absolute Docker paths")
    manifest_text = manifest.read_text(encoding="utf-8")
    for key in ("rustybench", "rustix", "crabc_rs"):
        if json.dumps(execution_sources[key]) not in manifest_text:
            raise RunnerError(f"retained manifest does not bind its execution {key} path")
    fixture_source = (workspace / "src/main.rs").read_text(encoding="utf-8")
    if json.dumps(execution_sources["frozen_source"]) not in fixture_source:
        raise RunnerError("retained fixture source does not bind its execution frozen source path")
    if "@" in manifest_text or "@CRABC_NATIVE_FROZEN_SOURCE@" in fixture_source:
        raise RunnerError("retained workspace still has an unresolved source marker")
    return workspace


def _dependency_base(
    root: Path,
    *,
    workspace: Path,
    cargo_home: Path,
    rustybench_source: Path,
    rustix_source: Path,
    kind: str,
) -> Path:
    root_physical = _physical_existing(root, "repository root")
    values = {
        "workspace": workspace,
        "rustybench": rustybench_source,
        "rustix": rustix_source,
        "crabc-rs": root_physical / "crabc-rs",
        "crabc-core": root_physical / "crabc-core",
        "cargo-registry": cargo_home / "registry/src",
    }
    if kind not in values:
        raise RunnerError(f"retained dependency has an unadmitted source kind: {kind!r}")
    return _physical_existing(values[kind], f"retained {kind} source base")


def _safe_relative(value: object, label: str) -> Path:
    if not isinstance(value, str) or Path(value).is_absolute():
        raise RunnerError(f"{label} must be a relative source path")
    path = Path(value)
    if any(component in ("", ".", "..") for component in path.parts if component != "."):
        if path.as_posix() != ".":
            raise RunnerError(f"{label} has an unsafe source path")
    if ".." in path.parts:
        raise RunnerError(f"{label} has an unsafe source path")
    return path


def _validate_dependency_graph(
    root: Path,
    profile: Mapping[str, Any],
    graph: object,
    *,
    workspace: Path,
    cargo_home: Path,
    rustybench_source: Path,
    rustix_source: Path,
    backend: str,
) -> None:
    mapping = _require_exact_keys(graph, {"metadata", "packages"}, f"{backend} dependency graph")
    metadata_path = _verify_retained_file(root, mapping["metadata"], f"{backend} Cargo metadata")
    metadata = _require_mapping(_load_json_file(metadata_path, f"{backend} Cargo metadata"), f"{backend} Cargo metadata")
    _lock_registry_checksums(workspace / "Cargo.lock", metadata, backend)
    packages = mapping["packages"]
    if not isinstance(packages, list) or not packages:
        raise RunnerError(f"{backend} dependency graph must retain package records")
    package_mappings = [
        _require_mapping(record, f"{backend} dependency package {index}")
        for index, record in enumerate(packages)
    ]
    validate_active_dependency_roster(profile, backend, package_mappings)
    ids: set[str] = set()
    names: set[str] = set()
    policy = _require_mapping(profile.get("dependency_policy"), "dependency policy")
    forbidden = set(policy["forbidden_active_packages"])
    for index, record in enumerate(package_mappings):
        parsed = _require_exact_keys(
            record, {"id", "name", "version", "source", "source_kind", "relative", "tree"},
            f"{backend} dependency package {index}",
        )
        package_id = parsed["id"]
        name = parsed["name"]
        if not isinstance(package_id, str) or not isinstance(name, str) or package_id in ids:
            raise RunnerError(f"{backend} dependency package roster differs")
        if name in forbidden:
            raise RunnerError(f"{backend} dependency graph selected forbidden {name}")
        ids.add(package_id)
        names.add(name)
        base = _dependency_base(
            root,
            workspace=workspace,
            cargo_home=cargo_home,
            rustybench_source=rustybench_source,
            rustix_source=rustix_source,
            kind=parsed["source_kind"],
        )
        package_root = _physical_existing(base / _safe_relative(parsed["relative"], f"{backend} dependency package"), "dependency package")
        if not _within(package_root, base):
            raise RunnerError(f"{backend} dependency package escapes its retained source root")
        verify_tree_identity(package_root, parsed["tree"], f"{backend} dependency {name}")
    validate_dependency_source_kinds(backend, package_mappings)
    required = {"rustybench", "rustybench-macros", "regex-lite", "lexopt", "miniserde"}
    if not required <= names:
        raise RunnerError(f"{backend} dependency graph omits a normal Rustybench package")


def _validate_build(
    root: Path,
    profile: Mapping[str, Any],
    record: object,
    *,
    workspace: Path,
    invocation: Path,
    cargo_home: Path,
    rustybench_source: Path,
    rustix_source: Path,
    backend: str,
    cpu: int,
) -> Path:
    mapping = _require_exact_keys(
        record, {"command", "artifact", "elf", "metadata_command", "dependency_graph"}, f"{backend} build"
    )
    command = _validate_command(root, mapping["command"], cpu=cpu, label=f"{backend} Cargo build")
    argv = command["argv"]
    target = _require_mapping(profile.get("execution"), "profile execution")["target"]
    workspace_logical = _work_relative(root, workspace)
    expected_build_tail = [
        "--bench", "native_x86", "--target", target, "--no-default-features", "--features", backend,
        "--no-run", "--locked", "--offline", "--message-format=json",
    ]
    if (
        len(argv) != 4 + len(expected_build_tail)
        or argv[:3] != ["cargo", "bench", "--manifest-path"]
        or argv[4:] != expected_build_tail
        or command["cwd"] != workspace_logical
    ):
        raise RunnerError(f"{backend} Cargo build command differs from stock-std contract")
    _require_execution_path_for_logical(argv[3], f"{workspace_logical}/Cargo.toml", f"{backend} Cargo manifest")
    artifact = _verify_retained_file(root, mapping["artifact"], f"{backend} benchmark ELF")
    target_root = _physical_existing(invocation / "target", "retained target root")
    if not _within(artifact, target_root) or not os.access(artifact, os.X_OK):
        raise RunnerError(f"{backend} benchmark ELF escaped the retained target root")
    elf = _require_exact_keys(mapping["elf"], {"file", "readelf"}, f"{backend} ELF record")
    _require_same(elf["file"], {key: mapping["artifact"][key] for key in ("sha256", "size", "mode")}, f"{backend} duplicated ELF identity")
    readelf = _validate_command(root, elf["readelf"], cpu=cpu, label=f"{backend} readelf")
    readelf_argv = readelf["argv"]
    if readelf_argv[:4] != ["readelf", "-h", "-l", "-d"] or len(readelf_argv) != 5:
        raise RunnerError(f"{backend} readelf command differs")
    _require_execution_path_for_logical(
        readelf_argv[4], _work_relative(root, artifact), f"{backend} readelf artifact"
    )
    readelf_path = _work_path_from_record(root, readelf["stdout"]["path"], f"{backend} readelf stdout")
    _validate_elf_text(readelf_path.read_text(encoding="utf-8"), backend)
    metadata_command = _validate_command(root, mapping["metadata_command"], cpu=cpu, label=f"{backend} Cargo metadata")
    expected_metadata_tail = [
        "--format-version=1", "--locked", "--offline", "--no-default-features", "--features", backend,
        "--filter-platform", target,
    ]
    metadata_argv = metadata_command["argv"]
    if (
        len(metadata_argv) != 4 + len(expected_metadata_tail)
        or metadata_argv[:3] != ["cargo", "metadata", "--manifest-path"]
        or metadata_argv[4:] != expected_metadata_tail
        or metadata_command["cwd"] != workspace_logical
    ):
        raise RunnerError(f"{backend} Cargo metadata command differs")
    _require_execution_path_for_logical(
        metadata_argv[3], f"{workspace_logical}/Cargo.toml", f"{backend} Cargo metadata manifest"
    )
    _validate_dependency_graph(
        root,
        profile,
        mapping["dependency_graph"],
        workspace=workspace,
        cargo_home=cargo_home,
        rustybench_source=rustybench_source,
        rustix_source=rustix_source,
        backend=backend,
    )
    return artifact


def _validate_invocation(
    root: Path,
    profile: Mapping[str, Any],
    record: object,
    *,
    expected_backend: str,
    expected_kind: str,
    artifact: Path,
    cpu: int,
) -> None:
    required_keys = {"backend", "kind", "command"}
    if expected_kind == "reduced":
        required_keys.add("summary")
    mapping = _require_exact_keys(record, required_keys, f"{expected_backend} {expected_kind} invocation")
    if mapping["backend"] != expected_backend or mapping["kind"] != expected_kind:
        raise RunnerError("retained invocation backend/kind roster differs")
    command_value = _require_mapping(mapping["command"], f"{expected_backend} {expected_kind} command")
    logical_argv = command_value.get("logical_argv")
    command_without_logical = dict(command_value)
    command_without_logical.pop("logical_argv", None)
    command = _validate_command(
        root, command_without_logical, cpu=cpu, label=f"{expected_backend} {expected_kind} invocation"
    )
    if not isinstance(logical_argv, list) or not all(isinstance(item, str) for item in logical_argv):
        raise RunnerError(f"{expected_backend} {expected_kind} invocation lacks logical argv")
    expected_program = _work_relative(root, artifact)
    if not logical_argv or logical_argv[0] != expected_program:
        raise RunnerError(f"{expected_backend} {expected_kind} invocation executable differs")
    raw_argv = command["argv"]
    _require_execution_path_for_logical(
        raw_argv[0], expected_program, f"{expected_backend} {expected_kind} raw executable"
    )
    if raw_argv[1:] != logical_argv[1:]:
        raise RunnerError(f"{expected_backend} {expected_kind} raw argv differs from its logical argv")
    if expected_kind == "correctness":
        if logical_argv != rustybench_invocation_argv(Path(expected_program), kind="correctness"):
            raise RunnerError(f"{expected_backend} correctness argv differs")
        text = _work_path_from_record(root, command["stdout"]["path"], f"{expected_backend} correctness stdout").read_text(
            encoding="utf-8", errors="replace"
        )
        validate_correctness_stdout(text)
        return
    _, sample_count, sample_size = require_admitted_mode("smoke")
    expected = rustybench_invocation_argv(
        Path(expected_program), kind="reduced", sample_count=sample_count, sample_size=sample_size,
    )
    if logical_argv != expected:
        raise RunnerError(f"{expected_backend} reduced argv differs")
    raw_path = _work_path_from_record(root, command["stdout"]["path"], f"{expected_backend} reduced stdout")
    summary = validate_benchmark_report(
        _load_json_file(raw_path, f"{expected_backend} reduced Rustybench stdout"),
        row_names(profile), sample_count=sample_count, sample_size=sample_size,
    )
    _require_same(summary, mapping["summary"], f"{expected_backend} reduced derived metrics")


def validate_report(
    root: Path,
    report_path: Path,
    *,
    rustybench_source: Path,
    rustix_source: Path,
) -> None:
    """Replay retained smoke evidence without Cargo, a container, or a benchmark."""

    root = _physical_existing(root, "repository root")
    report_path = require_private_work_path(root, report_path)
    report = _require_exact_keys(
        _load_json_file(report_path, "native facade report"),
        {
            "schema", "status", "mode", "profile", "work", "admission", "plan", "source_before",
            "source_after", "rendered", "environment", "diagnostics", "tools", "builds", "invocations",
        },
        "native facade report",
    )
    if report["schema"] != SCHEMA or report["status"] != "bounded-implementation-smoke" or report["mode"] != "smoke":
        raise RunnerError("native facade report status/schema/mode differs")
    profile = load_profile(root)
    profile_path = root / "compat/perf/native/x86_64_profile.toml"
    verify_file_identity(profile_path, report["profile"], "native facade profile")
    sources_before = _require_mapping(report["source_before"], "source-before snapshot")
    sources_after = _require_mapping(report["source_after"], "source-after snapshot")
    current_sources = capture_source_state(root, profile, rustybench_source, rustix_source)
    _require_same(sources_before, sources_after, "retained source snapshots")
    _require_same(current_sources, sources_before, "current source snapshot")
    work = _require_exact_keys(report["work"], {"work_root", "invocation", "cargo_home"}, "report work")
    work_root = _work_path_from_record(root, work["work_root"], "report work root")
    invocation = _work_path_from_record(root, work["invocation"], "report invocation")
    cargo_home = _work_path_from_record(root, work["cargo_home"], "report Cargo home")
    if invocation.is_symlink() or not invocation.is_dir() or not _within(invocation, work_root):
        raise RunnerError("report invocation is not a private work subtree")
    if cargo_home.is_symlink() or not cargo_home.is_dir() or not _within(cargo_home, work_root):
        raise RunnerError("report Cargo home is not a private work subtree")
    admission = _require_exact_keys(report["admission"], {"full_mode", "reason"}, "report admission")
    profile_admission = _require_mapping(profile.get("admission"), "profile admission")
    if admission["full_mode"] != "unavailable" or admission["reason"] != profile_admission.get("reason"):
        raise RunnerError("report full-mode admission differs")
    plan = _require_exact_keys(report["plan"], {"backends", "smoke", "normal_contract"}, "report plan")
    if plan["backends"] != list(BACKENDS):
        raise RunnerError("report backend roster differs")
    expected_smoke = {
        "invocations_per_backend": 1,
        "sample_count": 2,
        "sample_size": 3,
        "iter_count": 6,
    }
    if plan["smoke"] != expected_smoke:
        raise RunnerError("report smoke geometry differs")
    expected_normal = {
        "invocations_per_backend": 5,
        "sample_count": 100,
        "sample_size": 1000,
        "iter_count": 100_000,
    }
    if plan["normal_contract"] != expected_normal:
        raise RunnerError("report normal geometry differs")
    workspace = _validate_rendered_workspace(root, report)
    environment = _require_exact_keys(report["environment"], {"build", "client", "scrubbed_ambient_keys"}, "report environment")
    build_environment = _require_mapping(environment["build"], "report build environment")
    client_environment = _require_mapping(environment["client"], "report client environment")
    if set(build_environment) != SMOKE_BUILD_ENVIRONMENT_KEYS or not all(
        isinstance(value, str) for value in build_environment.values()
    ):
        raise RunnerError("report build environment shape differs")
    if set(client_environment) != CLIENT_ENVIRONMENT_KEYS or not all(
        isinstance(value, str) for value in client_environment.values()
    ):
        raise RunnerError("report client environment shape differs")
    if (
        build_environment.get("CARGO_NET_OFFLINE") != "true"
        or build_environment.get("CARGO_ENCODED_RUSTFLAGS") != ""
        or build_environment.get("RUSTUP_TOOLCHAIN") != "nightly-2026-07-24"
        or build_environment.get("LC_ALL") != "C"
        or build_environment.get("LANG") != "C"
        or build_environment.get("TZ") != "UTC"
        or client_environment.get("LC_ALL") != "C"
        or client_environment.get("LANG") != "C"
        or client_environment.get("TZ") != "UTC"
    ):
        raise RunnerError("report build environment does not retain offline stock flags")
    if any(key.startswith("RUSTYBENCH_") or key.startswith("LD_") for key in client_environment):
        raise RunnerError("report client environment retained a benchmark-affecting ambient key")
    scrubbed = environment["scrubbed_ambient_keys"]
    if not isinstance(scrubbed, list) or not all(isinstance(key, str) for key in scrubbed) or scrubbed != sorted(set(scrubbed)):
        raise RunnerError("report scrubbed ambient-key roster differs")
    diagnostics = _require_exact_keys(report["diagnostics"], {"client_cpu", "allowed_affinity", "cpuinfo", "frequency"}, "report diagnostics")
    cpu = _nonnegative_int(diagnostics["client_cpu"], "report client CPU")
    allowed = diagnostics["allowed_affinity"]
    if not isinstance(allowed, list) or not allowed or any(isinstance(value, bool) or not isinstance(value, int) for value in allowed):
        raise RunnerError("report allowed affinity differs")
    if allowed != sorted(set(allowed)) or cpu not in allowed:
        raise RunnerError("report client CPU is not a unique allowed affinity member")
    _verify_retained_file(root, diagnostics["cpuinfo"], "retained raw cpuinfo")
    frequency = _require_mapping(diagnostics["frequency"], "frequency diagnostics")
    if frequency.get("status") == "available":
        _verify_retained_file(root, frequency.get("raw"), "retained raw CPU frequency")
        if not isinstance(frequency.get("path"), str) or not frequency["path"].startswith("/sys/"):
            raise RunnerError("retained CPU frequency path differs")
    elif set(frequency) != {"status"} or frequency["status"] != "unavailable":
        raise RunnerError("frequency diagnostic status differs")
    tools = _require_exact_keys(report["tools"], {"rustc", "cargo", "rustup"}, "report tools")
    for name in ("rustc", "cargo", "rustup"):
        _validate_tool_record(root, tools[name], cpu=cpu, name=name)
    rustc_stdout = _work_path_from_record(root, tools["rustc"]["command"]["stdout"]["path"], "rustc stdout").read_text(encoding="utf-8")
    if "release: 1.99.0-nightly" not in rustc_stdout or "host: x86_64-unknown-linux-musl" not in rustc_stdout:
        raise RunnerError("retained rustc identity differs")
    builds = _require_exact_keys(report["builds"], set(BACKENDS), "report builds")
    artifacts: dict[str, Path] = {}
    for backend in BACKENDS:
        artifacts[backend] = _validate_build(
            root,
            profile,
            builds[backend],
            workspace=workspace,
            invocation=invocation,
            cargo_home=cargo_home,
            rustybench_source=rustybench_source,
            rustix_source=rustix_source,
            backend=backend,
            cpu=cpu,
        )
    invocations = report["invocations"]
    if not isinstance(invocations, list) or len(invocations) != 4:
        raise RunnerError("report invocation roster differs")
    expected_roster = [
        ("crabc", "correctness"), ("crabc", "reduced"),
        ("rustix", "correctness"), ("rustix", "reduced"),
    ]
    for value, (backend, kind) in zip(invocations, expected_roster, strict=True):
        _validate_invocation(
            root,
            profile,
            value,
            expected_backend=backend,
            expected_kind=kind,
            artifact=artifacts[backend],
            cpu=cpu,
        )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--prepare", action="store_true", help="fetch the static lock into private Cargo state")
    action.add_argument("--mode", choices=("smoke", "full"), help="run the bounded smoke; full is intentionally unavailable")
    action.add_argument("--validate-report", type=Path, help="host-replay one retained smoke report without Cargo")
    parser.add_argument("--report", type=Path, help="required output path for --mode smoke")
    parser.add_argument("--work-root", type=Path, default=None, help="private root below .work/x86_64")
    # Source paths are required for every executable/replay action, but not
    # syntactically required here: an attempted full mode must reach its
    # unconditional admission refusal before an incidental missing path can
    # obscure that boundary.
    parser.add_argument("--rustybench-source", type=Path, help="physical pinned Rustybench source")
    parser.add_argument("--rustix-source", type=Path, help="physical pinned Rustix source")
    parsed = parser.parse_args(argv)
    if parsed.mode == "smoke" and parsed.report is None:
        parser.error("--mode smoke requires --report")
    if parsed.report is not None and parsed.mode != "smoke":
        parser.error("--report is valid only with --mode smoke")
    return parsed


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv)
    root = repository_root()
    work_root = arguments.work_root or root / ".work/x86_64"
    try:
        if arguments.mode == "full":
            # Keep this before source resolution: a full request is refused by
            # admission itself, never by an incidental source/path failure.
            require_admitted_mode("full")
        rustybench_source, rustix_source = _require_sources(arguments.rustybench_source, arguments.rustix_source)
        if arguments.prepare:
            output = prepare_dependencies(
                root,
                work_root=work_root,
                rustybench_source=rustybench_source,
                rustix_source=rustix_source,
            )
            print(output)
            return 0
        if arguments.validate_report is not None:
            validate_report(
                root,
                arguments.validate_report,
                rustybench_source=rustybench_source,
                rustix_source=rustix_source,
            )
            print(arguments.validate_report)
            return 0
        assert arguments.mode is not None
        # The unconditional admission gate intentionally precedes image/source
        # setup, so no full execution can be smuggled through an input path.
        require_admitted_mode(arguments.mode)
        if arguments.mode == "full":
            raise AssertionError("full admission should have raised")
        report = run_smoke(
            root,
            report_path=arguments.report,
            work_root=work_root,
            rustybench_source=rustybench_source,
            rustix_source=rustix_source,
        )
        print(arguments.report)
        if report["status"] != "bounded-implementation-smoke":
            raise RunnerError("smoke did not retain its bounded status")
        return 0
    except RunnerError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
