#!/usr/bin/env python3
"""Run the exact pinned mimalloc upstream stress source through selected crabc libc.

This is deliberately separate from the reviewed ``native-shadow-stress``
fixture. That fixture applies a source patch which moves transferred-object
cleanup into fresh pthreads. This lane does not apply a patch or copy the
source: it verifies and compiles the archived ``test/test-stress.c`` with the
upstream ``USE_STD_MALLOC`` conditional enabled, so standard allocation names
bind to the selected native-mimalloc-shadow ``libc.so``.

The lane compiles one attested binary and runs its closed, ordered source
argument matrix. Each case receives a fresh process and watchdog. The runner
stops at the first unavailable prerequisite or non-pass; it never retries,
shrinks, or reschedules a source case. It is a failure-preservation gate, not
an allocator promotion claim.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[3]


def default_work_root() -> Path:
    """Return the checkout-local boundary for harness-owned mutable artifacts."""

    configured = os.environ.get("CRABC_WORK_DIR")
    if not configured:
        return ROOT / ".work"
    path = Path(configured).expanduser()
    return path if path.is_absolute() else ROOT / path


WORK_ROOT = default_work_root()
ALLOCATOR_ROOT = ROOT / "compat/allocator"
CONTRACT_PATH = ALLOCATOR_ROOT / "upstream-stress-v3.5.0.json"
UPSTREAMS_PATH = ROOT / "compat/upstreams.toml"
CACHE = WORK_ROOT / "allocator-cache"
DEFAULT_TARGET_DIR = ROOT / "target/debug"
DEFAULT_OUTPUT_DIR = WORK_ROOT / "target/compat/allocator/upstream-stress"
DEFAULT_REPORT = WORK_ROOT / "reports/allocator/upstream-stress/latest.json"
DEFAULT_DIAGNOSTIC_REPORT = (
    WORK_ROOT / "reports/allocator/upstream-stress/current-head.json"
)
DEFAULT_POST_OWNER_EXIT_CONCURRENT_FREE_REPORT = (
    WORK_ROOT / "reports/allocator/upstream-stress/post-owner-exit-concurrent-free.json"
)
DEFAULT_LIBC_BUILD_RECORD = DEFAULT_OUTPUT_DIR / "selected-libc-build.json"
CANONICAL_LOADER = Path("/lib/ld-crabc-aarch64.so.1")
CURRENT_HEAD_BUILD_RECORD_FORMAT = 1
CURRENT_HEAD_BUILD_RECORD_SCHEMA = "crabc-selected-libc-current-head-build"
DIAGNOSTIC_REPORT_FORMAT = 1
DIAGNOSTIC_REPORT_SCHEMA = (
    "crabc-mimalloc-canonical-upstream-stress-current-head-diagnostic-report"
)
POST_OWNER_EXIT_CONCURRENT_FREE_CASE_ID = "workers-2-scale-1-iterations-1"
GIT_SOURCE_STATE_READ_ENVIRONMENT = {"GIT_OPTIONAL_LOCKS": "0"}
FIXED_PIN = {
    "version": "3.5.0",
    "repository": "https://github.com/microsoft/mimalloc.git",
    "tag": "v3.5.0",
    "source": "https://codeload.github.com/microsoft/mimalloc/tar.gz/refs/tags/v3.5.0",
    "sha256": "1e432f0559a4ab512143b9bff7a700541a2c8d4712b26a72de3e0222790da305",
    "tag_object": "438b0c4b78d2599aede7fca3ddacc28863b0eae8",
    "revision": "18b08671c9302247bfb682286e6bf3cc1773f801",
    "archive_root": "mimalloc-3.5.0",
}
CANONICAL_UPSTREAM_STRESS_WORKERS = (1, 2, 4, 8)
SOURCE_LARGE_OBJECT_SCALE_THRESHOLD = 100
SOURCE_LARGE_OBJECT_MATRIX_SCALE = SOURCE_LARGE_OBJECT_SCALE_THRESHOLD + 1
SOURCE_LARGE_OBJECT_MATRIX_ITERATIONS = 1
SOURCE_LARGE_OBJECT_STDOUT_SUFFIX = " (allow large objects)"


class EvidenceError(RuntimeError):
    """The canonical workload could not establish its one recorded fact."""


class BlockedPrerequisite(EvidenceError):
    """A required native execution boundary was unavailable before stress began."""

    def __init__(
        self, prerequisite: str, message: str, details: Mapping[str, Any]
    ) -> None:
        super().__init__(message)
        self.prerequisite = prerequisite
        self.details = dict(details)


class ArtifactContractError(EvidenceError):
    """A built fixture contradicted the selected executable contract."""

    def __init__(self, boundary: str, observed: object, expected: object) -> None:
        super().__init__(f"canonical stress fixture {boundary} mismatch")
        self.boundary = boundary
        self.observed = observed
        self.expected = expected


@dataclass(frozen=True)
class RuntimeInputs:
    """The owned boundaries needed to compile and execute the source matrix."""

    sysroot: Path
    compiler: Path
    target_dir: Path
    manifest_path: Path
    purity_path: Path
    canonical_loader_path: Path
    purity: dict[str, Any]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def bytes_record(value: bytes) -> dict[str, Any]:
    return {
        "bytes": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
        "hex": value.hex(),
    }


def file_record(path: Path, *, root: Path | None = None) -> dict[str, Any]:
    return {
        "bytes": path.stat().st_size,
        "path": relative_path(path, root),
        "sha256": sha256_file(path),
    }


def byte_record_payload(record: object, subject: str) -> bytes:
    """Decode one self-attesting byte record before trusting its contents."""

    if not isinstance(record, dict) or set(record) != {"bytes", "sha256", "hex"}:
        raise EvidenceError(f"{subject} byte-stream record is invalid")
    try:
        payload = bytes.fromhex(str(record["hex"]))
    except (KeyError, ValueError) as error:
        raise EvidenceError(f"{subject} byte-stream record has invalid hex") from error
    if (
        type(record["bytes"]) is not int
        or record["bytes"] != len(payload)
        or record["sha256"] != hashlib.sha256(payload).hexdigest()
    ):
        raise EvidenceError(f"{subject} byte-stream record attestation drifted")
    return payload


def current_head_build_record_path(build_record_path: Path) -> Path:
    """Keep current-head provenance beside, but distinct from, the Cargo record."""

    path = build_record_path.expanduser()
    return path.with_name(f"{path.stem}-current-head.json")


def source_state_excludes(path: Path) -> bool:
    """Leave VCS metadata and known generated/cache roots out of source identity."""

    parts = path.parts
    return (
        bool(parts)
        and (
            parts[0] in {".git", ".work", "target"}
            or parts[:2] == ("compat", "reports")
            or parts[:3] == ("compat", "allocator", ".cache")
        )
    )


def workspace_tree_source_state() -> dict[str, Any]:
    """Hash the mounted source tree when a worktree's Git metadata is unavailable."""

    digest = hashlib.sha256()
    file_count = 0

    def update_field(value: bytes) -> None:
        digest.update(len(value).to_bytes(8, byteorder="big"))
        digest.update(value)

    def update_path(kind: bytes, path: Path, mode: int, payload: bytes | None = None) -> None:
        nonlocal file_count
        update_field(kind)
        update_field(path.as_posix().encode("utf-8", errors="surrogateescape"))
        update_field(mode.to_bytes(4, byteorder="big"))
        if payload is not None:
            update_field(payload)
        file_count += 1

    for directory, children, filenames in os.walk(ROOT, followlinks=False):
        directory_path = Path(directory)
        relative_directory = directory_path.relative_to(ROOT)
        kept_children: list[str] = []
        for child in sorted(children):
            child_path = directory_path / child
            relative = relative_directory / child
            if source_state_excludes(relative):
                continue
            if child_path.is_symlink():
                try:
                    update_path(
                        b"symlink",
                        relative,
                        child_path.lstat().st_mode & 0o777,
                        os.fsencode(os.readlink(child_path)),
                    )
                except OSError as error:
                    raise EvidenceError(
                        f"cannot read workspace source symlink: {child_path}"
                    ) from error
            else:
                kept_children.append(child)
        children[:] = kept_children
        for filename in sorted(filenames):
            path = directory_path / filename
            relative = relative_directory / filename
            if source_state_excludes(relative):
                continue
            try:
                if path.is_symlink():
                    update_path(
                        b"symlink",
                        relative,
                        path.lstat().st_mode & 0o777,
                        os.fsencode(os.readlink(path)),
                    )
                    continue
                if not path.is_file():
                    continue
                stat = path.stat()
                update_path(
                    b"file",
                    relative,
                    stat.st_mode & 0o777,
                    stat.st_size.to_bytes(8, byteorder="big"),
                )
                observed_bytes = 0
                with path.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
                        observed_bytes += len(block)
                if observed_bytes != stat.st_size or path.stat().st_size != stat.st_size:
                    raise EvidenceError(
                        f"workspace source changed while recording identity: {path}"
                    )
            except OSError as error:
                raise EvidenceError(f"cannot read workspace source file: {path}") from error
    return {
        "kind": "workspace-tree-sha256",
        "file_count": file_count,
        "sha256": digest.hexdigest(),
    }


def git_source_state_read_environment() -> dict[str, str]:
    """Preserve caller settings while making Git source-state reads index-safe."""

    environment = dict(os.environ)
    environment.update(GIT_SOURCE_STATE_READ_ENVIRONMENT)
    return environment


def current_head_source_state() -> dict[str, Any]:
    """Describe checked-out Git state, or the mounted source tree when Git is absent."""

    git = shutil.which("git")
    if git is None:
        return workspace_tree_source_state()
    environment = git_source_state_read_environment()
    revision_record = command_record(
        (git, "rev-parse", "--verify", "HEAD"), cwd=ROOT, environment=environment
    )
    status_record = command_record(
        (git, "status", "--porcelain=v1", "--untracked-files=all", "-z"),
        cwd=ROOT,
        environment=environment,
    )
    try:
        revision = byte_record_payload(revision_record.get("stdout"), "git revision").decode(
            "ascii", errors="strict"
        )
        worktree_status = byte_record_payload(
            status_record.get("stdout"), "git worktree status"
        )
    except (AttributeError, EvidenceError, UnicodeDecodeError):
        return workspace_tree_source_state()
    if (
        revision_record.get("kind") != "process"
        or revision_record.get("status") != 0
        or status_record.get("kind") != "process"
        or status_record.get("status") != 0
        or not re.fullmatch(r"[0-9a-f]{40}\n?", revision)
    ):
        return workspace_tree_source_state()
    return {
        "kind": "git",
        "revision": revision.strip(),
        "worktree_clean": worktree_status == b"",
        "worktree_status": bytes_record(worktree_status),
    }


def validate_current_head_source_state(state: object, subject: str) -> dict[str, Any]:
    """Validate the small source-state schema stored with one Cargo build."""

    if not isinstance(state, dict):
        raise EvidenceError(f"{subject} source state is invalid")
    kind = state.get("kind")
    if kind == "unavailable":
        if set(state) != {"kind", "reason"} or not isinstance(state.get("reason"), str):
            raise EvidenceError(f"{subject} unavailable source state is invalid")
        return dict(state)
    if kind == "workspace-tree-sha256":
        if set(state) != {"kind", "file_count", "sha256"}:
            raise EvidenceError(f"{subject} workspace source state is invalid")
        if type(state.get("file_count")) is not int or state["file_count"] < 0:
            raise EvidenceError(f"{subject} workspace source file count is invalid")
        digest = state.get("sha256")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise EvidenceError(f"{subject} workspace source digest is invalid")
        return dict(state)
    if kind != "git" or set(state) != {
        "kind",
        "revision",
        "worktree_clean",
        "worktree_status",
    }:
        raise EvidenceError(f"{subject} source state is invalid")
    revision = state.get("revision")
    if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise EvidenceError(f"{subject} source revision is invalid")
    if type(state.get("worktree_clean")) is not bool:
        raise EvidenceError(f"{subject} worktree cleanliness is invalid")
    payload = byte_record_payload(state.get("worktree_status"), f"{subject} worktree status")
    if state["worktree_clean"] != (payload == b""):
        raise EvidenceError(f"{subject} worktree cleanliness contradicted its status")
    return dict(state)


def require_clean_git_source_state(state: object, subject: str) -> dict[str, Any]:
    """Accept only a clean Git worktree as current-head source evidence."""

    normalized = validate_current_head_source_state(state, subject)
    if normalized.get("kind") != "git":
        raise EvidenceError(f"{subject} requires an available Git source state")
    if not normalized["worktree_clean"]:
        raise EvidenceError(f"{subject} requires a clean Git source tree")
    return normalized


def stable_source_member_record(
    path: Path, pin: Mapping[str, str], source_member: str
) -> dict[str, Any]:
    """Record an archive member without retaining its deleted extraction path."""

    record = file_record(path)
    record["path"] = str(PurePosixPath(pin["archive_root"]) / PurePosixPath(source_member))
    return record


def normalize_source_paths(
    value: object, source_root: Path, pin: Mapping[str, str]
) -> Any:
    """Replace one random extraction root throughout a durable process record."""

    source = str(source_root)
    stable = str(PurePosixPath("<pinned-source>") / pin["archive_root"])

    def normalize(item: object) -> Any:
        if isinstance(item, str):
            return item.replace(source, stable)
        if isinstance(item, list):
            return [normalize(element) for element in item]
        if isinstance(item, tuple):
            return tuple(normalize(element) for element in item)
        if isinstance(item, dict):
            if {"bytes", "sha256", "hex"}.issubset(item):
                try:
                    payload = bytes.fromhex(str(item["hex"]))
                except ValueError as error:
                    raise EvidenceError("process byte record contains invalid hex") from error
                normalized = payload.replace(source.encode(), stable.encode())
                record = dict(item)
                record.update(bytes_record(normalized))
                return record
            return {key: normalize(element) for key, element in item.items()}
        return item

    return normalize(value)


def relative_path(path: Path, root: Path | None = None) -> str:
    resolved = path.expanduser().resolve()
    if root is not None:
        try:
            return str(resolved.relative_to(root.resolve()))
        except ValueError:
            pass
    return str(resolved)


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
            exactly_matches(left, right) for left, right in zip(observed, expected)
        )
    return observed == expected


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read canonical upstream stress contract: {path}") from error
    if not isinstance(value, dict):
        raise EvidenceError("canonical upstream stress contract must be a JSON object")
    return value


def load_mimalloc_pin(path: Path = UPSTREAMS_PATH) -> dict[str, str]:
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise EvidenceError(f"cannot read upstream pin file: {path}") from error
    pin = raw.get("mimalloc")
    if not isinstance(pin, dict):
        raise EvidenceError("compat/upstreams.toml requires a [mimalloc] table")
    required = (
        "version",
        "repository",
        "tag",
        "source",
        "sha256",
        "tag_object",
        "revision",
        "archive_root",
    )
    if any(not isinstance(pin.get(key), str) or not pin[key] for key in required):
        raise EvidenceError("mimalloc pin has a missing or invalid required identity")
    normalized = {key: str(pin[key]) for key in required}
    if not exactly_matches(normalized, FIXED_PIN):
        raise EvidenceError("canonical upstream stress is fixed to mimalloc v3.5.0")
    return normalized


def source_cli_enables_large_objects(scale: int) -> bool:
    """Mirror the archived source's strict ``SCALE > 100`` enablement check."""

    return scale > SOURCE_LARGE_OBJECT_SCALE_THRESHOLD


def expected_matrix_case(workers: int, scale: int, iterations: int) -> dict[str, Any]:
    """Describe one unchanged-source invocation from the closed stress matrix."""

    arguments = [str(workers), str(scale), str(iterations)]
    large_object_suffix = (
        SOURCE_LARGE_OBJECT_STDOUT_SUFFIX
        if source_cli_enables_large_objects(scale)
        else ""
    )
    return {
        "id": f"workers-{workers}-scale-{scale}-iterations-{iterations}",
        "workers": workers,
        "scale": scale,
        "iterations": iterations,
        "arguments": arguments,
        "expected_stdout": (
            f"Using {workers} threads with a {scale}% load-per-thread and {iterations} "
            f"iterations{large_object_suffix}\n"
        ),
        "expected_stderr": "",
        "expected_exit_status": 0,
    }


def expected_execution_matrix() -> list[dict[str, Any]]:
    """Return the source-argument progression required by the native contract."""

    return [
        *(expected_matrix_case(count, 1, 1) for count in CANONICAL_UPSTREAM_STRESS_WORKERS),
        *(expected_matrix_case(count, 2, 2) for count in CANONICAL_UPSTREAM_STRESS_WORKERS),
        *(
            expected_matrix_case(
                count,
                SOURCE_LARGE_OBJECT_MATRIX_SCALE,
                SOURCE_LARGE_OBJECT_MATRIX_ITERATIONS,
            )
            for count in CANONICAL_UPSTREAM_STRESS_WORKERS
        ),
    ]


def expected_large_object_mode() -> dict[str, Any]:
    """Record the exact archived-source large-object activation boundary."""

    return {
        "status": "source-cli-enabled",
        "source_enablement": {
            "parameter": "SCALE",
            "operator": ">",
            "threshold": SOURCE_LARGE_OBJECT_SCALE_THRESHOLD,
            "expected_stdout_suffix": SOURCE_LARGE_OBJECT_STDOUT_SUFFIX,
        },
        "matrix_case_ids": [
            expected_matrix_case(
                workers,
                SOURCE_LARGE_OBJECT_MATRIX_SCALE,
                SOURCE_LARGE_OBJECT_MATRIX_ITERATIONS,
            )["id"]
            for workers in CANONICAL_UPSTREAM_STRESS_WORKERS
        ],
        "reason": (
            "The unmodified pinned source sets allow_large_objects only after source CLI "
            "parsing when SCALE > 100. Each listed case uses SCALE=101; no compile-time "
            "large-mode define is accepted. A passing row records source-mode activation "
            "and completed bounded workload execution, not that every probabilistic large "
            "allocation succeeded."
        ),
    }


def expected_contract(pin: Mapping[str, str]) -> dict[str, Any]:
    """Return the closed contract this lane accepts.

    Keeping the values in one executable shape means a prose edit cannot
    silently turn the canonical source gate into another adapted fixture.
    """

    upstream = {
        "project": "microsoft/mimalloc",
        "version": pin["version"],
        "tag": pin["tag"],
        "tag_object": pin["tag_object"],
        "revision": pin["revision"],
        "repository": pin["repository"],
        "archive_source": pin["source"],
        "archive_path": ".work/allocator-cache/mimalloc-3.5.0.tar.gz",
        "archive_root": pin["archive_root"],
        "archive_sha256": pin["sha256"],
    }
    target_id = "linux-aarch64-little-endian"
    backend_id = "crabc-libc-native-mimalloc-shadow"
    return {
        "format": 7,
        "schema": "crabc-mimalloc-canonical-upstream-stress",
        "scope": {
            "claim": "one canonical executable inventory of the exact pinned upstream test/test-stress.c through the selected native-mimalloc-shadow crabc libc",
            "not_a_promotion_gate": True,
            "purpose": "record the first unavailable prerequisite, build/link failure, or ordered matrix result without changing upstream scheduling, transfer ownership, or initial-thread cleanup",
            "first_fact_rule": "Run each listed case in order in one fresh process with one watchdog. Stop after the first non-pass; do not retry, shrink, or reschedule a case. A blocked prerequisite starts no stress process.",
        },
        "upstream": upstream,
        "target_inventory": {
            "selected": target_id,
            "targets": [
                {
                    "id": target_id,
                    "architecture": "aarch64",
                    "byte_order": "little",
                    "execution": "native-only",
                    "kernel_baseline": "5.10",
                    "status": "applicable",
                    "system": "Linux",
                }
            ],
        },
        "backend_inventory": {
            "selected": backend_id,
            "backends": [
                {
                    "id": backend_id,
                    "target": target_id,
                    "status": "applicable-nondefault",
                    "allocator_feature": "native-mimalloc-shadow",
                    "c_backend_fallback": False,
                    "runtime_selection": "the selected target directory's libc.so via LD_LIBRARY_PATH",
                    "artifact_attestation": {
                        "cargo_compiler_artifact": {
                            "build_record_format": 1,
                            "build_record_schema": "crabc-selected-libc-cargo-build",
                            "cargo_command": [
                                "cargo",
                                "build",
                                "--locked",
                                "-p",
                                "crabc-libc",
                                "--features",
                                "native-mimalloc-shadow",
                                "--profile",
                                "dev",
                                "--message-format=json-render-diagnostics",
                            ],
                            "package_id_suffix": "#crabc-libc@0.3.0",
                            "manifest_path": "libc/Cargo.toml",
                            "target": {
                                "kind": ["cdylib", "staticlib"],
                                "crate_types": ["cdylib", "staticlib"],
                                "name": "c",
                                "src_path": "libc/src/lib.rs",
                                "edition": "2021",
                                "doc": True,
                                "doctest": False,
                                "test": False,
                            },
                            "semantic_profile": "dev",
                            "profile": {
                                "opt_level": "2",
                                "debuginfo": 2,
                                "debug_assertions": True,
                                "overflow_checks": False,
                                "test": False,
                            },
                            "exact_features": ["default", "native-mimalloc-shadow"],
                            "artifacts": {
                                "selected_shared_libc": "libc.so",
                                "selected_static_libc": "libc.a",
                            },
                        },
                        "exported_free_route": {
                            "symbol": "free",
                            "required_callee_suffix": "native_free>",
                            "forbidden_callee_suffix": "mi_free>",
                        },
                    },
                }
            ],
        },
        "fixture": {
            "archive_member": "test/test-stress.c",
            "sha256": "e2bed5f2be12239b1fa696dafffda384d19140cb50a6ee2f6e096f70934d73df",
            "upstream_file_license": "MIT",
            "upstream_notice": "Copyright (c) 2018-2026 Microsoft Research, Daan Leijen",
        },
        "source_adaptation": {
            "kind": "upstream-preprocessor-symbol-selection-only",
            "compile_defines": ["USE_STD_MALLOC"],
            "patches": [],
            "forbidden_changes": [
                "checked-in source copy or patch",
                "worker scheduling change",
                "transfer ownership change",
                "post-worker cleanup relocation",
                "initial-thread cleanup change",
            ],
            "explanation": "USE_STD_MALLOC is an upstream conditional that binds custom allocation names to calloc, realloc, and free. The archived source is compiled byte-for-byte after its hash is verified. Worker count, scale, and iteration, including the source's SCALE > 100 large-object enablement, are source command-line arguments, never replacement compile-time scheduler or large-mode defines.",
        },
        "execution": {
            "matrix": expected_execution_matrix(),
            "source_randomness": {
                "caller_override": "none",
                "c_library_seed": "0x7feb352d",
                "kind": "upstream-source-fixed",
                "pthread_schedule": "nondeterministic",
                "worker_seed_rule": "(tid + 1) * 43",
            },
            "watchdog": {
                "process_retries": 0,
                "scope": "each fresh matrix process",
                "seconds": 30,
                "timeout_result": "failed",
            },
            "process_attempts_per_case": 1,
            "stop_after_first_nonpass": True,
            "large_object_mode": expected_large_object_mode(),
            "scheduler_and_ownership": [
                "The unmodified upstream main_participates value remains false.",
                "The unmodified upstream run_os_threads creates and joins the requested pthread workers before returning to test_stress.",
                "The unmodified upstream shared transfer buffer carries live allocations between source workers and source iterations.",
                "After run_os_threads returns, the unmodified initial thread performs free_items cleanup of transferred objects in test_stress.",
            ],
        },
        "capability": {
            "id": "canonical-unmodified-upstream-pthread-stress",
            "checked_in_status": "not-run",
            "status_values": ["not-run", "blocked", "failed", "passed"],
            "required_worker_counts": [1, 2, 4, 8],
            "evidence_scope": "shadow_subset",
            "blocked_is_failure_closed": True,
            "pass_condition": "Native Linux/AArch64 executes all matrix cases through the attested native-mimalloc-shadow backend with the expected exit status and exact streams before every watchdog expires.",
            "non_claims": [
                "Contract validation is not native runtime capability evidence.",
                "A blocked prerequisite, build failure, link-boundary failure, timeout, signal, stream mismatch, or partial matrix is not a capability pass.",
                "This nondefault shadow subset does not complete Gate 5D, selected-shadow acceptance, or allocator promotion.",
                "A passing source-cli-enabled row records source-mode activation and a bounded workload attempt, not a proof that every probabilistic large allocation succeeded.",
            ],
        },
        "report": {
            "format": 7,
            "schema": "crabc-mimalloc-canonical-upstream-stress-report",
            "path": ".work/reports/allocator/upstream-stress/latest.json",
            "atomic_publish": True,
            "file_artifact_record_fields": ["path", "bytes", "sha256"],
            "byte_stream_record_fields": ["bytes", "sha256", "hex"],
            "fixture_elf_fields": [
                "dynamic_dependencies",
                "elf_identity",
                "interpreter",
            ],
            "source_path_normalization": {
                "artifact": "mimalloc-3.5.0/test/test-stress.c",
                "extraction_root": "<pinned-source>/mimalloc-3.5.0",
            },
            "current_head": {
                "build_record_format": CURRENT_HEAD_BUILD_RECORD_FORMAT,
                "build_record_schema": CURRENT_HEAD_BUILD_RECORD_SCHEMA,
                "required_before_stress_compile": True,
                "git_read_environment": dict(GIT_SOURCE_STATE_READ_ENVIRONMENT),
                "capture_source": {
                    "kind": "git",
                    "worktree_clean": True,
                    "unchanged_during_selected_libc_build": True,
                },
                "execution_source": {
                    "kind": "git",
                    "worktree_clean": True,
                    "matches_selected_libc_build": True,
                },
                "report_fields": ["status", "record", "source"],
                "status_values": ["not-attested", "attested"],
            },
            "artifact_ids": [
                "contract",
                "upstream_archive",
                "source_member",
                "owned_sysroot_manifest",
                "owned_sysroot_purity",
                "owned_compiler",
                "selected_loader",
                "staged_canonical_loader",
                "selected_libc",
                "selected_static_libc",
                "selected_backend_build_record",
                "stress_binary",
            ],
            "execution_scoped_artifact_ids": ["staged_canonical_loader"],
        },
        "compile_requirements": {
            "allocator_feature": "native-mimalloc-shadow",
            "compiler": "crabc-cc from the installed owned crabc sysroot",
            "language": "C11",
            "compile_flags": ["-O2", "-DNDEBUG", "-fPIE", "-pie", "-ftls-model=initial-exec", "-pthread"],
            "include_directories": ["<extracted-root>/include"],
            "link_flags": ["-Wl,--allow-shlib-undefined"],
            "link_libraries": ["-lc"],
            "expected_dynamic_dependencies": ["libc.so"],
            "expected_elf_identity": {
                "class": "ELF64",
                "endianness": "little",
                "machine": "AArch64",
            },
            "expected_interpreter": "/lib/ld-crabc-aarch64.so.1",
            "canonical_loader": "/lib/ld-crabc-aarch64.so.1",
            "owned_test_launcher": "scripts/run_owned_test_suite.py",
            "selected_runtime_directory": "target/debug",
            "selected_libc_build_record": ".work/target/compat/allocator/upstream-stress/selected-libc-build.json",
            "isolated_output_directory": ".work/target/compat/allocator/upstream-stress",
            "sysroot_purity": {
                "required_crt_sysroot_pure_rust": True,
                "allowed_full_runtime_purity": [
                    {
                        "full_runtime_pure_rust": True,
                        "full_runtime_purity_status": "passed",
                    },
                    {
                        "full_runtime_pure_rust": False,
                        "full_runtime_purity_status": "blocked_by_native_allocator",
                    },
                ],
                "reason": "The installed driver and CRT/sysroot boundary must pass their owned purity audit. The separately recorded native-allocator blocker is only accepted in its exact documented form because this lane dynamically selects the native-mimalloc-shadow libc after the owned sysroot is built.",
            },
            "notes": "The caller captures the exact Cargo compiler-artifact emitted while building crabc-libc with native-mimalloc-shadow in the dev profile plus a current-head companion that records source state before and after Cargo. Before compiling the exact archive member or starting a stress process, the lane requires that companion to bind an unchanged clean Git source at capture and execution to both named libc outputs and the Cargo build record. It then selects the attested debug libc with LD_LIBRARY_PATH and has no source-level adaptation beyond the upstream USE_STD_MALLOC symbol. It records the owned sysroot purity record and blocks if that record is missing, rejected, or differs from the exact documented native-allocator exception.",
        },
    }


def load_contract() -> tuple[dict[str, Any], dict[str, str]]:
    pin = load_mimalloc_pin()
    contract = read_json(CONTRACT_PATH)
    expected = expected_contract(pin)
    if not exactly_matches(contract, expected):
        raise EvidenceError("canonical upstream stress contract drifted from its closed execution boundary")
    return contract, pin


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--offline",
        action="store_true",
        help="require the SHA-256-verified pinned archive to already be cached",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate the closed source/target/backend/report contract without compiling or running it",
    )
    parser.add_argument(
        "--diagnose",
        action="store_true",
        help=(
            "run only the closed matrix's first 1-worker/scale-1/iteration-1 "
            "current-head diagnostic; this is not a full-matrix capability pass"
        ),
    )
    parser.add_argument(
        "--post-owner-exit-concurrent-free",
        action="store_true",
        help=(
            "run only the closed matrix's smallest two-worker 2/1/1 source case; "
            "the unchanged upstream workers may concurrently exchange/free transfer slots, "
            "then its initial thread frees surviving transfers after both workers exit; "
            "this is not a full-matrix capability pass"
        ),
    )
    parser.add_argument(
        "--target-dir",
        type=Path,
        default=Path(os.environ.get("CRABC_TARGET_DIR", DEFAULT_TARGET_DIR)),
        help="selected debug libc and loader directory (default: CRABC_TARGET_DIR or target/debug)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(os.environ.get("CRABC_UPSTREAM_STRESS_OUTPUT_DIR", DEFAULT_OUTPUT_DIR)),
        help="isolated fixture output directory (default: CRABC_UPSTREAM_STRESS_OUTPUT_DIR or .work/target/compat/allocator/upstream-stress)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help=(
            "JSON report path (defaults to CRABC_UPSTREAM_STRESS_REPORT or "
            ".work/reports/allocator/upstream-stress/latest.json; --diagnose uses "
            "CRABC_UPSTREAM_STRESS_DIAGNOSTIC_REPORT or current-head.json; "
            "--post-owner-exit-concurrent-free uses "
            "CRABC_UPSTREAM_STRESS_POST_OWNER_EXIT_CONCURRENT_FREE_REPORT or "
            "post-owner-exit-concurrent-free.json)"
        ),
    )
    parser.add_argument(
        "--libc-build-record",
        type=Path,
        default=Path(
            os.environ.get("CRABC_UPSTREAM_STRESS_LIBC_BUILD_RECORD", DEFAULT_LIBC_BUILD_RECORD)
        ),
        help="exact Cargo compiler-artifact build record for the selected dev libc (default under .work/target)",
    )
    parser.add_argument(
        "--capture-selected-libc-build",
        type=Path,
        help=(
            "build the selected libc and atomically write its exact Cargo compiler-artifact "
            "record plus current-head companion"
        ),
    )
    parser.add_argument(
        "--current-head-build-record",
        type=Path,
        default=None,
        help=(
            "current-head companion to the selected Cargo build record; required by "
            "stress execution and written by --capture-selected-libc-build"
        ),
    )
    parsed = parser.parse_args(arguments)
    if parsed.diagnose and parsed.post_owner_exit_concurrent_free:
        parser.error("--diagnose and --post-owner-exit-concurrent-free cannot be combined")
    one_case_diagnostic = parsed.diagnose or parsed.post_owner_exit_concurrent_free
    if parsed.check and one_case_diagnostic:
        parser.error("--check and one-case diagnostics cannot be combined")
    if parsed.capture_selected_libc_build is not None and one_case_diagnostic:
        parser.error("--capture-selected-libc-build and one-case diagnostics are separate phases")
    if parsed.report is None:
        if parsed.diagnose:
            parsed.report = Path(
                os.environ.get(
                    "CRABC_UPSTREAM_STRESS_DIAGNOSTIC_REPORT", DEFAULT_DIAGNOSTIC_REPORT
                )
            )
        elif parsed.post_owner_exit_concurrent_free:
            parsed.report = Path(
                os.environ.get(
                    "CRABC_UPSTREAM_STRESS_POST_OWNER_EXIT_CONCURRENT_FREE_REPORT",
                    DEFAULT_POST_OWNER_EXIT_CONCURRENT_FREE_REPORT,
                )
            )
        else:
            parsed.report = Path(os.environ.get("CRABC_UPSTREAM_STRESS_REPORT", DEFAULT_REPORT))
    if parsed.current_head_build_record is None:
        anchor = (
            parsed.capture_selected_libc_build
            if parsed.capture_selected_libc_build is not None
            else parsed.libc_build_record
        )
        parsed.current_head_build_record = current_head_build_record_path(anchor)
    return parsed


def diagnostic_output_dir(args: argparse.Namespace) -> Path:
    """Avoid overwriting the canonical full-matrix fixture with one-case output."""

    name = (
        "post-owner-exit-concurrent-free"
        if args.post_owner_exit_concurrent_free
        else "current-head"
    )
    return args.output_dir.expanduser().resolve() / name


def archive_path(pin: Mapping[str, str]) -> Path:
    return CACHE / f"mimalloc-{pin['version']}.tar.gz"


def tag_attestation_path(pin: Mapping[str, str]) -> Path:
    return CACHE / f"mimalloc-{pin['version']}.tag.json"


def verify_archive(path: Path, pin: Mapping[str, str]) -> Path:
    if not path.is_file():
        raise EvidenceError(f"pinned mimalloc archive is unavailable: {path}")
    actual = sha256_file(path)
    if actual != pin["sha256"]:
        raise EvidenceError(
            "pinned mimalloc archive SHA-256 mismatch: "
            f"expected {pin['sha256']}, observed {actual}"
        )
    return path


def fetch_archive(pin: Mapping[str, str], *, offline: bool) -> Path:
    archive = archive_path(pin)
    if archive.exists():
        verified = verify_archive(archive, pin)
        verify_tag_identity(pin, offline=offline)
        return verified
    if offline:
        raise EvidenceError(
            "verified pinned mimalloc archive is absent from offline cache: "
            f"{archive}"
        )
    CACHE.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(pin["source"], timeout=30) as response:
            payload = response.read()
    except urllib.error.URLError as error:
        raise EvidenceError(f"failed to download pinned mimalloc archive: {error}") from error
    digest = hashlib.sha256(payload).hexdigest()
    if digest != pin["sha256"]:
        raise EvidenceError(
            "downloaded pinned mimalloc archive SHA-256 mismatch: "
            f"expected {pin['sha256']}, observed {digest}"
        )
    with tempfile.NamedTemporaryFile(dir=CACHE, prefix="mimalloc-download-", delete=False) as stream:
        stream.write(payload)
        staged = Path(stream.name)
    os.replace(staged, archive)
    verified = verify_archive(archive, pin)
    verify_tag_identity(pin, offline=False)
    return verified


def extract_exact_archive(archive: Path, pin: Mapping[str, str], destination: Path) -> Path:
    """Extract the oracle safely, retaining its root exactly once."""

    destination.mkdir(parents=True, exist_ok=True)
    root_name = pin["archive_root"]
    root = destination / root_name
    try:
        with tarfile.open(archive, "r:gz") as stream:
            members = stream.getmembers()
            for member in members:
                name = PurePosixPath(member.name)
                if not name.parts or name.parts[0] != root_name or ".." in name.parts:
                    raise EvidenceError(f"pinned archive member escapes expected root: {member.name}")
                if not (member.isdir() or member.isfile()):
                    raise EvidenceError(
                        f"pinned archive contains unsupported link/device member: {member.name}"
                    )
            for member in members:
                output = destination.joinpath(*PurePosixPath(member.name).parts)
                if member.isdir():
                    output.mkdir(parents=True, exist_ok=True)
                    continue
                output.parent.mkdir(parents=True, exist_ok=True)
                source = stream.extractfile(member)
                if source is None:
                    raise EvidenceError(f"cannot read pinned archive member: {member.name}")
                with source, output.open("wb") as target:
                    shutil.copyfileobj(source, target)
    except (OSError, tarfile.TarError) as error:
        raise EvidenceError(f"cannot extract pinned mimalloc archive: {archive}") from error
    if not root.is_dir():
        raise EvidenceError(f"pinned archive root was not extracted: {root}")
    return root


def require_native_aarch64() -> None:
    if (
        platform.system() != "Linux"
        or platform.machine() != "aarch64"
        or sys.byteorder != "little"
    ):
        raise BlockedPrerequisite(
            "native-linux-aarch64",
            "canonical upstream stress requires native Linux/AArch64 little-endian; "
            f"observed {platform.system()}/{platform.machine()}/{sys.byteorder}-endian",
            {
                "observed_architecture": platform.machine(),
                "observed_byte_order": sys.byteorder,
                "observed_system": platform.system(),
                "required_architecture": "aarch64",
                "required_byte_order": "little",
                "required_system": "Linux",
            },
        )
    release = platform.release()
    version = re.match(r"^(\d+)\.(\d+)", release)
    if version is None or (int(version.group(1)), int(version.group(2))) < (5, 10):
        raise BlockedPrerequisite(
            "native-linux-kernel-baseline",
            "canonical upstream stress requires the Linux 5.10 kernel baseline; "
            f"observed {release}",
            {
                "observed_kernel_release": release,
                "required_kernel_baseline": "5.10",
            },
        )


def require_owned_sysroot_purity(
    sysroot: Path, requirements: Mapping[str, Any]
) -> tuple[Path, dict[str, Any]]:
    """Require the owned compiler boundary without relabeling its purity state."""

    raw_requirement = requirements.get("sysroot_purity")
    if not isinstance(raw_requirement, dict):
        raise EvidenceError("canonical upstream stress contract lacks sysroot purity requirements")
    purity_path = sysroot / "share/crabc/purity.json"
    if not purity_path.is_file() or purity_path.is_symlink():
        raise BlockedPrerequisite(
            "owned-sysroot-purity",
            "canonical upstream stress requires the owned sysroot purity record; "
            f"unavailable: {purity_path}",
            {"purity": str(purity_path), "sysroot": str(sysroot)},
        )
    try:
        purity = json.loads(purity_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BlockedPrerequisite(
            "owned-sysroot-purity",
            "canonical upstream stress cannot read the owned sysroot purity record; "
            f"invalid: {purity_path}",
            {"purity": str(purity_path), "sysroot": str(sysroot)},
        ) from error
    if not isinstance(purity, dict):
        raise BlockedPrerequisite(
            "owned-sysroot-purity",
            "canonical upstream stress requires an object-shaped owned sysroot purity record",
            {"purity": str(purity_path), "sysroot": str(sysroot)},
        )
    if purity.get("crt_sysroot_pure_rust") is not raw_requirement[
        "required_crt_sysroot_pure_rust"
    ]:
        raise BlockedPrerequisite(
            "owned-sysroot-purity",
            "canonical upstream stress requires the owned CRT/sysroot purity contract to pass",
            {
                "purity": str(purity_path),
                "required_crt_sysroot_pure_rust": raw_requirement[
                    "required_crt_sysroot_pure_rust"
                ],
                "observed_crt_sysroot_pure_rust": purity.get("crt_sysroot_pure_rust"),
            },
        )
    allowed = raw_requirement.get("allowed_full_runtime_purity")
    if not isinstance(allowed, list) or not any(
        exactly_matches(
            {
                "full_runtime_pure_rust": purity.get("full_runtime_pure_rust"),
                "full_runtime_purity_status": purity.get("full_runtime_purity_status"),
            },
            candidate,
        )
        for candidate in allowed
    ):
        raise BlockedPrerequisite(
            "owned-sysroot-full-runtime-purity",
            "canonical upstream stress refuses an undocumented owned full-runtime purity state",
            {
                "purity": str(purity_path),
                "observed_full_runtime_pure_rust": purity.get("full_runtime_pure_rust"),
                "observed_full_runtime_purity_status": purity.get(
                    "full_runtime_purity_status"
                ),
                "allowed_full_runtime_purity": allowed,
            },
        )
    return purity_path, purity


def require_runtime_inputs(
    target_dir: Path, requirements: Mapping[str, Any] | None = None
) -> RuntimeInputs:
    if requirements is None:
        requirements = expected_contract(FIXED_PIN)["compile_requirements"]
        assert isinstance(requirements, dict)
    raw_sysroot = os.environ.get("CRABC_TEST_SYSROOT")
    if not raw_sysroot:
        raise BlockedPrerequisite(
            "owned-test-suite-environment",
            "canonical upstream stress requires CRABC_TEST_SYSROOT from "
            "scripts/run_owned_test_suite.py",
            {
                "environment_variable": "CRABC_TEST_SYSROOT",
                "required_launcher": "scripts/run_owned_test_suite.py",
            },
        )
    sysroot = Path(raw_sysroot).expanduser().resolve()
    manifest = sysroot / "share/crabc/manifest.json"
    compiler = sysroot / "bin/crabc-cc"
    if not manifest.is_file() or manifest.is_symlink():
        raise BlockedPrerequisite(
            "owned-sysroot-manifest",
            "canonical upstream stress requires a complete owned crabc sysroot; "
            f"missing manifest: {manifest}",
            {"manifest": str(manifest), "sysroot": str(sysroot)},
        )
    purity_path, purity = require_owned_sysroot_purity(sysroot, requirements)
    if not compiler.is_file() or not os.access(compiler, os.X_OK):
        raise BlockedPrerequisite(
            "owned-sysroot-driver",
            "canonical upstream stress requires the owned crabc C driver; "
            f"unavailable or not executable: {compiler}",
            {"compiler": str(compiler), "sysroot": str(sysroot)},
        )
    target_dir = target_dir.expanduser().resolve()
    selected_libc = target_dir / "libc.so"
    if not selected_libc.is_file() or selected_libc.is_symlink():
        raise BlockedPrerequisite(
            "selected-native-shadow-libc",
            "canonical upstream stress requires the selected native-mimalloc-shadow libc; "
            f"unavailable: {selected_libc}",
            {
                "artifact": str(selected_libc),
                "required_feature": "native-mimalloc-shadow",
            },
        )
    selected_loader = target_dir / "libldso.so"
    if not selected_loader.is_file() or selected_loader.is_symlink():
        raise BlockedPrerequisite(
            "selected-crabc-loader",
            "canonical upstream stress requires the selected crabc loader; "
            f"unavailable: {selected_loader}",
            {"artifact": str(selected_loader)},
        )
    if not CANONICAL_LOADER.is_file() or CANONICAL_LOADER.is_symlink():
        raise BlockedPrerequisite(
            "owned-canonical-loader-staging",
            "canonical upstream stress must run under scripts/run_owned_test_suite.py "
            "canonical-loader staging",
            {
                "canonical_loader": str(CANONICAL_LOADER),
                "required_launcher": "scripts/run_owned_test_suite.py",
            },
        )
    selected_loader_sha256 = sha256_file(selected_loader)
    canonical_loader_sha256 = sha256_file(CANONICAL_LOADER)
    if canonical_loader_sha256 != selected_loader_sha256:
        raise BlockedPrerequisite(
            "owned-canonical-loader-staging",
            "canonical upstream stress requires the staged canonical loader to "
            "match the selected crabc loader exactly",
            {
                "canonical_loader": str(CANONICAL_LOADER),
                "canonical_loader_sha256": canonical_loader_sha256,
                "selected_loader": str(selected_loader),
                "selected_loader_sha256": selected_loader_sha256,
                "required_launcher": "scripts/run_owned_test_suite.py",
            },
        )
    return RuntimeInputs(
        sysroot=sysroot,
        compiler=compiler,
        target_dir=target_dir,
        manifest_path=manifest,
        purity_path=purity_path,
        canonical_loader_path=CANONICAL_LOADER,
        purity=purity,
    )


def command_record(
    command: Sequence[str], *, cwd: Path, environment: Mapping[str, str] | None = None, timeout: int | None = None
) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            env=None if environment is None else dict(environment),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except FileNotFoundError as error:
        return {
            "command": list(command),
            "kind": "execution-error",
            "message": str(error),
            "status": "execution-error",
        }
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout if isinstance(error.stdout, bytes) else b""
        stderr = error.stderr if isinstance(error.stderr, bytes) else b""
        return {
            "command": list(command),
            "kind": "timeout",
            "status": "timeout",
            "stdout": bytes_record(stdout),
            "stderr": bytes_record(stderr),
            "timeout_seconds": timeout,
        }
    return {
        "command": list(command),
        "kind": "process",
        "status": completed.returncode,
        "stdout": bytes_record(completed.stdout),
        "stderr": bytes_record(completed.stderr),
    }


def cached_tag_attestation(pin: Mapping[str, str]) -> dict[str, Any] | None:
    path = tag_attestation_path(pin)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    expected = {
        "format": 1,
        "repository": pin["repository"],
        "tag": pin["tag"],
        "tag_object": pin["tag_object"],
        "revision": pin["revision"],
    }
    return value if exactly_matches(value, expected) else None


def verify_tag_identity(pin: Mapping[str, str], *, offline: bool) -> dict[str, Any]:
    """Verify the annotated v3.5.0 tag before accepting its source archive."""

    cached = cached_tag_attestation(pin)
    if cached is not None:
        return cached
    if offline:
        raise EvidenceError(
            "verified mimalloc tag identity is absent from offline cache: "
            f"{tag_attestation_path(pin)}"
        )
    git = shutil.which("git")
    if git is None:
        raise EvidenceError("git is required to verify the pinned mimalloc annotated tag")
    reference = f"refs/tags/{pin['tag']}"
    peeled = reference + "^{}"
    record = command_record((git, "ls-remote", pin["repository"], reference, peeled), cwd=ROOT)
    if record.get("kind") != "process" or record.get("status") != 0:
        raise EvidenceError(f"mimalloc annotated tag identity probe failed: {record}")
    stdout = record.get("stdout")
    if not isinstance(stdout, dict):
        raise EvidenceError("mimalloc annotated tag identity probe had no stdout record")
    identities: dict[str, str] = {}
    for line in bytes.fromhex(str(stdout["hex"])).decode("utf-8", errors="strict").splitlines():
        object_id, separator, name = line.partition("\t")
        if separator and re.fullmatch(r"[0-9a-f]{40}", object_id):
            identities[name] = object_id
    if identities.get(reference) != pin["tag_object"] or identities.get(peeled) != pin["revision"]:
        raise EvidenceError(
            "mimalloc annotated tag identity mismatch: "
            f"expected tag {pin['tag_object']} peeled {pin['revision']}, "
            f"observed tag {identities.get(reference)!r} peeled {identities.get(peeled)!r}"
        )
    attestation = {
        "format": 1,
        "repository": pin["repository"],
        "tag": pin["tag"],
        "tag_object": pin["tag_object"],
        "revision": pin["revision"],
    }
    write_json(tag_attestation_path(pin), attestation)
    return attestation


def dynamic_dependencies(binary: Path) -> list[str]:
    readelf = shutil.which("readelf")
    if readelf is None:
        raise EvidenceError("readelf is required to verify the fixture's dynamic dependency boundary")
    record = command_record((readelf, "-d", str(binary)), cwd=ROOT)
    if record.get("status") != 0:
        raise EvidenceError(f"readelf could not inspect canonical stress fixture: {record}")
    stderr = record["stderr"]
    stdout = record["stdout"]
    assert isinstance(stderr, dict) and isinstance(stdout, dict)
    if stderr["bytes"] != 0:
        raise EvidenceError("readelf wrote diagnostics while inspecting canonical stress fixture")
    output = bytes.fromhex(str(stdout["hex"])).decode("utf-8", errors="strict")
    return re.findall(r"\(NEEDED\).*?\[(.*?)\]", output)


def parse_elf_identity(header: str) -> dict[str, object]:
    """Normalize the three target identity fields emitted by ``readelf -h``."""

    class_match = re.search(r"(?m)^\s*Class:\s*(\S+)\s*$", header)
    data_match = re.search(r"(?m)^\s*Data:\s*(.+?)\s*$", header)
    machine_match = re.search(r"(?m)^\s*Machine:\s*(.+?)\s*$", header)
    data = data_match.group(1) if data_match is not None else None
    if data is not None and "little endian" in data:
        endianness: str | None = "little"
    elif data is not None and "big endian" in data:
        endianness = "big"
    else:
        endianness = None
    return {
        "class": class_match.group(1) if class_match is not None else None,
        "endianness": endianness,
        "machine": machine_match.group(1) if machine_match is not None else None,
    }


def parse_program_interpreters(program_headers: str) -> list[str]:
    return [
        value.strip()
        for value in re.findall(
            r"(?m)^\s*\[Requesting program interpreter:\s*([^\]]+)\]\s*$",
            program_headers,
        )
    ]


def audit_fixture_elf(binary: Path, contract: Mapping[str, Any]) -> dict[str, Any]:
    """Attest the exact executable the runner will pass to ``execve``."""

    requirements = contract.get("compile_requirements")
    if not isinstance(requirements, dict):
        raise EvidenceError("canonical stress contract lacks compile requirements")
    readelf = shutil.which("readelf")
    if readelf is None:
        raise EvidenceError("readelf is required to attest the canonical stress fixture")
    header = command_text(
        command_record((readelf, "-h", str(binary)), cwd=ROOT),
        "canonical stress fixture ELF identity inspection",
    )
    identity = parse_elf_identity(header)
    expected_identity = requirements["expected_elf_identity"]
    if identity != expected_identity:
        raise ArtifactContractError("elf-identity", identity, expected_identity)
    program_headers = command_text(
        command_record(
            (readelf, "--wide", "--program-headers", str(binary)), cwd=ROOT
        ),
        "canonical stress fixture PT_INTERP inspection",
    )
    interpreters = parse_program_interpreters(program_headers)
    expected_interpreter = requirements["expected_interpreter"]
    if interpreters != [expected_interpreter]:
        observed: object = interpreters[0] if len(interpreters) == 1 else interpreters
        raise ArtifactContractError("pt-interp", observed, expected_interpreter)
    dependencies = dynamic_dependencies(binary)
    expected_dependencies = requirements["expected_dynamic_dependencies"]
    if dependencies != expected_dependencies:
        raise ArtifactContractError("dt-needed", dependencies, expected_dependencies)
    return {
        "dynamic_dependencies": dependencies,
        "elf_identity": identity,
        "interpreter": interpreters[0],
    }


def command_text(record: Mapping[str, Any], subject: str) -> str:
    """Require one successful tool observation and decode its exact stdout."""

    if record.get("kind") != "process" or record.get("status") != 0:
        raise EvidenceError(f"{subject} failed: {record}")
    stdout = record.get("stdout")
    stderr = record.get("stderr")
    if not isinstance(stdout, dict) or not isinstance(stderr, dict):
        raise EvidenceError(f"{subject} omitted byte-stream records")
    if stderr.get("bytes") != 0:
        raise EvidenceError(f"{subject} wrote diagnostics: {record}")
    try:
        return bytes.fromhex(str(stdout["hex"])).decode("utf-8", errors="strict")
    except (KeyError, ValueError, UnicodeDecodeError) as error:
        raise EvidenceError(f"{subject} produced an invalid stdout record") from error


def cargo_artifact_contract(expectation: Mapping[str, Any]) -> dict[str, Any]:
    artifact = expectation.get("cargo_compiler_artifact")
    if not isinstance(artifact, dict):
        raise EvidenceError("native backend inventory lacks its Cargo compiler-artifact contract")
    return dict(artifact)


def expected_cargo_artifact_paths(
    target_dir: Path, artifact_contract: Mapping[str, Any]
) -> dict[str, Path]:
    filenames = artifact_contract.get("artifacts")
    if (
        not isinstance(filenames, dict)
        or set(filenames) != {"selected_shared_libc", "selected_static_libc"}
        or not all(isinstance(value, str) and value for value in filenames.values())
    ):
        raise EvidenceError("native backend inventory has an invalid Cargo artifact filename map")
    resolved_target = target_dir.expanduser().resolve()
    return {
        artifact_id: (resolved_target / filename).resolve()
        for artifact_id, filename in filenames.items()
    }


def validate_compiler_artifact(
    compiler_artifact: object,
    target_dir: Path,
    artifact_contract: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the exact crabc-libc compiler-artifact emitted by one Cargo build."""

    if not isinstance(compiler_artifact, dict):
        raise EvidenceError("selected libc build record omits its Cargo compiler-artifact")
    required_fields = {
        "reason",
        "package_id",
        "manifest_path",
        "target",
        "profile",
        "features",
        "filenames",
        "executable",
        "fresh",
    }
    if set(compiler_artifact) != required_fields:
        raise EvidenceError("selected libc Cargo compiler-artifact field inventory drifted")
    if compiler_artifact.get("reason") != "compiler-artifact":
        raise EvidenceError("selected libc build record is not a Cargo compiler-artifact")
    package_id = compiler_artifact.get("package_id")
    package_suffix = artifact_contract.get("package_id_suffix")
    if (
        not isinstance(package_id, str)
        or not isinstance(package_suffix, str)
        or not package_id.endswith(package_suffix)
    ):
        raise EvidenceError("selected libc Cargo package identity drifted")

    manifest_path = artifact_contract.get("manifest_path")
    if not isinstance(manifest_path, str) or not manifest_path:
        raise EvidenceError("native backend inventory has an invalid Cargo manifest path")
    try:
        observed_manifest = Path(str(compiler_artifact["manifest_path"])).resolve()
    except (KeyError, TypeError) as error:
        raise EvidenceError("selected libc Cargo manifest path is invalid") from error
    if observed_manifest != (ROOT / manifest_path).resolve():
        raise EvidenceError("selected libc Cargo manifest identity drifted")

    target = compiler_artifact.get("target")
    expected_target = artifact_contract.get("target")
    if not isinstance(target, dict) or not isinstance(expected_target, dict):
        raise EvidenceError("selected libc Cargo target identity is invalid")
    normalized_target = dict(target)
    src_path = normalized_target.get("src_path")
    expected_src_path = expected_target.get("src_path")
    if not isinstance(src_path, str) or not isinstance(expected_src_path, str):
        raise EvidenceError("selected libc Cargo target source path is invalid")
    normalized_target["src_path"] = relative_path(Path(src_path), ROOT)
    if not exactly_matches(normalized_target, expected_target):
        raise EvidenceError("selected libc Cargo target identity drifted")

    expected_profile = artifact_contract.get("profile")
    if not exactly_matches(compiler_artifact.get("profile"), expected_profile):
        raise EvidenceError("selected libc Cargo semantic profile drifted")
    features = compiler_artifact.get("features")
    expected_features = artifact_contract.get("exact_features")
    if (
        not isinstance(features, list)
        or not all(isinstance(feature, str) and feature for feature in features)
        or len(features) != len(set(features))
        or not isinstance(expected_features, list)
        or sorted(features) != sorted(expected_features)
    ):
        raise EvidenceError("selected libc Cargo feature inventory drifted")
    expected_paths = expected_cargo_artifact_paths(target_dir, artifact_contract)
    observed_filenames = compiler_artifact.get("filenames")
    if not isinstance(observed_filenames, list) or not all(
        isinstance(filename, str) and filename for filename in observed_filenames
    ):
        raise EvidenceError("selected libc Cargo artifact filenames are invalid")
    observed_paths = [Path(filename).resolve() for filename in observed_filenames]
    if observed_paths != list(expected_paths.values()):
        raise EvidenceError("selected libc Cargo artifact filenames drifted")
    if compiler_artifact.get("executable") is not None or type(compiler_artifact.get("fresh")) is not bool:
        raise EvidenceError("selected libc Cargo artifact executable/fresh identity drifted")
    return {
        "package_id": package_id,
        "target": normalized_target,
        "profile": dict(compiler_artifact["profile"]),
        "features": list(features),
        "filenames": [relative_path(path, ROOT) for path in observed_paths],
        "fresh": compiler_artifact["fresh"],
    }


def selected_libc_build_attestation(
    build_record_path: Path,
    target_dir: Path,
    expectation: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind the selected libc files to one explicit just-built Cargo record."""

    artifact_contract = cargo_artifact_contract(expectation)
    build_record = read_json(build_record_path)
    if set(build_record) != {
        "format",
        "schema",
        "cargo_command",
        "semantic_profile",
        "compiler_artifact",
        "artifacts",
    }:
        raise EvidenceError("selected libc Cargo build-record field inventory drifted")
    if (
        build_record.get("format") != artifact_contract.get("build_record_format")
        or build_record.get("schema") != artifact_contract.get("build_record_schema")
        or not exactly_matches(build_record.get("cargo_command"), artifact_contract.get("cargo_command"))
        or build_record.get("semantic_profile") != artifact_contract.get("semantic_profile")
    ):
        raise EvidenceError("selected libc Cargo build-record contract drifted")
    compiler_artifact = validate_compiler_artifact(
        build_record.get("compiler_artifact"), target_dir, artifact_contract
    )
    artifact_paths = expected_cargo_artifact_paths(target_dir, artifact_contract)
    recorded_artifacts = build_record.get("artifacts")
    if not isinstance(recorded_artifacts, dict) or set(recorded_artifacts) != set(artifact_paths):
        raise EvidenceError("selected libc Cargo build-record artifact inventory drifted")
    observed_artifacts: dict[str, dict[str, Any]] = {}
    for artifact_id, path in artifact_paths.items():
        if not path.is_file():
            raise EvidenceError(f"selected libc Cargo artifact is absent: {path}")
        observed = file_record(path, root=ROOT)
        if not exactly_matches(recorded_artifacts.get(artifact_id), observed):
            raise EvidenceError(
                f"selected libc Cargo artifact bytes drifted after build: {artifact_id}"
            )
        observed_artifacts[artifact_id] = observed
    return {
        "build_record": file_record(build_record_path, root=ROOT),
        "semantic_profile": build_record["semantic_profile"],
        "cargo_features": compiler_artifact["features"],
        "compiler_artifact": compiler_artifact,
        "artifacts": observed_artifacts,
    }


def compiler_artifacts_from_cargo_messages(payload: bytes) -> list[dict[str, Any]]:
    """Decode only Cargo's JSON message stream; arbitrary terminal text is rejected."""

    try:
        lines = payload.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise EvidenceError("selected libc Cargo message stream is not UTF-8") from error
    messages: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, start=1):
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as error:
            raise EvidenceError(
                f"selected libc Cargo message line {line_number} is not JSON"
            ) from error
        if not isinstance(message, dict):
            raise EvidenceError(
                f"selected libc Cargo message line {line_number} is not an object"
            )
        if message.get("reason") == "compiler-artifact":
            messages.append(message)
    return messages


def select_libc_compiler_artifact(
    compiler_artifacts: Sequence[Mapping[str, Any]],
    target_dir: Path,
    artifact_contract: Mapping[str, Any],
) -> dict[str, Any]:
    """Select crabc-libc from this invocation, never from global Cargo cache state."""

    manifest_path = artifact_contract.get("manifest_path")
    target_contract = artifact_contract.get("target")
    if not isinstance(manifest_path, str) or not isinstance(target_contract, dict):
        raise EvidenceError("native backend inventory has an invalid Cargo target locator")
    expected_manifest = (ROOT / manifest_path).resolve()
    target_name = target_contract.get("name")
    matches = [
        dict(artifact)
        for artifact in compiler_artifacts
        if isinstance(artifact.get("manifest_path"), str)
        and Path(str(artifact["manifest_path"])).resolve() == expected_manifest
        and isinstance(artifact.get("target"), dict)
        and artifact["target"].get("name") == target_name
    ]
    if len(matches) != 1:
        raise EvidenceError(
            "selected libc Cargo invocation must emit exactly one matching compiler-artifact; "
            f"observed {len(matches)}"
        )
    validate_compiler_artifact(matches[0], target_dir, artifact_contract)
    return matches[0]


def capture_selected_libc_build(
    contract: Mapping[str, Any],
    target_dir: Path,
    build_record_path: Path,
    current_head_record_path: Path | None = None,
) -> dict[str, Any]:
    """Run the canonical dev build and atomically preserve its exact artifact record."""

    backend = selected_backend_contract(contract)
    expectation = backend.get("artifact_attestation")
    if not isinstance(expectation, dict):
        raise EvidenceError("selected native backend lacks artifact attestation requirements")
    artifact_contract = cargo_artifact_contract(expectation)
    command = artifact_contract.get("cargo_command")
    if not isinstance(command, list) or not all(
        isinstance(argument, str) and argument for argument in command
    ):
        raise EvidenceError("selected libc Cargo build command is invalid")
    source_before = current_head_source_state()
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        sys.stderr.buffer.write(completed.stderr)
        raise EvidenceError(
            f"selected libc Cargo build failed with status {completed.returncode}"
        )
    target_dir = target_dir.expanduser().resolve()
    compiler_artifact = select_libc_compiler_artifact(
        compiler_artifacts_from_cargo_messages(completed.stdout),
        target_dir,
        artifact_contract,
    )
    artifacts = {
        artifact_id: file_record(path, root=ROOT)
        for artifact_id, path in expected_cargo_artifact_paths(
            target_dir, artifact_contract
        ).items()
    }
    build_record = {
        "format": artifact_contract["build_record_format"],
        "schema": artifact_contract["build_record_schema"],
        "cargo_command": list(command),
        "semantic_profile": artifact_contract["semantic_profile"],
        "compiler_artifact": compiler_artifact,
        "artifacts": artifacts,
    }
    write_json(build_record_path, build_record)
    source_after = current_head_source_state()
    if current_head_record_path is None:
        current_head_record_path = current_head_build_record_path(build_record_path)
    current_head_record = {
        "format": CURRENT_HEAD_BUILD_RECORD_FORMAT,
        "schema": CURRENT_HEAD_BUILD_RECORD_SCHEMA,
        "source_before": source_before,
        "source_after": source_after,
        "source_unchanged_during_build": exactly_matches(source_before, source_after),
        "selected_libc_build_record": file_record(build_record_path, root=ROOT),
        "artifacts": artifacts,
    }
    write_json(current_head_record_path, current_head_record)
    return build_record


def read_current_head_build_record(path: Path) -> dict[str, Any]:
    """Read the companion emitted during the exact selected-libc Cargo build."""

    resolved = path.expanduser().resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise BlockedPrerequisite(
            "current-head-build-record",
            "canonical upstream stress requires the companion record emitted with its "
            "selected libc Cargo build",
            {
                "build_record": str(resolved),
                "required_producer": "compat/allocator/upstream-stress/run.py --capture-selected-libc-build",
            },
        )
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BlockedPrerequisite(
            "current-head-build-record",
            "canonical upstream stress cannot read its selected libc build companion",
            {"build_record": str(resolved)},
        ) from error
    if not isinstance(value, dict) or set(value) != {
        "format",
        "schema",
        "source_before",
        "source_after",
        "source_unchanged_during_build",
        "selected_libc_build_record",
        "artifacts",
    }:
        raise BlockedPrerequisite(
            "current-head-build-record",
            "canonical upstream stress selected libc build companion schema drifted",
            {"build_record": str(resolved)},
        )
    if (
        value.get("format") != CURRENT_HEAD_BUILD_RECORD_FORMAT
        or value.get("schema") != CURRENT_HEAD_BUILD_RECORD_SCHEMA
        or type(value.get("source_unchanged_during_build")) is not bool
    ):
        raise BlockedPrerequisite(
            "current-head-build-record",
            "canonical upstream stress selected libc build companion identity drifted",
            {"build_record": str(resolved)},
        )
    try:
        source_before = validate_current_head_source_state(
            value["source_before"], "current-head build before"
        )
        source_after = validate_current_head_source_state(
            value["source_after"], "current-head build after"
        )
    except EvidenceError as error:
        raise BlockedPrerequisite(
            "current-head-build-record",
            "canonical upstream stress selected libc build companion source state drifted",
            {"build_record": str(resolved)},
        ) from error
    if value["source_unchanged_during_build"] != exactly_matches(source_before, source_after):
        raise BlockedPrerequisite(
            "current-head-build-record",
            "canonical upstream stress selected libc build companion contradicted its source state",
            {"build_record": str(resolved)},
        )
    record = dict(value)
    record["source_before"] = source_before
    record["source_after"] = source_after
    return record


def attest_current_head_build(
    current_head_record_path: Path,
    build_record_path: Path,
    backend_attestation: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind a clean current Git HEAD, the Cargo record, and selected runtime files."""

    record_path = current_head_record_path.expanduser().resolve()
    record = read_current_head_build_record(record_path)
    try:
        source_before = require_clean_git_source_state(
            record["source_before"], "current-head build companion source before capture"
        )
        source_after = require_clean_git_source_state(
            record["source_after"], "current-head build companion source after capture"
        )
    except EvidenceError as error:
        raise BlockedPrerequisite(
            "current-head-source-state",
            "canonical upstream stress requires a clean Git source at selected libc capture",
            {"build_record": str(record_path)},
        ) from error
    if not record["source_unchanged_during_build"] or not exactly_matches(
        source_before, source_after
    ):
        raise BlockedPrerequisite(
            "current-head-source-stability",
            "canonical upstream stress refuses a selected libc built while its source changed",
            {"build_record": str(record_path)},
        )
    try:
        observed_source = require_clean_git_source_state(
            current_head_source_state(), "current upstream stress execution source"
        )
    except EvidenceError as error:
        raise BlockedPrerequisite(
            "current-head-source-state",
            "canonical upstream stress requires a clean Git source at execution",
            {"build_record": str(record_path)},
        ) from error
    if not exactly_matches(observed_source, source_after):
        raise BlockedPrerequisite(
            "current-head-source-drift",
            "canonical upstream stress source no longer matches the selected libc build",
            {
                "build_record": str(record_path),
                "built_source": source_after,
                "observed_source": observed_source,
            },
        )
    build_record = build_record_path.expanduser().resolve()
    if not build_record.is_file() or build_record.is_symlink():
        raise BlockedPrerequisite(
            "selected-libc-build-record",
            "canonical upstream stress requires the selected libc Cargo build record",
            {"build_record": str(build_record)},
        )
    observed_build_record = file_record(build_record, root=ROOT)
    if not exactly_matches(record["selected_libc_build_record"], observed_build_record):
        raise BlockedPrerequisite(
            "current-head-build-record",
            "canonical upstream stress selected libc Cargo record drifted after capture",
            {"build_record": str(build_record)},
        )
    backend_build_record = backend_attestation.get("build_record")
    backend_artifacts = backend_attestation.get("artifacts")
    if (
        not exactly_matches(record["selected_libc_build_record"], backend_build_record)
        or not isinstance(backend_artifacts, dict)
        or not exactly_matches(record["artifacts"], backend_artifacts)
    ):
        raise EvidenceError(
            "canonical upstream stress selected libc companion does not bind the attested runtime artifact"
        )
    return {
        "record": file_record(record_path, root=ROOT),
        "source": source_after,
        "selected_libc_build_record": observed_build_record,
        "artifacts": dict(backend_artifacts),
    }


def selected_backend_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    inventory = contract.get("backend_inventory")
    if not isinstance(inventory, dict) or not isinstance(inventory.get("selected"), str):
        raise EvidenceError("canonical stress contract lacks a selected backend inventory")
    backends = inventory.get("backends")
    if not isinstance(backends, list):
        raise EvidenceError("canonical stress contract has an invalid backend inventory")
    selected = [
        backend
        for backend in backends
        if isinstance(backend, dict) and backend.get("id") == inventory["selected"]
    ]
    if len(selected) != 1:
        raise EvidenceError("canonical stress contract must select exactly one native backend")
    return dict(selected[0])


def attest_selected_backend(
    target_dir: Path, build_record_path: Path, contract: Mapping[str, Any]
) -> dict[str, Any]:
    """Prove that the selected ``libc.so`` routes public ``free`` to Rust."""

    backend = selected_backend_contract(contract)
    expectation = backend.get("artifact_attestation")
    if not isinstance(expectation, dict):
        raise EvidenceError("selected native backend lacks artifact attestation requirements")
    build_attestation = selected_libc_build_attestation(
        build_record_path, target_dir, expectation
    )
    route = expectation.get("exported_free_route")
    if not isinstance(route, dict):
        raise EvidenceError("selected native backend lacks its exported free route contract")
    symbol = route.get("symbol")
    required = route.get("required_callee_suffix")
    forbidden = route.get("forbidden_callee_suffix")
    if not all(isinstance(value, str) and value for value in (symbol, required, forbidden)):
        raise EvidenceError("selected native backend has an invalid exported free route contract")
    libc = target_dir / "libc.so"
    readelf = shutil.which("readelf")
    objdump = shutil.which("objdump")
    if readelf is None or objdump is None:
        raise EvidenceError("readelf and objdump are required to attest the native backend")
    symbols = command_text(
        command_record((readelf, "-W", "--dyn-syms", str(libc)), cwd=ROOT),
        "selected libc dynamic-symbol inspection",
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
        raise EvidenceError(f"selected native backend does not define dynamic {symbol}")
    disassembly = command_text(
        command_record(
            (objdump, "-d", f"--disassemble={symbol}", str(libc)), cwd=ROOT
        ),
        "selected libc exported free-route inspection",
    )
    branch = r"\b(?:b|bl)\s+[^<]*<[^>]*{}"
    if not re.search(branch.format(re.escape(required)), disassembly):
        raise EvidenceError(f"selected libc {symbol} does not branch to <{required}")
    if re.search(branch.format(re.escape(forbidden)), disassembly):
        raise EvidenceError(f"selected libc {symbol} branches to forbidden <{forbidden}")
    return {
        "backend": backend["id"],
        **build_attestation,
        "exported_free": {
            "symbol": symbol,
            "required_callee_suffix": required,
            "forbidden_callee_suffix": forbidden,
            "disassembly_sha256": hashlib.sha256(disassembly.encode("utf-8")).hexdigest(),
        },
        "status": "passed",
    }


def build_command(
    compiler: Path, source_root: Path, source_member: str, target_dir: Path, binary: Path, contract: Mapping[str, Any]
) -> list[str]:
    requirements = contract["compile_requirements"]
    adaptation = contract["source_adaptation"]
    assert isinstance(requirements, dict) and isinstance(adaptation, dict)
    flags = requirements["compile_flags"]
    defines = adaptation["compile_defines"]
    link_flags = requirements["link_flags"]
    libraries = requirements["link_libraries"]
    assert all(isinstance(value, list) for value in (flags, defines, link_flags, libraries))
    return [
        str(compiler),
        "-std=c11",
        *flags,
        *(f"-D{value}" for value in defines),
        "-I",
        str(source_root / "include"),
        "-L",
        str(target_dir),
        str(source_root / source_member),
        *link_flags,
        *libraries,
        "-o",
        str(binary),
    ]


def runtime_environment(target_dir: Path) -> dict[str, str]:
    """Return the complete, deliberately small environment of one stress process.

    The fixture is an allocator/loader boundary, so carrying arbitrary caller
    state into it would make a recorded result dependent on ambient preload,
    loader, allocator, locale, or diagnostic settings.  The binary is invoked
    by an absolute path and needs no inherited ``PATH``/``HOME``; the selected
    libc directory is the only dynamic-loader input this lane intentionally
    supplies.
    """

    return {
        "LC_ALL": "C",
        "LD_LIBRARY_PATH": str(target_dir),
        "TZ": "UTC",
    }


def runtime_environment_record(target_dir: Path) -> dict[str, object]:
    """Describe the closed fixture environment without host-specific paths."""

    return {
        "inheritance": "none",
        "variables": {
            "LC_ALL": "C",
            "LD_LIBRARY_PATH": relative_path(target_dir, ROOT),
            "TZ": "UTC",
        },
    }


def execution_cases(contract: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return the ordered source-argument cases without inventing a schedule."""

    execution = contract.get("execution")
    if not isinstance(execution, dict):
        raise EvidenceError("canonical upstream stress contract lacks execution settings")
    matrix = execution.get("matrix")
    if not isinstance(matrix, list) or not matrix or not all(
        isinstance(case, dict) for case in matrix
    ):
        raise EvidenceError("canonical upstream stress contract has an invalid execution matrix")
    return [dict(case) for case in matrix]


def case_inventory(case: Mapping[str, Any]) -> dict[str, Any]:
    """Keep report case identity separate from its observed process result."""

    fields = ("id", "workers", "scale", "iterations", "arguments")
    try:
        return {field: case[field] for field in fields}
    except KeyError as error:
        raise EvidenceError("canonical upstream stress case lacks its source arguments") from error


def run_command(binary: Path, case: Mapping[str, Any]) -> list[str]:
    """Invoke the one compiled upstream binary with only source CLI arguments."""

    arguments = case.get("arguments")
    if not isinstance(arguments, list) or not all(isinstance(value, str) for value in arguments):
        raise EvidenceError("canonical upstream stress case has invalid command-line arguments")
    return [str(binary), *arguments]


def diagnostic_case(contract: Mapping[str, Any]) -> dict[str, Any]:
    """Select the first closed matrix case without rewriting the full matrix."""

    cases = execution_cases(contract)
    expected = expected_matrix_case(1, 1, 1)
    if not exactly_matches(cases[0], expected):
        raise EvidenceError(
            "current-head diagnostic requires the canonical matrix to begin with "
            "workers=1 scale=1 iterations=1"
        )
    return cases[0]


def post_owner_exit_concurrent_free_case(contract: Mapping[str, Any]) -> dict[str, Any]:
    """Select the smallest existing two-worker source case by its closed identity.

    The archived source starts two pthread workers, leaves its atomic transfer
    exchange/free loop unchanged, joins both workers, and then has its original
    initial-thread transfer cleanup free any surviving objects. This selector
    does not assert that a particular pthread interleaving occurred.
    """

    expected = expected_matrix_case(2, 1, 1)
    matches = [
        case
        for case in execution_cases(contract)
        if case.get("id") == POST_OWNER_EXIT_CONCURRENT_FREE_CASE_ID
    ]
    if len(matches) != 1 or not exactly_matches(matches[0], expected):
        raise EvidenceError(
            "post-owner-exit concurrent-free diagnostic requires the canonical "
            "workers=2 scale=1 iterations=1 matrix case"
        )
    return matches[0]


def selected_diagnostic_case(
    contract: Mapping[str, Any], args: argparse.Namespace
) -> dict[str, Any]:
    """Choose one explicit one-case invocation without changing the matrix."""

    if args.post_owner_exit_concurrent_free:
        return post_owner_exit_concurrent_free_case(contract)
    return diagnostic_case(contract)


def diagnostic_metadata(args: argparse.Namespace) -> dict[str, Any]:
    """Keep the post-exit invocation's narrow evidence boundary explicit."""

    if not args.post_owner_exit_concurrent_free:
        return {
            "id": "current-head-first-case",
            "status": "not-run",
            "classification": "diagnostic-only",
            "native_execution_started": False,
        }
    return {
        "id": "post-owner-exit-concurrent-free",
        "status": "not-run",
        "classification": "one-case-source-shaped-only",
        "native_execution_started": False,
        "scope": {
            "source_unmodified": True,
            "selected_closed_matrix_case": POST_OWNER_EXIT_CONCURRENT_FREE_CASE_ID,
            "source_worker_count": 2,
            "source_scheduler": "upstream pthread schedule remains nondeterministic",
            "post_owner_exit_cleanup": (
                "the unmodified upstream initial thread frees surviving transfer entries "
                "after joining both source workers"
            ),
            "concurrent_free_overlap": "not-instrumented",
            "canonical_matrix": "not-run",
            "m5_accepted": False,
        },
    }


def selected_target_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    inventory = contract.get("target_inventory")
    if not isinstance(inventory, dict) or not isinstance(inventory.get("selected"), str):
        raise EvidenceError("canonical stress contract lacks a selected target inventory")
    targets = inventory.get("targets")
    if not isinstance(targets, list):
        raise EvidenceError("canonical stress contract has an invalid target inventory")
    selected = [
        target
        for target in targets
        if isinstance(target, dict) and target.get("id") == inventory["selected"]
    ]
    if len(selected) != 1:
        raise EvidenceError("canonical stress contract must select exactly one native target")
    return dict(selected[0])


def capability_record(contract: Mapping[str, Any]) -> dict[str, Any]:
    capability = contract.get("capability")
    if not isinstance(capability, dict):
        raise EvidenceError("canonical stress contract lacks its capability policy")
    return {
        "id": capability["id"],
        "status": capability["checked_in_status"],
        "failure_closed": True,
        "native_execution_started": False,
        "native_execution_completed": False,
        "passed_case_count": 0,
        "required_case_count": len(execution_cases(contract)),
        "fully_verified_worker_counts": [],
        "required_worker_counts": list(capability["required_worker_counts"]),
    }


def update_capability(report: dict[str, Any], contract: Mapping[str, Any], status: str) -> None:
    """Derive one conservative capability state from completed case records."""

    policy = contract["capability"]
    assert isinstance(policy, dict)
    states = policy["status_values"]
    if status not in states:
        raise EvidenceError(f"invalid canonical stress capability status: {status}")
    cases = execution_cases(contract)
    results = report["execution"]["case_results"]
    assert isinstance(results, list)
    passed_ids = {
        result["case"]["id"]
        for result in results
        if isinstance(result, dict)
        and result.get("state") == "passed"
        and isinstance(result.get("case"), dict)
    }
    verified_workers = [
        worker
        for worker in policy["required_worker_counts"]
        if all(case["id"] in passed_ids for case in cases if case["workers"] == worker)
    ]
    capability = report["capability"]
    assert isinstance(capability, dict)
    capability.update(
        {
            "status": status,
            "passed_case_count": len(passed_ids),
            "fully_verified_worker_counts": verified_workers,
            "native_execution_completed": status == "passed",
        }
    )


def current_head_report(
    attestation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Render the shared full-matrix and diagnostic source-attestation object."""

    if attestation is None:
        return {
            "status": "not-attested",
            "record": None,
            "source": None,
        }
    return {
        "status": "attested",
        "record": attestation["record"],
        "source": attestation["source"],
    }


def report_base(contract: Mapping[str, Any], pin: Mapping[str, str], args: argparse.Namespace) -> dict[str, Any]:
    fixture = contract["fixture"]
    adaptation = contract["source_adaptation"]
    execution = contract["execution"]
    assert isinstance(fixture, dict) and isinstance(adaptation, dict) and isinstance(execution, dict)
    cases = execution_cases(contract)
    report_contract = contract["report"]
    assert isinstance(report_contract, dict)
    artifact_ids = report_contract["artifact_ids"]
    assert isinstance(artifact_ids, list)
    contract_artifact = file_record(CONTRACT_PATH, root=ROOT)
    return {
        "format": report_contract["format"],
        "schema": report_contract["schema"],
        "status": "failed",
        "contract": {
            **contract_artifact,
            "upstream": dict(contract["upstream"]),
        },
        "artifacts": {
            artifact_id: contract_artifact if artifact_id == "contract" else None
            for artifact_id in artifact_ids
        },
        "fixture": {
            "archive_member": fixture["archive_member"],
            "expected_sha256": fixture["sha256"],
            "source_adaptation": {
                "compile_defines": list(adaptation["compile_defines"]),
                "patches": list(adaptation["patches"]),
            },
        },
        "execution": {
            "attempted": False,
            "attempted_process_count": 0,
            "case_count": len(cases),
            "case_results": [
                {"case": case_inventory(case), "state": "not-attempted"} for case in cases
            ],
            "process_attempts_per_case": execution["process_attempts_per_case"],
            "source_randomness": dict(execution["source_randomness"]),
            "watchdog": dict(execution["watchdog"]),
        },
        "requested_runtime": {
            "allocator_feature": contract["compile_requirements"]["allocator_feature"],
            "backend": selected_backend_contract(contract)["id"],
            "target_dir": relative_path(args.target_dir, ROOT),
            "output_dir": relative_path(args.output_dir, ROOT),
            "selected_libc_build_record": relative_path(args.libc_build_record, ROOT),
            "current_head_build_record": relative_path(
                args.current_head_build_record, ROOT
            ),
        },
        "selection": {
            "target": selected_target_contract(contract),
            "backend": selected_backend_contract(contract)["id"],
        },
        "observed_host": {
            "architecture": platform.machine(),
            "byte_order": sys.byteorder,
            "kernel_release": platform.release(),
            "system": platform.system(),
        },
        "capability": capability_record(contract),
        "current_head": current_head_report(),
        "blocked": None,
        "first_fact": None,
        "upstream_pin": dict(pin),
    }


def diagnostic_report_base(
    contract: Mapping[str, Any], pin: Mapping[str, str], args: argparse.Namespace
) -> dict[str, Any]:
    """Start a one-case report that cannot be mistaken for the canonical matrix."""

    fixture = contract["fixture"]
    adaptation = contract["source_adaptation"]
    execution = contract["execution"]
    assert isinstance(fixture, dict) and isinstance(adaptation, dict) and isinstance(execution, dict)
    case = selected_diagnostic_case(contract, args)
    report_contract = contract["report"]
    assert isinstance(report_contract, dict)
    artifact_ids = report_contract["artifact_ids"]
    assert isinstance(artifact_ids, list)
    contract_artifact = file_record(CONTRACT_PATH, root=ROOT)
    output_dir = diagnostic_output_dir(args)
    return {
        "format": DIAGNOSTIC_REPORT_FORMAT,
        "schema": DIAGNOSTIC_REPORT_SCHEMA,
        "status": "failed",
        "contract": {
            **contract_artifact,
            "upstream": dict(contract["upstream"]),
        },
        "artifacts": {
            artifact_id: contract_artifact if artifact_id == "contract" else None
            for artifact_id in artifact_ids
        },
        "fixture": {
            "archive_member": fixture["archive_member"],
            "expected_sha256": fixture["sha256"],
            "source_adaptation": {
                "compile_defines": list(adaptation["compile_defines"]),
                "patches": list(adaptation["patches"]),
            },
        },
        "diagnostic": diagnostic_metadata(args),
        "canonical_matrix": {
            "status": "not-run",
            "required_case_count": len(execution_cases(contract)),
            "completed_case_count": 0,
            "m5_accepted": False,
        },
        "execution": {
            "attempted": False,
            "case": case_inventory(case),
            "process_attempt_count": 0,
            "result": None,
            "source_randomness": dict(execution["source_randomness"]),
            "watchdog": dict(execution["watchdog"]),
        },
        "requested_runtime": {
            "allocator_feature": contract["compile_requirements"]["allocator_feature"],
            "backend": selected_backend_contract(contract)["id"],
            "target_dir": relative_path(args.target_dir, ROOT),
            "output_dir": relative_path(output_dir, ROOT),
            "selected_libc_build_record": relative_path(args.libc_build_record, ROOT),
            "current_head_build_record": relative_path(
                args.current_head_build_record, ROOT
            ),
        },
        "selection": {
            "target": selected_target_contract(contract),
            "backend": selected_backend_contract(contract)["id"],
        },
        "observed_host": {
            "architecture": platform.machine(),
            "byte_order": sys.byteorder,
            "kernel_release": platform.release(),
            "system": platform.system(),
        },
        "current_head": current_head_report(),
        "blocked": None,
        "first_fact": None,
        "upstream_pin": dict(pin),
    }


def blocked_record(error: BlockedPrerequisite) -> dict[str, Any]:
    """Describe one unavailable prerequisite without fabricating a stress result."""

    return {
        "format": 1,
        "kind": "execution-prerequisite",
        "message": str(error),
        "prerequisite": error.prerequisite,
        "details": dict(error.details),
        "stress_process_started": False,
    }


def successful_run(record: Mapping[str, Any], case: Mapping[str, Any]) -> bool:
    if record.get("kind") != "process" or record.get("status") != case["expected_exit_status"]:
        return False
    stdout = record.get("stdout")
    stderr = record.get("stderr")
    if not isinstance(stdout, dict) or not isinstance(stderr, dict):
        return False
    return (
        bytes.fromhex(str(stdout["hex"])).decode("utf-8", errors="strict")
        == case["expected_stdout"]
        and bytes.fromhex(str(stderr["hex"])).decode("utf-8", errors="strict")
        == case["expected_stderr"]
    )


def execute(contract: Mapping[str, Any], pin: Mapping[str, str], args: argparse.Namespace, report: dict[str, Any]) -> None:
    require_native_aarch64()
    archive = fetch_archive(pin, offline=args.offline)
    report["artifacts"]["upstream_archive"] = file_record(archive, root=ROOT)
    attestation = cached_tag_attestation(pin)
    if attestation is None:
        raise EvidenceError("pinned archive was accepted without a tag attestation")
    report["tag_attestation"] = attestation
    requirements = contract["compile_requirements"]
    assert isinstance(requirements, dict)
    runtime_inputs = require_runtime_inputs(args.target_dir, requirements)
    build_record_path = args.libc_build_record.expanduser().resolve()
    if not build_record_path.is_file():
        raise BlockedPrerequisite(
            "selected-libc-build-record",
            "canonical upstream stress requires the exact Cargo compiler-artifact "
            "record emitted by its selected libc build",
            {
                "build_record": str(build_record_path),
                "required_producer": "compat/allocator/upstream-stress/run.py --capture-selected-libc-build",
                "stress_process_started": False,
            },
        )
    backend_attestation = attest_selected_backend(
        runtime_inputs.target_dir, build_record_path, contract
    )
    current_head_attestation = attest_current_head_build(
        args.current_head_build_record,
        build_record_path,
        backend_attestation,
    )
    report["current_head"] = current_head_report(current_head_attestation)
    report["artifacts"].update(
        {
            "owned_sysroot_manifest": file_record(runtime_inputs.manifest_path, root=ROOT),
            "owned_sysroot_purity": file_record(runtime_inputs.purity_path, root=ROOT),
            "owned_compiler": file_record(runtime_inputs.compiler, root=ROOT),
            "selected_loader": file_record(
                runtime_inputs.target_dir / "libldso.so", root=ROOT
            ),
            "staged_canonical_loader": file_record(
                runtime_inputs.canonical_loader_path, root=ROOT
            ),
            "selected_libc": backend_attestation["artifacts"]["selected_shared_libc"],
            "selected_static_libc": backend_attestation["artifacts"]["selected_static_libc"],
            "selected_backend_build_record": backend_attestation["build_record"],
        }
    )
    report["runtime"] = {
        "compiler": relative_path(runtime_inputs.compiler, ROOT),
        "backend_attestation": backend_attestation,
        "environment": runtime_environment_record(runtime_inputs.target_dir),
        "sysroot": relative_path(runtime_inputs.sysroot, ROOT),
        "sysroot_purity": {
            "crt_sysroot_pure_rust": runtime_inputs.purity["crt_sysroot_pure_rust"],
            "full_runtime_pure_rust": runtime_inputs.purity["full_runtime_pure_rust"],
            "full_runtime_purity_status": runtime_inputs.purity[
                "full_runtime_purity_status"
            ],
        },
    }

    output_dir = args.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    binary = output_dir / "canonical-upstream-test-stress"
    fixture = contract["fixture"]
    execution = contract["execution"]
    assert isinstance(fixture, dict) and isinstance(execution, dict)

    with tempfile.TemporaryDirectory(prefix="pinned-source-", dir=output_dir) as temporary:
        source_root = extract_exact_archive(archive, pin, Path(temporary))
        source = source_root / str(fixture["archive_member"])
        if not source.is_file() or sha256_file(source) != fixture["sha256"]:
            raise EvidenceError("canonical stress source differs from the pinned archive member")
        source_artifact = stable_source_member_record(
            source, pin, str(fixture["archive_member"])
        )
        report["fixture"]["observed_source"] = source_artifact
        report["artifacts"]["source_member"] = source_artifact
        build = normalize_source_paths(
            command_record(
                build_command(
                    runtime_inputs.compiler,
                    source_root,
                    str(fixture["archive_member"]),
                    runtime_inputs.target_dir,
                    binary,
                    contract,
                ),
                cwd=source_root,
            ),
            source_root,
            pin,
        )
    report["build"] = build
    if build.get("kind") != "process" or build.get("status") != 0:
        update_capability(report, contract, "failed")
        report["first_fact"] = {
            "kind": "first-failure",
            "stage": "build",
            "observation": build,
        }
        return

    report["artifacts"]["stress_binary"] = file_record(binary, root=ROOT)
    try:
        fixture_elf = audit_fixture_elf(binary, contract)
    except ArtifactContractError as error:
        update_capability(report, contract, "failed")
        report["first_fact"] = {
            "kind": "first-failure",
            "stage": "artifact-contract",
            "boundary": error.boundary,
            "observed": error.observed,
            "expected": error.expected,
        }
        return
    report["fixture_elf"] = fixture_elf
    report["dynamic_dependencies"] = fixture_elf["dynamic_dependencies"]

    cases = execution_cases(contract)
    results = report["execution"]["case_results"]
    assert isinstance(results, list)
    fixture_environment = runtime_environment(runtime_inputs.target_dir)
    for process_attempt, case in enumerate(cases, start=1):
        case_directory = output_dir / "cases" / str(case["id"])
        case_directory.mkdir(parents=True, exist_ok=True)
        run = command_record(
            run_command(binary, case),
            cwd=case_directory,
            environment=fixture_environment,
            timeout=int(execution["watchdog"]["seconds"]),
        )
        if run.get("kind") in {"process", "timeout"}:
            report["capability"]["native_execution_started"] = True
        report["execution"]["attempted"] = True
        report["execution"]["attempted_process_count"] = process_attempt
        state = "passed" if successful_run(run, case) else "failed"
        results[process_attempt - 1] = {
            "case": case_inventory(case),
            "process_attempt": process_attempt,
            "state": state,
            "observation": run,
        }
        if state == "failed":
            update_capability(report, contract, "failed")
            report["first_fact"] = {
                "kind": "first-failure",
                "stage": "run",
                "case": case_inventory(case),
                "process_attempt": process_attempt,
                "observation": run,
                "expected": {
                    "exit_status": case["expected_exit_status"],
                    "stderr": case["expected_stderr"],
                    "stdout": case["expected_stdout"],
                },
            }
            return

    report["status"] = "passed"
    update_capability(report, contract, "passed")
    report["first_fact"] = {
        "kind": "pass",
        "stage": "matrix",
        "completed_case_count": len(cases),
    }


def execute_diagnostic(
    contract: Mapping[str, Any], pin: Mapping[str, str], args: argparse.Namespace, report: dict[str, Any]
) -> None:
    """Run one attested current-head observation without reducing the full matrix."""

    case = selected_diagnostic_case(contract, args)
    require_native_aarch64()
    archive = fetch_archive(pin, offline=args.offline)
    report["artifacts"]["upstream_archive"] = file_record(archive, root=ROOT)
    tag_attestation = cached_tag_attestation(pin)
    if tag_attestation is None:
        raise EvidenceError("pinned archive was accepted without a tag attestation")
    report["tag_attestation"] = tag_attestation
    requirements = contract["compile_requirements"]
    assert isinstance(requirements, dict)
    runtime_inputs = require_runtime_inputs(args.target_dir, requirements)
    build_record_path = args.libc_build_record.expanduser().resolve()
    if not build_record_path.is_file():
        raise BlockedPrerequisite(
            "selected-libc-build-record",
            "current-head diagnostic requires the exact Cargo compiler-artifact record "
            "emitted by its selected libc build",
            {
                "build_record": str(build_record_path),
                "required_producer": "compat/allocator/upstream-stress/run.py --capture-selected-libc-build",
                "stress_process_started": False,
            },
        )
    backend_attestation = attest_selected_backend(
        runtime_inputs.target_dir, build_record_path, contract
    )
    current_head_attestation = attest_current_head_build(
        args.current_head_build_record,
        build_record_path,
        backend_attestation,
    )
    report["current_head"] = current_head_report(current_head_attestation)
    report["artifacts"].update(
        {
            "owned_sysroot_manifest": file_record(runtime_inputs.manifest_path, root=ROOT),
            "owned_sysroot_purity": file_record(runtime_inputs.purity_path, root=ROOT),
            "owned_compiler": file_record(runtime_inputs.compiler, root=ROOT),
            "selected_loader": file_record(
                runtime_inputs.target_dir / "libldso.so", root=ROOT
            ),
            "staged_canonical_loader": file_record(
                runtime_inputs.canonical_loader_path, root=ROOT
            ),
            "selected_libc": backend_attestation["artifacts"]["selected_shared_libc"],
            "selected_static_libc": backend_attestation["artifacts"]["selected_static_libc"],
            "selected_backend_build_record": backend_attestation["build_record"],
        }
    )
    report["runtime"] = {
        "compiler": relative_path(runtime_inputs.compiler, ROOT),
        "backend_attestation": backend_attestation,
        "environment": runtime_environment_record(runtime_inputs.target_dir),
        "sysroot": relative_path(runtime_inputs.sysroot, ROOT),
        "sysroot_purity": {
            "crt_sysroot_pure_rust": runtime_inputs.purity["crt_sysroot_pure_rust"],
            "full_runtime_pure_rust": runtime_inputs.purity["full_runtime_pure_rust"],
            "full_runtime_purity_status": runtime_inputs.purity[
                "full_runtime_purity_status"
            ],
        },
    }

    output_dir = diagnostic_output_dir(args)
    output_dir.mkdir(parents=True, exist_ok=True)
    binary = output_dir / "canonical-upstream-test-stress"
    fixture = contract["fixture"]
    execution = contract["execution"]
    assert isinstance(fixture, dict) and isinstance(execution, dict)

    with tempfile.TemporaryDirectory(prefix="pinned-source-", dir=output_dir) as temporary:
        source_root = extract_exact_archive(archive, pin, Path(temporary))
        source = source_root / str(fixture["archive_member"])
        if not source.is_file() or sha256_file(source) != fixture["sha256"]:
            raise EvidenceError("canonical stress source differs from the pinned archive member")
        source_artifact = stable_source_member_record(
            source, pin, str(fixture["archive_member"])
        )
        report["fixture"]["observed_source"] = source_artifact
        report["artifacts"]["source_member"] = source_artifact
        build = normalize_source_paths(
            command_record(
                build_command(
                    runtime_inputs.compiler,
                    source_root,
                    str(fixture["archive_member"]),
                    runtime_inputs.target_dir,
                    binary,
                    contract,
                ),
                cwd=source_root,
            ),
            source_root,
            pin,
        )
    report["build"] = build
    if build.get("kind") != "process" or build.get("status") != 0:
        report["diagnostic"]["status"] = "failed"
        report["first_fact"] = {
            "kind": "first-failure",
            "stage": "build",
            "observation": build,
        }
        return

    report["artifacts"]["stress_binary"] = file_record(binary, root=ROOT)
    try:
        fixture_elf = audit_fixture_elf(binary, contract)
    except ArtifactContractError as error:
        report["diagnostic"]["status"] = "failed"
        report["first_fact"] = {
            "kind": "first-failure",
            "stage": "artifact-contract",
            "boundary": error.boundary,
            "observed": error.observed,
            "expected": error.expected,
        }
        return
    report["fixture_elf"] = fixture_elf
    report["runtime"]["library_selection"] = {
        "dynamic_dependencies": fixture_elf["dynamic_dependencies"],
        "ld_library_path": relative_path(runtime_inputs.target_dir, ROOT),
        "selected_shared_libc": backend_attestation["artifacts"]["selected_shared_libc"],
    }

    case_directory = output_dir / "cases" / str(case["id"])
    case_directory.mkdir(parents=True, exist_ok=True)
    fixture_environment = runtime_environment(runtime_inputs.target_dir)
    run = command_record(
        run_command(binary, case),
        cwd=case_directory,
        environment=fixture_environment,
        timeout=int(execution["watchdog"]["seconds"]),
    )
    if run.get("kind") in {"process", "timeout"}:
        report["diagnostic"]["native_execution_started"] = True
    report["execution"]["attempted"] = True
    report["execution"]["process_attempt_count"] = 1
    state = "passed" if successful_run(run, case) else "failed"
    report["execution"]["result"] = {
        "case": case_inventory(case),
        "process_attempt": 1,
        "state": state,
        "observation": run,
    }
    if state == "failed":
        report["diagnostic"]["status"] = "failed"
        report["first_fact"] = {
            "kind": "first-failure",
            "stage": "run",
            "case": case_inventory(case),
            "process_attempt": 1,
            "observation": run,
            "expected": {
                "exit_status": case["expected_exit_status"],
                "stderr": case["expected_stderr"],
                "stdout": case["expected_stdout"],
            },
        }
        return

    report["status"] = "passed"
    report["diagnostic"]["status"] = "passed"
    report["first_fact"] = {
        "kind": "pass",
        "stage": "diagnostic-run",
        "case": case_inventory(case),
        "process_attempt": 1,
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


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_arguments(arguments)
    try:
        contract, pin = load_contract()
        if args.capture_selected_libc_build is not None:
            capture_selected_libc_build(
                contract,
                args.target_dir,
                args.capture_selected_libc_build,
                args.current_head_build_record,
            )
            print(args.capture_selected_libc_build.expanduser().resolve())
            return 0
        if args.check:
            print(
                json.dumps(
                    {
                        "capability_status": contract["capability"]["checked_in_status"],
                        "contract": relative_path(CONTRACT_PATH, ROOT),
                        "contract_status": "passed",
                        "native_execution_started": False,
                    },
                    sort_keys=True,
                )
            )
            return 0
        one_case_diagnostic = args.diagnose or args.post_owner_exit_concurrent_free
        report = (
            diagnostic_report_base(contract, pin, args)
            if one_case_diagnostic
            else report_base(contract, pin, args)
        )
        try:
            if one_case_diagnostic:
                execute_diagnostic(contract, pin, args, report)
            else:
                execute(contract, pin, args, report)
        except BlockedPrerequisite as error:
            report["status"] = "blocked"
            report["blocked"] = blocked_record(error)
            if one_case_diagnostic:
                report["diagnostic"]["status"] = "blocked"
            else:
                update_capability(report, contract, "blocked")
        except EvidenceError as error:
            report["status"] = "failed"
            if one_case_diagnostic:
                report["diagnostic"]["status"] = "failed"
            else:
                update_capability(report, contract, "failed")
            report["first_fact"] = {
                "kind": "first-failure",
                "stage": "harness",
                "message": str(error),
            }
        write_json(args.report, report)
        print(args.report.expanduser().resolve())
        return 0 if report["status"] == "passed" else 1
    except EvidenceError as error:
        print(f"canonical-upstream-stress: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
