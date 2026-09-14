#!/usr/bin/env python3
"""Collect or replay the private pinned diagnostic-output C/Rust comparison.

This producer is intentionally prepared but uncollected.  A later root-owned
receiver may run it natively after wiring the selected mbind diagnostic body
to the private Rust owner.  The report preserves raw compiler/test commands,
statuses, stdout, and stderr; `--validate` reconstructs every finite trace
from those retained streams without launching a compiler, test, or child.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "compat/allocator/run.py"
FIXTURE = ROOT / "compat/allocator/x86_64_diagnostic_output_owner_oracle.c"
LOCKFILE = ROOT / "Cargo.lock"
TARGET = "x86_64-unknown-linux-musl"

# This is the finite source closure for the private owner trace, not a hash of
# every crate compiled by Cargo. `crabc-mimalloc/src/lib.rs` routes the test to
# `diagnostic_output`, which calls its private lock. The lock in turn requires
# crabc-core's module route, Result/Errno definitions, futex wrapper, and the
# selected x86-64 syscall boundary. The C/Rust receipt binds every one of those
# participating Rust modules before it admits a retained trace.
RUST_SOURCE_FILES = (
    ROOT / "crabc-mimalloc/src/lib.rs",
    ROOT / "crabc-mimalloc/src/diagnostic_output.rs",
    ROOT / "crabc-mimalloc/src/lock.rs",
    ROOT / "crabc-core/src/lib.rs",
    ROOT / "crabc-core/src/error.rs",
    ROOT / "crabc-core/src/thread.rs",
    ROOT / "crabc-core/src/syscall_x86_64.rs",
)

# Cargo resolves the selected package/feature graph and target profile through
# these tracked inputs. Cargo.lock remains a separately named receipt field
# because `--locked` makes its exact resolved dependency graph a distinct
# command precondition.
RUST_BUILD_INPUT_FILES = (
    ROOT / "Cargo.toml",
    ROOT / ".cargo/config.toml",
    ROOT / "crabc-mimalloc/Cargo.toml",
    ROOT / "crabc-core/Cargo.toml",
    ROOT / "rust-toolchain.toml",
)
PINNED_UPSTREAM = {
    "archive_sha256": "1e432f0559a4ab512143b9bff7a700541a2c8d4712b26a72de3e0222790da305",
    "revision": "18b08671c9302247bfb682286e6bf3cc1773f801",
}
PROFILE = "linux-x86_64-private-mimalloc-diagnostic-output-owner"
TRACE_BEGIN = "CRABC_MI_DIAGNOSTIC_OUTPUT_OWNER_TRACE_BEGIN"
TRACE_END = "CRABC_MI_DIAGNOSTIC_OUTPUT_OWNER_TRACE_END"
DEFAULT_STDERR_BEGIN = "CRABC_MI_DIAGNOSTIC_OUTPUT_OWNER_DEFAULT_STDERR_BEGIN"
DEFAULT_STDERR_END = "CRABC_MI_DIAGNOSTIC_OUTPUT_OWNER_DEFAULT_STDERR_END"
SCENARIOS = ("release", "enabled", "cap", "verbose", "delayed", "null", "post_init")
C_LINK_SOURCES = (
    "src/alloc.c",
    "src/alloc-aligned.c",
    "src/alloc-posix.c",
    "src/arena.c",
    "src/bitmap.c",
    "src/heap.c",
    "src/init.c",
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
    *C_LINK_SOURCES,
    # `src/prim/prim.c` includes this platform primitive in the same C
    # translation unit; retain its separate identity without compiling it twice.
    "src/prim/unix/prim.c",
)
PINNED_C_SOURCE_IDENTITIES = (
    ("include/mimalloc.h", "af34f215cb6fe9e4e97bf08d78bfda877ab4cdd63c9222640c483d7d6a4488a5"),
    ("include/mimalloc/internal.h", "4fd7b1dd450989b1a8a5b4cb54e163a36d932bbf7e341abcd882763251252852"),
    ("include/mimalloc/prim.h", "1987e8e2eedc07bb181bf2a11a27bec80a5309c32cfa66a56900fb4cbb64b172"),
    ("src/alloc.c", "fd4b4a86af93754227137a43c84e84f846d0ff0fd7046a264396a80c95e5c1a9"),
    ("src/alloc-aligned.c", "3546ff6046c384f050cde21e9f3f314b6dc7d4ba1f1b462960a5a38672b898ba"),
    ("src/alloc-posix.c", "a6dcdef4694964c972e6cf37f197f93c95f321566a3b5ccc1761129257255e93"),
    ("src/arena.c", "5d9aa2dc06fa6e942d6a46eb4748b0c10c81f96c2ed50042412a9e66fd6f4d7a"),
    ("src/bitmap.c", "c8dde3533b9803380fb948f86288ccf0a812a858aae7fca727e3b05e681d08b4"),
    ("src/heap.c", "c788b309cf5208f72679b81b00f0a68b59b8c01da6bebc891d3e4154857d0989"),
    ("src/init.c", "e22486042ba132e002822315ccd4b24738fc3a151fc14172e5e45426e8add299"),
    ("src/libc.c", "7cd5cbbe56d70fb5f232757a763f694c0bd847e99a71b70bd9d345707f4bbd8c"),
    ("src/options.c", "760c694c7663a18ae9745deb969215544d682c15fedd87ffe2645c6d31d5ba30"),
    ("src/os.c", "8410b04c2d5b37e59fff1854364fed1fba873133b064cfe02083277038388548"),
    ("src/page-map.c", "ff3509ae3d4185e9cb2a95e1f35daba3329e998bac917ac7938f1bf06dba0f78"),
    ("src/page.c", "f7b1c3c0725b425516e22cf49d3ff7e03b708732fdba4bd1f4c759484d52593c"),
    ("src/random.c", "c833eaf89ebd73c05a47a5ea8b439f4cc8a7ec5b87f85ddad4ddb72640d1c34e"),
    ("src/stats.c", "ce57c5f21ea2366f5d50591fbe6617de1493fd9e048452562df171ae0d20e1d3"),
    ("src/subproc.c", "39ab44c15b0dd91a53268fd52590d681e3c62e1930144b9392db0fde44439054"),
    ("src/theap.c", "2f1a4fddb96cb2da91433221976a0a3b6b8c923c0c38c9bc20b4f2420cb3e845"),
    ("src/threadlocal.c", "b3f140f7fbfa2ce8796dc397626b3a768285e2a17533cae8f0dbb19e4e4831f2"),
    ("src/prim/prim.c", "241b1087a0e22609de71b2deba6c771135dd37e756ea89ba79b5900165b4f229"),
    ("src/prim/prim-tls.c", "4970ab233c499a1080db2fa77386439cd35a029a9be7ce25eef817e281ad8d70"),
    ("src/prim/unix/prim.c", "8efeac14a9952aa7c3117ce2d9d801f93692bda6cd80e09a51ddca398d7ac774"),
)
HEX = re.compile(r"(?:[0-9a-f]{2})*")

PREFIX = "6d696d616c6c6f633a207761726e696e673a20"
SELECTED_BODY = "73656c6563746564206d62696e64206661696c7572650a"
FIRST = "66697273740a"
SECOND = "7365636f6e640a"
EARLY = "6561726c790a"
LATER = "6c617465720a"
POST_INIT = "6561726c790a0a6c617465720a"
EXPECTED_TRACE = {
    "release": [],
    "enabled": [PREFIX, SELECTED_BODY],
    "cap": [PREFIX, FIRST],
    "verbose": [PREFIX, FIRST, PREFIX, SECOND],
    "delayed": [EARLY, LATER],
    "null": [EARLY],
    "post_init": [POST_INIT],
}
EXPECTED_DEFAULT_STDERR_TRACE = {
    "release": [],
    "enabled": [],
    "cap": [],
    "verbose": [],
    "delayed": [],
    "null": ["7374646572720a"],
    "post_init": [EARLY, LATER],
}
EXPECTED_C_STDERR = {
    scenario: "".join(bytes.fromhex(fragment).decode("ascii") for fragment in fragments)
    for scenario, fragments in EXPECTED_DEFAULT_STDERR_TRACE.items()
}
SCOPE = {
    "claim": "private source-faithful diagnostic output owner trace",
    "public_runtime_support": False,
    "exclusions": [
        "public mi_register_output ABI or general callback API",
        "environment parsing and complete options API parity",
        "normal mapping-error receiver integration",
        "fputs FILE locking/buffering and short-write or error transport parity",
        "VM/M2 or M7 qualification, allocator backend selection, and runtime integration",
        "AArch64 evidence or public x86-64 support",
    ],
}


class EvidenceError(RuntimeError):
    """The bounded diagnostic-output evidence contract was not met."""


def work_root() -> Path:
    configured = os.environ.get("CRABC_WORK_DIR")
    return Path(configured) if configured else ROOT / ".work"


def default_report() -> Path:
    return work_root() / "reports/allocator/x86_64/diagnostic-output-owner.json"


def require_checkout_work_path(path: Path, purpose: str) -> Path:
    """Keep collector-owned state in this checkout's ignored `.work` tree."""

    resolved = path.resolve()
    try:
        resolved.relative_to((ROOT / ".work").resolve())
    except ValueError as error:
        raise EvidenceError(f"{purpose} must stay under this checkout's .work directory") from error
    return resolved


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def current_file_identity(path: Path) -> dict[str, str]:
    return {"path": relative(path), "sha256": sha256_file(path)}


def current_rust_source_records() -> list[dict[str, str]]:
    return [current_file_identity(path) for path in RUST_SOURCE_FILES]


def current_rust_build_input_records() -> list[dict[str, str]]:
    return [current_file_identity(path) for path in RUST_BUILD_INPUT_FILES]


def relative(path: Path) -> str:
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


def command_record(command: Sequence[str], cwd: Path) -> dict[str, Any]:
    environment = {"PATH": os.environ.get("PATH", "")}
    for name in ("CARGO_HOME", "CRABC_WORK_DIR", "RUSTUP_HOME", "TMPDIR"):
        if name in os.environ:
            environment[name] = os.environ[name]
    completed = subprocess.run(
        list(command), cwd=cwd, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False,
    )
    return {
        "command": list(command),
        "cwd": str(cwd),
        "status": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def require_native_x86_64() -> dict[str, str]:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise EvidenceError("diagnostic-output collection requires a native Linux/x86-64 host")
    if os.environ.get("CRABC_EXECUTION_MODE") != "native":
        raise EvidenceError("diagnostic-output collection requires CRABC_EXECUTION_MODE=native")
    host = os.environ.get("CRABC_HOST_ARCH", platform.machine().lower())
    if host not in {"x86_64", "amd64"}:
        raise EvidenceError("diagnostic-output collection has non-x86 native provenance")
    return {"execution_mode": "native", "host_architecture": host}


def load_harness() -> Any:
    spec = importlib.util.spec_from_file_location("crabc_diagnostic_output_harness", RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise EvidenceError("pinned allocator source harness is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def source_records(source: Path) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for member in C_SOURCE_FILES:
        path = source / member
        if not path.is_file():
            raise EvidenceError(f"pinned source closure has no {member}")
        records.append({"path": member, "sha256": sha256_file(path)})
    return records


def expected_pinned_c_source_records() -> list[dict[str, str]]:
    return [{"path": member, "sha256": digest} for member, digest in PINNED_C_SOURCE_IDENTITIES]


def parse_trace(output: str, begin: str | None, end: str | None) -> dict[str, list[str]]:
    lines = output.splitlines()
    if begin is not None:
        try:
            start = lines.index(begin) + 1
            stop = lines.index(end or "", start)
        except ValueError as error:
            raise EvidenceError("trace markers are missing or out of order") from error
        lines = lines[start:stop]
    trace: dict[str, list[str]] = {}
    for line in lines:
        if "=" not in line:
            raise EvidenceError(f"trace line lacks a key: {line!r}")
        name, encoded = line.split("=", 1)
        if name not in SCENARIOS or name in trace:
            raise EvidenceError(f"trace scenario is invalid or duplicated: {name!r}")
        fragments = [] if encoded == "" else encoded.split(":")
        if not all(HEX.fullmatch(fragment) for fragment in fragments):
            raise EvidenceError(f"trace has non-hex fragment for {name}")
        trace[name] = fragments
    if tuple(trace) != SCENARIOS:
        raise EvidenceError("trace scenario order or coverage drifted")
    return trace


def parse_single_trace(output: str, scenario: str) -> list[str]:
    lines = output.splitlines()
    if len(lines) != 1 or "=" not in lines[0]:
        raise EvidenceError(f"C {scenario} trace does not retain one raw line")
    name, encoded = lines[0].split("=", 1)
    if name != scenario:
        raise EvidenceError(f"C trace scenario drifted: {name!r}")
    fragments = [] if encoded == "" else encoded.split(":")
    if not all(HEX.fullmatch(fragment) for fragment in fragments):
        raise EvidenceError(f"C {scenario} trace has non-hex fragment")
    return fragments


def expected_default_stderr_stream() -> str:
    return "\n".join(
        [DEFAULT_STDERR_BEGIN]
        + [f"{scenario}={':'.join(EXPECTED_DEFAULT_STDERR_TRACE[scenario])}" for scenario in SCENARIOS]
        + [DEFAULT_STDERR_END, ""]
    )


def c_compile_command(compiler: str, source: Path, binary: Path) -> list[str]:
    return [
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
        "-O3",
        "-DNDEBUG",
        "-DMI_BUILD_RELEASE=1",
        "-DMI_DEBUG=0",
        "-DMI_STAT=0",
        "-DMI_SECURE=0",
        "-DMI_GUARDED=0",
        str(FIXTURE),
        *(str(source / member) for member in C_LINK_SOURCES),
        "-pthread",
        "-o", str(binary),
    ]


def rust_command(cargo: str, target: Path) -> list[str]:
    return [
        cargo, "test", "--quiet", "--config=build.rustflags=[\"-Awarnings\"]", "--locked",
        "--target", TARGET, "--target-dir", str(target),
        "-p", "crabc-mimalloc", "--lib",
        "diagnostic_output::tests::diagnostic_output_owner_trace_for_future_pinned_c_comparison",
        "--", "--exact", "--nocapture", "--test-threads=1",
    ]


def candidate_report_path(report_path: Path) -> Path:
    """Name the non-admitted raw candidate stored beside one requested report."""

    return report_path.with_name(f"{report_path.stem}.candidate.json")


def candidate_artifact_root(report_path: Path) -> Path:
    """Name the retained physical C/Rust work tree for one raw candidate."""

    return candidate_report_path(report_path).with_suffix("")


def begin_candidate(report_path: Path) -> tuple[Path, Path, dict[str, Any]]:
    """Persist source inputs before a native collection starts.

    Candidates are diagnostics only: their status never becomes `passed`, and
    they are not accepted by `validate_report`. The admitted receipt still
    appears only after complete semantic validation succeeds.
    """

    candidate_path = require_checkout_work_path(candidate_report_path(report_path), "candidate receipt")
    artifact_root = require_checkout_work_path(candidate_artifact_root(report_path), "candidate artifact root")
    if candidate_path.exists() or artifact_root.exists():
        raise EvidenceError("diagnostic-output candidate path already exists; choose a fresh report path")
    artifact_root.mkdir(parents=True)
    candidate: dict[str, Any] = {
        "format": 1,
        "kind": "mimalloc-x86_64-diagnostic-output-owner-candidate",
        "status": "unvalidated",
        "admitted_report_path": str(report_path),
        "source_inputs": {
            "cargo_lock": current_file_identity(LOCKFILE),
            "fixture": current_file_identity(FIXTURE),
            "rust_build_inputs": current_rust_build_input_records(),
            "rust_source_files": current_rust_source_records(),
        },
        "upstream": PINNED_UPSTREAM,
        "c_oracle": {
            "binary": str(artifact_root / "diagnostic-output-owner-c-oracle"),
            "runs": {},
            "source_files": None,
            "source_root": None,
            "build": None,
        },
        "rust": None,
        "rust_target": str(artifact_root / "rust-target"),
    }
    persist_candidate(candidate_path, candidate)
    return candidate_path, artifact_root, candidate


def persist_candidate(candidate_path: Path, candidate: Mapping[str, Any]) -> None:
    """Atomically retain the raw collection state without admitting it."""

    atomic_write_json(candidate_path, candidate)


def collect(archive: Path, report_path: Path) -> dict[str, Any]:
    provenance = require_native_x86_64()
    require_checkout_work_path(report_path, "evidence report")
    if not archive.is_file() or sha256_file(archive) != PINNED_UPSTREAM["archive_sha256"]:
        raise EvidenceError("collector requires the exact pinned mimalloc archive")
    harness = load_harness()
    require_checkout_work_path(Path(harness.WORK_ROOT), "allocator harness work root")
    harness.require_tool("musl-gcc")
    if shutil_which("cargo") is None:
        raise EvidenceError("collector requires cargo")

    candidate_path, artifact_root, candidate = begin_candidate(report_path)
    source = harness.safe_extract(archive, artifact_root / "source", "mimalloc-3.5.0")
    c_oracle = candidate["c_oracle"]
    assert isinstance(c_oracle, dict)
    c_oracle["source_root"] = str(source)
    c_oracle["source_files"] = source_records(source)
    persist_candidate(candidate_path, candidate)

    binary = artifact_root / "diagnostic-output-owner-c-oracle"
    compile_command = c_compile_command("musl-gcc", source, binary)
    c_oracle["build"] = command_record(compile_command, source)
    persist_candidate(candidate_path, candidate)
    build = c_oracle["build"]
    assert isinstance(build, Mapping)
    if build["status"] != 0:
        raise EvidenceError("pinned diagnostic-output C oracle failed to build")

    runs = c_oracle["runs"]
    assert isinstance(runs, dict)
    for scenario in SCENARIOS:
        runs[scenario] = command_record([str(binary), scenario], source)
        persist_candidate(candidate_path, candidate)
    if any(run["status"] != 0 for run in runs.values()):
        raise EvidenceError("pinned diagnostic-output C oracle scenario failed")

    target = artifact_root / "rust-target"
    candidate["rust"] = command_record(rust_command("cargo", target), ROOT)
    persist_candidate(candidate_path, candidate)
    rust = candidate["rust"]
    assert isinstance(rust, Mapping)
    if rust["status"] != 0:
        raise EvidenceError("private diagnostic-output Rust trace failed")

    report = {
        "cargo_lock": current_file_identity(LOCKFILE),
        "c_oracle": {
            "build": build,
            "runs": runs,
            "source_files": c_oracle["source_files"],
        },
        "fixture": current_file_identity(FIXTURE),
        "format": 1,
        "kind": "mimalloc-x86_64-diagnostic-output-owner-evidence",
        "native_execution_provenance": provenance,
        "profile": PROFILE,
        "rust": rust,
        "rust_build_inputs": current_rust_build_input_records(),
        "rust_source_files": current_rust_source_records(),
        "scope": SCOPE,
        "status": "passed",
        "target": {"architecture": "x86_64", "endianness": "little", "rust_target": TARGET, "system": "linux"},
        "upstream": PINNED_UPSTREAM,
    }
    if c_oracle["source_files"] != expected_pinned_c_source_records():
        raise EvidenceError("extracted C source closure differs from the admitted pinned archive")
    validate_report(report)
    atomic_write_json(report_path, report)
    return report


def shutil_which(name: str) -> str | None:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def require_record(record: object, name: str) -> Mapping[str, Any]:
    if not isinstance(record, Mapping) or set(record) != {"command", "cwd", "status", "stdout", "stderr"}:
        raise EvidenceError(f"{name} raw command/stream record drifted")
    if not isinstance(record["command"], list) or not all(isinstance(item, str) for item in record["command"]):
        raise EvidenceError(f"{name} command is not retained exactly")
    if (
        not isinstance(record["cwd"], str)
        or not Path(record["cwd"]).is_absolute()
        or type(record["status"]) is not int
        or not isinstance(record["stdout"], str)
        or not isinstance(record["stderr"], str)
    ):
        raise EvidenceError(f"{name} status or raw streams are invalid")
    return record


def collector_source_root(build: Mapping[str, Any]) -> Path:
    source = require_checkout_work_path(Path(str(build["cwd"])), "C oracle source cwd")
    if source.name != "mimalloc-3.5.0" or source.parent.name != "source":
        raise EvidenceError("C oracle source cwd is not the collector's pinned source root")
    return source


def validate_report(report: object) -> None:
    if not isinstance(report, Mapping) or set(report) != {
        "c_oracle", "cargo_lock", "fixture", "format", "kind", "native_execution_provenance", "profile",
        "rust", "rust_build_inputs", "rust_source_files", "scope", "status", "target", "upstream",
    }:
        raise EvidenceError("diagnostic-output report schema drifted")
    if report["format"] != 1 or report["kind"] != "mimalloc-x86_64-diagnostic-output-owner-evidence":
        raise EvidenceError("diagnostic-output report identity drifted")
    if report["status"] != "passed":
        raise EvidenceError("diagnostic-output report status drifted")
    if report["profile"] != PROFILE or report["scope"] != SCOPE or report["upstream"] != PINNED_UPSTREAM:
        raise EvidenceError("diagnostic-output report contract drifted")
    if report["target"] != {"architecture": "x86_64", "endianness": "little", "rust_target": TARGET, "system": "linux"}:
        raise EvidenceError("diagnostic-output report target drifted")
    provenance = report["native_execution_provenance"]
    if provenance not in ({"execution_mode": "native", "host_architecture": "x86_64"}, {"execution_mode": "native", "host_architecture": "amd64"}):
        raise EvidenceError("diagnostic-output report native provenance drifted")
    if report["fixture"] != current_file_identity(FIXTURE):
        raise EvidenceError("diagnostic-output fixture identity drifted")
    if report["cargo_lock"] != current_file_identity(LOCKFILE):
        raise EvidenceError("diagnostic-output Cargo.lock identity drifted")
    if report["rust_source_files"] != current_rust_source_records():
        raise EvidenceError("diagnostic-output Rust source closure drifted")
    if report["rust_build_inputs"] != current_rust_build_input_records():
        raise EvidenceError("diagnostic-output Rust build-input closure drifted")
    c_oracle = report["c_oracle"]
    if not isinstance(c_oracle, Mapping) or set(c_oracle) != {"build", "runs", "source_files"}:
        raise EvidenceError("diagnostic-output C oracle schema drifted")
    build = require_record(c_oracle["build"], "C build")
    source = collector_source_root(build)
    temporary = source.parent.parent
    binary = temporary / "diagnostic-output-owner-c-oracle"
    if (
        build["status"] != 0
        or build["command"] != c_compile_command("musl-gcc", source, binary)
        or build["stdout"] != ""
        or build["stderr"] != ""
    ):
        raise EvidenceError("diagnostic-output C build receipt drifted")
    runs = c_oracle["runs"]
    if not isinstance(runs, Mapping) or tuple(runs) != SCENARIOS:
        raise EvidenceError("diagnostic-output C scenario roster drifted")
    c_trace: dict[str, list[str]] = {}
    for scenario in SCENARIOS:
        run = require_record(runs[scenario], f"C {scenario}")
        if (
            run["status"] != 0
            or run["cwd"] != str(source)
            or run["command"] != [str(binary), scenario]
            or run["stderr"] != EXPECTED_C_STDERR[scenario]
        ):
            raise EvidenceError(f"diagnostic-output C {scenario} command/status drifted")
        c_trace[scenario] = parse_single_trace(run["stdout"], scenario)
    if c_trace != EXPECTED_TRACE:
        raise EvidenceError("pinned C diagnostic-output trace drifted")
    source_files = c_oracle["source_files"]
    if source_files != expected_pinned_c_source_records():
        raise EvidenceError("diagnostic-output C source identity drifted")
    rust = require_record(report["rust"], "Rust trace")
    target = temporary / "rust-target"
    if (
        rust["status"] != 0
        or rust["cwd"] != str(ROOT)
        or rust["command"] != rust_command("cargo", target)
    ):
        raise EvidenceError("diagnostic-output Rust command/status drifted")
    rust_trace = parse_trace(rust["stdout"], TRACE_BEGIN, TRACE_END)
    if rust_trace != EXPECTED_TRACE or rust_trace != c_trace:
        raise EvidenceError("diagnostic-output C/Rust trace reconstruction drifted")
    if rust["stderr"] != expected_default_stderr_stream():
        raise EvidenceError("diagnostic-output Rust default-stderr raw stream drifted")
    rust_default_stderr = parse_trace(rust["stderr"], DEFAULT_STDERR_BEGIN, DEFAULT_STDERR_END)
    if rust_default_stderr != EXPECTED_DEFAULT_STDERR_TRACE:
        raise EvidenceError("diagnostic-output Rust default-stderr trace drifted")
    if {
        scenario: b"".join(bytes.fromhex(fragment) for fragment in fragments).decode("ascii")
        for scenario, fragments in rust_default_stderr.items()
    } != EXPECTED_C_STDERR:
        raise EvidenceError("diagnostic-output C/Rust default-stderr reconstruction drifted")


def atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = Path(output.name)
    temporary.replace(path)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    collect_parser = commands.add_parser("collect", help="run the native C/Rust producer")
    collect_parser.add_argument("--archive", type=Path, required=True)
    collect_parser.add_argument("--report", type=Path, default=default_report())
    validate_parser = commands.add_parser("validate", help="reconstruct a retained report without execution")
    validate_parser.add_argument("report", type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        if arguments.command == "collect":
            report = collect(arguments.archive, arguments.report)
            print(f"diagnostic-output evidence collected: {arguments.report} ({report['status']})")
        else:
            validate_report(json.loads(arguments.report.read_text(encoding="utf-8")))
            print(f"diagnostic-output evidence validated without execution: {arguments.report}")
    except (EvidenceError, OSError, json.JSONDecodeError) as error:
        print(f"diagnostic-output evidence: FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
