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
RUST_SOURCE = ROOT / "crabc-mimalloc/src/diagnostic_output.rs"
LOCKFILE = ROOT / "Cargo.lock"
TARGET = "x86_64-unknown-linux-musl"
PINNED_UPSTREAM = {
    "archive_sha256": "1e432f0559a4ab512143b9bff7a700541a2c8d4712b26a72de3e0222790da305",
    "revision": "18b08671c9302247bfb682286e6bf3cc1773f801",
}
PROFILE = "linux-x86_64-private-mimalloc-diagnostic-output-owner"
TRACE_BEGIN = "CRABC_MI_DIAGNOSTIC_OUTPUT_OWNER_TRACE_BEGIN"
TRACE_END = "CRABC_MI_DIAGNOSTIC_OUTPUT_OWNER_TRACE_END"
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
HEX = re.compile(r"(?:[0-9a-f]{2})*")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")

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
SCOPE = {
    "claim": "private source-faithful diagnostic output owner trace",
    "public_runtime_support": False,
    "exclusions": [
        "public mi_register_output ABI or general callback API",
        "environment parsing and complete options API parity",
        "normal mapping-error receiver integration",
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


def relative(path: Path) -> str:
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


def command_record(command: Sequence[str], cwd: Path) -> dict[str, Any]:
    environment = {"PATH": os.environ.get("PATH", "")}
    for name in ("CARGO_HOME", "CRABC_WORK_DIR", "TMPDIR"):
        if name in os.environ:
            environment[name] = os.environ[name]
    completed = subprocess.run(
        list(command), cwd=cwd, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False,
    )
    return {
        "command": list(command),
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
        cargo, "test", "--locked", "--target", TARGET, "--target-dir", str(target),
        "-p", "crabc-mimalloc", "--lib",
        "diagnostic_output::tests::diagnostic_output_owner_trace_for_future_pinned_c_comparison",
        "--", "--exact", "--nocapture", "--test-threads=1",
    ]


def collect(archive: Path, report_path: Path) -> dict[str, Any]:
    provenance = require_native_x86_64()
    require_checkout_work_path(report_path, "evidence report")
    if not archive.is_file() or sha256_file(archive) != PINNED_UPSTREAM["archive_sha256"]:
        raise EvidenceError("collector requires the exact pinned mimalloc archive")
    harness = load_harness()
    require_checkout_work_path(Path(harness.WORK_ROOT), "allocator harness work root")
    compiler = harness.require_tool("musl-gcc")
    cargo = shutil_which("cargo")
    if cargo is None:
        raise EvidenceError("collector requires cargo")
    with harness.temporary_directory(prefix="crabc-diagnostic-output-owner-") as temporary:
        temporary_path = Path(temporary)
        source = harness.safe_extract(archive, temporary_path / "source", "mimalloc-3.5.0")
        binary = temporary_path / "diagnostic-output-owner-c-oracle"
        compile_command = c_compile_command(compiler, source, binary)
        build = command_record(compile_command, source)
        if build["status"] != 0:
            raise EvidenceError("pinned diagnostic-output C oracle failed to build")
        c_runs = {
            scenario: command_record([str(binary), scenario], source) for scenario in SCENARIOS
        }
        if any(run["status"] != 0 for run in c_runs.values()):
            raise EvidenceError("pinned diagnostic-output C oracle scenario failed")
        target = temporary_path / "rust-target"
        rust = command_record(rust_command(cargo, target), ROOT)
        if rust["status"] != 0:
            raise EvidenceError("private diagnostic-output Rust trace failed")
        report = {
            "cargo_lock": {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)},
            "c_oracle": {
                "build": build,
                "runs": c_runs,
                "source_files": source_records(source),
            },
            "fixture": {"path": relative(FIXTURE), "sha256": sha256_file(FIXTURE)},
            "format": 1,
            "kind": "mimalloc-x86_64-diagnostic-output-owner-evidence",
            "native_execution_provenance": provenance,
            "profile": PROFILE,
            "rust": rust,
            "rust_source": {"path": relative(RUST_SOURCE), "sha256": sha256_file(RUST_SOURCE)},
            "scope": SCOPE,
            "status": "passed",
            "target": {"architecture": "x86_64", "endianness": "little", "rust_target": TARGET, "system": "linux"},
            "upstream": PINNED_UPSTREAM,
        }
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
    if not isinstance(record, Mapping) or set(record) != {"command", "status", "stdout", "stderr"}:
        raise EvidenceError(f"{name} raw command/stream record drifted")
    if not isinstance(record["command"], list) or not all(isinstance(item, str) for item in record["command"]):
        raise EvidenceError(f"{name} command is not retained exactly")
    if type(record["status"]) is not int or not isinstance(record["stdout"], str) or not isinstance(record["stderr"], str):
        raise EvidenceError(f"{name} status or raw streams are invalid")
    return record


def validate_report(report: object) -> None:
    if not isinstance(report, Mapping) or set(report) != {
        "c_oracle", "cargo_lock", "fixture", "format", "kind", "native_execution_provenance", "profile",
        "rust", "rust_source", "scope", "status", "target", "upstream",
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
    fixture = report["fixture"]
    if not isinstance(fixture, Mapping) or fixture.get("path") != relative(FIXTURE) or not isinstance(fixture.get("sha256"), str) or not SHA256.fullmatch(fixture["sha256"]):
        raise EvidenceError("diagnostic-output fixture identity drifted")
    for name, path in (("Cargo lock", LOCKFILE), ("Rust source", RUST_SOURCE)):
        record = report["cargo_lock" if name == "Cargo lock" else "rust_source"]
        if not isinstance(record, Mapping) or record.get("path") != relative(path) or not isinstance(record.get("sha256"), str) or not SHA256.fullmatch(record["sha256"]):
            raise EvidenceError(f"diagnostic-output {name.lower()} identity drifted")
    c_oracle = report["c_oracle"]
    if not isinstance(c_oracle, Mapping) or set(c_oracle) != {"build", "runs", "source_files"}:
        raise EvidenceError("diagnostic-output C oracle schema drifted")
    build = require_record(c_oracle["build"], "C build")
    if build["status"] != 0 or not any(
        argument.endswith("/src/options.c") for argument in build["command"]
    ):
        raise EvidenceError("diagnostic-output C build does not retain the pinned options source")
    runs = c_oracle["runs"]
    if not isinstance(runs, Mapping) or tuple(runs) != SCENARIOS:
        raise EvidenceError("diagnostic-output C scenario roster drifted")
    c_trace: dict[str, list[str]] = {}
    for scenario in SCENARIOS:
        run = require_record(runs[scenario], f"C {scenario}")
        if (
            run["status"] != 0
            or len(run["command"]) != 2
            or run["command"][1] != scenario
            or Path(run["command"][0]).name != "diagnostic-output-owner-c-oracle"
        ):
            raise EvidenceError(f"diagnostic-output C {scenario} command/status drifted")
        c_trace[scenario] = parse_single_trace(run["stdout"], scenario)
    if c_trace != EXPECTED_TRACE:
        raise EvidenceError("pinned C diagnostic-output trace drifted")
    source_files = c_oracle["source_files"]
    if not isinstance(source_files, list) or [item.get("path") if isinstance(item, Mapping) else None for item in source_files] != list(C_SOURCE_FILES):
        raise EvidenceError("diagnostic-output C source roster drifted")
    if not all(isinstance(item, Mapping) and SHA256.fullmatch(str(item.get("sha256"))) for item in source_files):
        raise EvidenceError("diagnostic-output C source identity is invalid")
    rust = require_record(report["rust"], "Rust trace")
    if rust["status"] != 0 or "--locked" not in rust["command"] or TARGET not in rust["command"]:
        raise EvidenceError("diagnostic-output Rust command/status drifted")
    rust_trace = parse_trace(rust["stdout"], TRACE_BEGIN, TRACE_END)
    if rust_trace != EXPECTED_TRACE or rust_trace != c_trace:
        raise EvidenceError("diagnostic-output C/Rust trace reconstruction drifted")


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
