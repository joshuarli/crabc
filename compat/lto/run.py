#!/usr/bin/env python3
"""Measure the bounded AArch64 Rust/LLVM static/build-std matrix.

This runner is deliberately an evidence collector, not a benchmark wrapper.
Each configuration is built with an isolated temporary Cargo project, and its
exact argv, selected environment, compiler output, artifact hashes, ELF/LLVM
inspection, and (when available) runtime/syscall observations are written to a
JSON report.  A missing cross tool, an unavailable linker-plugin feature, and
a normal compiler/linker failure are represented separately; none is turned
into a successful measurement.

Run this inside the pinned native Linux/AArch64 image after building crabc:

    python3 compat/lto/run.py

The macOS development host is intentionally reported as unsupported.  This
keeps a host-side invocation useful for diagnosing setup without pretending
that an Apple process measured a Linux AArch64 ELF.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import importlib.util
import json
import os
import platform
import resource
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path
from typing import Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).resolve().parent / "fixtures/src/main.rs"
STATIC_FIXTURE = Path(__file__).resolve().parent / "fixtures/static.c"
FIXTURE_MANIFEST = Path(__file__).resolve().parent / "fixtures/Cargo.toml"
UPSTREAMS = ROOT / "compat/upstreams.toml"
REPORT = ROOT / "compat/reports/lto/latest.json"
TARGET = "aarch64-unknown-linux-musl"
TOOLCHAIN = "nightly-2026-07-24"
MUSL_VERSION = "1.2.6"
MUSL_ROOT = Path(f"/opt/musl-{MUSL_VERSION}")
SYSROOT_TOOL = ROOT / "scripts/crabc_sysroot.py"
DEFAULT_SYSROOT = ROOT / "target/crabc-sysroot"


SYSROOT_SPEC = importlib.util.spec_from_file_location("crabc_lto_sysroot", SYSROOT_TOOL)
assert SYSROOT_SPEC is not None and SYSROOT_SPEC.loader is not None
SYSROOT = importlib.util.module_from_spec(SYSROOT_SPEC)
sys.modules[SYSROOT_SPEC.name] = SYSROOT
SYSROOT_SPEC.loader.exec_module(SYSROOT)


class RunnerError(RuntimeError):
    """A harness setup or contract error."""


@dataclasses.dataclass(frozen=True)
class Configuration:
    """One planned build, with the claims it is allowed to make."""

    key: str
    label: str
    runtime: str
    build_std: bool
    static: bool
    lto: str
    linker_plugin_lto: bool
    stock_std: bool
    workload: str


CONFIGURATIONS = (
    Configuration(
        "A",
        "musl static (controlled C)",
        "musl",
        build_std=False,
        static=True,
        lto="off",
        linker_plugin_lto=False,
        stock_std=False,
        workload="c-static",
    ),
    Configuration(
        "B",
        "crabc static (controlled C)",
        "crabc-static",
        build_std=False,
        static=True,
        lto="off",
        linker_plugin_lto=False,
        stock_std=False,
        workload="c-static",
    ),
    Configuration(
        "C",
        "crabc build-std",
        "crabc",
        build_std=True,
        static=False,
        lto="off",
        linker_plugin_lto=False,
        stock_std=False,
        workload="rust",
    ),
    Configuration(
        "D",
        "crabc build-std fat/linker-plugin LTO",
        "crabc-static-lto",
        build_std=True,
        static=True,
        lto="fat",
        linker_plugin_lto=True,
        stock_std=False,
        workload="rust",
    ),
)


@dataclasses.dataclass(frozen=True)
class ProcessResult:
    status: int | str
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    wall_time_ns: int | None = None
    max_rss_raw: int | None = None
    max_rss_unit: str = "unknown"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def snapshot(value: bytes, *, preview_limit: int = 131_072) -> dict[str, object]:
    """Keep exact byte length/hash and a bounded readable diagnostic preview."""

    preview = value[:preview_limit]
    return {
        "byte_length": len(value),
        "sha256": sha256_bytes(value),
        "preview": preview.decode("utf-8", errors="replace"),
        "preview_truncated": len(value) > len(preview),
    }


def require_command(name: str) -> str | None:
    return shutil.which(name)


def select_command(*names: str) -> tuple[str | None, list[str]]:
    """Return the first available spelling and all spellings that were tried."""

    tried = list(names)
    for name in names:
        path = require_command(name)
        if path is not None:
            return path, tried
    return None, tried


def command_record(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Run a tool without a shell and retain its complete invocation/result."""

    try:
        result = subprocess.run(
            list(command),
            cwd=cwd,
            env=dict(environment) if environment is not None else None,
            check=False,
            capture_output=True,
        )
        return {
            "command": list(command),
            "cwd": str(cwd) if cwd is not None else None,
            "returncode": result.returncode,
            "stdout": snapshot(result.stdout),
            "stderr": snapshot(result.stderr),
        }
    except OSError as error:
        return {
            "command": list(command),
            "cwd": str(cwd) if cwd is not None else None,
            "returncode": f"OSERROR:{error.errno or 'unknown'}",
            "stdout": snapshot(b""),
            "stderr": snapshot(str(error).encode()),
        }


def command_text(record: Mapping[str, object]) -> str:
    """Recover the bounded textual evidence from a command record."""

    value = record.get("stdout")
    if not isinstance(value, Mapping):
        return ""
    text = value.get("preview")
    return text if isinstance(text, str) else ""


def reject_glibc(text: str, description: str) -> None:
    markers = ("glibc", "gnu c library", "ld-linux", "libc.so.6")
    lowered = text.lower()
    if any(marker in lowered for marker in markers):
        raise RunnerError(f"glibc artifact/toolchain evidence detected in {description}")


def patched_interpreter_bytes(binary: bytes, interpreter: str) -> bytes:
    """Patch only PT_INTERP in an ELF64 little-endian AArch64 executable."""

    if len(binary) < 64 or binary[:4] != b"\x7fELF" or binary[4] != 2 or binary[5] != 1:
        raise RunnerError("fixture output is not an ELF64 little-endian executable")
    if int.from_bytes(binary[18:20], "little") != 183:
        raise RunnerError("fixture output is not an AArch64 ELF")
    phoff = int.from_bytes(binary[32:40], "little")
    phentsize = int.from_bytes(binary[54:56], "little")
    phnum = int.from_bytes(binary[56:58], "little")
    if phentsize < 56:
        raise RunnerError("fixture ELF has an invalid program-header size")

    result = bytearray(binary)
    encoded = interpreter.encode("ascii") + b"\0"
    for index in range(phnum):
        offset = phoff + index * phentsize
        if offset + 56 > len(result):
            raise RunnerError("fixture ELF program headers exceed the file")
        if int.from_bytes(result[offset : offset + 4], "little") != 3:  # PT_INTERP
            continue
        file_offset = int.from_bytes(result[offset + 8 : offset + 16], "little")
        file_size = int.from_bytes(result[offset + 32 : offset + 40], "little")
        if len(encoded) > file_size or file_offset + file_size > len(result):
            raise RunnerError(
                f"interpreter path {interpreter!r} does not fit PT_INTERP ({file_size} bytes)"
            )
        result[file_offset : file_offset + file_size] = encoded + b"\0" * (file_size - len(encoded))
        return bytes(result)
    raise RunnerError("fixture ELF has no PT_INTERP segment")


def patch_interpreter(source: Path, destination: Path, interpreter: str) -> None:
    destination.write_bytes(patched_interpreter_bytes(source.read_bytes(), interpreter))
    destination.chmod(source.stat().st_mode | stat.S_IXUSR)


def sanitize_environment() -> dict[str, str]:
    """Build one explicit environment contract for every workload process."""

    environment = dict(os.environ)
    for key in tuple(environment):
        if key.startswith(("LD_", "DYLD_", "RUST", "CARGO", "CRABC", "MUSL")):
            environment.pop(key, None)
    environment.update(
        {
            "PATH": "/bin:/usr/bin",
            "HOME": "/root",
            "TMPDIR": "/tmp",
            "PWD": "/tmp",
            "OLDPWD": "/tmp",
            "LC_ALL": "C",
            "CRABC_LTO_FIXTURE": "aarch64-musl",
        }
    )
    return environment


def environment_evidence(environment: Mapping[str, str]) -> dict[str, object]:
    encoded = "\0".join(f"{key}={environment[key]}" for key in sorted(environment)).encode()
    public_keys = {
        "PATH",
        "HOME",
        "TMPDIR",
        "PWD",
        "OLDPWD",
        "LC_ALL",
        "CRABC_LTO_FIXTURE",
        "LD_LIBRARY_PATH",
        "RUSTFLAGS",
        "CARGO_TARGET_DIR",
        "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER",
    }
    visible = {
        key: environment[key]
        for key in sorted(environment)
        if key in public_keys or key.startswith("CARGO_TARGET_")
    }
    return {
        "sha256": sha256_bytes(encoded),
        "variables": visible,
        "redacted_variable_names": sorted(set(environment) - set(visible)),
    }


def run_binary(
    binary: Path,
    environment: Mapping[str, str],
    timeout: float,
    *,
    cwd: Path,
    library_path: Path | None = None,
) -> ProcessResult:
    process_environment = dict(environment)
    if library_path is not None:
        process_environment["LD_LIBRARY_PATH"] = str(library_path)
    else:
        process_environment.pop("LD_LIBRARY_PATH", None)

    def disable_core_dump() -> None:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    rss_before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    started = time.monotonic_ns()
    try:
        process = subprocess.Popen(
            [str(binary)],
            cwd=cwd,
            env=process_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=disable_core_dump,
            close_fds=True,
        )
    except OSError as error:
        return ProcessResult(f"EXEC_ERROR:{error.errno or 'unknown'}", b"", str(error).encode())
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        process.kill()
        stdout, stderr = process.communicate()
        elapsed = time.monotonic_ns() - started
        return ProcessResult(
            "TIMEOUT",
            stdout or error.stdout or b"",
            stderr or error.stderr or b"",
            timed_out=True,
            wall_time_ns=elapsed,
        )
    elapsed = time.monotonic_ns() - started
    rss_after = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    # Linux reports KiB.  The target is Linux/AArch64; preserve the raw value
    # and unit instead of presenting a host/macOS value as a Linux measurement.
    return ProcessResult(
        process.returncode,
        stdout,
        stderr,
        wall_time_ns=elapsed,
        max_rss_raw=max(0, rss_after - rss_before),
        max_rss_unit="KiB (Linux ru_maxrss)",
    )


def result_record(result: ProcessResult) -> dict[str, object]:
    return {
        "status": result.status,
        "timed_out": result.timed_out,
        "wall_time_ns": result.wall_time_ns,
        "max_rss_raw": result.max_rss_raw,
        "max_rss_unit": result.max_rss_unit,
        # RUSAGE_CHILDREN is cumulative and retains the largest child value.
        # Its delta is useful run evidence, but not an isolated process peak.
        "max_rss_limit": "raw RUSAGE_CHILDREN delta; not an isolated process peak",
        "stdout": snapshot(result.stdout),
        "stderr": snapshot(result.stderr),
    }


def parse_syscall_summary(text: str) -> dict[str, object]:
    """Parse the stable, tabular part of ``strace -f -c`` output."""

    rows: list[dict[str, object]] = []
    in_table = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "syscall" in line and "calls" in line:
            in_table = True
            continue
        if not in_table or line.startswith("---") or line.startswith("% time"):
            continue
        fields = line.split()
        if len(fields) < 5:
            continue
        if fields[-1] == "total":
            continue
        # strace leaves the zero-error column blank.  ``split`` therefore
        # yields five fields for a normal row and six when errors is nonzero.
        if len(fields) >= 6 and fields[-3].isdigit() and fields[-2].isdigit():
            calls = int(fields[-3])
            errors = int(fields[-2])
        elif fields[-2].isdigit():
            calls = int(fields[-2])
            errors = 0
        else:
            continue
        rows.append({"syscall": fields[-1], "calls": calls, "errors": errors})
    return {"syscalls": rows, "total_calls": sum(row["calls"] for row in rows)}


def syscall_measurement(
    binary: Path,
    environment: Mapping[str, str],
    timeout: float,
    *,
    cwd: Path,
    library_path: Path | None,
    output_file: Path,
) -> dict[str, object]:
    tracer = require_command("strace")
    if tracer is None:
        return {"status": "unsupported", "reason": "strace is unavailable"}
    process_environment = dict(environment)
    if library_path is not None:
        process_environment["LD_LIBRARY_PATH"] = str(library_path)
    else:
        process_environment.pop("LD_LIBRARY_PATH", None)
    command = [tracer, "-f", "-c", "-o", str(output_file), str(binary)]
    started = time.monotonic_ns()
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=process_environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        timed_out = False
    except subprocess.TimeoutExpired as error:
        completed = None
        timed_out = True
        stderr = (error.stderr or b"") if isinstance(error.stderr, bytes) else str(error).encode()
        return {
            "status": "TIMEOUT",
            "command": command,
            "wall_time_ns": time.monotonic_ns() - started,
            "stdout": snapshot(b""),
            "stderr": snapshot(stderr),
            "timed_out": True,
        }
    assert completed is not None
    trace = output_file.read_bytes() if output_file.is_file() else b""
    parsed = parse_syscall_summary(trace.decode("utf-8", errors="replace"))
    return {
        "status": completed.returncode,
        "command": command,
        "wall_time_ns": time.monotonic_ns() - started,
        "timed_out": timed_out,
        "stdout": snapshot(completed.stdout),
        "stderr": snapshot(completed.stderr),
        "trace": snapshot(trace),
        **parsed,
    }


def parse_text_size(readelf_text: str) -> int | None:
    """Extract the sum of .text-like section sizes from readelf -SW output."""

    sizes = parse_named_section_sizes(readelf_text, ".text")
    return sum(sizes) if sizes else None


def parse_named_section_sizes(readelf_text: str, prefix: str) -> list[int]:
    """Extract section sizes from readelf -SW rows whose names have prefix."""

    sizes: list[int] = []
    for line in readelf_text.splitlines():
        fields = line.split()
        if len(fields) < 6:
            continue
        section_index = 2 if fields[0] == "[" else 1 if fields[0].startswith("[") else -1
        if section_index < 0 or len(fields) <= section_index + 4:
            continue
        if not fields[section_index].startswith(prefix):
            continue
        try:
            sizes.append(int(fields[section_index + 4], 16))
        except ValueError:
            continue
    return sizes


def lto_provenance(cargo_target: Path, configuration: Configuration, tools: Mapping[str, str]) -> dict[str, object]:
    """Bounded positive evidence for Rust rlib bitcode, never for crabc.

    Rust's build-std rlibs are intermediate artifacts.  They can show that
    bitcode was emitted for the Rust application/std graph, but they cannot
    prove that the externally linked crabc libc participated in one graph.
    """

    if not configuration.build_std:
        return {"status": "not_applicable", "scope": "prebuilt stock std"}
    rlibs = sorted(cargo_target.rglob("*.rlib"))
    # Avoid making inspection itself an unbounded benchmark if a toolchain
    # happens to retain many incremental artifacts.
    examined = rlibs[:64]
    readelf = tools.get("llvm_readelf")
    bitcode_rlibs = 0
    bitcode_section_bytes = 0
    inspected_commands = 0
    for rlib in examined:
        sizes: list[int] = []
        if readelf:
            record = command_record([readelf, "-SW", str(rlib)])
            inspected_commands += 1
            sizes = parse_named_section_sizes(command_text(record), ".llvmbc")
        else:
            # Keep a conservative fallback when llvm-readelf is not present:
            # a marker is evidence that an archive contains such a section,
            # not a byte count of its payload.
            try:
                blob = rlib.read_bytes()
            except OSError:
                blob = b""
            if b".llvmbc" in blob:
                sizes = [0]
        if sizes:
            bitcode_rlibs += 1
            bitcode_section_bytes += sum(sizes)
    return {
        "status": "observed" if bitcode_rlibs else "not_observed",
        "scope": "Rust application/std rlibs only; crabc libc is external and opaque",
        "rlib_count": len(rlibs),
        "rlibs_examined": len(examined),
        "bitcode_rlib_count": bitcode_rlibs,
        "bitcode_section_bytes": bitcode_section_bytes,
        "llvm_readelf_invocations": inspected_commands,
        "final_elf_bitcode_expected": False,
        "whole_program_lto_proven": False,
    }


def queried_gcc_file(musl_gcc: str, name: str) -> tuple[Path | None, dict[str, object]]:
    """Resolve a GCC support file while retaining the exact query evidence."""

    record = command_record([musl_gcc, f"-print-file-name={name}"])
    value = command_text(record).strip()
    path = Path(value) if value and value != name else None
    return path, record


def musl_static_crt_evidence(inputs: Mapping[str, object], musl_gcc: str) -> tuple[dict[str, Path], list[dict[str, object]]]:
    """Resolve A's musl/GCC static support inputs as oracle evidence only."""

    musl_root = inputs["musl_root"]
    assert isinstance(musl_root, Path)
    paths = {
        "crt1": musl_root / "lib/Scrt1.o",
        "crti": musl_root / "lib/crti.o",
        "crtn": musl_root / "lib/crtn.o",
        "libssp_nonshared": musl_root / "lib/libssp_nonshared.a",
    }
    records: list[dict[str, object]] = []
    for key, name in (
        ("crtbeginS", "crtbeginS.o"),
        ("crtendS", "crtendS.o"),
        ("libgcc", "libgcc.a"),
        ("libgcc_eh", "libgcc_eh.a"),
    ):
        path, record = queried_gcc_file(musl_gcc, name)
        record["purpose"] = key
        records.append(record)
        if path is None:
            raise RunnerError(f"musl-gcc did not resolve {name}")
        paths[key] = path
    missing = [str(path) for path in paths.values() if not path.is_file()]
    if missing:
        raise RunnerError(f"static CRT/support files unavailable: {missing}")
    return paths, records


def owned_static_sysroot_evidence(inputs: Mapping[str, object]) -> dict[str, object]:
    """Resolve B's sealed application-CRT inputs without a musl fallback.

    Configuration B is a direct consumer of the installed application sysroot.
    Its C source remains an application input, while the CRT, libc archive, and
    compiler-helper archive are selected only by ``crabc-cc``. Keep this
    boundary here instead of reconstructing an owned link from individual
    paths: the wrapper seals target search paths and ordering.
    """

    configured = inputs["sysroot"]
    assert isinstance(configured, Path)
    try:
        sysroot = SYSROOT.require_directory(configured, "owned crabc sysroot")
        manifest = SYSROOT.load_installed_manifest(sysroot)
        runtime = SYSROOT.installed_runtime_paths(sysroot)
    except SYSROOT.SysrootError as error:
        raise RunnerError(str(error)) from error
    wrapper = sysroot / "bin/crabc-cc"
    if not wrapper.is_file() or not os.access(wrapper, os.X_OK):
        raise RunnerError(f"owned crabc compiler wrapper is missing or not executable: {wrapper}")
    for name in ("crt1.o", "crti.o", "crtn.o", "libc.a", "builtins"):
        runtime_path = runtime[name]
        if not runtime_path.is_file():
            raise RunnerError(f"owned sysroot runtime input is absent ({name}): {runtime_path}")
    return {
        "sysroot": sysroot,
        "wrapper": wrapper,
        "manifest": manifest,
        "runtime": runtime,
    }


def owned_static_command(wrapper: Path, source: Path, binary: Path, map_file: Path) -> list[str]:
    """Build B through the sealed driver, including its resolved-link trace."""

    return [
        str(wrapper),
        "-O3",
        "-static",
        "-no-pie",
        "-fno-builtin",
        "-fno-stack-protector",
        str(source),
        f"-Wl,-Map={map_file}",
        "-Wl,--trace",
        "-o",
        str(binary),
    ]


def run_static_c_configuration(
    configuration: Configuration,
    inputs: Mapping[str, object],
    environment: Mapping[str, str],
    timeout: float,
    workspace: Path,
) -> dict[str, object]:
    """Build the musl oracle A and owned-sysroot candidate B from one C source."""

    tools = inputs["tools"]
    source = inputs["static_fixture"]
    musl_gcc = tools.get("musl_gcc")
    assert isinstance(tools, Mapping) and isinstance(source, Path)
    project = workspace
    project.mkdir(parents=True)
    binary = project / f"static-{configuration.key.lower()}"
    map_file = project / "link.map"
    command_records: list[dict[str, object]] = []
    if configuration.key == "A":
        if musl_gcc is None:
            return {"status": "unsupported", "reason": "musl-gcc is unavailable"}
        try:
            crt, crt_records = musl_static_crt_evidence(inputs, musl_gcc)
        except RunnerError as error:
            return {"status": "unsupported", "reason": str(error)}
        command = [
            musl_gcc,
            "-O3",
            "-static",
            "-no-pie",
            "-fno-builtin",
            "-fno-stack-protector",
            str(source),
            f"-Wl,-Map={map_file}",
            "-o",
            str(binary),
        ]
        record = command_record(command, cwd=project)
        command_records.append(record)
    else:
        try:
            owned = owned_static_sysroot_evidence(inputs)
        except RunnerError as error:
            return {"status": "unsupported", "reason": str(error)}
        wrapper = owned["wrapper"]
        assert isinstance(wrapper, Path)
        command = owned_static_command(wrapper, source, binary, map_file)
        # The wrapper itself seals all target search paths. Supplying the same
        # environment makes the recorded command independent from a caller's
        # target-runtime shell variables.
        record = command_record(command, cwd=project, environment=SYSROOT.seal_environment())
        command_records.append(record)
        crt = {}
        crt_records = []

    build: dict[str, object] = {
        "commands": command_records,
        "crt_files": {name: str(path) for name, path in crt.items()},
        "crt_queries": crt_records,
        "binary": str(binary),
        "returncode": record["returncode"],
    }
    output_text = command_text(record) + str(record.get("stderr", ""))
    if record["returncode"] != 0:
        return {"status": "unbuildable", "reason": "static C link failed", "build": build}
    if not binary.is_file() or not os.access(binary, os.X_OK):
        return {"status": "unbuildable", "reason": "static C link produced no executable", "build": build}
    try:
        inspection = inspect_and_validate_elf(binary, configuration, tools)
    except RunnerError as error:
        return {"status": "invalid", "reason": str(error), "build": build}
    build.update({"binary_sha256": sha256_file(binary), "artifact": inspection})
    map_text = map_file.read_text(encoding="utf-8", errors="replace") if map_file.is_file() else ""
    candidate_archive = (
        owned["runtime"]["libc.a"] if configuration.key == "B" else inputs["candidate_archive"]
    )
    assert isinstance(candidate_archive, Path)
    candidate_marker = str(candidate_archive)
    candidate_nm_record: dict[str, object] | None = None
    candidate_members: list[str] = []
    llvm_nm = tools.get("llvm_nm")
    if configuration.key == "B" and llvm_nm:
        candidate_nm_record = command_record([llvm_nm, "-g", "--defined-only", candidate_marker])
        candidate_members = archive_member_names(command_text(candidate_nm_record))
        build["candidate_archive_llvm_nm"] = candidate_nm_record
    candidate_member_matches = [
        member for member in candidate_members if f"({member})" in map_text
    ]
    contains_candidate_path = configuration.key == "B" and candidate_marker in map_text
    contains_candidate_member = bool(candidate_member_matches)
    contains_candidate = contains_candidate_path or contains_candidate_member
    contains_musl_archive = str(inputs["musl_archive"]) in map_text
    owned_trace_audit: dict[str, object] | None = None
    if configuration.key == "B":
        trace_bytes = b""
        trace_truncated = False
        for stream_name in ("stdout", "stderr"):
            stream = record.get(stream_name, {})
            if isinstance(stream, Mapping):
                trace_bytes += str(stream.get("preview", "")).encode()
                trace_truncated = trace_truncated or bool(stream.get("preview_truncated"))
        sysroot = owned["sysroot"]
        assert isinstance(sysroot, Path)
        owned_trace_audit = (
            {"status": "unverified", "reason": "controlled-C linker trace exceeded retained evidence"}
            if trace_truncated
            else SYSROOT.audit_linker_trace(trace_bytes, sysroot, [source], [project])
        )
        build["owned_sysroot"] = {
            "path": str(sysroot),
            "manifest": owned["manifest"],
            "runtime": {
                name: str(path)
                for name, path in owned["runtime"].items()
                if name in {"crt1.o", "crti.o", "crtn.o", "libc.a", "builtins"}
            },
            "link_trace_audit": owned_trace_audit,
        }
    claims = {
        "controlled_c_fixture": True,
        "static_crt_explicit": configuration.key == "A",
        "static_crt_owned_sysroot": configuration.key == "B",
        "static_link_map": snapshot(map_text.encode()),
        "static_link_map_sha256": sha256_bytes(map_text.encode()),
        "static_link_map_contains_candidate": contains_candidate,
        "static_link_map_contains_candidate_path": contains_candidate_path,
        "static_link_map_candidate_member_anchors": candidate_members,
        "static_link_map_candidate_member_matches": candidate_member_matches,
        "static_link_map_contains_musl": contains_musl_archive,
        "static_link_map_contains_musl_root": str(inputs["musl_root"]) in map_text,
        "static_crabc_linkage_proven": (
            configuration.key == "B"
            and contains_candidate
            and not contains_musl_archive
            and owned_trace_audit is not None
            and owned_trace_audit.get("status") == "passed"
        ),
        "runtime_status_zero": None,
        "whole_program_lto_proven": False,
    }
    build["claims"] = claims
    if configuration.key == "B" and not claims["static_crabc_linkage_proven"]:
        return {
            "status": "invalid",
            "reason": "owned static link does not prove exclusive crabc sysroot inputs",
            "build": build,
        }
    runtime_workspace = project / "runtime"
    runtime_workspace.mkdir()
    runtime = run_binary(binary, environment, timeout, cwd=runtime_workspace)
    build["runtime"] = result_record(runtime)
    claims["runtime_status_zero"] = runtime.status == 0
    build["runtime"]["command"] = [str(binary)]
    build["runtime"]["cwd"] = str(runtime_workspace)
    build["syscalls"] = syscall_measurement(
        binary,
        environment,
        timeout,
        cwd=runtime_workspace,
        library_path=None,
        output_file=runtime_workspace / "strace.txt",
    )
    if runtime.status != 0:
        return {
            "status": "runtime-failed",
            "reason": f"static executable exited with status {runtime.status!r}",
            "build": build,
        }
    return {"status": "built", "build": build}


def build_crabc_lto_archive(inputs: Mapping[str, object], tools: Mapping[str, str], workspace: Path) -> tuple[Path | None, dict[str, object]]:
    """Build a temporary bitcode-bearing crabc ``libc.a`` for static D."""

    clang = tools.get("clang")
    if clang is None:
        return None, {"status": "unsupported", "reason": "clang is unavailable for crabc LTO rebuild"}
    target_dir = workspace / "crabc-target"
    flags = [
        "-C",
        "opt-level=3",
        "-C",
        "codegen-units=1",
        "-C",
        "panic=abort",
        "-C",
        "target-feature=+crt-static",
        "-C",
        "embed-bitcode=yes",
        "-C",
        "lto=fat",
        "-C",
        "linker-plugin-lto",
        "-C",
        "link-arg=--target=aarch64-unknown-linux-musl",
        "-C",
        "link-arg=--sysroot=/opt/musl-1.2.6",
        "-C",
        "link-arg=-fuse-ld=lld",
        "-C",
        "link-arg=-B/usr/lib/gcc/aarch64-alpine-linux-musl/15.2.0",
        "-C",
        "link-arg=-L/usr/lib/gcc/aarch64-alpine-linux-musl/15.2.0",
        "-C",
        "link-arg=-L/opt/musl-1.2.6/lib",
    ]
    command = ["cargo", f"+{TOOLCHAIN}", "build", "-p", "crabc-libc", "--release", "--target", TARGET]
    environment = dict(os.environ)
    for key in tuple(environment):
        if key in {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"} or key.startswith("CARGO_TARGET_"):
            environment.pop(key, None)
    environment.update(
        {
            "CARGO_TARGET_DIR": str(target_dir),
            "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER": clang,
            "RUSTFLAGS": " ".join(flags),
        }
    )
    started = time.monotonic_ns()
    result = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, check=False)
    build: dict[str, object] = {
        "status": "built" if result.returncode == 0 else "unbuildable",
        "command": command,
        "cwd": str(ROOT),
        "linker": clang,
        "rustflags": environment["RUSTFLAGS"],
        "environment_sha256": environment_evidence(environment)["sha256"],
        "environment_variables": environment_evidence(environment)["variables"],
        "returncode": result.returncode,
        "wall_time_ns": time.monotonic_ns() - started,
        "stdout": snapshot(result.stdout),
        "stderr": snapshot(result.stderr),
    }
    output_text = (result.stdout + result.stderr).decode("utf-8", errors="replace")
    reject_glibc(output_text, "temporary crabc LTO build")
    archive = target_dir / TARGET / "release/libc.a"
    if result.returncode != 0 or not archive.is_file():
        build["reason"] = "temporary crabc bitcode/static archive build failed"
        return None, build
    archive_bytes = archive.read_bytes()
    build.update(
        {
            "archive": str(archive),
            "archive_sha256": sha256_file(archive),
            "archive_size_bytes": archive.stat().st_size,
            "archive_contains_llvmbc_marker": b".llvmbc" in archive_bytes,
            "archive_llvmbc_marker_count": archive_bytes.count(b".llvmbc"),
        }
    )
    llvm_nm = tools.get("llvm_nm")
    if llvm_nm:
        build["llvm_nm"] = command_record([llvm_nm, "-g", "--defined-only", str(archive)])
    return archive, build


def symbol_names(nm_text: str) -> list[str]:
    names: list[str] = []
    for line in nm_text.splitlines():
        fields = line.split()
        if fields:
            names.append(fields[-1])
    return names


def archive_member_names(nm_text: str, *, limit: int = 32) -> list[str]:
    """Extract archive-member headings from llvm-nm archive output.

    LLD's map format may retain ``libc.a(member.o)`` while omitting the
    absolute archive pathname.  Member names are therefore a useful second,
    exact selection anchor; they are only accepted when they came from the
    candidate archive's own llvm-nm output.
    """

    members: list[str] = []
    for raw_line in nm_text.splitlines():
        line = raw_line.strip()
        if not line or not line.endswith(":") or line.startswith("-"):
            continue
        member = line[:-1]
        if " " in member or "\t" in member:
            continue
        if member not in members:
            members.append(member)
        if len(members) >= limit:
            break
    return members


def fixture_helper_mentions(symbol_text: str) -> dict[str, bool]:
    """Report whether the fixture's deliberately named Rust helpers survived.

    This is only a bounded observation over nm/disassembly text. Absence is
    compatible with inlining or internalization; it is not by itself a
    whole-program LTO claim.
    """

    return {
        helper: helper in symbol_text
        for helper in ("mix", "workload", "libc_probe")
    }


def artifact_inspection(binary: Path, tools: Mapping[str, str]) -> dict[str, object]:
    """Collect independent ELF, symbol, disassembly, file, and size evidence."""

    records: dict[str, object] = {}
    file_tool = tools.get("file")
    if file_tool:
        records["file"] = command_record([file_tool, str(binary)])
    llvm_nm = tools.get("llvm_nm")
    if llvm_nm:
        records["llvm_nm"] = command_record([llvm_nm, "-g", "--defined-only", str(binary)])
    readelf = tools.get("readelf")
    if readelf:
        records["readelf"] = command_record([readelf, "-h", "-l", "-S", "-d", str(binary)])
        section_record = command_record([readelf, "-SW", str(binary)])
        records["readelf_sections"] = section_record
    objdump = tools.get("objdump")
    if objdump:
        records["objdump"] = command_record([objdump, "-d", str(binary)])

    llvm_nm_text = command_text(records.get("llvm_nm", {})) if isinstance(records.get("llvm_nm"), Mapping) else ""
    readelf_text = command_text(records.get("readelf_sections", {})) if isinstance(records.get("readelf_sections"), Mapping) else ""
    objdump_text = command_text(records.get("objdump", {})) if isinstance(records.get("objdump"), Mapping) else ""
    names = symbol_names(llvm_nm_text)
    text_bytes = readelf_text.encode()
    records["file_size_bytes"] = binary.stat().st_size
    records["sha256"] = sha256_file(binary)
    records["text_size_bytes"] = parse_text_size(readelf_text)
    records["defined_global_symbol_count"] = len(names)
    records["defined_global_symbol_sha256"] = sha256_bytes("\n".join(names).encode())
    records["direct_libc_symbol_mentions"] = {
        symbol: (symbol in objdump_text or symbol in llvm_nm_text)
        for symbol in ("getpid", "write", "malloc", "free")
    }
    records["fixture_helper_symbol_mentions"] = fixture_helper_mentions(
        f"{llvm_nm_text}\n{objdump_text}"
    )
    records["elf_has_embedded_bitcode_section"] = any(
        marker in text_bytes.decode("utf-8", errors="replace")
        for marker in (".llvmbc", ".llvmcmd")
    )

    strip_tool = tools.get("llvm_strip") or tools.get("strip")
    if strip_tool:
        with tempfile.TemporaryDirectory(prefix="lto-strip-") as temporary_name:
            stripped = Path(temporary_name) / binary.name
            shutil.copy2(binary, stripped)
            strip_record = command_record([strip_tool, "-o", str(stripped), str(stripped)])
            records["strip"] = strip_record
            records["stripped_file_size_bytes"] = stripped.stat().st_size if stripped.is_file() else None
            records["stripped_sha256"] = sha256_file(stripped) if stripped.is_file() else None
            records["strip_tool"] = strip_tool
    else:
        records["stripped_file_size_bytes"] = None
        records["stripped_sha256"] = None
        records["strip_status"] = "unsupported: strip tool unavailable"

    return records


def discover_tools() -> tuple[dict[str, str], dict[str, object]]:
    selected: dict[str, str] = {}
    attempts: dict[str, object] = {}
    for key, names in (
        ("cargo", ("cargo",)),
        ("rustc", ("rustc",)),
        ("rustup", ("rustup",)),
        ("musl_gcc", ("musl-gcc",)),
        ("file", ("file",)),
        ("llvm_nm", ("llvm-nm",)),
        ("readelf", ("readelf", "llvm-readelf")),
        ("llvm_readelf", ("llvm-readelf",)),
        ("objdump", ("objdump", "llvm-objdump")),
        ("llvm_strip", ("llvm-strip",)),
        ("strip", ("strip",)),
        ("strace", ("strace",)),
        ("clang", ("clang",)),
    ):
        path, tried = select_command(*names)
        attempts[key] = {"tried": tried, "selected": path}
        if path is not None:
            selected[key] = path
    return selected, attempts


def load_pins() -> dict[str, object]:
    try:
        with UPSTREAMS.open("rb") as stream:
            upstreams = tomllib.load(stream)
    except OSError as error:
        raise RunnerError(f"pinned upstream manifest unavailable: {UPSTREAMS}") from error
    environment = upstreams.get("environment")
    musl = upstreams.get("musl")
    if not isinstance(environment, dict) or not isinstance(musl, dict):
        raise RunnerError("compat/upstreams.toml lacks environment/musl pins")
    if environment.get("platform") != "linux/arm64":
        raise RunnerError("compat/upstreams.toml is not pinned to linux/arm64")
    if environment.get("rust_toolchain") != TOOLCHAIN:
        raise RunnerError("compat/upstreams.toml has an unexpected Rust toolchain")
    if musl.get("version") != MUSL_VERSION:
        raise RunnerError("compat/upstreams.toml has an unexpected musl version")
    return {"environment": environment, "musl": musl}


def validate_inputs(args: argparse.Namespace, tools: Mapping[str, str]) -> dict[str, object]:
    if args.timeout <= 0:
        raise RunnerError("--timeout must be positive")
    musl_root = args.musl_root.expanduser().resolve()
    target_dir = args.target_dir.expanduser().resolve()
    sysroot = args.sysroot.expanduser().resolve()
    fixture = args.fixture.expanduser().resolve()
    if musl_root.name != f"musl-{MUSL_VERSION}":
        raise RunnerError(f"--musl-root must name pinned musl-{MUSL_VERSION}: {musl_root}")
    if not fixture.is_file() or not FIXTURE_MANIFEST.is_file() or not STATIC_FIXTURE.is_file():
        raise RunnerError("LTO fixture source, static C fixture, or Cargo manifest is unavailable")
    return {
        "musl_root": musl_root,
        "musl_loader": musl_root / "lib/ld-musl-aarch64.so.1",
        "musl_libc": musl_root / "lib/libc.so",
        "musl_archive": musl_root / "lib/libc.a",
        "target_dir": target_dir,
        "sysroot": sysroot,
        "candidate_loader": target_dir / "libldso.so",
        "candidate_libc": target_dir / "libc.so",
        "candidate_archive": target_dir / "libc.a",
        "fixture": fixture,
        "fixture_manifest": FIXTURE_MANIFEST,
        "static_fixture": STATIC_FIXTURE,
        "tools": dict(tools),
    }


def host_capability_reasons(inputs: Mapping[str, object], tool_attempts: Mapping[str, object]) -> list[str]:
    reasons: list[str] = []
    if platform.system() != "Linux":
        reasons.append(f"requires Linux, got {platform.system()}")
    if platform.machine().lower() not in {"aarch64", "arm64"}:
        reasons.append(f"requires native AArch64, got {platform.machine()!r}")
    required = ("cargo", "rustc", "rustup", "musl_gcc", "file", "llvm_nm", "readelf", "objdump")
    for name in required:
        if name not in inputs["tools"]:
            selected = tool_attempts.get(name, {})
            reasons.append(f"required tool unavailable: {selected}")
    for key in ("musl_loader", "musl_libc", "musl_archive"):
        path = inputs[key]
        assert isinstance(path, Path)
        if not path.is_file():
            reasons.append(f"pinned musl artifact unavailable: {path}")
    try:
        owned_static_sysroot_evidence(inputs)
    except RunnerError as error:
        reasons.append(f"owned static B sysroot unavailable: {error}")
    if platform.system() == "Linux" and platform.machine().lower() in {"aarch64", "arm64"}:
        active = command_record([inputs["tools"]["rustup"], "show", "active-toolchain"])
        active_text = command_text(active)
        if not active_text.startswith(TOOLCHAIN):
            reasons.append(f"active Rust toolchain is not pinned {TOOLCHAIN}: {active_text}")
        rustc = command_record([inputs["tools"]["rustc"], f"+{TOOLCHAIN}", "-Vv"])
        rustc_text = command_text(rustc)
        if f"host: {TARGET}" not in rustc_text:
            reasons.append(f"rustc host is not {TARGET}: {rustc_text}")
        reject_glibc(rustc_text, "rustc -Vv")
    return reasons


def collect_toolchain_evidence(tools: Mapping[str, str]) -> dict[str, object]:
    """Retain exact version commands instead of only recording tool paths."""

    evidence: dict[str, object] = {}
    if "rustup" in tools:
        evidence["active_toolchain"] = command_record([tools["rustup"], "show", "active-toolchain"])
    if "rustc" in tools:
        evidence["rustc_vv"] = command_record([tools["rustc"], f"+{TOOLCHAIN}", "-Vv"])
    if "cargo" in tools:
        evidence["cargo_version"] = command_record([tools["cargo"], f"+{TOOLCHAIN}", "-V"])
    if "musl_gcc" in tools:
        evidence["musl_gcc_version"] = command_record([tools["musl_gcc"], "-v"])
    if "clang" in tools:
        evidence["clang_version"] = command_record([tools["clang"], "--version"])
    for name, record in evidence.items():
        if isinstance(record, Mapping):
            stdout = record.get("stdout", {})
            stderr = record.get("stderr", {})
            text = ""
            if isinstance(stdout, Mapping):
                text += str(stdout.get("preview", ""))
            if isinstance(stderr, Mapping):
                text += str(stderr.get("preview", ""))
            reject_glibc(text, f"toolchain command {name}")
    return evidence


def fixture_project(source: Path, manifest: Path, workspace: Path) -> Path:
    project = workspace / "project"
    (project / "src").mkdir(parents=True)
    shutil.copy2(source, project / "src/main.rs")
    shutil.copy2(manifest, project / "Cargo.toml")
    return project


def build_command(
    configuration: Configuration,
    *,
    target_dir: Path,
    candidate_dir: Path,
    linker: str,
    map_file: Path,
    candidate_archive: Path | None = None,
) -> tuple[list[str], str]:
    command = ["cargo", f"+{TOOLCHAIN}", "build", "--release", "--target", TARGET]
    if configuration.build_std:
        command.extend(["-Z", "build-std=std,panic_abort"])
    flags = ["-C", "opt-level=3", "-C", "codegen-units=1", "-C", "panic=abort"]
    flags.extend(["-C", f"target-feature={'+' if configuration.static else '-'}crt-static"])
    # The pinned Alpine GCC keeps libgcc_s outside the musl sysroot.  This is
    # the same explicit non-libc support path used by the stock-std harness;
    # omitting it makes an otherwise valid dynamic C/D link fail before libc
    # selection is even tested.
    flags.extend(["-C", "link-arg=-L/usr/lib"])
    if configuration.static:
        flags.extend(["-C", f"link-arg=-Wl,-Map={map_file}"])
    else:
        # Put the candidate shared object ahead of the musl search path.  The
        # runtime still stages the canonical musl SONAME and never uses an
        # LD_PRELOAD substitution.
        flags.extend(["-C", f"link-arg=-L{candidate_dir}"])
    if configuration.runtime == "crabc-static":
        flags.extend(["-C", f"link-arg={candidate_dir / 'libc.a'}"])
    if configuration.runtime == "crabc-static-lto":
        if candidate_archive is None:
            raise RunnerError("static D requires a rebuilt crabc libc.a")
        flags.extend(
            [
                "-C",
                "link-arg=-Wl,-u,getauxval",
                "-C",
                f"link-arg={candidate_archive}",
                "-C",
                "link-arg=--target=aarch64-unknown-linux-musl",
                "-C",
                "link-arg=--sysroot=/opt/musl-1.2.6",
                "-C",
                "link-arg=-fuse-ld=lld",
                "-C",
                "link-arg=-B/usr/lib/gcc/aarch64-alpine-linux-musl/15.2.0",
                "-C",
                "link-arg=-L/usr/lib/gcc/aarch64-alpine-linux-musl/15.2.0",
                "-C",
                "link-arg=-L/opt/musl-1.2.6/lib",
            ]
        )
    if configuration.lto == "fat":
        flags.extend(
            [
                "-C",
                "lto=fat",
                "-C",
                "embed-bitcode=yes",
                "-C",
                "linker-plugin-lto",
                "-C",
                "link-arg=--target=aarch64-unknown-linux-musl",
                "-C",
                "link-arg=-fuse-ld=lld",
            ]
        )
    return command, " ".join(flags)


def classify_build_failure(configuration: Configuration, output: str) -> str:
    lowered = output.lower()
    unsupported_markers = (
        "linker-plugin-lto",
        "unsupported",
        "not supported",
        "unknown codegen option",
        "unknown option",
        "could not execute",
        "linker `",
    )
    if configuration.linker_plugin_lto and any(marker in lowered for marker in unsupported_markers):
        return "unsupported"
    return "unbuildable"


def inspect_and_validate_elf(binary: Path, configuration: Configuration, tools: Mapping[str, str]) -> dict[str, object]:
    inspection = artifact_inspection(binary, tools)
    text = ""
    for key in ("file", "readelf", "readelf_sections"):
        value = inspection.get(key)
        if isinstance(value, Mapping):
            text += command_text(value)
    reject_glibc(text, f"{configuration.key} artifact inspection")
    readelf_value = inspection.get("readelf")
    readelf_text = command_text(readelf_value) if isinstance(readelf_value, Mapping) else ""
    has_interp = "INTERP" in readelf_text
    inspection["has_interp"] = has_interp
    expected_interp = not configuration.static
    inspection["expected_interp"] = expected_interp
    inspection["elf_shape_valid"] = has_interp == expected_interp
    return inspection


def stage_runtime(
    configuration: Configuration,
    binary: Path,
    inputs: Mapping[str, object],
    temporary: Path,
) -> tuple[Path, Path | None, dict[str, object]]:
    """Prepare a disposable interpreter/libc boundary and return its binary."""

    runtime = temporary / "runtime"
    runtime.mkdir()
    evidence: dict[str, object] = {"runtime": configuration.runtime}
    if configuration.static:
        return binary, None, evidence

    candidate_loader = inputs["candidate_loader"]
    candidate_libc = inputs["candidate_libc"]
    assert isinstance(candidate_loader, Path) and isinstance(candidate_libc, Path)
    if not candidate_loader.is_file() or not candidate_libc.is_file():
        raise RunnerError("crabc loader/libc unavailable for dynamic runtime")
    loader = runtime / "r" if configuration.runtime == "musl" else runtime / "c"
    shutil.copy2(candidate_loader if configuration.runtime != "musl" else inputs["musl_loader"], loader)
    loader.chmod(loader.stat().st_mode | stat.S_IXUSR)
    libc_source = candidate_libc if configuration.runtime != "musl" else inputs["musl_libc"]
    libc_name = runtime / "libc.musl-aarch64.so.1"
    shutil.copy2(libc_source, libc_name)
    # Some linkers retain libc.so rather than the musl SONAME.  Supplying the
    # same bytes under both names makes this explicit and still keeps the
    # reference/candidate boundary symmetric.
    shutil.copy2(libc_source, runtime / "libc.so")
    for extra in (Path("/usr/lib/libgcc_s.so.1"), Path("/lib/libgcc_s.so.1")):
        if extra.is_file():
            shutil.copy2(extra, runtime / "libgcc_s.so.1")
            evidence["libgcc_s_sha256"] = sha256_file(extra)
            break
    patched = temporary / "runtime-binary"
    patch_interpreter(binary, patched, str(loader))
    evidence.update(
        {
            "interpreter": str(loader),
            "interpreter_sha256": sha256_file(loader),
            "libc": str(libc_name),
            "libc_sha256": sha256_file(libc_name),
            "library_path_text": str(runtime),
        }
    )
    return patched, runtime, evidence


def run_configuration(
    configuration: Configuration,
    inputs: Mapping[str, object],
    environment: Mapping[str, str],
    timeout: float,
    workspace: Path,
) -> dict[str, object]:
    source = inputs["fixture"]
    manifest = inputs["fixture_manifest"]
    tools = inputs["tools"]
    assert isinstance(source, Path) and isinstance(manifest, Path) and isinstance(tools, Mapping)
    if configuration.workload == "c-static":
        return run_static_c_configuration(configuration, inputs, environment, timeout, workspace)
    if configuration.linker_plugin_lto and "clang" not in tools:
        return {
            "status": "unsupported",
            "reason": "linker-plugin LTO requires an available clang/lld linker",
        }
    project = fixture_project(source, manifest, workspace)
    crabc_build: dict[str, object] | None = None
    candidate_archive: Path | None = None
    if configuration.runtime == "crabc-static-lto":
        candidate_archive, crabc_build = build_crabc_lto_archive(inputs, tools, workspace / "crabc-build")
        if candidate_archive is None:
            return {
                "status": crabc_build.get("status", "unbuildable"),
                "reason": crabc_build.get("reason", "temporary crabc LTO build failed"),
                "build": {"crabc_build": crabc_build},
            }
    cargo_target = workspace / "cargo-target"
    map_file = workspace / f"{configuration.key.lower()}.map"
    linker = tools.get("musl_gcc")
    if configuration.linker_plugin_lto:
        linker = tools.get("clang") or linker
    if linker is None:
        return {
            "status": "unsupported",
            "reason": "no linker available for this configuration",
        }
    command, rustflags = build_command(
        configuration,
        target_dir=cargo_target,
        candidate_dir=inputs["target_dir"],
        linker=linker,
        map_file=map_file,
        candidate_archive=candidate_archive,
    )
    build_environment = dict(os.environ)
    for key in tuple(build_environment):
        if key in {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"} or key.startswith("CARGO_TARGET_"):
            build_environment.pop(key, None)
    build_environment.update(
        {
            "CARGO_TARGET_DIR": str(cargo_target),
            "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER": linker,
            "RUSTFLAGS": rustflags,
        }
    )
    build_environment_evidence = environment_evidence(build_environment)
    started = time.monotonic_ns()
    result = subprocess.run(
        command,
        cwd=project,
        env=build_environment,
        capture_output=True,
        check=False,
        text=False,
    )
    build_record: dict[str, object] = {
        "command": command,
        "cwd": str(project),
        "environment_sha256": build_environment_evidence["sha256"],
        "environment_variables": build_environment_evidence["variables"],
        "linker": linker,
        "rustflags": rustflags,
        "returncode": result.returncode,
        "wall_time_ns": time.monotonic_ns() - started,
        "stdout": snapshot(result.stdout),
        "stderr": snapshot(result.stderr),
    }
    if crabc_build is not None:
        build_record["crabc_build"] = crabc_build
    output_text = (result.stdout + result.stderr).decode("utf-8", errors="replace")
    reject_glibc(output_text, f"{configuration.key} compiler output")
    binary = cargo_target / TARGET / "release/crabc-lto-fixture"
    build_record["lto_provenance"] = lto_provenance(cargo_target, configuration, tools)
    if result.returncode != 0:
        return {
            "status": classify_build_failure(configuration, output_text),
            "reason": "compiler/linker returned non-zero",
            "build": build_record,
        }
    if not binary.is_file() or not os.access(binary, os.X_OK):
        return {
            "status": "unbuildable",
            "reason": f"build succeeded without executable: {binary}",
            "build": build_record,
        }
    try:
        inspection = inspect_and_validate_elf(binary, configuration, tools)
    except RunnerError as error:
        return {"status": "invalid", "reason": str(error), "build": build_record}
    build_record.update(
        {
            "binary": str(binary),
            "binary_sha256": sha256_file(binary),
            "artifact": inspection,
        }
    )
    if not inspection["elf_shape_valid"]:
        return {"status": "invalid", "reason": "ELF shape does not match static/dynamic contract", "build": build_record}

    try:
        # musl's PT_INTERP slot is only 26 bytes in these binaries.  Keep the
        # disposable runtime root intentionally short so the absolute loader
        # path remains patchable even for D's successful LLD output.
        with tempfile.TemporaryDirectory(prefix="l") as runtime_name:
            runtime_workspace = Path(runtime_name)
            runnable, library_path, runtime_evidence = stage_runtime(
                configuration, binary, inputs, runtime_workspace
            )
            runtime = run_binary(
                runnable,
                environment,
                timeout,
                cwd=runtime_workspace,
                library_path=library_path,
            )
            syscall = syscall_measurement(
                runnable,
                environment,
                timeout,
                cwd=runtime_workspace,
                library_path=library_path,
                output_file=runtime_workspace / "strace.txt",
            )
            build_record["runtime_artifacts"] = runtime_evidence
            runtime_record = result_record(runtime)
            runtime_record["command"] = [str(runnable)]
            runtime_record["cwd"] = str(runtime_workspace)
            build_record["runtime"] = runtime_record
            build_record["syscalls"] = syscall
    except (OSError, RunnerError) as error:
        return {"status": "unbuildable", "reason": f"runtime setup failed: {error}", "build": build_record}
    # A successful build is still not proof that static B used only crabc, or
    # that D's requested LTO was accepted by the linker.  Keep those as
    # explicit evidence fields instead of silently upgrading the claim.
    claims = {
        "runtime_status_zero": build_record["runtime"]["status"] == 0,
        "static_crabc_linkage_proven": None,
        "whole_program_lto_proven": False,
        "lto_flags_requested": configuration.lto == "fat",
        "linker_plugin_lto_requested": configuration.linker_plugin_lto,
    }
    if configuration.runtime in {"crabc-static", "crabc-static-lto"}:
        map_text = map_file.read_text(encoding="utf-8", errors="replace") if map_file.is_file() else ""
        candidate_archive = inputs["candidate_archive"]
        candidate_members: list[str] = []
        if configuration.runtime == "crabc-static-lto" and isinstance(crabc_build, dict):
            rebuilt_archive = crabc_build.get("archive")
            if isinstance(rebuilt_archive, str):
                candidate_archive = Path(rebuilt_archive)
            nm_record = crabc_build.get("llvm_nm")
            if isinstance(nm_record, Mapping):
                candidate_members = archive_member_names(command_text(nm_record))
        elif configuration.runtime == "crabc-static":
            nm_record = build_record.get("candidate_archive_llvm_nm")
            if isinstance(nm_record, Mapping):
                candidate_members = archive_member_names(command_text(nm_record))
        assert isinstance(candidate_archive, Path)
        candidate_marker = str(candidate_archive)
        candidate_member_matches = [
            member for member in candidate_members if f"({member})" in map_text
        ]
        contains_candidate_path = bool(map_text) and candidate_marker in map_text
        contains_candidate_member = bool(candidate_member_matches)
        contains_candidate = contains_candidate_path or contains_candidate_member
        contains_musl_root = "/opt/musl" in map_text
        contains_self_contained_musl = "/self-contained/libc.a" in map_text
        contains_musl = contains_musl_root or contains_self_contained_musl
        claims["static_crabc_linkage_proven"] = contains_candidate and not contains_musl
        claims["static_link_map"] = snapshot(map_text.encode())
        claims["static_link_map_sha256"] = sha256_bytes(map_text.encode())
        claims["static_link_map_contains_candidate"] = contains_candidate
        claims["static_link_map_contains_candidate_path"] = contains_candidate_path
        claims["static_link_map_candidate_member_anchors"] = candidate_members
        claims["static_link_map_candidate_member_matches"] = candidate_member_matches
        claims["static_link_map_contains_musl"] = contains_musl
        claims["static_link_map_contains_musl_root"] = contains_musl_root
        claims["static_link_map_contains_rust_self_contained_musl"] = contains_self_contained_musl
        claims["static_link_map_candidate_path"] = candidate_marker
        if not claims["static_crabc_linkage_proven"] and configuration.runtime == "crabc-static":
            build_record["claims"] = claims
            return {
                "status": "invalid",
                "reason": "crabc static link map does not prove exclusive candidate archive use",
                "build": build_record,
            }
        if not contains_candidate and configuration.runtime == "crabc-static-lto":
            build_record["claims"] = claims
            return {
                "status": "invalid",
                "reason": (
                    "rebuilt crabc libc.a is absent from static D link map "
                    "(checked absolute archive path and llvm-nm-derived member anchors)"
                ),
                "build": build_record,
            }
        if contains_candidate and contains_musl and configuration.runtime == "crabc-static-lto":
            build_record["claims"] = claims
            return {
                "status": "invalid",
                "reason": "static D map selects crabc and a musl libc archive; exclusive crabc linkage is unproven",
                "build": build_record,
            }
    build_record["claims"] = claims
    return {"status": "built", "build": build_record}


def enforce_matrix_contract(configurations: Mapping[str, object]) -> None:
    """Reject B when it is not observably distinct from the musl baseline."""

    baseline = configurations.get("A")
    candidate = configurations.get("B")
    if not isinstance(baseline, dict) or not isinstance(candidate, dict):
        return
    if baseline.get("status") != "built" or candidate.get("status") != "built":
        return
    baseline_build = baseline.get("build")
    candidate_build = candidate.get("build")
    if not isinstance(baseline_build, dict) or not isinstance(candidate_build, dict):
        return
    if baseline_build.get("binary_sha256") != candidate_build.get("binary_sha256"):
        return
    candidate["status"] = "invalid"
    candidate["reason"] = "crabc static artifact is byte-identical to musl static baseline"
    claims = candidate_build.get("claims")
    if isinstance(claims, dict):
        claims["static_crabc_linkage_proven"] = False
        claims["static_linkage_unproven"] = True


def atomic_write_json(path: Path, report: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--musl-root", type=Path, default=Path(os.environ.get("MUSL_ROOT", MUSL_ROOT)))
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target/debug")
    parser.add_argument(
        "--sysroot",
        type=Path,
        default=Path(os.environ.get("CRABC_SYSROOT", DEFAULT_SYSROOT)),
        help="installed owned crabc sysroot used by controlled-C candidate B",
    )
    parser.add_argument("--fixture", type=Path, default=FIXTURE)
    parser.add_argument("--report", type=Path, default=REPORT)
    parser.add_argument("--timeout", type=float, default=20.0)
    return parser.parse_args(argv)


def run(args: argparse.Namespace) -> tuple[str, Path]:
    pins = load_pins()
    tools, tool_attempts = discover_tools()
    inputs = validate_inputs(args, tools)
    report: dict[str, object] = {
        "schema_version": 1,
        "runner": "compat/lto/run.py",
        "result": "error",
        "target": TARGET,
        "host": {"system": platform.system(), "machine": platform.machine(), "python": sys.version},
        "tool_attempts": tool_attempts,
        "selected_tools": tools,
        "toolchain": collect_toolchain_evidence(tools),
        "pins": pins,
        "fixture": {
            "source": str(inputs["fixture"]),
            "source_sha256": sha256_file(inputs["fixture"]),
            "static_source": str(inputs["static_fixture"]),
            "static_source_sha256": sha256_file(inputs["static_fixture"]),
            "manifest": str(inputs["fixture_manifest"]),
            "manifest_sha256": sha256_file(inputs["fixture_manifest"]),
        },
        "inputs": {
            "musl_root": str(inputs["musl_root"]),
            "musl_loader_sha256": sha256_file(inputs["musl_loader"]) if inputs["musl_loader"].is_file() else None,
            "musl_libc_sha256": sha256_file(inputs["musl_libc"]) if inputs["musl_libc"].is_file() else None,
            "musl_archive_sha256": sha256_file(inputs["musl_archive"]) if inputs["musl_archive"].is_file() else None,
            "target_dir": str(inputs["target_dir"]),
            "candidate_loader_sha256": sha256_file(inputs["candidate_loader"]) if inputs["candidate_loader"].is_file() else None,
            "candidate_libc_sha256": sha256_file(inputs["candidate_libc"]) if inputs["candidate_libc"].is_file() else None,
            "candidate_archive_sha256": sha256_file(inputs["candidate_archive"]) if inputs["candidate_archive"].is_file() else None,
        },
        "environment_contract": environment_evidence(sanitize_environment()),
        "normalization": "none",
        "configurations": {},
    }
    try:
        reasons = host_capability_reasons(inputs, tool_attempts)
    except RunnerError as error:
        reasons = [str(error)]
    if reasons:
        for configuration in CONFIGURATIONS:
            report["configurations"][configuration.key] = {
                "label": configuration.label,
                "status": "unsupported",
                "reasons": reasons,
                "contract": dataclasses.asdict(configuration),
            }
        report["result"] = "partial"
        report["capability_reasons"] = reasons
        report_path = args.report.expanduser().resolve()
        atomic_write_json(report_path, report)
        return "partial", report_path

    environment = sanitize_environment()
    with tempfile.TemporaryDirectory(prefix="crabc-lto-") as temporary_name:
        root = Path(temporary_name)
        for configuration in CONFIGURATIONS:
            result = run_configuration(configuration, inputs, environment, args.timeout, root / configuration.key)
            result["label"] = configuration.label
            result["contract"] = dataclasses.asdict(configuration)
            report["configurations"][configuration.key] = result
    enforce_matrix_contract(report["configurations"])
    statuses = [value["status"] for value in report["configurations"].values()]
    report["result"] = "complete" if all(status == "built" for status in statuses) else "partial"
    report_path = args.report.expanduser().resolve()
    atomic_write_json(report_path, report)
    return str(report["result"]), report_path


def main(argv: Sequence[str] | None = None) -> int:
    try:
        result, report = run(parse_args(argv))
    except RunnerError as error:
        print(f"lto: ERROR: {error}", file=sys.stderr)
        return 2
    print(f"lto: {result.upper()}: report: {report}")
    # Unsupported/unbuildable configurations are a valid research result and
    # are encoded in the report.  Exit non-zero only for harness setup errors.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
