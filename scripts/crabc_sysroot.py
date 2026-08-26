#!/usr/bin/env python3
"""Assemble and drive the sealed Linux/AArch64 crabc application sysroot.

This is deliberately a small, standard-library-only host tool rather than a
shell wrapper.  It has two durable boundaries:

* ``assemble`` accepts only explicitly named crabc runtime/CRT artifacts and
  produces a relocatable installed tree plus provenance reports.
* the installed ``bin/crabc-cc`` imports this same module from
  ``share/crabc`` and computes every target include, CRT, library, and
  interpreter input from its own location.

It does not build a CRT and it never substitutes musl or a compiler runtime
when a crabc artifact is absent.  CRT producers hand this tool their completed
objects and (when available) their Rust-source provenance record.
"""

from __future__ import annotations

import argparse
import dataclasses
import enum
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


TARGET_TRIPLE = "aarch64-unknown-linux-musl"
CANONICAL_INTERPRETER = "/lib/ld-crabc-aarch64.so.1"
COMPATIBLE_INTERPRETER = "ld-musl-aarch64.so.1"
CRT_OBJECTS = ("crt1.o", "Scrt1.o", "rcrt1.o", "crti.o", "crtn.o")
CRT_SOURCE_FILES = {
    "crt1.o": "crt1.rs",
    "Scrt1.o": "Scrt1.rs",
    "rcrt1.o": "rcrt1.rs",
    "crti.o": "crti.rs",
    "crtn.o": "crtn.rs",
}
CRT_PINNED_TOOLCHAIN = "nightly-2026-07-24"
FULL_RUNTIME_SOURCE_ROOTS = frozenset(
    {"libc/src", "ldso/src", "crabc-mimalloc/src", "crt/src", "builtins/src"}
)
RUNTIME_ALIAS_NAMES = (
    "libm.so",
    "libdl.so",
    "libpthread.so",
    "librt.so",
    "libutil.so",
)
# These are the application-facing link-mode names published in a sysroot
# manifest and attested by the packaged-archive smoke report.  They describe
# the user-visible driver invocations, not the more implementation-specific
# ``LinkMode`` enum spellings: ``-no-pie`` is dynamic non-PIE and ``-static``
# is the normal static executable mode.
PUBLISHED_APPLICATION_LINK_MODE_ATTESTATIONS = (
    ("dynamic-pie", "dynamic_pie"),
    ("dynamic-non-pie", "dynamic_non_pie"),
    ("static", "static"),
    ("static-pie", "static_pie"),
)
PUBLISHED_APPLICATION_LINK_MODES = tuple(
    mode for mode, _report_key in PUBLISHED_APPLICATION_LINK_MODE_ATTESTATIONS
)
PUBLISHED_APPLICATION_LINK_MODE_REPORT_KEYS = dict(PUBLISHED_APPLICATION_LINK_MODE_ATTESTATIONS)
SEALED_ENVIRONMENT_KEYS = (
    "CPATH",
    "C_INCLUDE_PATH",
    "CPLUS_INCLUDE_PATH",
    "OBJC_INCLUDE_PATH",
    "LIBRARY_PATH",
    "COMPILER_PATH",
    "GCC_EXEC_PREFIX",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
)
FOREIGN_RUNTIME_COMPONENTS = (
    "libgcc",
    "libatomic",
    "libssp",
    "compiler-rt",
    "crtbegin",
    "crtend",
)
REQUIRED_RUST_COMPILER_HELPERS = frozenset(
    {
        "__addtf3",
        "__divtf3",
        "__eqtf2",
        "__extenddftf2",
        "__extendsftf2",
        "__gttf2",
        "__lttf2",
        "__muldc3",
        "__multf3",
        "__netf2",
        "__subtf3",
        "__trunctfdf2",
        "__trunctfsf2",
    }
)
REQUIRED_COMPILER_BUILTINS_FEATURES = frozenset(
    {"arch", "compiler-builtins", "default", "unmangled-names"}
)
REQUIRED_COMPILER_BUILTINS_BUILD_SCRIPT_INPUTS = frozenset(
    {"rust-src/library/compiler-builtins/libm/configure.rs"}
)
STATIC_RUNTIME_ROLES = frozenset({"crabc_rust_runtime", "native_allocator_exception"})
STATIC_RUNTIME_REQUIRED_SYMBOLS = {
    "crabc_rust_runtime": "__libc_start_main",
    "native_allocator_exception": "mi_malloc",
}
STATIC_RUNTIME_COMMAND_KINDS = frozenset(
    {
        "enumerate_cargo_staticlib_members",
        "extract_selected_runtime_members",
        "create_deterministic_static_runtime_archive",
        "audit_selected_runtime_members",
    }
)
STATIC_RUNTIME_RUST_TARGET_FEATURE = "target-feature=-crt-static,-outline-atomics"
STATIC_RUNTIME_TLS_MODEL = "-Ztls-model=initial-exec"
STATIC_RUNTIME_CFLAGS_KEY = "CFLAGS_aarch64_unknown_linux_musl"
STATIC_RUNTIME_CFLAGS_VALUE = "-mno-outline-atomics"
ELF_STB_LOCAL = 0
ELF_STT_TLS = 6
ELF_STV_DEFAULT = 0
R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21 = 541
R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC = 542
R_AARCH64_TLSDESC_FIRST = 562
R_AARCH64_TLSDESC_LAST = 569
R_AARCH64_TLS_TPREL64 = 1030
STATIC_RUNTIME_LIFECYCLE_TLS_RELOCATION_NAMES = {
    R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21: "R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21",
    R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC: "R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC",
}
STATIC_RUNTIME_LIFECYCLE_TLS_RELOCATION_TYPES = frozenset(
    STATIC_RUNTIME_LIFECYCLE_TLS_RELOCATION_NAMES
)
STATIC_RUNTIME_LIFECYCLE_TLS_SYMBOL = re.compile(
    r"crabc_mimalloc.*runtime_lifecycle.*THREAD_LIFECYCLE"
)
HOST_BUILD_PATH_ROOTS = frozenset({"Users", "home", "private", "root", "tmp", "var", "workspace", "build", "opt"})
BUILD_PATH_COMPONENTS = frozenset(
    {".cargo", ".rustup", "cargo", "crabc-sysroot", "crabc-sysroot-build-comparison", "crabc-sysroot-build-primary", "debug", "release", "target"}
)
BUILD_PATH_SUFFIXES = frozenset({".a", ".c", ".cc", ".cpp", ".cxx", ".d", ".o", ".rlib", ".rs", ".s", ".S", ".so"})
EMBEDDED_ABSOLUTE_PATH = re.compile(rb"/(?:[A-Za-z0-9._+@%=-]+/)+[A-Za-z0-9._+@%=-]+")
NATIVE_IMPLEMENTATION_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".s", ".S", ".asm"}
NATIVE_COMPILER_RUNTIME_MEMBER = re.compile(
    r"^[0-9a-f]+-(?:aarch64|lse_(?:cas|swp|ldadd|ldclr|ldeor|ldset)[0-9]+_(?:relax|acq|rel|acq_rel)|"
    r"(?:absv|addv|cmp|div|ffs|fp_mode|int_util|mul|neg|parity|popcount|subv|ucmp)[a-z0-9_]*)(?:\.o)$"
)
NATIVE_COMPILER_RUNTIME_PATH_MARKERS = ("/compiler-rt/", "/lib/builtins/")
ELF_MAGIC = b"\x7fELF"
EM_AARCH64 = 183
AR_MAGIC = b"!<arch>\n"
SCHEMA_VERSION = 1


class SysrootError(RuntimeError):
    """A violated sysroot contract, distinct from an invoked tool failure."""


class ToolInvocationError(SysrootError):
    """A configured host compiler or linker could not be invoked."""


class LinkMode(str, enum.Enum):
    COMPILE = "compile"
    PREPROCESS = "preprocess"
    ASSEMBLY = "assembly"
    RELOCATABLE = "relocatable"
    SHARED = "shared"
    DYNAMIC_PIE = "dynamic-pie"
    DYNAMIC_EXECUTABLE = "dynamic-executable"
    STATIC_EXECUTABLE = "static-executable"
    STATIC_PIE = "static-pie"


@dataclasses.dataclass(frozen=True)
class CommandResult:
    command: tuple[str, ...]
    status: int | str
    stdout: bytes
    stderr: bytes
    timed_out: bool = False

    def record(self) -> dict[str, object]:
        return {
            "command": list(self.command),
            "status": self.status,
            "stdout": stream_record(self.stdout),
            "stderr": stream_record(self.stderr),
            "timed_out": self.timed_out,
        }


@dataclasses.dataclass(frozen=True)
class Toolchain:
    clang: Path
    lld: Path
    resource_dir: Path
    clang_version: str
    lld_version: str

    def record(self) -> dict[str, str]:
        return {
            "clang": str(self.clang),
            "lld": str(self.lld),
            "resource_dir": str(self.resource_dir),
            "clang_version": self.clang_version,
            "lld_version": self.lld_version,
        }


@dataclasses.dataclass(frozen=True)
class RuntimeInputs:
    include_dir: Path
    libc_shared: Path
    libc_static: Path
    loader: Path
    crt_dir: Path
    builtins: Path
    crt_provenance: Path | None
    crt_commands: Path | None
    builtins_provenance: Path | None
    builtins_commands: Path | None
    libc_static_provenance: Path | None = None
    libc_static_commands: Path | None = None

    def required_paths(self) -> dict[str, Path]:
        paths = {
            "include_dir": self.include_dir,
            "libc.so": self.libc_shared,
            "libc.a": self.libc_static,
            "loader": self.loader,
            "libcrabc-builtins.a": self.builtins,
        }
        paths.update({name: self.crt_dir / name for name in CRT_OBJECTS})
        return paths


@dataclasses.dataclass(frozen=True)
class DriverConfiguration:
    clang: str
    lld: str
    target: str
    canonical_interpreter: str

    @classmethod
    def from_manifest(cls, manifest: Mapping[str, object]) -> "DriverConfiguration":
        toolchain = manifest.get("toolchain")
        if not isinstance(toolchain, dict):
            raise SysrootError("installed manifest has no toolchain table")
        clang = toolchain.get("clang")
        lld = toolchain.get("lld")
        target = manifest.get("target")
        interpreter = manifest.get("canonical_interpreter")
        if not all(isinstance(value, str) and value for value in (clang, lld, target, interpreter)):
            raise SysrootError("installed manifest has an invalid driver configuration")
        return cls(clang=clang, lld=lld, target=target, canonical_interpreter=interpreter)


@dataclasses.dataclass(frozen=True)
class DriverRequest:
    mode: LinkMode
    user_arguments: tuple[str, ...]
    omit_startfiles: bool
    omit_default_libraries: bool
    print_sysroot: bool = False
    print_manifest: bool = False
    print_link_plan: bool = False


@dataclasses.dataclass(frozen=True)
class LinkInput:
    path: str
    classification: str
    reason: str

    def record(self) -> dict[str, str]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class LinkTraceInput:
    """One resolved lld trace input, retaining an archive member if named."""

    path: Path
    archive_member: str | None = None

    def record(self) -> dict[str, str | None]:
        return {"path": str(self.path), "archive_member": self.archive_member}


@dataclasses.dataclass(frozen=True)
class LinkPlan:
    mode: LinkMode
    command: tuple[str, ...]
    startup_objects: tuple[Path, ...]
    end_objects: tuple[Path, ...]
    default_libraries: tuple[str, ...]
    interpreter: str | None
    link_inputs: tuple[LinkInput, ...]

    def record(self) -> dict[str, object]:
        return {
            "schema": SCHEMA_VERSION,
            "mode": self.mode.value,
            "command": list(self.command),
            "startup_objects": [str(path) for path in self.startup_objects],
            "end_objects": [str(path) for path in self.end_objects],
            "default_libraries": list(self.default_libraries),
            "interpreter": self.interpreter,
            "link_inputs": [item.record() for item in self.link_inputs],
        }


@dataclasses.dataclass(frozen=True)
class ElfHeader:
    elf_type: int
    machine: int
    program_header_offset: int
    program_header_entry_size: int
    program_header_count: int
    section_header_offset: int
    section_header_entry_size: int
    section_header_count: int
    section_name_index: int


def stream_record(data: bytes) -> dict[str, object]:
    return {
        "byte_length": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "hex": data.hex(),
        "text": data.decode("utf-8", errors="replace"),
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def atomic_json_write(path: Path, value: Mapping[str, object]) -> None:
    """Write canonical JSON atomically so evidence never exposes a half report."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def require_regular_file(path: Path, description: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise SysrootError(f"{description} must not be a symlink: {path}")
    resolved = candidate.resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise SysrootError(f"{description} must be a regular file: {path}")
    return resolved


def require_directory(path: Path, description: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise SysrootError(f"{description} must not be a symlink: {path}")
    resolved = candidate.resolve()
    if not resolved.is_dir() or resolved.is_symlink():
        raise SysrootError(f"{description} must be a real directory: {path}")
    return resolved


def require_tool(path_or_name: str, description: str) -> Path:
    candidate = Path(path_or_name)
    if candidate.parent != Path("."):
        resolved = candidate.expanduser().resolve()
    else:
        located = shutil.which(path_or_name)
        resolved = Path(located).resolve() if located is not None else None
    if resolved is None:
        raise SysrootError(f"{description} is unavailable: {path_or_name}")
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise SysrootError(f"{description} is not an executable file: {path_or_name}")
    return resolved


def run_command(
    command: Sequence[str], *, environment: Mapping[str, str] | None = None, timeout: float = 60.0, cwd: Path | None = None
) -> CommandResult:
    try:
        completed = subprocess.run(
            list(command),
            check=False,
            capture_output=True,
            cwd=cwd,
            env=dict(environment) if environment is not None else None,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        return CommandResult(tuple(command), "TIMEOUT", error.stdout or b"", error.stderr or b"", True)
    except OSError as error:
        raise ToolInvocationError(f"could not execute {' '.join(command)!r}: {error}") from error
    return CommandResult(tuple(command), completed.returncode, completed.stdout, completed.stderr)


def command_output(command: Sequence[str], *, environment: Mapping[str, str] | None = None) -> str:
    result = run_command(command, environment=environment)
    if result.status != 0:
        raise ToolInvocationError(f"tool probe failed ({result.status}): {' '.join(command)}")
    return result.stdout.decode("utf-8", errors="replace").strip()


def seal_environment(base: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return a compilation environment with ambient target search paths removed."""

    environment = dict(os.environ if base is None else base)
    for key in SEALED_ENVIRONMENT_KEYS:
        environment.pop(key, None)
    environment["LC_ALL"] = "C"
    environment["LANG"] = "C"
    return environment


def discover_toolchain(clang: str, lld: str, *, environment: Mapping[str, str] | None = None) -> Toolchain:
    sealed = seal_environment(environment)
    clang_path = require_tool(clang, "clang")
    lld_path = require_tool(lld, "ld.lld")
    resource_text = command_output((str(clang_path), "-print-resource-dir"), environment=sealed)
    resource_dir = require_directory(Path(resource_text), "clang resource directory")
    require_directory(resource_dir / "include", "clang resource include directory")
    clang_version = command_output((str(clang_path), "--version"), environment=sealed).splitlines()[0]
    lld_version = command_output((str(lld_path), "--version"), environment=sealed).splitlines()[0]
    return Toolchain(clang_path, lld_path, resource_dir, clang_version, lld_version)


def read_crt_provenance(
    path: Path | None,
    objects_by_name: Mapping[str, Path],
    commands_path: Path | None,
) -> dict[str, object]:
    """Bind every supplied CRT object to Rust source and its producer log.

    A list of names or a source-language label is not ownership evidence.  The
    report must name the exact five input bytes, their direct pinned-rustc
    commands, and the command-record hash before this assembler can call the
    CRT portion of the sysroot pure Rust.
    """

    if path is None and commands_path is None:
        return {
            "status": "unverified",
            "reason": "no CRT provenance or producer-command record was supplied",
            "objects": list(CRT_OBJECTS),
        }
    if path is None or commands_path is None:
        return {
            "status": "rejected",
            "reason": "CRT provenance and producer-command record must be supplied together",
            "objects": list(CRT_OBJECTS),
        }
    provenance = require_regular_file(path, "CRT provenance")
    commands_file = require_regular_file(commands_path, "CRT producer-command record")
    try:
        value = json.loads(provenance.read_text(encoding="utf-8"))
        commands = json.loads(commands_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SysrootError(f"invalid CRT provenance or command JSON: {provenance}") from error
    if not isinstance(value, dict) or value.get("schema") != SCHEMA_VERSION:
        raise SysrootError("CRT provenance must have schema 1")
    objects = value.get("objects")
    command_binding = value.get("commands")
    if not isinstance(objects, dict) or not isinstance(command_binding, dict):
        raise SysrootError("CRT provenance must contain object and command records")
    command_records_valid = bool(
        isinstance(commands, list)
        and commands
        and isinstance(commands[0], dict)
        and command_binding.get("name") == commands_file.name
        and command_binding.get("sha256") == sha256_file(commands_file)
        and commands[0].get("kind") == "toolchain"
    )
    compile_entries = [
        entry
        for entry in commands
        if isinstance(entry, dict) and entry.get("kind") == "compile" and isinstance(entry.get("object"), str)
    ] if isinstance(commands, list) else []
    compile_records = {
        entry.get("object"): entry
        for entry in compile_entries
    }
    machine_entries = [
        entry
        for entry in commands
        if isinstance(entry, dict)
        and entry.get("kind") == "machine_entry_audit"
        and isinstance(entry.get("object"), str)
    ] if isinstance(commands, list) else []
    machine_records = {
        entry.get("object"): entry
        for entry in machine_entries
    }
    checked: dict[str, object] = {}
    valid = (
        value.get("target") == TARGET_TRIPLE
        and value.get("toolchain") == CRT_PINNED_TOOLCHAIN
        and command_records_valid
        and len(compile_entries) == len(CRT_OBJECTS)
        and set(compile_records) == set(CRT_OBJECTS)
        and len(machine_entries) == len(CRT_OBJECTS)
        and set(machine_records) == set(CRT_OBJECTS)
    )
    for name in CRT_OBJECTS:
        entry = objects.get(name)
        supplied = objects_by_name.get(name)
        if not isinstance(entry, dict) or supplied is None:
            valid = False
            checked[name] = {"status": "missing"}
            continue
        producer = entry.get("producer")
        command = compile_records.get(name, {}).get("command")
        machine_contract = entry.get("entry_machine_contract")
        machine_record = machine_records.get(name, {})
        entry_machine_valid = (
            isinstance(machine_record, dict)
            and machine_record.get("returncode") == 0
            and isinstance(machine_record.get("command"), list)
            and "--disassemble-symbols=_start" in machine_record["command"]
        )
        if name in {"crt1.o", "Scrt1.o", "rcrt1.o"}:
            entry_machine_valid = (
                entry_machine_valid
                and isinstance(machine_contract, dict)
                and machine_contract.get("status") == "verified"
                and machine_contract.get("no_return_or_call_before_handoff") is True
                and machine_contract.get("no_early_system_or_tls_register_read") is True
            )
        else:
            entry_machine_valid = entry_machine_valid and machine_contract == {"status": "not_applicable"}
        object_valid = (
            entry.get("path") == name
            and entry.get("sha256") == sha256_file(supplied)
            and entry.get("source") == f"/crabc/crt/src/{CRT_SOURCE_FILES[name]}"
            and entry.get("source_languages") == ["Rust"]
            and isinstance(producer, list)
            and producer == command
            and "--emit=obj" in producer
            and "--target" in producer
            and TARGET_TRIPLE in producer
            and f"$CRABC_CRT_OUT/{name}" in producer
            and compile_records.get(name, {}).get("returncode") == 0
            and entry_machine_valid
        )
        if not object_valid:
            valid = False
        checked[name] = {**entry, "input_sha256": sha256_file(supplied), "status": "verified" if object_valid else "rejected"}
    return {
        "status": "verified" if valid else "rejected",
        "provenance": {"name": provenance.name, "sha256": sha256_file(provenance)},
        "commands": {"name": commands_file.name, "sha256": sha256_file(commands_file)},
        "objects": checked,
    }


def read_builtins_provenance(
    path: Path | None,
    archive: Path,
    commands_path: Path | None,
) -> dict[str, object]:
    """Bind the helper archive to its pure-Rust source/configuration record.

    ``compiler_builtins`` retains upstream ``links = \"compiler-rt\"``
    metadata so Rust's own build can opt into C fallbacks.  crabc accepts its
    source-built lane only when the provenance proves that the ``c`` and
    ``mem`` features were disabled, no native build command ran, and the
    installed archive came from that fresh source build rather than rustup's
    prebuilt target archive.
    """

    if path is None and commands_path is None:
        return {
            "status": "unverified",
            "reason": "no compiler-helper provenance or producer-command record was supplied",
        }
    if path is None or commands_path is None:
        return {
            "status": "rejected",
            "reason": "compiler-helper provenance and producer-command record must be supplied together",
        }
    provenance = require_regular_file(path, "compiler-helper provenance")
    commands_file = require_regular_file(commands_path, "compiler-helper producer-command record")
    try:
        value = json.loads(provenance.read_text(encoding="utf-8"))
        commands = json.loads(commands_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SysrootError(f"invalid compiler-helper provenance or command JSON: {provenance}") from error
    if not isinstance(value, dict):
        raise SysrootError("compiler-helper provenance must be a JSON object")
    component = value.get("component")
    archive_record = value.get("archive")
    build = value.get("build")
    source = value.get("source")
    dependency_purity = value.get("dependency_purity")
    upstream = dependency_purity.get("upstream_source_build") if isinstance(dependency_purity, dict) else None
    archive_symbols = archive_record.get("defined_symbols") if isinstance(archive_record, dict) else None
    archive_members = archive_record.get("members") if isinstance(archive_record, dict) else None
    selected_sources = source.get("upstream_selected_files") if isinstance(source, dict) else None
    build_script_inputs = source.get("upstream_build_script_inputs") if isinstance(source, dict) else None
    selected_features = upstream.get("selected_features") if isinstance(upstream, dict) else None
    source_built_components = upstream.get("source_built_standard_components") if isinstance(upstream, dict) else None
    source_built_rlib_sha256 = upstream.get("source_built_rlib_sha256") if isinstance(upstream, dict) else None
    command_binding = build.get("exact_command_record") if isinstance(build, dict) else None
    operations = commands.get("operations") if isinstance(commands, dict) else None
    operation_by_kind = {
        entry.get("kind"): entry
        for entry in operations
        if isinstance(entry, dict) and isinstance(entry.get("kind"), str)
    } if isinstance(operations, list) else {}
    source_build_operation = operation_by_kind.get("source_build_compiler_builtins")
    local_operation = operation_by_kind.get("compile_local_helpers")
    archive_operation = operation_by_kind.get("create_deterministic_archive")
    command_record_valid = (
        isinstance(commands, dict)
        and commands.get("schema") == SCHEMA_VERSION
        and commands.get("archive") == archive.name
        and isinstance(command_binding, dict)
        and command_binding.get("name") == commands_file.name
        and command_binding.get("sha256") == sha256_file(commands_file)
        and set(operation_by_kind)
        == {
            "compile_local_helpers",
            "source_build_compiler_builtins",
            "extract_source_built_members",
            "create_deterministic_archive",
            "audit_archive_surface",
        }
        and isinstance(local_operation, dict)
        and isinstance(local_operation.get("command"), list)
        and "--emit=obj" in local_operation["command"]
        and TARGET_TRIPLE in local_operation["command"]
        and isinstance(source_build_operation, dict)
        and isinstance(source_build_operation.get("command"), list)
        and "--locked" in source_build_operation["command"]
        and "-Zbuild-std=core,compiler_builtins" in source_build_operation["command"]
        and isinstance(source_build_operation.get("audit"), dict)
        and source_build_operation["audit"].get("native_build_commands") == []
        and source_build_operation["audit"].get("target_link_directives") == []
        and isinstance(archive_operation, dict)
        and isinstance(archive_operation.get("command"), list)
        and "rcsD" in archive_operation["command"]
        and f"$CRABC_BUILTINS_OUT/{archive.name}" in archive_operation["command"]
    )
    upstream_valid = (
        isinstance(upstream, dict)
        and upstream.get("package") == "compiler_builtins"
        and upstream.get("version") == "0.1.160"
        and upstream.get("links_metadata") == "compiler-rt"
        and isinstance(selected_features, list)
        and set(selected_features) == REQUIRED_COMPILER_BUILTINS_FEATURES
        and upstream.get("disabled_features") == ["c", "mem"]
        and upstream.get("native_build_commands") == []
        and upstream.get("target_link_directives") == []
        and upstream.get("prebuilt_compiler_builtins_input") is False
        and source_built_components == ["core", "compiler_builtins"]
        and isinstance(source_built_rlib_sha256, str)
        and len(source_built_rlib_sha256) == 64
    )
    archive_valid = (
        isinstance(archive_symbols, list)
        and REQUIRED_RUST_COMPILER_HELPERS.issubset(archive_symbols)
        and archive_record.get("undefined_symbols") == []
        and isinstance(archive_members, list)
        and len(archive_members) > 1
        and archive_members[0] == "crabc-builtins.o"
        and all(isinstance(member, str) and member.startswith("compiler_builtins-") for member in archive_members[1:])
    )
    source_valid = (
        isinstance(selected_sources, list)
        and bool(selected_sources)
        and all(
            isinstance(entry, dict)
            and isinstance(entry.get("path"), str)
            and entry["path"].startswith("rust-src/library/compiler-builtins/")
            and isinstance(entry.get("sha256"), str)
            for entry in selected_sources
        )
    )
    build_script_inputs_valid = (
        isinstance(build_script_inputs, list)
        and {
            entry.get("path")
            for entry in build_script_inputs
            if isinstance(entry, dict) and isinstance(entry.get("path"), str)
        }
        == REQUIRED_COMPILER_BUILTINS_BUILD_SCRIPT_INPUTS
        and all(
            isinstance(entry, dict)
            and isinstance(entry.get("sha256"), str)
            and len(entry["sha256"]) == 64
            for entry in build_script_inputs
        )
    )
    valid = (
        isinstance(component, dict)
        and component.get("name") == "crabc-builtins"
        and component.get("target") == TARGET_TRIPLE
        and isinstance(archive_record, dict)
        and archive_record.get("name") == "libcrabc-builtins.a"
        and archive_record.get("sha256") == sha256_file(archive)
        and archive_valid
        and isinstance(source, dict)
        and source.get("languages") == ["Rust"]
        and source_valid
        and build_script_inputs_valid
        and command_record_valid
        and isinstance(dependency_purity, dict)
        and dependency_purity.get("uses_alloc") is False
        and dependency_purity.get("uses_native_source") is False
        and dependency_purity.get("uses_native_assembly") is False
        and dependency_purity.get("uses_unwinding") is False
        and dependency_purity.get("requires_panic_runtime") is False
        and upstream_valid
    )
    return {
        "status": "verified" if valid else "rejected",
        "provenance": {"name": provenance.name, "sha256": sha256_file(provenance)},
        "commands": {"name": commands_file.name, "sha256": sha256_file(commands_file)},
        "archive": archive_record if isinstance(archive_record, dict) else {},
        "source": source if isinstance(source, dict) else {},
        "dependency_purity": dependency_purity if isinstance(dependency_purity, dict) else {},
    }


def _archive_elf_members(record: Mapping[str, object]) -> list[dict[str, object]]:
    """Return actual object members, excluding the archive's symbol index."""

    members = record.get("members")
    if not isinstance(members, list):
        return []
    return [
        member
        for member in members
        if isinstance(member, dict) and isinstance(member.get("elf"), dict)
    ]


def _archive_member_symbols(member: Mapping[str, object]) -> set[str]:
    elf = member.get("elf")
    symbols = elf.get("defined_symbols") if isinstance(elf, dict) else None
    if not isinstance(symbols, list):
        return set()
    return {
        name
        for symbol in symbols
        if isinstance(symbol, dict)
        and symbol.get("binding") in {1, 2}
        and isinstance((name := symbol.get("name")), str)
        and name
    }


def audit_static_runtime_lifecycle_tls(member: Mapping[str, object]) -> dict[str, object]:
    """Recompute the private post-LTO lifecycle TLS proof from ``libc.a``.

    The installed static archive deliberately keeps a single Rust runtime
    object. Fat LTO folds crabc-mimalloc into that member, so this exact ELF
    check binds the named private pthread lifecycle root to the initial-exec
    model without creating a public allocator or C ABI symbol.
    """

    elf = member.get("elf")
    symbols = elf.get("defined_symbols") if isinstance(elf, dict) else None
    relocations = elf.get("relocations") if isinstance(elf, dict) else None
    if not isinstance(symbols, list) or not isinstance(relocations, list):
        return {
            "status": "rejected",
            "reason": "selected Rust runtime member lacks parsed ELF symbols or relocations",
        }
    matched = [
        symbol
        for symbol in symbols
        if isinstance(symbol, dict)
        and isinstance(symbol.get("name"), str)
        and STATIC_RUNTIME_LIFECYCLE_TLS_SYMBOL.search(symbol["name"])
    ]
    if len(matched) != 1:
        return {
            "status": "rejected",
            "reason": f"expected exactly one private runtime lifecycle TLS symbol, found {len(matched)}",
        }
    symbol = matched[0]
    symbol_valid = (
        symbol.get("type") == ELF_STT_TLS
        and symbol.get("binding") == ELF_STB_LOCAL
        and symbol.get("visibility") == ELF_STV_DEFAULT
        and isinstance(symbol.get("size"), int)
        and symbol["size"] > 0
        and isinstance(symbol.get("table_index"), int)
        and isinstance(symbol.get("entry_index"), int)
        and isinstance(symbol.get("name"), str)
    )
    root_relocations = [
        relocation
        for relocation in relocations
        if isinstance(relocation, dict)
        and relocation.get("symbol_table_index") == symbol.get("table_index")
        and relocation.get("symbol_index") == symbol.get("entry_index")
        and isinstance(relocation.get("type"), int)
    ]
    relocation_types = frozenset(int(relocation["type"]) for relocation in root_relocations)
    relocation_valid = (
        STATIC_RUNTIME_LIFECYCLE_TLS_RELOCATION_TYPES <= relocation_types
        and relocation_types <= STATIC_RUNTIME_LIFECYCLE_TLS_RELOCATION_TYPES
    )
    if not symbol_valid or not relocation_valid:
        return {
            "status": "rejected",
            "reason": "private runtime lifecycle TLS root is not a local initial-exec symbol",
            "observed_relocation_types": sorted(relocation_types),
        }
    return {
        "status": "verified",
        "access_model": "initial-exec",
        "symbol": {
            "name": symbol["name"],
            "size": symbol["size"],
            "type": "TLS",
            "binding": "LOCAL",
            "visibility": "DEFAULT",
        },
        "required_relocations": [
            STATIC_RUNTIME_LIFECYCLE_TLS_RELOCATION_NAMES[relocation]
            for relocation in sorted(STATIC_RUNTIME_LIFECYCLE_TLS_RELOCATION_TYPES)
        ],
        "forbidden_tls_forms": [],
    }


def audit_shared_runtime_tls(path: Path) -> dict[str, object]:
    """Verify the final shared libc image kept initial-exec TLS relocation form.

    Release libc.so is stripped, so it cannot retain the named private root.
    The paired static-root audit supplies that identity; this final-link audit
    proves the shared image contains TLS offsets rather than TLSDESC or a
    dynamic TLS resolver boundary.
    """

    elf = inspect_elf(path)
    relocations = elf.get("relocations")
    undefined_symbols = elf.get("undefined_symbols")
    relocation_types = {
        relocation.get("type")
        for relocation in relocations
        if isinstance(relocation, dict) and isinstance(relocation.get("type"), int)
    } if isinstance(relocations, list) else set()
    dynamic_relocations = sorted(
        relocation
        for relocation in relocation_types
        if isinstance(relocation, int) and R_AARCH64_TLSDESC_FIRST <= relocation <= R_AARCH64_TLSDESC_LAST
    )
    resolver_symbol = any(
        isinstance(symbol, dict)
        and isinstance(symbol.get("name"), str)
        and "__tls_get_addr" in symbol["name"]
        for symbol in undefined_symbols
    ) if isinstance(undefined_symbols, list) else True
    if R_AARCH64_TLS_TPREL64 not in relocation_types or dynamic_relocations or resolver_symbol:
        return {
            "status": "rejected",
            "reason": "shared libc does not retain the required initial-exec TLS link form",
            "observed_tls_tprel64": R_AARCH64_TLS_TPREL64 in relocation_types,
            "forbidden_tls_forms": dynamic_relocations + (["__tls_get_addr"] if resolver_symbol else []),
        }
    return {
        "status": "verified",
        "access_model": "initial-exec",
        "required_relocation": "R_AARCH64_TLS_TPREL64",
        "observed_tls_tprel64_count": sum(
            1
            for relocation in relocations
            if isinstance(relocation, dict) and relocation.get("type") == R_AARCH64_TLS_TPREL64
        ),
        "forbidden_tls_forms": [],
    }


def read_static_runtime_provenance(
    path: Path | None,
    archive: Path,
    commands_path: Path | None,
) -> dict[str, object]:
    """Bind installed ``libc.a`` to its compiler-runtime-free reconstruction.

    Cargo's staticlib output is intentionally only an intermediate artifact:
    it bundles rustup's compiler-builtins closure and native compiler-rt
    fallbacks.  The installed archive may retain only the crabc Rust runtime
    root plus the separately disclosed native allocator object.  Compiler
    helpers remain in the independently source-built ``libcrabc-builtins.a``.
    """

    if path is None and commands_path is None:
        return {
            "status": "unverified",
            "reason": "no static-runtime provenance or producer-command record was supplied",
        }
    if path is None or commands_path is None:
        return {
            "status": "rejected",
            "reason": "static-runtime provenance and producer-command record must be supplied together",
        }
    provenance = require_regular_file(path, "static-runtime provenance")
    commands_file = require_regular_file(commands_path, "static-runtime producer-command record")
    try:
        value = json.loads(provenance.read_text(encoding="utf-8"))
        commands = json.loads(commands_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SysrootError(f"invalid static-runtime provenance or command JSON: {provenance}") from error
    if not isinstance(value, dict) or value.get("schema") != SCHEMA_VERSION:
        raise SysrootError("static-runtime provenance must have schema 1")
    if not isinstance(commands, dict) or commands.get("schema") != SCHEMA_VERSION:
        raise SysrootError("static-runtime producer-command record must have schema 1")

    component = value.get("component")
    archive_record = value.get("archive")
    build = value.get("build")
    excluded = value.get("excluded_members")
    allocator_exception = value.get("native_allocator_exception")
    recorded_lifecycle_tls = value.get("runtime_lifecycle_tls")
    operations = commands.get("operations")
    operation_by_kind = {
        entry.get("kind"): entry
        for entry in operations
        if isinstance(entry, dict) and isinstance(entry.get("kind"), str)
    } if isinstance(operations, list) else {}
    command_binding = build.get("exact_command_record") if isinstance(build, dict) else None
    command_record_valid = (
        commands.get("archive") == archive.name
        and isinstance(command_binding, dict)
        and command_binding.get("name") == commands_file.name
        and command_binding.get("sha256") == sha256_file(commands_file)
        and set(operation_by_kind) == STATIC_RUNTIME_COMMAND_KINDS
        and isinstance(operation_by_kind.get("enumerate_cargo_staticlib_members"), dict)
        and isinstance(operation_by_kind.get("extract_selected_runtime_members"), dict)
        and isinstance(operation_by_kind.get("create_deterministic_static_runtime_archive"), dict)
        and isinstance(operation_by_kind.get("audit_selected_runtime_members"), dict)
    )
    extracted = operation_by_kind.get("extract_selected_runtime_members")
    created = operation_by_kind.get("create_deterministic_static_runtime_archive")
    command_record_valid = command_record_valid and isinstance(extracted, dict) and isinstance(created, dict)
    if isinstance(extracted, dict):
        command_record_valid = command_record_valid and isinstance(extracted.get("command"), list) and isinstance(
            extracted.get("selected_members"), list
        )
    if isinstance(created, dict):
        command = created.get("command")
        command_record_valid = command_record_valid and isinstance(command, list) and "rcsD" in command

    archive_inspection = inspect_archive(archive)
    actual_members = _archive_elf_members(archive_inspection)
    non_elf_members = [
        member.get("name")
        for member in archive_inspection.get("members", [])
        if isinstance(member, dict) and not isinstance(member.get("elf"), dict) and member.get("name") not in {"", None}
    ]
    expected_members = archive_record.get("members") if isinstance(archive_record, dict) else None
    checked_members: list[dict[str, object]] = []
    member_valid = (
        isinstance(expected_members, list)
        and len(expected_members) == len(STATIC_RUNTIME_ROLES)
        and len(actual_members) == len(STATIC_RUNTIME_ROLES)
        and not non_elf_members
    )
    expected_by_name: dict[str, dict[str, object]] = {}
    if isinstance(expected_members, list):
        for member in expected_members:
            if not isinstance(member, dict) or not isinstance(member.get("name"), str):
                member_valid = False
                continue
            expected_by_name[member["name"]] = member
    if len(expected_by_name) != len(STATIC_RUNTIME_ROLES):
        member_valid = False
    observed_roles: set[str] = set()
    runtime_member: dict[str, object] | None = None
    for member in actual_members:
        name = member.get("name")
        expected = expected_by_name.get(name) if isinstance(name, str) else None
        role = expected.get("role") if isinstance(expected, dict) else None
        required_symbol = STATIC_RUNTIME_REQUIRED_SYMBOLS.get(role) if isinstance(role, str) else None
        symbols = _archive_member_symbols(member)
        valid_member = (
            isinstance(expected, dict)
            and isinstance(role, str)
            and role in STATIC_RUNTIME_ROLES
            and expected.get("sha256") == member.get("sha256")
            and expected.get("required_symbol") == required_symbol
            and required_symbol in symbols
            and isinstance(expected.get("defined_symbols"), list)
            and set(expected["defined_symbols"]) == symbols
        )
        if not valid_member:
            member_valid = False
        if isinstance(role, str):
            observed_roles.add(role)
            if role == "crabc_rust_runtime":
                runtime_member = member
        checked_members.append(
            {
                "name": name,
                "role": role,
                "sha256": member.get("sha256"),
                "required_symbol": required_symbol,
                "defined_symbol_count": len(symbols),
                "status": "verified" if valid_member else "rejected",
            }
        )
    member_valid = member_valid and observed_roles == STATIC_RUNTIME_ROLES
    actual_lifecycle_tls = (
        audit_static_runtime_lifecycle_tls(runtime_member)
        if runtime_member is not None
        else {"status": "rejected", "reason": "static archive has no crabc Rust runtime member"}
    )
    lifecycle_tls_valid = (
        actual_lifecycle_tls.get("status") == "verified"
        and isinstance(recorded_lifecycle_tls, dict)
        and all(
            recorded_lifecycle_tls.get(key) == actual_lifecycle_tls.get(key)
            for key in ("access_model", "symbol", "required_relocations", "forbidden_tls_forms")
        )
    )

    all_excluded = excluded.get("all") if isinstance(excluded, dict) else None
    stock_builtins = excluded.get("stock_compiler_builtins") if isinstance(excluded, dict) else None
    native_compiler_rt = excluded.get("native_compiler_rt") if isinstance(excluded, dict) else None
    excluded_valid = (
        isinstance(all_excluded, list)
        and isinstance(stock_builtins, list)
        and isinstance(native_compiler_rt, list)
        and bool(stock_builtins)
        and bool(native_compiler_rt)
        and all(isinstance(name, str) and name.startswith("compiler_builtins-") for name in stock_builtins)
        and all(isinstance(name, str) and NATIVE_COMPILER_RUNTIME_MEMBER.fullmatch(name) for name in native_compiler_rt)
        and set(stock_builtins).issubset(set(all_excluded))
        and set(native_compiler_rt).issubset(set(all_excluded))
    )
    actual_member_names = {str(member.get("name")) for member in actual_members}
    no_embedded_stock_runtime = not any(
        name.startswith("compiler_builtins-") or NATIVE_COMPILER_RUNTIME_MEMBER.fullmatch(name)
        for name in actual_member_names
    )
    build_valid = (
        isinstance(build, dict)
        and isinstance(build.get("runtime_rustflags"), list)
        and STATIC_RUNTIME_RUST_TARGET_FEATURE in build["runtime_rustflags"]
        and STATIC_RUNTIME_TLS_MODEL in build["runtime_rustflags"]
        and isinstance(build.get("runtime_cflags"), dict)
        and build["runtime_cflags"].get(STATIC_RUNTIME_CFLAGS_KEY) == STATIC_RUNTIME_CFLAGS_VALUE
    )
    allocator_valid = (
        isinstance(allocator_exception, dict)
        and allocator_exception.get("status") == "blocked_by_native_allocator"
        and isinstance(allocator_exception.get("member"), str)
        and allocator_exception.get("member")
        in {
            member.get("name")
            for member in actual_members
            if isinstance(member, dict)
        }
    )
    valid = (
        isinstance(component, dict)
        and component.get("name") == "crabc-libc-static"
        and component.get("target") == TARGET_TRIPLE
        and isinstance(archive_record, dict)
        and archive_record.get("name") == archive.name
        and archive_record.get("sha256") == sha256_file(archive)
        and command_record_valid
        and member_valid
        and excluded_valid
        and no_embedded_stock_runtime
        and build_valid
        and lifecycle_tls_valid
        and allocator_valid
    )
    return {
        "status": "verified" if valid else "rejected",
        "provenance": {"name": provenance.name, "sha256": sha256_file(provenance)},
        "commands": {"name": commands_file.name, "sha256": sha256_file(commands_file)},
        "archive": {
            "name": archive.name,
            "sha256": sha256_file(archive),
            "members": checked_members,
            "non_elf_members": non_elf_members,
        },
        "excluded_members": {
            "stock_compiler_builtins": stock_builtins if isinstance(stock_builtins, list) else [],
            "native_compiler_rt": native_compiler_rt if isinstance(native_compiler_rt, list) else [],
        },
        "native_allocator_exception": allocator_exception if isinstance(allocator_exception, dict) else {},
        "runtime_lifecycle_tls": actual_lifecycle_tls,
        "checks": {
            "commands": "verified" if command_record_valid else "rejected",
            "members": "verified" if member_valid else "rejected",
            "excluded_runtime": "verified" if excluded_valid and no_embedded_stock_runtime else "rejected",
            "build_flags": "verified" if build_valid else "rejected",
            "runtime_lifecycle_tls": "verified" if lifecycle_tls_valid else "rejected",
            "allocator_exception": "verified" if allocator_valid else "rejected",
        },
    }


def classify_source_file(path: Path) -> str:
    suffix = path.suffix
    if suffix == ".rs":
        return "Rust target runtime implementation"
    if suffix in NATIVE_IMPLEMENTATION_SUFFIXES:
        return "rejected native target runtime implementation"
    if suffix == ".h":
        return "C public declaration or fixture"
    return "other"


def stable_input_label(path: Path) -> str:
    """Name an audited repository input without embedding its checkout path."""

    if path.parent == path:
        return path.name
    return f"{path.parent.name}/{path.name}"


def audit_runtime_sources(source_roots: Sequence[Path]) -> dict[str, object]:
    """Audit selected target-runtime source roots, preserving declarations separately."""

    roots = [require_directory(root, "runtime source root") for root in source_roots]
    records: list[dict[str, str]] = []
    rejected: list[str] = []
    counts: dict[str, int] = {}
    for root in sorted(roots):
        root_label = stable_input_label(root)
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            classification = classify_source_file(path)
            counts[classification] = counts.get(classification, 0) + 1
            relative = str(path.relative_to(root))
            records.append({"root": root_label, "path": relative, "classification": classification})
            if classification == "rejected native target runtime implementation":
                rejected.append(f"{root_label}/{relative}")
    root_labels = {stable_input_label(root) for root in roots}
    coverage_status = "complete" if FULL_RUNTIME_SOURCE_ROOTS <= root_labels else ("partial" if roots else "unverified")
    status = "rejected" if rejected else ("passed" if coverage_status == "complete" else coverage_status)
    return {
        "status": status,
        "coverage_status": coverage_status,
        "roots": sorted(root_labels),
        "required_full_runtime_roots": sorted(FULL_RUNTIME_SOURCE_ROOTS),
        "missing_full_runtime_roots": sorted(FULL_RUNTIME_SOURCE_ROOTS - root_labels),
        "counts": counts,
        "files": records,
        "rejected_native_sources": rejected,
    }


def _build_script_uses_native_tool(text: str) -> bool:
    return bool(re.search(r"(?i)(?:\bcc\b|clang\+\+|\bclang\b|\bgcc\b|\bcmake\b|autoconf|automake)", text))


def _native_allocator_exception_contract(
    manifest_path: Path,
    package: Mapping[str, object],
    build_script: Path,
    build_script_text: str | None,
    resolved_features: Sequence[str],
) -> dict[str, object]:
    """Describe the one separately scoped native allocator input exactly.

    This is deliberately narrower than a package-name allowlist. The current
    temporary exception is the pinned `libmimalloc-sys` v3 static source only;
    a changed feature, build-script selection, package version, or source path
    becomes an ordinary unapproved purity failure.
    """

    if package.get("name") != "libmimalloc-sys":
        return {"status": "not_applicable"}
    source = manifest_path.parent / "c_src/mimalloc/v3/src/static.c"
    source_label = f"{stable_input_label(manifest_path)[:-len('Cargo.toml')]}c_src/mimalloc/v3/src/static.c"
    expected_build_script = (
        build_script_text is not None
        and bool(
            re.search(
                r'let\s+static_source\s*=\s*include_root\s*\.join\("src"\)\s*\.join\("static\.c"\)',
                build_script_text,
            )
        )
        and "build.file(&static_source)" in build_script_text
        and 'build.compile("mimalloc")' in build_script_text
    )
    valid = (
        package.get("version") == "0.1.49"
        and build_script.is_file()
        and source.is_file()
        and "v2" not in resolved_features
        and expected_build_script
    )
    return {
        "status": "verified" if valid else "rejected",
        "package": "libmimalloc-sys",
        "version": package.get("version"),
        "resolved_features": sorted(resolved_features),
        "build_script": {
            "path": stable_input_label(build_script) if build_script.is_file() else None,
            "sha256": sha256_file(build_script) if build_script.is_file() else None,
            "selects_v3_static_source": expected_build_script,
        },
        "selected_native_source": {
            "path": source_label,
            "sha256": sha256_file(source) if source.is_file() else None,
        },
        "reason": (
            "separately tracked native allocator blocker; no other package or transitive native input is exempt"
            if valid
            else "pinned native allocator source-selection contract no longer matches"
        ),
    }


def _native_allocator_build_helper_contract(manifest_path: Path, package: Mapping[str, object]) -> dict[str, object]:
    """Bind the allocator's one host C-driver helper to its pinned source."""

    if package.get("name") != "cc":
        return {"status": "not_applicable"}
    source = manifest_path.parent / "src/detect_compiler_family.c"
    source_label = f"{stable_input_label(manifest_path)[:-len('Cargo.toml')]}src/detect_compiler_family.c"
    valid = package.get("version") == "1.4.3" and source.is_file()
    return {
        "status": "verified" if valid else "rejected",
        "package": "cc",
        "version": package.get("version"),
        "selected_native_source": {
            "path": source_label,
            "sha256": sha256_file(source) if source.is_file() else None,
        },
        "reason": (
            "pinned host compiler-discovery helper used only to build the documented libmimalloc-sys exception"
            if valid
            else "pinned allocator build-helper contract no longer matches"
        ),
    }


def audit_dependencies(
    manifest_paths: Sequence[Path], *, cargo_metadata: Sequence[Path] = ()
) -> dict[str, object]:
    """Audit the production normal/build dependency closure, never test-only deps.

    Cargo metadata's package list includes every resolved dev dependency.  A
    blanket scan therefore misclassified test fixtures (including their
    deliberately foreign assembly) as target-runtime inputs.  Start from the
    explicit runtime components and traverse only normal and build edges; keep
    the excluded dev-only package identities in the evidence record.
    """

    explicit_manifests = [require_regular_file(path, "Cargo manifest") for path in manifest_paths]
    metadata_files = [require_regular_file(path, "Cargo metadata JSON") for path in cargo_metadata]
    packages_by_id: dict[str, dict[str, object]] = {}
    nodes_by_id: dict[str, dict[str, object]] = {}
    resolved_features_by_id: dict[str, list[str]] = {}
    manifest_to_ids: dict[Path, set[str]] = {}
    metadata_complete = bool(metadata_files)
    for metadata_path in metadata_files:
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise SysrootError(f"invalid Cargo metadata JSON: {metadata_path}") from error
        package_values = metadata.get("packages") if isinstance(metadata, dict) else None
        if not isinstance(package_values, list) or not package_values:
            raise SysrootError("Cargo metadata JSON must contain a non-empty packages list")
        for index, package in enumerate(package_values):
            if not isinstance(package, dict) or not isinstance(package.get("manifest_path"), str):
                raise SysrootError("Cargo metadata package lacks manifest_path")
            package_id = package.get("id")
            if not isinstance(package_id, str) or not package_id:
                # Fixtures for parser tests may omit Cargo's opaque ID.  They
                # cannot prove a graph closure, but remain useful for the
                # manifest-level audit below.
                package_id = f"{metadata_path.name}:package:{index}"
                metadata_complete = False
            manifest = require_regular_file(Path(package["manifest_path"]), "Cargo metadata manifest")
            packages_by_id[package_id] = {**package, "_manifest": manifest}
            manifest_to_ids.setdefault(manifest.resolve(), set()).add(package_id)
        resolve = metadata.get("resolve") if isinstance(metadata, dict) else None
        node_values = resolve.get("nodes") if isinstance(resolve, dict) else None
        if not isinstance(node_values, list):
            metadata_complete = False
            continue
        for node in node_values:
            if not isinstance(node, dict) or not isinstance(node.get("id"), str):
                metadata_complete = False
                continue
            nodes_by_id[node["id"]] = node
            features = node.get("features")
            resolved_features_by_id[node["id"]] = (
                sorted(feature for feature in features if isinstance(feature, str))
                if isinstance(features, list)
                else []
            )

    root_ids: set[str] = set()
    uncovered_explicit: list[str] = []
    for manifest in explicit_manifests:
        ids = manifest_to_ids.get(manifest.resolve(), set())
        if metadata_files and not ids:
            uncovered_explicit.append(stable_input_label(manifest))
        root_ids.update(ids)

    normal_build_edges: dict[str, set[str]] = {}
    excluded_dev_ids: set[str] = set()
    selected_ids: set[str] = set()
    missing_resolve_nodes: set[str] = set()
    if metadata_files and metadata_complete:
        pending = list(root_ids)
        while pending:
            package_id = pending.pop()
            if package_id in selected_ids:
                continue
            selected_ids.add(package_id)
            node = nodes_by_id.get(package_id)
            if node is None:
                missing_resolve_nodes.add(package_id)
                continue
            selected_dependencies: set[str] = set()
            dependencies = node.get("deps")
            if not isinstance(dependencies, list):
                missing_resolve_nodes.add(package_id)
                continue
            for dependency in dependencies:
                if not isinstance(dependency, dict) or not isinstance(dependency.get("pkg"), str):
                    missing_resolve_nodes.add(package_id)
                    continue
                dependency_id = dependency["pkg"]
                dep_kinds = dependency.get("dep_kinds")
                if not isinstance(dep_kinds, list) or not dep_kinds:
                    missing_resolve_nodes.add(package_id)
                    continue
                kinds = {
                    entry.get("kind")
                    for entry in dep_kinds
                    if isinstance(entry, dict) and entry.get("kind") in {None, "build", "dev"}
                }
                if kinds.intersection({None, "build"}):
                    selected_dependencies.add(dependency_id)
                    pending.append(dependency_id)
                elif "dev" in kinds:
                    excluded_dev_ids.add(dependency_id)
            normal_build_edges[package_id] = selected_dependencies
        if missing_resolve_nodes:
            metadata_complete = False
    elif metadata_files:
        # Preserve the older manifest-only test fixture behavior while making
        # its incomplete closure explicit in the resulting record.
        selected_ids = set(packages_by_id)

    if not metadata_files:
        selected_paths = {manifest.resolve() for manifest in explicit_manifests}
    else:
        selected_paths = {
            package["_manifest"].resolve()
            for package_id, package in packages_by_id.items()
            if package_id in selected_ids and isinstance(package.get("_manifest"), Path)
        }
    package_id_by_manifest: dict[Path, str] = {}
    for package_id, package in packages_by_id.items():
        manifest = package.get("_manifest")
        if isinstance(manifest, Path) and package_id in selected_ids:
            package_id_by_manifest.setdefault(manifest.resolve(), package_id)
    manifests = sorted(selected_paths)
    packages: list[dict[str, object]] = []
    rejected: list[dict[str, str]] = []
    for manifest_path in manifests:
        try:
            with manifest_path.open("rb") as stream:
                manifest = tomllib.load(stream)
        except tomllib.TOMLDecodeError as error:
            raise SysrootError(f"invalid Cargo manifest: {manifest_path}") from error
        package = manifest.get("package")
        if not isinstance(package, dict):
            raise SysrootError(f"Cargo manifest has no package table: {manifest_path}")
        links = package.get("links")
        build = package.get("build")
        build_script = manifest_path.parent / (str(build) if isinstance(build, str) else "build.rs")
        build_script_text: str | None = None
        native_build = False
        if build_script.is_file():
            build_script_text = build_script.read_text(encoding="utf-8", errors="replace")
            native_build = _build_script_uses_native_tool(build_script_text)
        selected_source_root = manifest_path.parent / "src"
        native_source_inputs: list[str] = []
        bundled_native_archives: list[str] = []
        if selected_source_root.is_dir():
            for source in sorted(path for path in selected_source_root.rglob("*") if path.is_file()):
                label = f"{stable_input_label(manifest_path)[:-len('Cargo.toml')]}{source.relative_to(manifest_path.parent)}"
                if source.suffix in NATIVE_IMPLEMENTATION_SUFFIXES:
                    native_source_inputs.append(label)
                if source.suffix in {".a", ".so", ".o"}:
                    bundled_native_archives.append(label)
        package_id = package_id_by_manifest.get(manifest_path.resolve())
        allocator_contract = _native_allocator_exception_contract(
            manifest_path,
            package,
            build_script,
            build_script_text,
            resolved_features_by_id.get(package_id, []) if isinstance(package_id, str) else [],
        )
        allocator_build_helper_contract = _native_allocator_build_helper_contract(manifest_path, package)
        selected_native_inputs = list(native_source_inputs)
        if allocator_contract.get("status") != "not_applicable":
            source_record = allocator_contract.get("selected_native_source")
            if isinstance(source_record, dict) and isinstance(source_record.get("path"), str):
                selected_native_inputs.append(source_record["path"])
        package_record = {
            "manifest": stable_input_label(manifest_path),
            "package_id": package_id,
            "package": package.get("name"),
            "version": package.get("version"),
            "resolved_features": resolved_features_by_id.get(package_id, []) if isinstance(package_id, str) else [],
            "links": links,
            "build_script": stable_input_label(build_script) if build_script.is_file() else None,
            "build_script_native_tool_reference": native_build,
            "normal_dependencies": sorted((manifest.get("dependencies") or {}).keys()),
            "build_dependencies": sorted((manifest.get("build-dependencies") or {}).keys()),
            "selected_source_root": stable_input_label(selected_source_root) if selected_source_root.is_dir() else None,
            "native_source_inputs": native_source_inputs,
            "selected_native_build_inputs": selected_native_inputs,
            "bundled_native_archives": bundled_native_archives,
            "native_allocator_exception_contract": allocator_contract,
            "native_allocator_build_helper_contract": allocator_build_helper_contract,
        }
        packages.append(package_record)
        if isinstance(links, str) and links:
            rejected.append(
                {
                    "manifest": stable_input_label(manifest_path),
                    "package_id": str(package_id_by_manifest.get(manifest_path.resolve(), "")),
                    "reason": "package.links is forbidden",
                }
            )
        if native_build:
            rejected.append(
                {
                    "manifest": stable_input_label(manifest_path),
                    "package_id": str(package_id_by_manifest.get(manifest_path.resolve(), "")),
                    "reason": "build script references a native build tool",
                }
            )
        if selected_native_inputs:
            rejected.append(
                {
                    "manifest": stable_input_label(manifest_path),
                    "package_id": str(package_id_by_manifest.get(manifest_path.resolve(), "")),
                    "reason": "selected target source contains native implementation input: " + ", ".join(selected_native_inputs),
                }
            )
        if bundled_native_archives:
            rejected.append(
                {
                    "manifest": stable_input_label(manifest_path),
                    "package_id": str(package_id_by_manifest.get(manifest_path.resolve(), "")),
                    "reason": "selected target source contains bundled native archive/object: " + ", ".join(bundled_native_archives),
                }
            )
        if allocator_contract.get("status") == "rejected":
            rejected.append(
                {
                    "manifest": stable_input_label(manifest_path),
                    "package_id": str(package_id_by_manifest.get(manifest_path.resolve(), "")),
                    "reason": "native allocator exception contract is not verified",
                }
            )
        if allocator_build_helper_contract.get("status") == "rejected":
            rejected.append(
                {
                    "manifest": stable_input_label(manifest_path),
                    "package_id": str(package_id_by_manifest.get(manifest_path.resolve(), "")),
                    "reason": "native allocator build-helper contract is not verified",
                }
            )
    if uncovered_explicit:
        rejected.extend(
            {"manifest": label, "package_id": "", "reason": "not represented by supplied Cargo metadata closure"}
            for label in uncovered_explicit
        )

    allocator_roots = {
        package_id
        for package_id, package in packages_by_id.items()
        if package_id in selected_ids and package.get("name") == "libmimalloc-sys"
    }
    allocator_closure: set[str] = set()
    pending_allocator = list(allocator_roots)
    while pending_allocator:
        package_id = pending_allocator.pop()
        if package_id in allocator_closure:
            continue
        allocator_closure.add(package_id)
        pending_allocator.extend(normal_build_edges.get(package_id, ()))
    # The exception is only the pinned sys crate itself.  Its normal/build
    # closure remains visible for review, but a future native dependency below
    # it is an independent purity failure rather than something this label can
    # silently absorb.
    verified_allocator_roots = {
        str(package.get("package_id"))
        for package in packages
        if isinstance(package, dict)
        and package.get("package_id") in allocator_roots
        and isinstance(package.get("native_allocator_exception_contract"), dict)
        and package["native_allocator_exception_contract"].get("status") == "verified"
    }
    package_records_by_id = {
        package.get("package_id"): package
        for package in packages
        if isinstance(package, dict) and isinstance(package.get("package_id"), str)
    }
    verified_allocator_build_helpers: set[str] = set()
    for allocator_id in verified_allocator_roots:
        for dependency_id in normal_build_edges.get(allocator_id, ()):
            record = package_records_by_id.get(dependency_id)
            contract = record.get("native_allocator_build_helper_contract") if isinstance(record, dict) else None
            if isinstance(contract, dict) and contract.get("status") == "verified":
                verified_allocator_build_helpers.add(dependency_id)
    approved_allocator_exception_ids = verified_allocator_roots | verified_allocator_build_helpers
    allocator_rejections = [entry for entry in rejected if entry.get("package_id") in approved_allocator_exception_ids]
    unapproved_rejections = [entry for entry in rejected if entry.get("package_id") not in approved_allocator_exception_ids]
    closure_status = "complete" if metadata_files and metadata_complete else ("partial" if manifests else "unverified")
    if unapproved_rejections:
        status = "rejected"
    elif allocator_rejections and allocator_roots and closure_status == "complete":
        status = "blocked_by_native_allocator"
    elif rejected:
        status = "rejected"
    elif manifests and closure_status == "complete":
        status = "passed"
    else:
        status = closure_status
    return {
        "status": status,
        "closure_status": closure_status,
        "cargo_metadata": [
            {"name": path.name, "sha256": sha256_file(path)} for path in metadata_files
        ],
        "uncovered_explicit_manifests": sorted(uncovered_explicit),
        "production_closure": {
            "root_package_ids": sorted(root_ids),
            "selected_package_ids": sorted(selected_ids),
            "excluded_dev_package_ids": sorted(excluded_dev_ids - selected_ids),
            "missing_resolve_nodes": sorted(missing_resolve_nodes),
        },
        "manifests": packages,
        "rejected": rejected,
        "allocator_exception": {
            "status": "blocked_by_native_allocator" if allocator_rejections and not unapproved_rejections else "not_applicable",
            "package_ids": sorted(allocator_roots),
            "verified_package_ids": sorted(verified_allocator_roots),
            "verified_build_helper_package_ids": sorted(verified_allocator_build_helpers),
            "closure_package_ids": sorted(allocator_closure),
            "rejected": allocator_rejections,
        },
        "unapproved_rejected": unapproved_rejections,
        "note": "Only normal/build Cargo edges are target-runtime inputs; dev-only resolution is reported but excluded from purity classification.",
    }


def _read_elf_header(data: bytes, path: Path) -> ElfHeader:
    if len(data) < 64 or data[:4] != ELF_MAGIC:
        raise SysrootError(f"not an ELF file: {path}")
    if data[4] != 2 or data[5] != 1:
        raise SysrootError(f"ELF must be 64-bit little-endian: {path}")
    values = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
    return ElfHeader(
        elf_type=values[1],
        machine=values[2],
        program_header_offset=values[5],
        section_header_offset=values[6],
        program_header_entry_size=values[9],
        program_header_count=values[10],
        section_header_entry_size=values[11],
        section_header_count=values[12],
        section_name_index=values[13],
    )


def _bounded_slice(data: bytes, offset: int, length: int, path: Path, what: str) -> bytes:
    if offset < 0 or length < 0 or offset + length > len(data):
        raise SysrootError(f"ELF {what} exceeds file bounds: {path}")
    return data[offset : offset + length]


def _cstring(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        return "<invalid>"
    end = data.find(b"\0", offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode("utf-8", errors="replace")


def embedded_build_paths(data: bytes) -> list[str]:
    """Find retained host-build paths without treating runtime file names as paths.

    Remapped `/crabc/...` source names and the installed interpreter are
    intentional artifact strings. Ordinary runtime paths such as
    `/etc/resolv.conf` are also not build provenance. Everything else is
    classified by a host-root, build-directory, or source/artifact suffix so
    a checkout under an arbitrary root cannot hide merely because it is not
    named `/workspace` or `/tmp`.
    """

    paths: set[str] = set()
    for raw in EMBEDDED_ABSOLUTE_PATH.findall(data):
        value = raw.decode("utf-8", errors="replace")
        if value == CANONICAL_INTERPRETER or value.startswith("/crabc/"):
            continue
        candidate = PurePosixPath(value)
        parts = candidate.parts
        components = set(parts[1:-1])
        if (
            len(parts) > 1
            and parts[1] in HOST_BUILD_PATH_ROOTS
            or components.intersection(BUILD_PATH_COMPONENTS)
            or candidate.suffix in BUILD_PATH_SUFFIXES
        ):
            paths.add(value)
    return sorted(paths)


def _aligned_size(value: int, alignment: int) -> int:
    """Round one checked ELF note field size up to its required alignment."""

    if alignment <= 0:
        raise SysrootError("ELF note alignment is invalid")
    remainder = value % alignment
    return value if remainder == 0 else value + alignment - remainder


def _note_records(data: bytes, source: Path, section_name: str) -> list[dict[str, object]]:
    """Inspect every ELF note without interpreting producer-specific payloads."""

    records: list[dict[str, object]] = []
    cursor = 0
    while cursor < len(data):
        if len(data) - cursor < 12:
            raise SysrootError(f"ELF note section is truncated: {source}:{section_name}")
        name_size, description_size, note_type = struct.unpack_from("<III", data, cursor)
        cursor += 12
        name_end = cursor + name_size
        if name_end > len(data):
            raise SysrootError(f"ELF note name exceeds section: {source}:{section_name}")
        name = data[cursor:name_end].rstrip(b"\0").decode("utf-8", errors="replace")
        cursor += _aligned_size(name_size, 4)
        description_end = cursor + description_size
        if description_end > len(data):
            raise SysrootError(f"ELF note descriptor exceeds section: {source}:{section_name}")
        description = data[cursor:description_end]
        records.append(
            {
                "section": section_name,
                "name": name,
                "type": note_type,
                "description_size": description_size,
                "description_sha256": hashlib.sha256(description).hexdigest(),
            }
        )
        cursor += _aligned_size(description_size, 4)
        if cursor > len(data):
            raise SysrootError(f"ELF note padding exceeds section: {source}:{section_name}")
    return records


def inspect_elf(path: Path) -> dict[str, object]:
    """Parse the ELF facts relevant to installed-runtime provenance without host tools."""

    source = require_regular_file(path, "ELF artifact")
    data = source.read_bytes()
    header = _read_elf_header(data, source)
    if header.machine != EM_AARCH64:
        raise SysrootError(f"ELF is not AArch64: {source}")
    program_headers: list[dict[str, int]] = []
    for index in range(header.program_header_count):
        offset = header.program_header_offset + index * header.program_header_entry_size
        values = struct.unpack("<IIQQQQQQ", _bounded_slice(data, offset, 56, source, "program header"))
        program_headers.append(
            {
                "type": values[0],
                "flags": values[1],
                "offset": values[2],
                "vaddr": values[3],
                "filesz": values[5],
                "memsz": values[6],
                "align": values[7],
            }
        )
    # Preserve every section-header field in the report.  The artifact report
    # is deliberately a parsed audit rather than a hand-wavy `readelf` text
    # scrape, and consumers need flags/links as well as a section's name.
    raw_sections: list[tuple[int, int, int, int, int, int, int, int, int, int]] = []
    for index in range(header.section_header_count):
        offset = header.section_header_offset + index * header.section_header_entry_size
        values = struct.unpack("<IIQQQQIIQQ", _bounded_slice(data, offset, 64, source, "section header"))
        raw_sections.append(values)
    names = b""
    if 0 <= header.section_name_index < len(raw_sections):
        _, _, _, _, offset, size, _, _, _, _ = raw_sections[header.section_name_index]
        names = _bounded_slice(data, offset, size, source, "section name table")
    sections: list[dict[str, object]] = []
    defined_symbols: list[dict[str, object]] = []
    undefined_symbols: list[dict[str, object]] = []
    dynamic_needed: list[str] = []
    dynamic_tags: list[int] = []
    dynamic_entries: list[dict[str, int]] = []
    relocation_sections: list[str] = []
    relocation_entries: list[dict[str, object]] = []
    notes: list[dict[str, object]] = []
    for index, raw_section in enumerate(raw_sections):
        (
            name_offset,
            section_type,
            section_flags,
            section_address,
            offset,
            size,
            link,
            info,
            addralign,
            entry_size,
        ) = raw_section
        section_name = _cstring(names, name_offset)
        sections.append(
            {
                "index": index,
                "name": section_name,
                "type": section_type,
                "flags": section_flags,
                "address": section_address,
                "offset": offset,
                "size": size,
                "link": link,
                "info": info,
                "address_alignment": addralign,
                "entry_size": entry_size,
            }
        )
        if section_type in {4, 9, 19}:
            relocation_sections.append(section_name)
            if section_type == 4 and entry_size < 24:
                raise SysrootError(f"ELF RELA section has short entries: {source}:{section_name}")
            if section_type == 9 and entry_size < 16:
                raise SysrootError(f"ELF REL section has short entries: {source}:{section_name}")
            relocation_data = _bounded_slice(data, offset, size, source, "relocation section")
            if section_type == 4:
                for entry in range(0, len(relocation_data) - (len(relocation_data) % entry_size), entry_size):
                    relocation_offset, relocation_info, addend = struct.unpack_from("<QQq", relocation_data, entry)
                    relocation_entries.append(
                        {
                            "section": section_name,
                            "symbol_table_index": link,
                            "file_offset": offset + entry,
                            "offset": relocation_offset,
                            "type": relocation_info & 0xffff_ffff,
                            "symbol_index": relocation_info >> 32,
                            "addend": addend,
                        }
                    )
            elif section_type == 9:
                for entry in range(0, len(relocation_data) - (len(relocation_data) % entry_size), entry_size):
                    relocation_offset, relocation_info = struct.unpack_from("<QQ", relocation_data, entry)
                    relocation_entries.append(
                        {
                            "section": section_name,
                            "symbol_table_index": link,
                            "file_offset": offset + entry,
                            "offset": relocation_offset,
                            "type": relocation_info & 0xffff_ffff,
                            "symbol_index": relocation_info >> 32,
                        }
                    )
            else:
                # A RELR word is either an aligned relocation address or a
                # bitmap.  Preserve the raw words because the packing is part
                # of static-PIE evidence and cannot be reconstructed from a
                # relocation type alone.
                if entry_size not in {0, 8}:
                    raise SysrootError(f"ELF RELR section has unexpected entry size: {source}:{section_name}")
                if len(relocation_data) % 8:
                    raise SysrootError(f"ELF RELR section is not word aligned: {source}:{section_name}")
                for entry in range(0, len(relocation_data), 8):
                    relocation_entries.append(
                        {
                            "section": section_name,
                            "file_offset": offset + entry,
                            "relr_word": struct.unpack_from("<Q", relocation_data, entry)[0],
                        }
                    )
        if section_type == 7:
            notes.extend(_note_records(_bounded_slice(data, offset, size, source, "note section"), source, section_name))
        if section_type == 6:
            if link >= len(raw_sections) or entry_size < 16:
                raise SysrootError(f"ELF dynamic section is invalid: {source}")
            _, _, _, _, string_offset, string_size, _, _, _, _ = raw_sections[link]
            strings = _bounded_slice(data, string_offset, string_size, source, "dynamic string table")
            dynamic_data = _bounded_slice(data, offset, size, source, "dynamic section")
            for entry in range(0, len(dynamic_data) - (len(dynamic_data) % entry_size), entry_size):
                tag, value = struct.unpack_from("<qQ", dynamic_data, entry)
                dynamic_tags.append(tag)
                dynamic_entries.append({"tag": tag, "value": value})
                if tag == 1:
                    dynamic_needed.append(_cstring(strings, value))
        if section_type not in {2, 11} or entry_size == 0:
            continue
        if link >= len(raw_sections):
            raise SysrootError(f"ELF symbol string table is invalid: {source}")
        _, _, _, _, string_offset, string_size, _, _, _, _ = raw_sections[link]
        strings = _bounded_slice(data, string_offset, string_size, source, "symbol string table")
        symbol_data = _bounded_slice(data, offset, size, source, "symbol table")
        for entry_index, entry in enumerate(range(0, len(symbol_data) - (len(symbol_data) % entry_size), entry_size)):
            if entry_size < 24:
                raise SysrootError(f"ELF symbol entry is too small: {source}")
            name_offset, info, other, section_index, value, symbol_size = struct.unpack_from(
                "<IBBHQQ", symbol_data, entry
            )
            # Entry zero is the ELF-mandated null symbol, not an unresolved
            # link input.  Treating it as undefined made a pure-Rust archive
            # appear to require one foreign symbol.
            if entry_index == 0 and name_offset == 0 and info == 0 and other == 0 and section_index == 0 and value == 0 and symbol_size == 0:
                continue
            symbol = {
                "table": section_name,
                "table_index": index,
                "entry_index": entry_index,
                "name": _cstring(strings, name_offset) if name_offset else "",
                "binding": info >> 4,
                "type": info & 0x0f,
                "visibility": other & 0x03,
                "section_index": section_index,
                "value": value,
                "size": symbol_size,
            }
            if section_index == 0:
                undefined_symbols.append(symbol)
            else:
                defined_symbols.append(symbol)
        del strings
    interpreter: str | None = None
    for program in program_headers:
        if program["type"] == 3:
            blob = _bounded_slice(data, program["offset"], program["filesz"], source, "PT_INTERP")
            interpreter = blob.rstrip(b"\0").decode("utf-8", errors="replace")
    absolute_paths = embedded_build_paths(data)
    return {
        "kind": "elf",
        "path": str(source),
        "sha256": sha256_file(source),
        "elf_type": header.elf_type,
        "machine": header.machine,
        "interpreter": interpreter,
        "program_headers": program_headers,
        "sections": sections,
        "dynamic_needed": dynamic_needed,
        "dynamic_tags": dynamic_tags,
        "dynamic_entries": dynamic_entries,
        "relocation_sections": relocation_sections,
        "relocations": relocation_entries,
        "notes": notes,
        "has_relro": any(program["type"] == 0x6474E552 for program in program_headers),
        "gnu_stack_executable": any(
            program["type"] == 0x6474E551 and bool(program["flags"] & 1) for program in program_headers
        ),
        "defined_symbols": defined_symbols,
        "undefined_symbols": undefined_symbols,
        "defined_symbol_count": len(defined_symbols),
        "undefined_symbol_count": len(undefined_symbols),
        "absolute_build_paths": absolute_paths,
    }


def inspect_archive(path: Path) -> dict[str, object]:
    """Enumerate deterministic Unix archive members and inspect ELF members."""

    source = require_regular_file(path, "archive artifact")
    data = source.read_bytes()
    if not data.startswith(AR_MAGIC):
        raise SysrootError(f"not an archive: {source}")
    offset = len(AR_MAGIC)
    string_table = b""
    members: list[dict[str, object]] = []
    absolute_paths: set[str] = set()
    while offset < len(data):
        header = _bounded_slice(data, offset, 60, source, "archive header")
        offset += 60
        name_text = header[:16].decode("ascii", errors="replace").rstrip()
        size_text = header[48:58].decode("ascii", errors="replace").strip()
        if header[58:60] != b"`\n" or not size_text.isdigit():
            raise SysrootError(f"invalid archive member header: {source}")
        size = int(size_text)
        payload = _bounded_slice(data, offset, size, source, "archive member")
        offset += size
        if offset % 2:
            offset += 1
        if name_text == "//":
            string_table = payload
            continue
        member_name = name_text.rstrip("/")
        if name_text.startswith("/") and name_text[1:].isdigit():
            index = int(name_text[1:])
            terminator = string_table.find(b"/\n", index)
            if terminator == -1:
                terminator = len(string_table)
            member_name = string_table[index:terminator].decode("utf-8", errors="replace")
        member: dict[str, object] = {"name": member_name, "size": size, "sha256": hashlib.sha256(payload).hexdigest()}
        if payload.startswith(ELF_MAGIC):
            temporary_path: Path | None = None
            try:
                with tempfile.NamedTemporaryFile(prefix="crabc-archive-member-", delete=False) as stream:
                    stream.write(payload)
                    temporary_path = Path(stream.name)
                member["elf"] = inspect_elf(temporary_path)
                elf = member["elf"]
                assert isinstance(elf, dict)
                absolute_paths.update(str(item) for item in elf["absolute_build_paths"])
            finally:
                if temporary_path is not None:
                    temporary_path.unlink(missing_ok=True)
        members.append(member)
    return {
        "kind": "archive",
        "path": str(source),
        "sha256": sha256_file(source),
        "members": members,
        "absolute_build_paths": sorted(absolute_paths),
    }


def inspect_artifact(path: Path) -> dict[str, object]:
    data = require_regular_file(path, "artifact").read_bytes()[:8]
    if data.startswith(ELF_MAGIC):
        return inspect_elf(path)
    if data.startswith(AR_MAGIC):
        return inspect_archive(path)
    raise SysrootError(f"artifact is neither ELF nor archive: {path}")


def classify_link_path(
    path: Path,
    sysroot: Path,
    application_paths: Iterable[Path] = (),
    application_library_roots: Iterable[Path] = (),
) -> LinkInput:
    resolved = path.expanduser().resolve()
    runtime_root = sysroot.resolve()
    applications = {candidate.expanduser().resolve() for candidate in application_paths}
    library_roots = {candidate.expanduser().resolve() for candidate in application_library_roots}
    normalized = str(resolved).lower()
    if "/opt/musl-" in normalized or any(component in normalized for component in FOREIGN_RUNTIME_COMPONENTS):
        return LinkInput(str(resolved), "rejected foreign target runtime", "known foreign runtime location or component")
    try:
        resolved.relative_to(runtime_root)
    except ValueError:
        pass
    else:
        return LinkInput(str(resolved), "crabc Rust runtime", "installed crabc sysroot input")
    if resolved in applications:
        return LinkInput(str(resolved), "application object", "explicit caller input")
    for root in library_roots:
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        return LinkInput(str(resolved), "application object", "resolved beneath caller-declared application library root")
    return LinkInput(str(resolved), "rejected foreign target runtime", "outside explicit sysroot and application allowlist")


def audit_link_inputs(
    paths: Sequence[Path],
    sysroot: Path,
    application_paths: Iterable[Path] = (),
    application_library_roots: Iterable[Path] = (),
) -> dict[str, object]:
    inputs = [
        classify_link_path(path, sysroot, application_paths, application_library_roots)
        for path in paths
    ]
    rejected = [item.record() for item in inputs if item.classification == "rejected foreign target runtime"]
    return {
        "status": "passed" if not rejected else "rejected",
        "inputs": [item.record() for item in inputs],
        "foreign_target_runtime_inputs": rejected,
        "musl_target_inputs": [item for item in rejected if "/musl" in item["path"].lower()],
        "gcc_target_inputs": [item for item in rejected if "gcc" in item["path"].lower()],
        "compiler_runtime_inputs": [
            item
            for item in rejected
            if any(component in item["path"].lower() for component in FOREIGN_RUNTIME_COMPONENTS)
        ],
    }


def parse_linker_trace_inputs(output: bytes) -> list[LinkTraceInput]:
    """Extract existing absolute input paths from lld ``--trace`` output.

    lld writes one resolved input per line, with archive members commonly
    rendered as ``/path/libx.a(member.o)``.  Diagnostics may be interleaved,
    so this deliberately accepts only a path that exists at audit time rather
    than treating arbitrary diagnostic text as provenance.
    """

    inputs: list[LinkTraceInput] = []
    seen: set[tuple[Path, str | None]] = set()
    for line in output.decode("utf-8", errors="replace").splitlines():
        candidate_text = line.strip()
        if candidate_text.startswith("ld.lld: "):
            candidate_text = candidate_text[len("ld.lld: ") :].strip()
        archive_member: str | None = None
        if candidate_text.endswith(")") and "(" in candidate_text:
            archive_path, member = candidate_text.rsplit("(", 1)
            if member[:-1] and Path(archive_path).is_absolute() and Path(archive_path).is_file():
                candidate_text = archive_path
                archive_member = member[:-1]
        candidate = Path(candidate_text)
        if not candidate.is_absolute() or not candidate.is_file():
            continue
        resolved = candidate.resolve()
        identity = (resolved, archive_member)
        if identity not in seen:
            seen.add(identity)
            inputs.append(LinkTraceInput(resolved, archive_member))
    return inputs


def parse_linker_trace_paths(output: bytes) -> list[Path]:
    """Return unique trace paths for callers that do not need member identity."""

    paths: list[Path] = []
    seen: set[Path] = set()
    for input_record in parse_linker_trace_inputs(output):
        if input_record.path not in seen:
            seen.add(input_record.path)
            paths.append(input_record.path)
    return paths


def audit_linker_trace(
    output: bytes,
    sysroot: Path,
    application_paths: Iterable[Path] = (),
    application_library_roots: Iterable[Path] = (),
) -> dict[str, object]:
    trace_inputs = parse_linker_trace_inputs(output)
    paths: list[Path] = []
    seen_paths: set[Path] = set()
    for input_record in trace_inputs:
        if input_record.path not in seen_paths:
            seen_paths.add(input_record.path)
            paths.append(input_record.path)
    if not paths:
        return {
            "status": "unverified",
            "reason": "linker trace contained no resolved existing input paths",
            "inputs": [],
            "foreign_target_runtime_inputs": [],
            "musl_target_inputs": [],
            "gcc_target_inputs": [],
            "compiler_runtime_inputs": [],
            "trace_paths": [],
            "trace_inputs": [],
            "archive_member_inputs": [],
        }
    result = audit_link_inputs(paths, sysroot, application_paths, application_library_roots)
    result["trace_paths"] = [str(path) for path in paths]
    classification_by_path = {
        input_record["path"]: input_record
        for input_record in result["inputs"]
        if isinstance(input_record, dict) and isinstance(input_record.get("path"), str)
    }
    trace_records: list[dict[str, object]] = []
    for input_record in trace_inputs:
        record: dict[str, object] = input_record.record()
        classified = classification_by_path.get(str(input_record.path))
        if classified is not None:
            record["classification"] = classified.get("classification")
            record["reason"] = classified.get("reason")
        trace_records.append(record)
    result["trace_inputs"] = trace_records
    result["archive_member_inputs"] = [
        record for record in trace_records if isinstance(record.get("archive_member"), str)
    ]
    return result


def _copy_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    destination.chmod(stat.S_IMODE(source.stat().st_mode))


def _relative_symlink(destination: Path, target: Path) -> None:
    relative = os.path.relpath(target, destination.parent)
    if Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise SysrootError(f"symlink target escapes sysroot: {destination} -> {relative}")
    destination.symlink_to(relative)


def installed_paths(sysroot: Path) -> dict[str, Path]:
    root = require_directory(sysroot, "installed sysroot")
    return {
        "root": root,
        "bin": root / "bin",
        "lib": root / "lib",
        "include": root / "usr/include",
        "usr_lib": root / "usr/lib",
        "share": root / "share/crabc",
        "manifest": root / "share/crabc/manifest.json",
        "purity": root / "share/crabc/purity.json",
    }


def installed_runtime_paths(sysroot: Path) -> dict[str, Path]:
    paths = installed_paths(sysroot)
    runtime = {
        "libc.so": paths["usr_lib"] / "libc.so",
        "libc.a": paths["usr_lib"] / "libc.a",
        "builtins": paths["usr_lib"] / "libcrabc-builtins.a",
        "loader": paths["lib"] / Path(CANONICAL_INTERPRETER).name,
    }
    runtime.update({name: paths["usr_lib"] / name for name in CRT_OBJECTS})
    return runtime


def _relativize_artifact_record(record: dict[str, object], root: Path, label: str) -> dict[str, object]:
    """Remove staging-directory names from an installed-artifact record."""

    value = dict(record)
    value["path"] = label
    members = value.get("members")
    if isinstance(members, list):
        normalized_members: list[object] = []
        for member in members:
            if not isinstance(member, dict):
                normalized_members.append(member)
                continue
            normalized = dict(member)
            elf = normalized.get("elf")
            if isinstance(elf, dict):
                normalized["elf"] = _relativize_artifact_record(
                    elf,
                    root,
                    f"{label}!{normalized.get('name', '<member>')}",
                )
            normalized_members.append(normalized)
        value["members"] = normalized_members
    return value


def artifact_records(paths: Mapping[str, Path], *, relative_to: Path | None = None) -> dict[str, object]:
    records: dict[str, object] = {}
    for name, path in sorted(paths.items()):
        record = inspect_artifact(path)
        if relative_to is not None:
            record = _relativize_artifact_record(record, relative_to, str(path.relative_to(relative_to)))
        records[name] = record
    return records


def audit_runtime_artifacts(
    artifacts: Mapping[str, object],
    static_runtime: Mapping[str, object],
) -> dict[str, object]:
    """Reject native compiler-runtime material in the installed artifact set.

    The report keeps raw archive and ELF records for inspection, while this
    focused decision checks the static archive boundary that Cargo otherwise
    blurs.  It deliberately permits only the named mimalloc member as the
    temporary full-runtime-purity exception; the separately source-built
    helper archive is the sole allowed home for compiler-builtins objects.
    """

    rejected: list[dict[str, str]] = []
    approved_absolute_paths: list[dict[str, str]] = []
    libc = artifacts.get("libc.a")
    builtins = artifacts.get("builtins")
    expected_static_members = static_runtime.get("archive", {}).get("members") if isinstance(static_runtime.get("archive"), dict) else None
    expected_static_sha256 = static_runtime.get("archive", {}).get("sha256") if isinstance(static_runtime.get("archive"), dict) else None
    expected_static_names = [
        entry.get("name")
        for entry in expected_static_members
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    ] if isinstance(expected_static_members, list) else []
    libc_members = _archive_elf_members(libc) if isinstance(libc, dict) else []
    libc_names = [member.get("name") for member in libc_members]
    if static_runtime.get("status") != "verified":
        rejected.append({"artifact": "libc.a", "reason": "static runtime provenance is not verified"})
    if libc_names != expected_static_names:
        rejected.append(
            {
                "artifact": "libc.a",
                "reason": "installed static archive members differ from provenance-selected runtime roots",
            }
        )
    if not isinstance(libc, dict) or libc.get("sha256") != expected_static_sha256:
        rejected.append({"artifact": "libc.a", "reason": "installed static archive hash differs from provenance"})
    for name in libc_names:
        if not isinstance(name, str):
            rejected.append({"artifact": "libc.a", "reason": "static archive has an unnamed ELF member"})
        elif name.startswith("compiler_builtins-") or NATIVE_COMPILER_RUNTIME_MEMBER.fullmatch(name):
            rejected.append({"artifact": "libc.a", "reason": f"forbidden compiler runtime member: {name}"})

    builtins_members = _archive_elf_members(builtins) if isinstance(builtins, dict) else []
    builtins_names = [member.get("name") for member in builtins_members]
    if not builtins_names or builtins_names[0] != "crabc-builtins.o":
        rejected.append({"artifact": "builtins", "reason": "helper archive has no crabc-owned root member"})
    for name in builtins_names[1:]:
        if not isinstance(name, str) or not name.startswith("compiler_builtins-"):
            rejected.append({"artifact": "builtins", "reason": f"unexpected helper archive member: {name}"})
        elif NATIVE_COMPILER_RUNTIME_MEMBER.fullmatch(name):
            rejected.append({"artifact": "builtins", "reason": f"native compiler runtime member: {name}"})

    for artifact_name, record in artifacts.items():
        if not isinstance(record, dict):
            rejected.append({"artifact": str(artifact_name), "reason": "artifact record is not an object"})
            continue
        paths = record.get("absolute_build_paths")
        if not isinstance(paths, list):
            rejected.append({"artifact": str(artifact_name), "reason": "artifact lacks absolute-build-path audit"})
            continue
        for path in paths:
            if not isinstance(path, str):
                rejected.append({"artifact": str(artifact_name), "reason": "artifact path audit contains a non-string"})
                continue
            lowered = path.lower()
            if any(marker in lowered for marker in NATIVE_COMPILER_RUNTIME_PATH_MARKERS) or Path(path).suffix in NATIVE_IMPLEMENTATION_SUFFIXES:
                rejected.append({"artifact": str(artifact_name), "reason": f"native compiler runtime source retained: {path}"})
            elif artifact_name == "builtins" and path.startswith("/rust-src/library/compiler-builtins/"):
                approved_absolute_paths.append({"artifact": str(artifact_name), "path": path})

    return {
        "status": "passed" if not rejected else "rejected",
        "libc_static_members": libc_names,
        "builtins_members": builtins_names,
        "approved_absolute_build_paths": approved_absolute_paths,
        "rejected": rejected,
    }


def _copy_python_driver(staging: Path) -> None:
    destination = staging / "share/crabc/crabc_sysroot.py"
    _copy_file(Path(__file__).resolve(), destination)
    wrapper = staging / "bin/crabc-cc"
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    wrapper.write_text(
        "#!/usr/bin/env python3\n"
        "\"\"\"Relocatable crabc C compiler entry point.\"\"\"\n"
        "from __future__ import annotations\n"
        "import sys\n"
        "from pathlib import Path\n"
        "sys.dont_write_bytecode = True\n"
        "_ROOT = Path(__file__).resolve().parents[1]\n"
        "sys.path.insert(0, str(_ROOT / 'share' / 'crabc'))\n"
        "from crabc_sysroot import installed_driver_main\n"
        "raise SystemExit(installed_driver_main(_ROOT, sys.argv[1:]))\n",
        encoding="utf-8",
        newline="\n",
    )
    wrapper.chmod(0o755)


def assemble_sysroot(
    output: Path,
    inputs: RuntimeInputs,
    toolchain: Toolchain,
    *,
    source_roots: Sequence[Path] = (),
    cargo_manifests: Sequence[Path] = (),
    cargo_metadata: Sequence[Path] = (),
) -> dict[str, object]:
    """Install exactly supplied crabc files into a new, relocatable sysroot."""

    destination = output.expanduser().resolve()
    if destination.exists():
        raise SysrootError(f"refusing to replace existing sysroot: {destination}")
    if destination.parent == destination:
        raise SysrootError("sysroot output cannot be filesystem root")
    include_dir = require_directory(inputs.include_dir, "public include directory")
    checked_paths: dict[str, Path] = {}
    for name, path in inputs.required_paths().items():
        if name == "include_dir":
            continue
        checked_paths[name] = require_regular_file(path, f"required {name}")
    loader_name = checked_paths["loader"].name.lower()
    if "musl" in loader_name or any(component in loader_name for component in FOREIGN_RUNTIME_COMPONENTS):
        raise SysrootError(f"loader input is not a crabc-owned artifact: {checked_paths['loader']}")
    for name, path in checked_paths.items():
        lowered = str(path).lower()
        if "/opt/musl-" in lowered or any(component in lowered for component in FOREIGN_RUNTIME_COMPONENTS):
            raise SysrootError(f"borrowed foreign runtime input is forbidden ({name}): {path}")
    source_audit = audit_runtime_sources(source_roots)
    dependency_audit = audit_dependencies(cargo_manifests, cargo_metadata=cargo_metadata)
    crt_provenance = read_crt_provenance(
        inputs.crt_provenance,
        {name: checked_paths[name] for name in CRT_OBJECTS},
        inputs.crt_commands,
    )
    builtins_provenance = read_builtins_provenance(
        inputs.builtins_provenance,
        checked_paths["libcrabc-builtins.a"],
        inputs.builtins_commands,
    )
    static_runtime_provenance = read_static_runtime_provenance(
        inputs.libc_static_provenance,
        checked_paths["libc.a"],
        inputs.libc_static_commands,
    )
    shared_runtime_tls = audit_shared_runtime_tls(checked_paths["libc.so"])
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{destination.name}.", dir=destination.parent) as temporary:
        staging = Path(temporary) / destination.name
        (staging / "usr/lib").mkdir(parents=True)
        shutil.copytree(include_dir, staging / "usr/include", symlinks=False)
        _copy_file(checked_paths["libc.so"], staging / "usr/lib/libc.so")
        _copy_file(checked_paths["libc.a"], staging / "usr/lib/libc.a")
        _copy_file(checked_paths["libcrabc-builtins.a"], staging / "usr/lib/libcrabc-builtins.a")
        if inputs.crt_provenance is not None:
            _copy_file(inputs.crt_provenance, staging / "share/crabc/crt.provenance.json")
        if inputs.crt_commands is not None:
            _copy_file(inputs.crt_commands, staging / "share/crabc/crt.commands.json")
        if inputs.builtins_provenance is not None:
            _copy_file(inputs.builtins_provenance, staging / "share/crabc/libcrabc-builtins.provenance.json")
        if inputs.builtins_commands is not None:
            _copy_file(inputs.builtins_commands, staging / "share/crabc/libcrabc-builtins.commands.json")
        if inputs.libc_static_provenance is not None:
            _copy_file(inputs.libc_static_provenance, staging / "share/crabc/libc-static.provenance.json")
        if inputs.libc_static_commands is not None:
            _copy_file(inputs.libc_static_commands, staging / "share/crabc/libc-static.commands.json")
        for name in CRT_OBJECTS:
            _copy_file(checked_paths[name], staging / "usr/lib" / name)
        canonical_loader = staging / "lib" / Path(CANONICAL_INTERPRETER).name
        _copy_file(checked_paths["loader"], canonical_loader)
        _relative_symlink(staging / "lib" / COMPATIBLE_INTERPRETER, canonical_loader)
        for name in RUNTIME_ALIAS_NAMES:
            _relative_symlink(staging / "usr/lib" / name, staging / "usr/lib/libc.so")
        _copy_python_driver(staging)
        runtime = installed_runtime_paths(staging)
        installed_artifacts = artifact_records(runtime, relative_to=staging)
        installed_link_audit = audit_link_inputs(list(runtime.values()), staging)
        artifact_purity = audit_runtime_artifacts(installed_artifacts, static_runtime_provenance)
        manifest: dict[str, object] = {
            "schema": SCHEMA_VERSION,
            "target": TARGET_TRIPLE,
            "platform": {"os": "linux", "architecture": "aarch64", "endianness": "little", "kernel_minimum": "5.10"},
            "canonical_interpreter": CANONICAL_INTERPRETER,
            "toolchain": toolchain.record(),
            "supported_link_modes": list(PUBLISHED_APPLICATION_LINK_MODES),
            "layout": {
                "bin": "bin/crabc-cc",
                "loader": "lib/ld-crabc-aarch64.so.1",
                "compatibility_loader_alias": "lib/ld-musl-aarch64.so.1",
                "include": "usr/include",
                "library": "usr/lib",
            },
            "artifacts": installed_artifacts,
            "provenance": {
                "crt": crt_provenance.get("provenance"),
                "compiler_helpers": builtins_provenance.get("provenance"),
                "static_runtime": static_runtime_provenance.get("provenance"),
                "shared_runtime_tls": shared_runtime_tls,
            },
            "driver_module": "share/crabc/crabc_sysroot.py",
        }
        absolute_build_paths = sorted(
            {
                item
                for artifact in installed_artifacts.values()
                if isinstance(artifact, dict)
                for item in artifact.get("absolute_build_paths", [])
                if isinstance(item, str)
            }
        )
        source_passed = source_audit["status"] == "passed"
        dependency_passed = dependency_audit["status"] == "passed"
        crt_verified = crt_provenance["status"] == "verified"
        builtins_verified = builtins_provenance["status"] == "verified"
        static_runtime_verified = static_runtime_provenance["status"] == "verified"
        shared_runtime_tls_verified = shared_runtime_tls["status"] == "verified"
        artifact_purity_passed = artifact_purity["status"] == "passed"
        link_passed = installed_link_audit["status"] == "passed"
        crt_sysroot_pure_rust = (
            source_passed
            and crt_verified
            and builtins_verified
            and static_runtime_verified
            and shared_runtime_tls_verified
            and artifact_purity_passed
            and link_passed
        )
        full_runtime_pure_rust = crt_sysroot_pure_rust and dependency_passed
        allocator_is_only_remaining_blocker = (
            crt_sysroot_pure_rust
            and dependency_audit.get("status") == "blocked_by_native_allocator"
            and not dependency_audit.get("unapproved_rejected")
        )
        purity: dict[str, object] = {
            "schema": SCHEMA_VERSION,
            "crt_owned": crt_provenance,
            "compiler_helpers": builtins_provenance,
            "static_runtime": static_runtime_provenance,
            "shared_runtime_tls": shared_runtime_tls,
            "startup_objects": {name: installed_artifacts[name] for name in CRT_OBJECTS},
            "runtime_source_languages": source_audit,
            "dependency_purity": dependency_audit,
            "artifact_purity": artifact_purity,
            "external_native_source_inputs": source_audit["rejected_native_sources"],
            "foreign_target_runtime_inputs": installed_link_audit["foreign_target_runtime_inputs"],
            "compiler_runtime_inputs": installed_link_audit["compiler_runtime_inputs"],
            "musl_target_inputs": installed_link_audit["musl_target_inputs"],
            "gcc_target_inputs": installed_link_audit["gcc_target_inputs"],
            "absolute_build_paths": absolute_build_paths,
            "reproducible": {"status": "unverified", "reason": "double-build evidence is owned by compat/sysroot/run.py"},
            "crt_sysroot_pure_rust": crt_sysroot_pure_rust,
            "crt_sysroot_purity_scope": {
                "status": "passed" if crt_sysroot_pure_rust else "rejected",
                "covers": [
                    "Rust CRT source and startup objects",
                    "Rust compiler-helper archive",
                    "compiler-runtime-free static libc archive boundary",
                    "private runtime initial-exec TLS static-root and shared-link audit",
                    "installed archive and ELF member/source audit",
                    "sealed application driver and final-link inputs",
                    "crabc runtime source-language audit",
                ],
                "does_not_claim": [
                    "complete allocator implementation purity while libc retains the documented libmimalloc-sys member",
                ],
            },
            "full_runtime_pure_rust": full_runtime_pure_rust,
            "full_runtime_purity_status": (
                "passed"
                if full_runtime_pure_rust
                else "blocked_by_native_allocator"
                if allocator_is_only_remaining_blocker
                else "rejected"
            ),
            "full_runtime_pure_rust_basis": {
                "source_audit": source_audit["status"],
                "dependency_audit": dependency_audit["status"],
                "crt_provenance": crt_provenance["status"],
                "builtins_provenance": builtins_provenance["status"],
                "static_runtime_provenance": static_runtime_provenance["status"],
                "shared_runtime_tls": shared_runtime_tls["status"],
                "artifact_purity": artifact_purity["status"],
                "link_input_audit": installed_link_audit["status"],
            },
        }
        atomic_json_write(staging / "share/crabc/manifest.json", manifest)
        atomic_json_write(staging / "share/crabc/purity.json", purity)
        os.replace(staging, destination)
    return manifest


def load_installed_manifest(sysroot: Path) -> dict[str, object]:
    paths = installed_paths(sysroot)
    manifest_path = require_regular_file(paths["manifest"], "sysroot manifest")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise SysrootError(f"invalid installed manifest: {manifest_path}") from error
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA_VERSION:
        raise SysrootError("installed manifest must use schema 1")
    if manifest.get("target") != TARGET_TRIPLE or manifest.get("canonical_interpreter") != CANONICAL_INTERPRETER:
        raise SysrootError("installed manifest does not identify the crabc AArch64 sysroot")
    return manifest


def _reject_sealed_driver_overrides(arguments: Sequence[str]) -> None:
    """Reject options that would override the installed driver contract.

    ``build_driver_plan`` puts the sealed compiler and linker selection before
    caller arguments.  Clang's last-option-wins behavior would otherwise let a
    caller replace those selections, so inspect both joined and separate
    option forms before constructing a command.  Keep prefix checks narrow:
    for example, ``-target-feature`` is not a target-triple option.
    """

    for index, argument in enumerate(arguments):
        if argument == "--":
            break

        if (
            argument == "--sysroot"
            or argument.startswith("--sysroot=")
            or argument == "-isysroot"
            or argument.startswith("-isysroot")
        ):
            raise SysrootError("crabc-cc owns the target sysroot; a caller may not replace it")

        if argument in {"--target", "-target"} or argument.startswith("--target=") or argument.startswith("-target="):
            raise SysrootError("crabc-cc owns target selection; a caller may not replace it")

        if argument == "-B" or argument.startswith("-B"):
            raise SysrootError("crabc-cc owns compiler and linker search prefixes; a caller may not replace -B")

        if argument in {"--gcc-toolchain", "-gcc-toolchain"}:
            raise SysrootError("crabc-cc owns the compiler toolchain; a caller may not replace --gcc-toolchain")
        if argument.startswith("--gcc-toolchain=") or argument.startswith("-gcc-toolchain="):
            raise SysrootError("crabc-cc owns the compiler toolchain; a caller may not replace --gcc-toolchain")

        if argument == "-fuse-ld" or argument.startswith("-fuse-ld="):
            raise SysrootError("crabc-cc owns linker selection; a caller may not replace -fuse-ld")

        if argument == "-resource-dir" or argument.startswith("-resource-dir="):
            raise SysrootError("crabc-cc owns the compiler resource directory; a caller may not replace it")

        if argument in {"-rtlib", "--rtlib"} or argument.startswith("-rtlib=") or argument.startswith("--rtlib="):
            raise SysrootError("crabc-cc owns the compiler runtime; a caller may not replace -rtlib")
        if argument in {"-unwindlib", "--unwindlib"} or argument.startswith("-unwindlib=") or argument.startswith("--unwindlib="):
            raise SysrootError("crabc-cc owns the unwind runtime; a caller may not replace -unwindlib")
        if argument == "-moutline-atomics":
            raise SysrootError("crabc-cc disables AArch64 outline atomics; no helper-runtime override is installed")

        # Direct cc1 arguments can bypass the driver's target validation.  The
        # ordinary ``-Xclang`` escape hatch remains available for unrelated
        # frontend controls, but not for target/resource/sysroot selection.
        if argument == "-Xclang" and index + 1 < len(arguments):
            if arguments[index + 1] in {"-isysroot", "-resource-dir", "-target", "-target-feature", "-triple"}:
                raise SysrootError("crabc-cc owns target and toolchain selection; -Xclang may not replace it")

        # `-Xlinker` passes one raw argument through clang's normal driver
        # validation. Keep ordinary application-library selection in the
        # supported direct `-L`/`-l` surface, but do not allow this escape
        # hatch to inject a linker script, foreign sysroot, or secondary
        # target-library search root.
        if argument == "-Xlinker":
            if index + 1 >= len(arguments):
                raise SysrootError("-Xlinker requires one argument")
            linker_argument = arguments[index + 1]
            if (
                linker_argument in {"-L", "--library-path", "-T", "--script", "--sysroot", "-dynamic-linker", "--dynamic-linker", "-rpath-link", "--rpath-link"}
                or linker_argument.startswith(("-L", "--library-path=", "-T", "--script=", "--sysroot=", "-dynamic-linker=", "--dynamic-linker=", "-rpath-link=", "--rpath-link="))
            ):
                raise SysrootError("crabc-cc rejects linker search, script, sysroot, and interpreter overrides through -Xlinker")
        if argument.startswith("-Xlinker="):
            raise SysrootError("crabc-cc accepts no joined -Xlinker escape hatch")


def parse_driver_request(arguments: Sequence[str]) -> DriverRequest:
    args = tuple(arguments)
    print_sysroot = "--print-sysroot" in args
    print_manifest = "--crabc-print-manifest" in args
    print_link_plan = "--crabc-print-link-plan" in args
    special = {"--print-sysroot", "--crabc-print-manifest", "--crabc-print-link-plan"}
    stripped = tuple(argument for argument in args if argument not in special)
    _reject_sealed_driver_overrides(stripped)
    for index, argument in enumerate(stripped):
        if argument == "-Xlinker" and index + 1 < len(stripped) and "dynamic-linker" in stripped[index + 1]:
            raise SysrootError("crabc-cc owns the dynamic interpreter")
        if "dynamic-linker" in argument or argument.startswith("-Wl,-I"):
            raise SysrootError("crabc-cc owns the dynamic interpreter and linker script selection")
        if argument.startswith("-Wl,"):
            linker_arguments = argument[len("-Wl,") :].split(",")
            if any(
                linker_argument in {"-L", "--library-path", "-T", "--script", "--sysroot", "-rpath-link", "--rpath-link"}
                or linker_argument.startswith(("-L", "--library-path=", "-T", "--script=", "--sysroot=", "-rpath-link=", "--rpath-link="))
                for linker_argument in linker_arguments
            ):
                raise SysrootError("crabc-cc rejects linker search, script, sysroot, and rpath-link overrides through -Wl")
    compile_flags = {"-c": LinkMode.COMPILE, "-E": LinkMode.PREPROCESS, "-S": LinkMode.ASSEMBLY}
    selected_compile = [mode for flag, mode in compile_flags.items() if flag in stripped]
    if len(set(selected_compile)) > 1:
        raise SysrootError("compile-only modes -c, -E, and -S are mutually exclusive")
    if selected_compile:
        mode = selected_compile[0]
    elif "-r" in stripped:
        mode = LinkMode.RELOCATABLE
    elif "-shared" in stripped:
        mode = LinkMode.SHARED
    elif "-static-pie" in stripped:
        mode = LinkMode.STATIC_PIE
    elif "-static" in stripped:
        mode = LinkMode.STATIC_EXECUTABLE
    elif "-no-pie" in stripped:
        mode = LinkMode.DYNAMIC_EXECUTABLE
    else:
        mode = LinkMode.DYNAMIC_PIE
    if mode in {LinkMode.COMPILE, LinkMode.PREPROCESS, LinkMode.ASSEMBLY} and ("-shared" in stripped or "-r" in stripped):
        raise SysrootError("link-mode flags cannot accompany a compile-only request")
    return DriverRequest(
        mode=mode,
        user_arguments=stripped,
        omit_startfiles="-nostdlib" in stripped or "-nostartfiles" in stripped,
        omit_default_libraries="-nostdlib" in stripped or "-nodefaultlibs" in stripped,
        print_sysroot=print_sysroot,
        print_manifest=print_manifest,
        print_link_plan=print_link_plan,
    )


def _compiler_from_configuration(configuration: DriverConfiguration) -> Path:
    override = os.environ.get("CRABC_CLANG")
    if override is not None and (not override or any(character.isspace() for character in override)):
        raise SysrootError("CRABC_CLANG must name one executable path, without shell words")
    return require_tool(override or configuration.clang, "configured clang")


def _linker_from_configuration(configuration: DriverConfiguration) -> Path:
    override = os.environ.get("CRABC_LLD")
    if override is not None and (not override or any(character.isspace() for character in override)):
        raise SysrootError("CRABC_LLD must name one executable path, without shell words")
    return require_tool(override or configuration.lld, "configured ld.lld")


def _resource_include(clang: Path, environment: Mapping[str, str]) -> Path:
    resource = Path(command_output((str(clang), "-print-resource-dir"), environment=environment))
    return require_directory(resource / "include", "clang resource include directory")


def _existing_runtime(sysroot: Path, name: str) -> Path:
    path = installed_runtime_paths(sysroot)[name]
    return require_regular_file(path, f"installed runtime input {name}")


def _application_paths(arguments: Sequence[str]) -> set[Path]:
    paths: set[Path] = set()
    consume_next = False
    for argument in arguments:
        if consume_next:
            consume_next = False
            continue
        if argument in {"-o", "-I", "-isystem", "-L", "-include", "-D", "-U", "-Xlinker"}:
            consume_next = True
            continue
        candidate = Path(argument)
        if not argument.startswith("-") and candidate.exists() and candidate.is_file():
            paths.add(candidate.resolve())
    return paths


def application_library_roots(arguments: Sequence[str]) -> set[Path]:
    """Identify explicit application library directories without ambient fallthrough."""

    roots: set[Path] = set()
    consume_next = False
    for argument in arguments:
        if consume_next:
            consume_next = False
            candidate = Path(argument)
            if candidate.is_dir():
                roots.add(candidate.resolve())
            continue
        if argument == "-L":
            consume_next = True
            continue
        if argument.startswith("-L") and len(argument) > 2:
            candidate = Path(argument[2:])
            if candidate.is_dir():
                roots.add(candidate.resolve())
    return roots


def build_driver_plan(sysroot: Path, request: DriverRequest, *, clang: Path, lld: Path, resource_include: Path) -> LinkPlan:
    root = require_directory(sysroot, "sysroot")
    paths = installed_paths(root)
    include_dir = require_directory(paths["include"], "installed public include directory")
    compiler_prefix = [
        str(clang),
        f"--target={TARGET_TRIPLE}",
        # The installed helper archive deliberately does not provide the
        # AArch64 outline-atomic ABI. Keep ordinary C links on inline LL/SC
        # sequences unless crabc later ships and proves that separate runtime.
        "-mno-outline-atomics",
        "-nostdinc",
        "-isystem",
        str(include_dir),
        "-isystem",
        str(resource_include),
    ]
    if request.mode in {LinkMode.COMPILE, LinkMode.PREPROCESS, LinkMode.ASSEMBLY}:
        return LinkPlan(request.mode, tuple(compiler_prefix + list(request.user_arguments)), (), (), (), None, ())
    base = compiler_prefix + ["-fuse-ld=lld", "-nostdlib", f"-B{lld.parent}"]
    startup: list[Path] = []
    end: list[Path] = []
    library_search: list[str] = []
    libraries: list[str] = []
    interpreter: str | None = None
    mode_arguments: list[str] = []
    if request.mode == LinkMode.RELOCATABLE:
        mode_arguments.append("-r")
    elif request.mode == LinkMode.SHARED:
        mode_arguments.extend(["-shared", "-fPIC"])
        if not request.omit_startfiles:
            startup.append(_existing_runtime(root, "crti.o"))
            end.append(_existing_runtime(root, "crtn.o"))
    else:
        if request.mode == LinkMode.DYNAMIC_PIE:
            mode_arguments.extend(["-pie", f"-Wl,--dynamic-linker,{CANONICAL_INTERPRETER}"])
            interpreter = CANONICAL_INTERPRETER
            crt = "Scrt1.o"
        elif request.mode == LinkMode.DYNAMIC_EXECUTABLE:
            mode_arguments.extend(["-no-pie", f"-Wl,--dynamic-linker,{CANONICAL_INTERPRETER}"])
            interpreter = CANONICAL_INTERPRETER
            crt = "crt1.o"
        elif request.mode == LinkMode.STATIC_EXECUTABLE:
            mode_arguments.extend(["-static", "-no-pie"])
            crt = "crt1.o"
        elif request.mode == LinkMode.STATIC_PIE:
            mode_arguments.extend(["-static-pie", "-pie"])
            crt = "rcrt1.o"
        else:
            raise AssertionError(f"unexpected link mode: {request.mode}")
        if not request.omit_startfiles:
            startup.extend((_existing_runtime(root, crt), _existing_runtime(root, "crti.o")))
            end.append(_existing_runtime(root, "crtn.o"))
    if request.mode not in {LinkMode.RELOCATABLE, LinkMode.SHARED} and not request.omit_default_libraries:
        # Put the owned library root before caller-supplied `-L` paths. This
        # keeps an ordinary redundant `-lc` from silently selecting an
        # application-directory libc while still allowing application DSOs
        # such as `-lfoo` to resolve from their explicit search directories.
        library_search = ["-L", str(paths["usr_lib"])]
        libraries = ["-lc", "-l:libcrabc-builtins.a"]
    security = [] if request.mode == LinkMode.RELOCATABLE else ["-Wl,-z,relro", "-Wl,-z,now", "-Wl,-z,noexecstack"]
    default_libraries = tuple(library_search + libraries)
    command = tuple(
        base
        + mode_arguments
        + security
        + [str(item) for item in startup]
        + library_search
        + list(request.user_arguments)
        + libraries
        + [str(item) for item in end]
    )
    app_paths = _application_paths(request.user_arguments)
    link_inputs = tuple(
        [classify_link_path(item, root, app_paths) for item in (*startup, *end)]
        + [LinkInput(str(clang), "host tool", "configured compiler frontend"), LinkInput(str(lld), "host tool", "configured linker")]
        + [LinkInput(str(resource_include), "compiler intrinsic header/declaration", "clang resource include directory")]
    )
    return LinkPlan(request.mode, command, tuple(startup), tuple(end), default_libraries, interpreter, link_inputs)


def installed_driver_main(sysroot: Path, arguments: Sequence[str]) -> int:
    """Entry point used only by the installed relocatable ``crabc-cc`` wrapper."""

    root = require_directory(sysroot, "wrapper sysroot")
    manifest = load_installed_manifest(root)
    request = parse_driver_request(arguments)
    if request.print_sysroot:
        print(root)
        return 0
    if request.print_manifest:
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0
    configuration = DriverConfiguration.from_manifest(manifest)
    sealed = seal_environment()
    clang = _compiler_from_configuration(configuration)
    lld = _linker_from_configuration(configuration)
    resource_include = _resource_include(clang, sealed)
    plan = build_driver_plan(root, request, clang=clang, lld=lld, resource_include=resource_include)
    if request.print_link_plan:
        print(json.dumps(plan.record(), indent=2, sort_keys=True))
        return 0
    result = run_command(plan.command, environment=sealed)
    if result.stdout:
        sys.stdout.buffer.write(result.stdout)
    if result.stderr:
        sys.stderr.buffer.write(result.stderr)
    return int(result.status) if isinstance(result.status, int) else 1


def _assemble_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser("assemble", help="assemble a new owned sysroot from explicit Rust artifacts")
    parser.add_argument("--output", type=Path, required=True, help="new sysroot destination; it must not already exist")
    parser.add_argument("--include-dir", type=Path, required=True)
    parser.add_argument("--libc-shared", type=Path, required=True)
    parser.add_argument("--libc-static", type=Path, required=True)
    parser.add_argument("--libc-static-provenance", type=Path)
    parser.add_argument("--libc-static-commands", type=Path)
    parser.add_argument("--loader", type=Path, required=True)
    parser.add_argument("--crt-dir", type=Path, required=True)
    parser.add_argument("--builtins", type=Path, required=True)
    parser.add_argument("--builtins-provenance", type=Path)
    parser.add_argument("--builtins-commands", type=Path)
    parser.add_argument("--crt-provenance", type=Path)
    parser.add_argument("--crt-commands", type=Path)
    parser.add_argument("--clang", default=os.environ.get("CRABC_SYSROOT_CLANG", "clang"))
    parser.add_argument("--lld", default=os.environ.get("CRABC_SYSROOT_LLD", "ld.lld"))
    parser.add_argument("--runtime-source-root", action="append", type=Path, default=[])
    parser.add_argument("--cargo-manifest", action="append", type=Path, default=[])
    parser.add_argument(
        "--cargo-metadata",
        type=Path,
        action="append",
        default=[],
        help="locked Cargo metadata JSON for the complete selected target dependency closure",
    )


def _audit_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser("audit", help="audit an installed sysroot's artifacts and purity evidence")
    parser.add_argument("--sysroot", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)


def parse_args(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    _assemble_parser(subparsers)
    _audit_parser(subparsers)
    return parser.parse_args(arguments)


def audit_installed_sysroot(sysroot: Path) -> dict[str, object]:
    root = require_directory(sysroot, "installed sysroot")
    manifest = load_installed_manifest(root)
    runtime_paths = installed_runtime_paths(root)
    artifacts = artifact_records(runtime_paths, relative_to=root)
    link_audit = audit_link_inputs(list(runtime_paths.values()), root)
    purity_path = require_regular_file(root / "share/crabc/purity.json", "installed purity report")
    try:
        installed_purity = json.loads(purity_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise SysrootError(f"invalid installed purity report: {purity_path}") from error
    static_runtime = installed_purity.get("static_runtime") if isinstance(installed_purity, dict) else None
    artifact_purity = audit_runtime_artifacts(artifacts, static_runtime if isinstance(static_runtime, dict) else {})
    return {
        "schema": SCHEMA_VERSION,
        "sysroot": str(root),
        "manifest": manifest,
        "artifacts": artifacts,
        "runtime_artifact_purity": artifact_purity,
        "link_input_audit": link_audit,
        "shared_runtime_tls": audit_shared_runtime_tls(runtime_paths["libc.so"]),
        "generated_at_unix_seconds": int(time.time()),
    }


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(arguments)
    try:
        if args.command == "assemble":
            inputs = RuntimeInputs(
                include_dir=args.include_dir,
                libc_shared=args.libc_shared,
                libc_static=args.libc_static,
                loader=args.loader,
                crt_dir=args.crt_dir,
                builtins=args.builtins,
                crt_provenance=args.crt_provenance,
                crt_commands=args.crt_commands,
                builtins_provenance=args.builtins_provenance,
                builtins_commands=args.builtins_commands,
                libc_static_provenance=args.libc_static_provenance,
                libc_static_commands=args.libc_static_commands,
            )
            toolchain = discover_toolchain(args.clang, args.lld)
            manifest = assemble_sysroot(
                args.output,
                inputs,
                toolchain,
                source_roots=args.runtime_source_root,
                cargo_manifests=args.cargo_manifest,
                cargo_metadata=args.cargo_metadata,
            )
            print(json.dumps(manifest, indent=2, sort_keys=True))
            return 0
        if args.command == "audit":
            report = audit_installed_sysroot(args.sysroot)
            atomic_json_write(args.report, report)
            print(args.report)
            return 0
        raise AssertionError(f"unknown command: {args.command}")
    except SysrootError as error:
        print(f"crabc-sysroot: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
