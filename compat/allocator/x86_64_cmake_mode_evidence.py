#!/usr/bin/env python3
"""Prove one pinned native x86-64 CMake configure/build/install profile.

This private oracle lane configures exactly one Linux/x86-64 normal-release
shared-library profile from the pinned mimalloc archive, builds and installs
it, then records the source-bound cache selection, compiler mode, installed
public-header bytes, and installed shared-object ELF identity.  It deliberately
does not execute a consumer, test allocator behavior, or claim Rust/public x86
runtime support.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shlex
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "compat/allocator/run.py"
SCHEMA_PATH = ROOT / "compat/allocator/x86_64-cmake-mode-evidence-v3.5.0.json"
SOURCE_LEDGER_PATH = ROOT / "compat/allocator/x86_64-api-coverage-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/cmake-mode-evidence.json"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class EvidenceError(RuntimeError):
    """The bounded native CMake mode evidence failed."""


TARGET = {
    "architecture": "x86_64",
    "endianness": "little",
    "system": "linux",
    "rust_target": "x86_64-unknown-linux-musl",
}
UPSTREAM = {
    "version": "3.5.0",
    "archive_root": "mimalloc-3.5.0",
    "revision": "18b08671c9302247bfb682286e6bf3cc1773f801",
    "archive_sha256": "1e432f0559a4ab512143b9bff7a700541a2c8d4712b26a72de3e0222790da305",
}
PROFILE = "linux-x86_64-pinned-mimalloc-cmake-normal-release-shared"
ROOT_CMAKE = {
    "bytes": 46629,
    "member": "CMakeLists.txt",
    "sha256": "9b38dd30d4c503ffbef7c809dab3642b563adca9633615134902ce3a503fe4fd",
}
TEST_CMAKE = {
    "bytes": 2182,
    "member": "test/CMakeLists.txt",
    "sha256": "50b19c62f11f9cda88d1434bbd412c3948aff5ee439ff6e2ca4f8d77e8e8826d",
}
INSTALLED_PUBLIC_HEADERS = (
    "include/mimalloc.h",
    "include/mimalloc-override.h",
    "include/mimalloc-new-delete.h",
    "include/mimalloc-stats.h",
)
INSTALLED_HEADER_RECORDS = {
    "include/mimalloc.h": {
        "bytes": 49389,
        "sha256": "af34f215cb6fe9e4e97bf08d78bfda877ab4cdd63c9222640c483d7d6a4488a5",
    },
    "include/mimalloc-override.h": {
        "bytes": 3094,
        "sha256": "21fcf61c4443341ac6bf6ea528af31dc7267e8e3456fc64bfd07704503032175",
    },
    "include/mimalloc-new-delete.h": {
        "bytes": 4044,
        "sha256": "1bc31e20fb0340d9d071c69eaac2f07d0dfe4cdf95849ed8d91fb2bd7538d55b",
    },
    "include/mimalloc-stats.h": {
        "bytes": 7489,
        "sha256": "7bc3c522d9a5203b27464179177845f3c09eea4453b82545d20ce61a711a9a1e",
    },
}
SELECTED_MODE_DECLARATIONS = (
    {"name": "MI_SECURE", "source_line": 7, "value": "OFF"},
    {"name": "MI_OVERRIDE", "source_line": 10, "value": "ON"},
    {"name": "MI_GUARDED", "source_line": 13, "value": "OFF"},
    {"name": "MI_USE_CXX", "source_line": 14, "value": "OFF"},
    {"name": "MI_OPT_ARCH", "source_line": 15, "value": "OFF"},
    {"name": "MI_OPT_SIMD", "source_line": 16, "value": "OFF"},
    {"name": "MI_DEBUG", "source_line": 21, "value": "OFF"},
    {"name": "MI_TRACK", "source_line": 24, "value": "OFF"},
    {"name": "MI_BUILD_SHARED", "source_line": 30, "value": "ON"},
    {"name": "MI_BUILD_STATIC", "source_line": 31, "value": "OFF"},
    {"name": "MI_BUILD_OBJECT", "source_line": 32, "value": "OFF"},
    {"name": "MI_BUILD_TESTS", "source_line": 33, "value": "OFF"},
    {"name": "MI_LIBC_MUSL", "source_line": 39, "value": "ON"},
    {"name": "MI_INSTALL_TOPLEVEL", "source_line": 42, "value": "ON"},
)
CACHE_VALUES = {
    "CMAKE_BUILD_TYPE": "Release",
    "MI_SECURE": "OFF",
    "MI_OVERRIDE": "ON",
    "MI_GUARDED": "OFF",
    "MI_USE_CXX": "OFF",
    "MI_OPT_ARCH": "OFF",
    "MI_OPT_SIMD": "OFF",
    "MI_DEBUG": "OFF",
    "MI_TRACK": "OFF",
    "MI_BUILD_SHARED": "ON",
    "MI_BUILD_STATIC": "OFF",
    "MI_BUILD_OBJECT": "OFF",
    "MI_BUILD_TESTS": "OFF",
    "MI_LIBC_MUSL": "ON",
    "MI_INSTALL_TOPLEVEL": "ON",
}
COMPILE_MODE = {
    "definitions": [
        "-DMI_BUILD_RELEASE",
        "-DMI_CMAKE_BUILD_TYPE=release",
        "-DMI_LIBC_MUSL=1",
        "-DMI_SHARED_LIB",
        "-DMI_SHARED_LIB_EXPORT",
    ],
    "flags": ["-ftls-model=initial-exec"],
    "source_member": "src/alloc.c",
}
SCOPE = {
    "aarch64_status_reused": False,
    "behavior_claimed": False,
    "cmake_configure_build_install_claimed": True,
    "consumer_compile_link_claimed": False,
    "consumer_execution_claimed": False,
    "emulation_accepted": False,
    "native_linux_x86_64_required": True,
    "public_crabc_support": False,
    "public_x86_libc_or_ldso_support": False,
    "rust_implementation_claimed": False,
    "static_or_object_cmake_mode_claimed": False,
}
EXPECTED_ELF = {
    "class": "ELF64",
    "endianness": "little",
    "machine": "Advanced Micro Devices X86-64",
}


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


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_schema(path: Path | None = None) -> dict[str, Any]:
    """Load the exact selected CMake profile rather than a generic mode set."""

    path = SCHEMA_PATH if path is None else path
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read x86-64 CMake mode evidence schema") from error
    expected_source = {
        "installed_header_records": INSTALLED_HEADER_RECORDS,
        "installed_public_headers": list(INSTALLED_PUBLIC_HEADERS),
        "root_cmake": ROOT_CMAKE,
        "selected_mode_declarations": list(SELECTED_MODE_DECLARATIONS),
        "test_cmake": TEST_CMAKE,
    }
    expected_configuration = {
        "cache_values": CACHE_VALUES,
        "compile_mode": COMPILE_MODE,
        "generator": "Unix Makefiles",
    }
    expected_fields = {
        "configuration",
        "format",
        "profile",
        "schema",
        "scope",
        "source",
        "target",
        "upstream",
    }
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise EvidenceError("CMake mode evidence schema fields drifted")
    if type(value["format"]) is not int or value["format"] != 1:
        raise EvidenceError("unsupported CMake mode evidence format")
    if value["schema"] != "crabc-mimalloc-x86_64-cmake-mode-evidence":
        raise EvidenceError("unsupported CMake mode evidence schema")
    if value["profile"] != PROFILE or not exactly_matches(value["target"], TARGET):
        raise EvidenceError("CMake mode target or profile drifted")
    if not exactly_matches(value["upstream"], UPSTREAM) or not exactly_matches(value["scope"], SCOPE):
        raise EvidenceError("CMake mode upstream or scope drifted")
    if not exactly_matches(value["source"], expected_source):
        raise EvidenceError("CMake mode source boundary drifted")
    if not exactly_matches(value["configuration"], expected_configuration):
        raise EvidenceError("CMake mode configuration selection drifted")
    return value


def require_native_x86_64() -> dict[str, str]:
    try:
        return run.require_native_x86_64()
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def normalize_command(command: Sequence[str], temporary: Path, source: Path | None) -> list[str]:
    """Erase only ephemeral paths while preserving the exact command shape."""

    normalized: list[str] = []
    temporary_text = str(temporary)
    source_text = str(source) if source is not None else None
    for item in command:
        value = item
        if source_text is not None:
            value = value.replace(source_text, NORMALIZED_PINNED_SOURCE)
        value = value.replace(temporary_text, NORMALIZED_EVIDENCE_ROOT)
        normalized.append(value)
    return normalized


def configure_command(
    cmake: str, compiler: str, source: Path, build: Path, prefix: Path
) -> list[str]:
    command = [
        cmake,
        "-S",
        str(source),
        "-B",
        str(build),
        "-G",
        "Unix Makefiles",
        f"-DCMAKE_C_COMPILER={compiler}",
        f"-DCMAKE_BUILD_TYPE={CACHE_VALUES['CMAKE_BUILD_TYPE']}",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        f"-DCMAKE_INSTALL_PREFIX={prefix}",
    ]
    command.extend(
        f"-D{name}={value}"
        for name, value in CACHE_VALUES.items()
        if name != "CMAKE_BUILD_TYPE"
    )
    return command


def build_command(cmake: str, build: Path) -> list[str]:
    return [cmake, "--build", str(build), "--parallel"]


def install_command(cmake: str, build: Path) -> list[str]:
    return [cmake, "--install", str(build)]


def validate_normalized_configure_command(command: object) -> None:
    if not isinstance(command, list) or not command or not all(isinstance(item, str) for item in command):
        raise EvidenceError("CMake configure command is malformed")
    expected = configure_command(
        "cmake",
        "musl-gcc",
        Path(NORMALIZED_PINNED_SOURCE),
        Path(NORMALIZED_EVIDENCE_ROOT) / "build",
        Path(NORMALIZED_EVIDENCE_ROOT) / "install",
    )
    if Path(command[0]).name != "cmake" or len(command) != len(expected):
        raise EvidenceError("CMake configure command tool or length drifted")
    compiler_index = expected.index("-DCMAKE_C_COMPILER=musl-gcc")
    if command[1:compiler_index] != expected[1:compiler_index] or command[compiler_index + 1 :] != expected[compiler_index + 1 :]:
        raise EvidenceError("CMake configure command selection drifted")
    compiler_argument = command[compiler_index]
    prefix = "-DCMAKE_C_COMPILER="
    if not compiler_argument.startswith(prefix) or Path(compiler_argument.removeprefix(prefix)).name != "musl-gcc":
        raise EvidenceError("CMake configure command compiler drifted")


def validate_normalized_build_command(command: object) -> None:
    expected = ["cmake", "--build", f"{NORMALIZED_EVIDENCE_ROOT}/build", "--parallel"]
    if not isinstance(command, list) or len(command) != len(expected) or Path(command[0]).name != "cmake" or command[1:] != expected[1:]:
        raise EvidenceError("CMake build command drifted")


def validate_normalized_install_command(command: object) -> None:
    expected = ["cmake", "--install", f"{NORMALIZED_EVIDENCE_ROOT}/build"]
    if not isinstance(command, list) or len(command) != len(expected) or Path(command[0]).name != "cmake" or command[1:] != expected[1:]:
        raise EvidenceError("CMake install command drifted")


def command(args: Sequence[str], cwd: Path, description: str) -> dict[str, Any]:
    try:
        record = run.command_record(args, cwd=cwd)
        run.require_success(record, description)
        return record
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def parse_cache(path: Path) -> dict[str, str]:
    try:
        contents = path.read_text(encoding="utf-8")
    except OSError as error:
        raise EvidenceError("CMake configure did not produce CMakeCache.txt") from error
    values: dict[str, str] = {}
    for line in contents.splitlines():
        match = re.fullmatch(r"([^:#=]+):[^=]*=(.*)", line)
        if match is not None:
            values[match.group(1)] = match.group(2)
    return values


def selected_cache_values(cache: Mapping[str, str]) -> dict[str, str]:
    observed: dict[str, str] = {}
    for name, expected in CACHE_VALUES.items():
        value = cache.get(name)
        if value != expected:
            raise EvidenceError(f"CMake cache selection drifted for {name}: expected {expected!r}, got {value!r}")
        observed[name] = value
    return observed


def selected_compile_mode(path: Path) -> dict[str, Any]:
    try:
        entries = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("CMake configure did not produce compile_commands.json") from error
    if not isinstance(entries, list):
        raise EvidenceError("CMake compile database is not a list")
    member = COMPILE_MODE["source_member"]
    command_line: list[str] | None = None
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("file"), str):
            continue
        if entry["file"].replace("\\", "/").endswith(member):
            if isinstance(entry.get("arguments"), list) and all(isinstance(item, str) for item in entry["arguments"]):
                command_line = list(entry["arguments"])
            elif isinstance(entry.get("command"), str):
                command_line = shlex.split(entry["command"])
            break
    if command_line is None:
        raise EvidenceError("CMake compile database lacks the selected alloc.c compilation")
    definitions = set(item for item in command_line if item.startswith("-D"))
    flags = set(command_line)
    missing_definitions = set(COMPILE_MODE["definitions"]) - definitions
    missing_flags = set(COMPILE_MODE["flags"]) - flags
    if missing_definitions or missing_flags:
        raise EvidenceError("CMake selected compiler mode differs from the fixed shared profile")
    return {
        "definitions": list(COMPILE_MODE["definitions"]),
        "flags": list(COMPILE_MODE["flags"]),
        "source_member": member,
    }


def parse_dynamic_section(readelf: str, artifact: Path, cwd: Path) -> tuple[str, list[str]]:
    record = command((readelf, "-d", str(artifact)), cwd, "installed shared library dynamic-section inspection")
    output = str(record["stdout"])
    sonames = re.findall(r"\(SONAME\).*?\[([^]]+)\]", output)
    if len(sonames) != 1 or sonames[0] != "libmimalloc.so.3":
        raise EvidenceError("installed shared library SONAME drifted")
    needed = sorted(set(re.findall(r"\(NEEDED\).*?\[([^]]+)\]", output)))
    return sonames[0], needed


def shared_library_record(readelf: str, prefix: Path, cwd: Path) -> dict[str, Any]:
    candidates = sorted(
        path
        for path in prefix.rglob("libmimalloc.so.*")
        if path.is_file() and not path.is_symlink()
    )
    if len(candidates) != 1:
        raise EvidenceError("installed CMake profile did not produce one real shared mimalloc library")
    artifact = candidates[0]
    header = command((readelf, "-h", str(artifact)), cwd, "installed shared library ELF inspection")
    try:
        elf = run.parse_elf_identity(str(header["stdout"]), "x86_64")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    soname, needed = parse_dynamic_section(readelf, artifact, cwd)
    return {
        "bytes": artifact.stat().st_size,
        "elf": elf,
        "needed": needed,
        "path": artifact.relative_to(prefix).as_posix(),
        "sha256": sha256_bytes(artifact.read_bytes()),
        "soname": soname,
    }


def installed_manifest(build: Path, prefix: Path) -> list[str]:
    manifest = build / "install_manifest.txt"
    try:
        paths = [line for line in manifest.read_text(encoding="utf-8").splitlines() if line]
    except OSError as error:
        raise EvidenceError("CMake install did not produce install_manifest.txt") from error
    relative: list[str] = []
    for item in paths:
        try:
            # Keep the manifest's lexical entry.  CMake records the real shared
            # object and its SONAME/linker-name symlinks separately; resolving
            # those entries would collapse valid installed links into one path.
            relative_path = Path(item).relative_to(prefix)
        except ValueError as error:
            raise EvidenceError("CMake install manifest escapes its temporary prefix") from error
        if not relative_path.parts or ".." in relative_path.parts:
            raise EvidenceError("CMake install manifest escapes its temporary prefix")
        installed = prefix / relative_path
        if not installed.is_file() and not installed.is_symlink():
            raise EvidenceError("CMake install manifest names a missing installed entry")
        relative.append(relative_path.as_posix())
    if not relative or len(relative) != len(set(relative)):
        raise EvidenceError("CMake install manifest is empty or has duplicate entries")
    return sorted(relative)


def installed_headers(prefix: Path, schema: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    observed: dict[str, dict[str, Any]] = {}
    expected_records = schema["source"]["installed_header_records"]
    for member in schema["source"]["installed_public_headers"]:
        path = prefix / member
        try:
            contents = path.read_bytes()
        except OSError as error:
            raise EvidenceError(f"CMake install lacks public header {member}") from error
        record = {"bytes": len(contents), "sha256": sha256_bytes(contents)}
        if not exactly_matches(record, expected_records[member]):
            raise EvidenceError(f"CMake installed header bytes drifted: {member}")
        observed[member] = record
    return observed


def validate_source_boundary(schema: Mapping[str, Any], source: Path) -> None:
    for record in (schema["source"]["root_cmake"], schema["source"]["test_cmake"]):
        path = source / record["member"]
        if (
            not path.is_file()
            or path.stat().st_size != record["bytes"]
            or sha256_bytes(path.read_bytes()) != record["sha256"]
        ):
            raise EvidenceError(f"pinned CMake source hash drifted: {record['member']}")
    for member, expected in schema["source"]["installed_header_records"].items():
        path = source / member
        if not path.is_file() or not exactly_matches(
            {"bytes": path.stat().st_size, "sha256": sha256_bytes(path.read_bytes())}, expected
        ):
            raise EvidenceError(f"pinned public header source hash drifted: {member}")
    try:
        ledger = json.loads(SOURCE_LEDGER_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read the target-local x86 CMake source ledger") from error
    source_ledger = ledger.get("source")
    if not isinstance(source_ledger, dict) or source_ledger.get("root_cmake") != schema["source"]["root_cmake"]:
        raise EvidenceError("x86 source ledger root CMake identity drifted")
    test_members = source_ledger.get("test_members")
    if not isinstance(test_members, list) or schema["source"]["test_cmake"] not in test_members:
        raise EvidenceError("x86 source ledger test CMake identity drifted")
    header_surfaces = ledger.get("header_surfaces")
    if not isinstance(header_surfaces, list):
        raise EvidenceError("x86 source ledger public-header surfaces are invalid")
    header_records = {
        entry.get("member"): entry.get("source")
        for entry in header_surfaces
        if isinstance(entry, dict)
    }
    for member, expected in schema["source"]["installed_header_records"].items():
        if not isinstance(header_records.get(member), dict) or header_records[member].get("sha256") != expected["sha256"]:
            raise EvidenceError(f"x86 source ledger installed header identity drifted: {member}")
    modes = ledger.get("build_mode_declarations")
    if not isinstance(modes, dict) or not isinstance(modes.get("declarations"), list):
        raise EvidenceError("x86 source ledger mode declarations are invalid")
    declared_lines = {
        entry.get("name"): entry.get("source_line")
        for entry in modes["declarations"]
        if isinstance(entry, dict)
    }
    for selected in schema["source"]["selected_mode_declarations"]:
        if declared_lines.get(selected["name"]) != selected["source_line"]:
            raise EvidenceError(f"x86 source ledger selected CMake declaration drifted: {selected['name']}")


def report_from_results(
    *,
    schema: Mapping[str, Any],
    provenance: Mapping[str, str],
    configuration: Mapping[str, Any],
    build: Mapping[str, Any],
    install: Mapping[str, Any],
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "build": dict(build),
        "configuration": dict(configuration),
        "format": 1,
        "install": dict(install),
        "profile": schema["profile"],
        "provenance": dict(provenance),
        "schema": schema["schema"],
        "scope": schema["scope"],
        "source": schema["source"],
        "status": "passed",
        "target": schema["target"],
        "upstream": schema["upstream"],
    }
    validate_report(report)
    return report


def validate_report(report: Mapping[str, Any]) -> None:
    required = {
        "build",
        "configuration",
        "format",
        "install",
        "profile",
        "provenance",
        "schema",
        "scope",
        "source",
        "status",
        "target",
        "upstream",
    }
    if not isinstance(report, dict) or set(report) != required:
        raise EvidenceError("CMake mode report fields drifted")
    if type(report["format"]) is not int or report["format"] != 1 or report["status"] != "passed":
        raise EvidenceError("CMake mode report must be a passing format-1 result")
    if report["schema"] != "crabc-mimalloc-x86_64-cmake-mode-evidence" or report["profile"] != PROFILE:
        raise EvidenceError("CMake mode report identity drifted")
    if not exactly_matches(report["target"], TARGET) or not exactly_matches(report["upstream"], UPSTREAM):
        raise EvidenceError("CMake mode report target or upstream drifted")
    if not exactly_matches(report["scope"], SCOPE):
        raise EvidenceError("CMake mode report scope drifted")
    if not any(
        exactly_matches(report["provenance"], candidate)
        for candidate in (
            {"execution_mode": "native", "host_architecture": "x86_64"},
            {"execution_mode": "native", "host_architecture": "amd64"},
        )
    ):
        raise EvidenceError("CMake mode report lacks native x86-64 provenance")
    schema = load_schema()
    if not exactly_matches(report["source"], schema["source"]):
        raise EvidenceError("CMake mode report source boundary drifted")
    configuration = report["configuration"]
    if not isinstance(configuration, dict) or set(configuration) != {"cache_values", "command", "compile_mode", "status"}:
        raise EvidenceError("CMake mode report configuration record drifted")
    if configuration["status"] != "passed" or not exactly_matches(configuration["cache_values"], CACHE_VALUES) or not exactly_matches(configuration["compile_mode"], COMPILE_MODE):
        raise EvidenceError("CMake mode report selected configuration drifted")
    validate_normalized_configure_command(configuration["command"])
    build = report["build"]
    if not isinstance(build, dict) or set(build) != {"command", "shared_library", "status"} or build["status"] != "passed":
        raise EvidenceError("CMake mode report build record drifted")
    validate_normalized_build_command(build["command"])
    shared = build["shared_library"]
    if not isinstance(shared, dict) or set(shared) != {"bytes", "elf", "needed", "path", "sha256", "soname"}:
        raise EvidenceError("CMake mode report shared-library record drifted")
    if type(shared["bytes"]) is not int or shared["bytes"] <= 0 or not exactly_matches(shared["elf"], EXPECTED_ELF):
        raise EvidenceError("CMake mode report shared-library identity drifted")
    if not isinstance(shared["path"], str) or shared["path"].startswith("/") or ".." in Path(shared["path"]).parts:
        raise EvidenceError("CMake mode report shared-library path drifted")
    if not re.fullmatch(r"[0-9a-f]{64}", str(shared["sha256"])) or shared["soname"] != "libmimalloc.so.3":
        raise EvidenceError("CMake mode report shared-library metadata drifted")
    if not isinstance(shared["needed"], list) or shared["needed"] != sorted(set(shared["needed"])) or not all(isinstance(name, str) for name in shared["needed"]):
        raise EvidenceError("CMake mode report shared-library dependencies drifted")
    install = report["install"]
    if not isinstance(install, dict) or set(install) != {"command", "headers", "manifest", "status"} or install["status"] != "passed":
        raise EvidenceError("CMake mode report install record drifted")
    validate_normalized_install_command(install["command"])
    if not exactly_matches(install["headers"], INSTALLED_HEADER_RECORDS):
        raise EvidenceError("CMake mode report installed headers drifted")
    manifest = install["manifest"]
    if not isinstance(manifest, list) or not manifest or manifest != sorted(set(manifest)) or not all(isinstance(item, str) and not item.startswith("/") and ".." not in Path(item).parts for item in manifest):
        raise EvidenceError("CMake mode report install manifest drifted")
    if not set(INSTALLED_PUBLIC_HEADERS).issubset(manifest):
        raise EvidenceError("CMake mode report install manifest lacks public headers")
    if shared["path"] not in manifest:
        raise EvidenceError("CMake mode report install manifest lacks the installed shared library")


def run_evidence(*, offline: bool, report_path: Path) -> dict[str, Any]:
    schema = load_schema()
    provenance = require_native_x86_64()
    try:
        pin = run.load_pin()
        archive = run.fetch_archive(pin, offline)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    observed_upstream = {
        "version": pin["version"],
        "archive_root": pin["archive_root"],
        "revision": pin["revision"],
        "archive_sha256": pin["sha256"],
    }
    if not exactly_matches(observed_upstream, UPSTREAM):
        raise EvidenceError("CMake mode repository pin disagrees with schema")
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86-cmake-") as temporary_name:
        temporary = Path(temporary_name)
        try:
            source = run.safe_extract(archive, temporary / "source", pin["archive_root"])
            cmake = run.require_tool("cmake")
            compiler = run.require_tool("musl-gcc")
            readelf = run.require_tool("readelf")
        except run.HarnessError as error:
            raise EvidenceError(str(error)) from error
        validate_source_boundary(schema, source)
        build = temporary / "build"
        prefix = temporary / "install"
        configure = configure_command(cmake, compiler, source, build, prefix)
        command(configure, temporary, "pinned CMake normal-release configure")
        cache_values = selected_cache_values(parse_cache(build / "CMakeCache.txt"))
        compile_mode = selected_compile_mode(build / "compile_commands.json")
        build_args = build_command(cmake, build)
        command(build_args, temporary, "pinned CMake normal-release build")
        install_args = install_command(cmake, build)
        command(install_args, temporary, "pinned CMake normal-release install")
        headers = installed_headers(prefix, schema)
        manifest = installed_manifest(build, prefix)
        shared = shared_library_record(readelf, prefix, temporary)
        report = report_from_results(
            schema=schema,
            provenance=provenance,
            configuration={
                "command": normalize_command(configure, temporary, source),
                "cache_values": cache_values,
                "compile_mode": compile_mode,
                "status": "passed",
            },
            build={
                "command": normalize_command(build_args, temporary, source),
                "shared_library": shared,
                "status": "passed",
            },
            install={
                "command": normalize_command(install_args, temporary, source),
                "headers": headers,
                "manifest": manifest,
                "status": "passed",
            },
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
        print(f"allocator x86-64 CMake mode evidence: FAIL: {error}", file=os.sys.stderr)
        return 1
    print(
        "allocator x86-64 CMake mode evidence: PASS "
        f"({len(report['install']['headers'])} installed public headers; report: "
        f"{report_path_display(arguments.report)})"
    )
    return 0


def report_path_display(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


if __name__ == "__main__":
    raise SystemExit(main())
