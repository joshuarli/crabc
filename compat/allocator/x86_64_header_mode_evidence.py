#!/usr/bin/env python3
"""Compile/link selected pinned public-header modes on native x86-64.

This native-only lane stages exact public-header bytes from the pinned source,
builds the fixed normal-release C shared object, and compile-links selected C
and C++ consumer translation units against it. It proves neither installation
through CMake nor consumer execution or allocator behavior.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "compat/allocator/run.py"
SCHEMA_PATH = ROOT / "compat/allocator/x86_64-header-mode-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/header-mode-evidence.json"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class EvidenceError(RuntimeError):
    """The bounded native public-header compile/link evidence failed."""


TARGET = {
    "architecture": "x86_64",
    "endianness": "little",
    "system": "linux",
    "rust_target": "x86_64-unknown-linux-musl",
}
PROFILE = "linux-x86_64-pinned-mimalloc-normal-release-staged-public-headers"
UPSTREAM = {
    "version": "3.5.0",
    "archive_root": "mimalloc-3.5.0",
    "revision": "18b08671c9302247bfb682286e6bf3cc1773f801",
    "archive_sha256": "1e432f0559a4ab512143b9bff7a700541a2c8d4712b26a72de3e0222790da305",
}
COMPILE_DEFINITIONS = ("-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1")
CXX_TOOL = {"driver": "g++", "runtime": "native-image-musl"}
SCOPE = {
    "native_linux_x86_64_required": True,
    "public_crabc_support": False,
    "public_x86_libc_or_ldso_support": False,
    "behavior_claimed": False,
    "rust_claimed": False,
    "execution_claimed": False,
    "cmake_mode_claimed": False,
    "cmake_install_claimed": False,
    "staged_pinned_public_headers_only": True,
    "emulation_accepted": False,
}
PUBLIC_HEADER_BYTES = {
    "include/mimalloc.h": "af34f215cb6fe9e4e97bf08d78bfda877ab4cdd63c9222640c483d7d6a4488a5",
    "include/mimalloc-stats.h": "7bc3c522d9a5203b27464179177845f3c09eea4453b82545d20ce61a711a9a1e",
    "include/mimalloc-new-delete.h": "1bc31e20fb0340d9d071c69eaac2f07d0dfe4cdf95849ed8d91fb2bd7538d55b",
    "include/mimalloc-override.h": "21fcf61c4443341ac6bf6ea528af31dc7267e8e3456fc64bfd07704503032175",
}
MODES = (
    "c-base",
    "c-stats",
    "c-inline-helpers",
    "cxx-base",
    "cxx-new-delete",
    "c-override",
)
C_PROBES = {
    "c-base": "#include <mimalloc.h>\nint main(void) { void* p = mi_malloc(8); mi_free(p); return mi_version() == 0; }\n",
    "c-stats": "#include <mimalloc-stats.h>\nint main(void) { mi_stats_t stats; mi_stats_init(&stats); return mi_stats_get(&stats) ? 0 : 1; }\n",
    # This only compile-links the five static-inline ``*_csize`` helpers at
    # pinned ``include/mimalloc.h:398-412``. The volatile size makes both
    # header branches compile/link inputs without running the consumer.
    "c-inline-helpers": (
        "#include <mimalloc.h>\n"
        "int main(void) {\n"
        "  volatile size_t size = 8;\n"
        "  mi_theap_t* theap = mi_theap_get_default();\n"
        "  void* malloced = mi_malloc_csize(size);\n"
        "  void* zalloced = mi_zalloc_csize(size);\n"
        "  void* theap_malloced = mi_theap_malloc_csize(theap, size);\n"
        "  void* theap_zalloced = mi_theap_zalloc_csize(theap, size);\n"
        "  mi_free_csize(malloced, size);\n"
        "  mi_free_csize(zalloced, size);\n"
        "  mi_free_csize(theap_malloced, size);\n"
        "  mi_free_csize(theap_zalloced, size);\n"
        "  return 0;\n"
        "}\n"
    ),
    "c-override": "#include <mimalloc-override.h>\nint main(void) { void* p = malloc(8); free(p); return 0; }\n",
}
CXX_PROBES = {
    "cxx-base": "#include <mimalloc.h>\nint main() { mi_stl_allocator<int> allocator; int* p = allocator.allocate(1); allocator.deallocate(p, 1); return 0; }\n",
    "cxx-new-delete": "#include <mimalloc-new-delete.h>\nint main() { int* p = new int(1); delete p; return 0; }\n",
}
EXPECTED_C_ELF = {
    "class": "ELF64",
    "endianness": "little",
    "machine": "Advanced Micro Devices X86-64",
}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def exactly_matches(observed: object, expected: object) -> bool:
    """Compare JSON values without Python's bool/int equality loophole."""

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


def relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def expected_probe_sources() -> dict[str, str]:
    probes = {**C_PROBES, **CXX_PROBES}
    return {mode: sha256_bytes(probes[mode].encode("utf-8")) for mode in MODES}


def load_schema(path: Path | None = None) -> dict[str, Any]:
    if path is None:
        path = SCHEMA_PATH
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read header-mode evidence schema") from error
    expected_fields = {
        "compile_definitions",
        "cxx_tool",
        "format",
        "profile",
        "probe_sources",
        "public_header_bytes",
        "release_flags",
        "release_source_set",
        "schema",
        "scope",
        "selected_modes",
        "target",
        "upstream",
    }
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise EvidenceError("header-mode schema fields drifted")
    if type(value.get("format")) is not int or value["format"] != 1:
        raise EvidenceError("unsupported header-mode evidence format")
    if value.get("schema") != "crabc-mimalloc-x86_64-header-mode-evidence":
        raise EvidenceError("unsupported header-mode evidence schema")
    if not exactly_matches(value.get("target"), TARGET) or value.get("profile") != PROFILE:
        raise EvidenceError("header-mode target or profile drifted")
    if not exactly_matches(value.get("upstream"), UPSTREAM) or not exactly_matches(value.get("scope"), SCOPE):
        raise EvidenceError("header-mode upstream or scope drifted")
    if not exactly_matches(value.get("release_source_set"), list(run.ORACLE_SOURCES)):
        raise EvidenceError("header-mode normal-release source set drifted")
    if not exactly_matches(value.get("release_flags"), list(run.CONFIGURATION_PROFILES["release"])):
        raise EvidenceError("header-mode normal-release flags drifted")
    if not exactly_matches(value.get("compile_definitions"), list(COMPILE_DEFINITIONS)):
        raise EvidenceError("header-mode normal-release definitions drifted")
    if not exactly_matches(value.get("cxx_tool"), CXX_TOOL):
        raise EvidenceError("header-mode pinned C++ tool contract drifted")
    if not exactly_matches(value.get("public_header_bytes"), PUBLIC_HEADER_BYTES):
        raise EvidenceError("header-mode staged public-header bytes drifted")
    if not exactly_matches(value.get("selected_modes"), list(MODES)):
        raise EvidenceError("header-mode selected modes drifted")
    if not exactly_matches(value.get("probe_sources"), expected_probe_sources()):
        raise EvidenceError("header-mode probe source contract drifted")
    return value


def require_native_x86_64() -> dict[str, str]:
    try:
        return run.require_native_x86_64()
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def normalize_command(command: Sequence[str], temporary: Path, source: Path | None) -> list[str]:
    normalized: list[str] = []
    temporary_text = str(temporary)
    source_text = str(source) if source is not None else None
    for part in command:
        if source_text is not None and (part == source_text or part.startswith(source_text + "/")):
            normalized.append(NORMALIZED_PINNED_SOURCE + part[len(source_text) :])
        elif part == temporary_text or part.startswith(temporary_text + "/"):
            normalized.append(NORMALIZED_EVIDENCE_ROOT + part[len(temporary_text) :])
        elif part == "-Wl,-rpath," + temporary_text:
            normalized.append("-Wl,-rpath," + NORMALIZED_EVIDENCE_ROOT)
        else:
            normalized.append(part)
    return normalized


def shared_command(compiler: str, source: Path, output: Path, schema: Mapping[str, Any]) -> list[str]:
    command = run.profile_command(compiler, source, output, tuple(schema["release_flags"]))
    validate_shared_command(command, schema)
    return command


def validate_shared_command(command: Sequence[str], schema: Mapping[str, Any]) -> None:
    definitions = [part for part in command if part in COMPILE_DEFINITIONS]
    flags = [part for part in command if part in run.CONFIGURATION_PROFILES["release"]]
    if definitions != list(schema["compile_definitions"]) or definitions != list(COMPILE_DEFINITIONS):
        raise EvidenceError("header-mode shared command compile definitions drifted")
    if flags != list(schema["release_flags"]):
        raise EvidenceError("header-mode shared command release flags drifted")
    if "-shared" not in command or "-pthread" not in command or "-ftls-model=initial-exec" not in command:
        raise EvidenceError("header-mode shared command lacks selected shared pthread/TLS mode")


def consumer_command(
    *,
    mode: str,
    c_compiler: str,
    cxx_compiler: str,
    include: Path,
    library_directory: Path,
    probe: Path,
    output: Path,
) -> list[str]:
    if mode.startswith("cxx-"):
        return [
            cxx_compiler,
            "-std=c++17",
            "-I",
            str(include),
            str(probe),
            "-L",
            str(library_directory),
            "-l:libmimalloc-header-modes.so",
            "-Wl,-rpath," + str(library_directory),
            "-o",
            str(output),
        ]
    return [
        c_compiler,
        "-std=c11",
        "-I",
        str(include),
        str(probe),
        "-L",
        str(library_directory),
        "-l:libmimalloc-header-modes.so",
        "-Wl,-rpath," + str(library_directory),
        "-o",
        str(output),
    ]


def validate_normalized_shared_command(command: object, schema: Mapping[str, Any]) -> None:
    if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
        raise EvidenceError("header-mode report shared command is malformed")
    if Path(command[0]).name != "musl-gcc":
        raise EvidenceError("header-mode report shared compiler drifted")
    expected = [
        "-std=c11", "-fPIC", "-fvisibility=hidden", "-ftls-model=initial-exec",
        *list(schema["compile_definitions"]), *list(schema["release_flags"]),
        "-I", f"{NORMALIZED_PINNED_SOURCE}/include", "-shared",
        "-Wl,-soname,libmimalloc-header-modes.so", "-pthread", "-o",
        f"{NORMALIZED_EVIDENCE_ROOT}/libmimalloc-header-modes.so",
        *(f"{NORMALIZED_PINNED_SOURCE}/{member}" for member in schema["release_source_set"]),
    ]
    if command[1:] != expected:
        raise EvidenceError("header-mode report shared command drifted")


def validate_normalized_consumer_command(command: object, mode: str) -> None:
    if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
        raise EvidenceError("header-mode report consumer command is malformed")
    suffix = ".cpp" if mode.startswith("cxx-") else ".c"
    if mode.startswith("cxx-"):
        expected = [
            "-std=c++17", "-I",
            f"{NORMALIZED_EVIDENCE_ROOT}/include", f"{NORMALIZED_EVIDENCE_ROOT}/{mode}{suffix}",
            "-L", NORMALIZED_EVIDENCE_ROOT, "-l:libmimalloc-header-modes.so", "-Wl,-rpath," + NORMALIZED_EVIDENCE_ROOT,
            "-o", f"{NORMALIZED_EVIDENCE_ROOT}/{mode}",
        ]
        if Path(command[0]).name != CXX_TOOL["driver"] or command[1:] != expected:
            raise EvidenceError("header-mode report C++ consumer command drifted")
        return
    expected = [
        "-std=c11", "-I", f"{NORMALIZED_EVIDENCE_ROOT}/include",
        f"{NORMALIZED_EVIDENCE_ROOT}/{mode}{suffix}", "-L", NORMALIZED_EVIDENCE_ROOT,
        "-l:libmimalloc-header-modes.so", "-Wl,-rpath," + NORMALIZED_EVIDENCE_ROOT, "-o",
        f"{NORMALIZED_EVIDENCE_ROOT}/{mode}",
    ]
    if Path(command[0]).name != "musl-gcc" or command[1:] != expected:
        raise EvidenceError("header-mode report C consumer command drifted")


def command(args: Sequence[str], cwd: Path, description: str) -> None:
    try:
        run.require_success(run.command_record(args, cwd=cwd), description)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def elf_identity(readelf: str, artifact: Path, cwd: Path, description: str) -> dict[str, str]:
    try:
        record = run.command_record((readelf, "-h", str(artifact)), cwd=cwd)
        run.require_success(record, description)
        return run.parse_elf_identity(str(record["stdout"]), "x86_64")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def report_from_results(
    *,
    schema: Mapping[str, Any],
    provenance: Mapping[str, str],
    shared_library: Mapping[str, Any],
    modes: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "format": 1,
        "schema": schema["schema"],
        "status": "passed",
        "provenance": dict(provenance),
        "target": schema["target"],
        "upstream": schema["upstream"],
        "profile": schema["profile"],
        "source": {
            "compile_definitions": list(schema["compile_definitions"]),
            "public_header_bytes": schema["public_header_bytes"],
            "release_flags": list(schema["release_flags"]),
            "release_source_set": list(schema["release_source_set"]),
        },
        "shared_library": dict(shared_library),
        "modes": [dict(mode) for mode in modes],
        "scope": schema["scope"],
    }
    validate_report(report)
    return report


def validate_report(report: Mapping[str, Any]) -> None:
    required = {"format", "modes", "profile", "provenance", "schema", "scope", "shared_library", "source", "status", "target", "upstream"}
    if not isinstance(report, dict) or set(report) != required:
        raise EvidenceError("header-mode report schema drifted")
    if type(report["format"]) is not int or report["format"] != 1 or report["status"] != "passed":
        raise EvidenceError("header-mode report must record a passing format-1 result")
    if report["schema"] != "crabc-mimalloc-x86_64-header-mode-evidence" or report["profile"] != PROFILE:
        raise EvidenceError("header-mode report identity drifted")
    if not exactly_matches(report["target"], TARGET) or not exactly_matches(report["upstream"], UPSTREAM) or not exactly_matches(report["scope"], SCOPE):
        raise EvidenceError("header-mode report target or scope drifted")
    if not any(
        exactly_matches(report["provenance"], candidate)
        for candidate in ({"execution_mode": "native", "host_architecture": "x86_64"}, {"execution_mode": "native", "host_architecture": "amd64"})
    ):
        raise EvidenceError("header-mode report lacks native x86-64 provenance")
    schema = load_schema()
    if not exactly_matches(report["source"], {
        "compile_definitions": schema["compile_definitions"],
        "public_header_bytes": schema["public_header_bytes"],
        "release_flags": schema["release_flags"],
        "release_source_set": schema["release_source_set"],
    }):
        raise EvidenceError("header-mode report source selection drifted")
    shared = report["shared_library"]
    if not isinstance(shared, dict) or set(shared) != {"build_command", "elf"}:
        raise EvidenceError("header-mode report shared library record drifted")
    if not exactly_matches(shared["elf"], EXPECTED_C_ELF):
        raise EvidenceError("header-mode report shared ELF identity drifted")
    validate_normalized_shared_command(shared["build_command"], schema)
    modes = report["modes"]
    if not isinstance(modes, list) or len(modes) != len(MODES):
        raise EvidenceError("header-mode report mode records drifted")
    if [record.get("mode") if isinstance(record, dict) else None for record in modes] != list(MODES):
        raise EvidenceError("header-mode report mode selection drifted")
    for record in modes:
        if not isinstance(record, dict) or set(record) != {"build_command", "elf", "mode", "probe_sha256", "status"}:
            raise EvidenceError("header-mode report consumer record drifted")
        mode = record["mode"]
        if record["status"] != "passed" or record["probe_sha256"] != expected_probe_sources()[mode]:
            raise EvidenceError("header-mode report consumer source result drifted")
        if not exactly_matches(record["elf"], EXPECTED_C_ELF):
            raise EvidenceError("header-mode report consumer ELF identity drifted")
        validate_normalized_consumer_command(record["build_command"], mode)


def run_evidence(*, offline: bool, report_path: Path) -> dict[str, Any]:
    schema = load_schema()
    provenance = require_native_x86_64()
    try:
        pin = run.load_pin()
        archive = run.fetch_archive(pin, offline)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    if not exactly_matches(
        {"version": pin["version"], "archive_root": pin["archive_root"], "revision": pin["revision"], "archive_sha256": pin["sha256"]},
        UPSTREAM,
    ):
        raise EvidenceError("header-mode repository pin disagrees with schema")
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86-header-") as temporary_name:
        temporary = Path(temporary_name)
        try:
            source = run.safe_extract(archive, temporary / "source", pin["archive_root"])
            c_compiler = run.require_tool("musl-gcc")
            cxx_compiler = run.require_tool(CXX_TOOL["driver"])
            readelf = run.require_tool("readelf")
        except run.HarnessError as error:
            raise EvidenceError(str(error)) from error
        include = temporary / "include"
        include.mkdir()
        for member, digest in PUBLIC_HEADER_BYTES.items():
            data = (source / member).read_bytes()
            if sha256_bytes(data) != digest:
                raise EvidenceError(f"header-mode public header hash drifted: {member}")
            (include / Path(member).name).write_bytes(data)

        library = temporary / "libmimalloc-header-modes.so"
        shared = shared_command(c_compiler, source, library, schema)
        command(shared, source, "pinned C header-mode shared-object build")
        shared_record = {
            "build_command": normalize_command(shared, temporary, source),
            "elf": elf_identity(readelf, library, source, "pinned C header-mode shared-object ELF identity"),
        }
        modes: list[dict[str, Any]] = []
        for mode in MODES:
            suffix = ".cpp" if mode.startswith("cxx-") else ".c"
            source_text = (CXX_PROBES if mode.startswith("cxx-") else C_PROBES)[mode]
            probe = temporary / f"{mode}{suffix}"
            probe.write_text(source_text, encoding="utf-8")
            executable = temporary / mode
            consumer = consumer_command(
                mode=mode,
                c_compiler=c_compiler,
                cxx_compiler=cxx_compiler,
                include=include,
                library_directory=temporary,
                probe=probe,
                output=executable,
            )
            command(consumer, temporary, f"header-mode {mode} compile/link")
            modes.append({
                "build_command": normalize_command(consumer, temporary, source),
                "elf": elf_identity(readelf, executable, temporary, f"header-mode {mode} ELF identity"),
                "mode": mode,
                "probe_sha256": sha256_bytes(source_text.encode("utf-8")),
                "status": "passed",
            })
        report = report_from_results(
            schema=schema,
            provenance=provenance,
            shared_library=shared_record,
            modes=modes,
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
        print(f"allocator x86-64 staged header-mode evidence: FAIL: {error}", file=os.sys.stderr)
        return 1
    print(
        "allocator x86-64 staged header-mode evidence: PASS "
        f"({len(report['modes'])} C/C++ compile-link modes; report: {relative(arguments.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
