#!/usr/bin/env python3
"""Build pinned mimalloc static and static-object override linkability on x86-64.

This lane intentionally stops at compilation, archive/object production, and
consumer link.  It does not execute a consumer, claim allocator behavior, or
exercise CMake installation.  The static-object form follows the pinned
upstream ``src/static.c`` amalgamation, which is the source's documented
single-object static override mechanism.
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
SCHEMA_PATH = ROOT / "compat/allocator/x86_64-static-mode-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/static-mode-evidence.json"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class EvidenceError(RuntimeError):
    """The bounded native static/object evidence failed."""


TARGET = {
    "architecture": "x86_64",
    "endianness": "little",
    "system": "linux",
    "rust_target": "x86_64-unknown-linux-musl",
}
PROFILE = "linux-x86_64-pinned-mimalloc-normal-release-static-object-override"
UPSTREAM = {
    "version": "3.5.0",
    "archive_root": "mimalloc-3.5.0",
    "revision": "18b08671c9302247bfb682286e6bf3cc1773f801",
    "archive_sha256": "1e432f0559a4ab512143b9bff7a700541a2c8d4712b26a72de3e0222790da305",
}
RELEASE_FLAGS = tuple(run.CONFIGURATION_PROFILES["release"])
# These are the target definitions CMake derives for a Release, musl build.
# `MI_MALLOC_OVERRIDE` is enabled by the pinned CMake default for both the
# static archive and the amalgamated object target.  The explicit release
# profile below remains part of this evidence contract so the direct command
# cannot silently change optimization/debug policy.
STATIC_LIBRARY_DEFINITIONS = (
    "-DMI_LIBC_MUSL=1", "-DMI_CMAKE_BUILD_TYPE=release", "-DMI_BUILD_RELEASE",
    "-DMI_STATIC_LIB", "-DMI_MALLOC_OVERRIDE",
)
STATIC_OBJECT_DEFINITIONS = (
    "-DMI_LIBC_MUSL=1", "-DMI_CMAKE_BUILD_TYPE=release", "-DMI_BUILD_RELEASE",
    "-DMI_MALLOC_OVERRIDE",
)
# CMake's GNU/musl branch adds local-dynamic TLS to static targets (not the
# shared target's initial-exec model), and adds these warning/override flags.
STATIC_COMPILE_FLAGS = (
    "-Wno-unknown-pragmas", "-fvisibility=hidden", "-Wstrict-prototypes",
    "-ftls-model=local-dynamic", "-fno-builtin-malloc",
)
CONSUMER_COMPILE_FLAGS = (
    "-Wno-unknown-pragmas", "-fvisibility=hidden", "-Wstrict-prototypes",
    "-fno-builtin-malloc",
)
STATIC_OBJECT_SOURCE = "src/static.c"
MODES = ("static-library", "static-object-override")
STATIC_OBJECT_REQUIRED_SYMBOLS = ("free", "malloc", "mi_free", "mi_malloc")
PROBES = {
    "static-library": (
        "#include <mimalloc.h>\n"
        "int main(void) { void* p = mi_malloc(16); mi_free(p); return p == 0; }\n"
    ),
    "static-object-override": (
        "#include <stdlib.h>\n"
        "int main(void) { void* p = malloc(16); free(p); return p == 0; }\n"
    ),
}
SCOPE = {
    "native_linux_x86_64_required": True,
    "public_crabc_support": False,
    "public_x86_libc_or_ldso_support": False,
    "behavior_claimed": False,
    "rust_claimed": False,
    "execution_claimed": False,
    "cmake_mode_claimed": False,
    "cmake_install_claimed": False,
    "static_library_linkability_only": True,
    "static_object_override_linkability_only": True,
    "emulation_accepted": False,
}
EXPECTED_ELF = {
    "class": "ELF64",
    "endianness": "little",
    "machine": "Advanced Micro Devices X86-64",
}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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


def relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def object_name(member: str) -> str:
    return member.replace("/", "_") + ".o"


def expected_probe_sources() -> dict[str, str]:
    return {mode: sha256_bytes(PROBES[mode].encode("utf-8")) for mode in MODES}


def load_schema(path: Path | None = None) -> dict[str, Any]:
    path = SCHEMA_PATH if path is None else path
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read static-mode evidence schema") from error
    fields = {
        "format", "probe_sources", "profile", "release_flags", "schema", "scope",
        "selected_modes", "static_library_definitions", "static_library_source_set",
        "static_compile_flags", "consumer_compile_flags", "static_object_definitions",
        "static_object_required_symbols", "static_object_source", "target", "upstream",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise EvidenceError("static-mode schema fields drifted")
    if type(value["format"]) is not int or value["format"] != 1:
        raise EvidenceError("unsupported static-mode evidence format")
    if value["schema"] != "crabc-mimalloc-x86_64-static-mode-evidence":
        raise EvidenceError("unsupported static-mode evidence schema")
    if value["profile"] != PROFILE or not exactly_matches(value["target"], TARGET):
        raise EvidenceError("static-mode target or profile drifted")
    if not exactly_matches(value["upstream"], UPSTREAM) or not exactly_matches(value["scope"], SCOPE):
        raise EvidenceError("static-mode upstream or scope drifted")
    if not exactly_matches(value["release_flags"], list(RELEASE_FLAGS)):
        raise EvidenceError("static-mode release flags drifted")
    if not exactly_matches(value["static_library_definitions"], list(STATIC_LIBRARY_DEFINITIONS)):
        raise EvidenceError("static-mode static-library definitions drifted")
    if not exactly_matches(value["static_object_definitions"], list(STATIC_OBJECT_DEFINITIONS)):
        raise EvidenceError("static-mode static-object definitions drifted")
    if not exactly_matches(value["static_compile_flags"], list(STATIC_COMPILE_FLAGS)):
        raise EvidenceError("static-mode CMake static compile flags drifted")
    if not exactly_matches(value["consumer_compile_flags"], list(CONSUMER_COMPILE_FLAGS)):
        raise EvidenceError("static-mode CMake consumer compile flags drifted")
    if not exactly_matches(value["static_object_required_symbols"], list(STATIC_OBJECT_REQUIRED_SYMBOLS)):
        raise EvidenceError("static-mode override symbol contract drifted")
    if value["static_object_source"] != STATIC_OBJECT_SOURCE:
        raise EvidenceError("static-mode object source drifted")
    if not exactly_matches(value["static_library_source_set"], list(run.ORACLE_SOURCES)):
        raise EvidenceError("static-mode normal static source set drifted")
    if not exactly_matches(value["selected_modes"], list(MODES)):
        raise EvidenceError("static-mode selection drifted")
    if not exactly_matches(value["probe_sources"], expected_probe_sources()):
        raise EvidenceError("static-mode probe source contract drifted")
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
            normalized.append(NORMALIZED_PINNED_SOURCE + part[len(source_text):])
        elif part == temporary_text or part.startswith(temporary_text + "/"):
            normalized.append(NORMALIZED_EVIDENCE_ROOT + part[len(temporary_text):])
        else:
            normalized.append(part)
    return normalized


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


def archive_members(archiver: str, archive: Path, cwd: Path) -> tuple[list[str], list[str]]:
    """Return the normalized command and the member names observed by `ar t`."""

    args = [archiver, "t", str(archive)]
    try:
        record = run.command_record(args, cwd=cwd)
        run.require_success(record, "pinned static archive member listing")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    members = [line for line in str(record["stdout"]).splitlines() if line]
    if any("\x00" in member for member in members):
        raise EvidenceError("static archive member listing contains NUL")
    return args, members


def defined_symbols(nm: str, artifact: Path, cwd: Path) -> tuple[list[str], list[str]]:
    """Return the command and all globally defined names observed by `nm`."""

    args = [nm, "-g", "--defined-only", str(artifact)]
    try:
        record = run.command_record(args, cwd=cwd)
        run.require_success(record, "pinned static override object symbol listing")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    symbols: list[str] = []
    for line in str(record["stdout"]).splitlines():
        fields = line.split()
        if len(fields) >= 2:
            symbols.append(fields[-1])
    if not symbols or len(symbols) != len(set(symbols)):
        raise EvidenceError("static override object symbol listing is empty or duplicated")
    return args, sorted(symbols)


def static_compile_command(
    compiler: str, source: Path, member: str, output: Path, schema: Mapping[str, Any]
) -> list[str]:
    return [
        compiler, "-std=c11", "-fPIC", *list(schema["static_compile_flags"]),
        *list(schema["static_library_definitions"]), *list(schema["release_flags"]),
        "-I", str(source / "include"), "-c", str(source / member), "-o", str(output),
    ]


def object_compile_command(
    compiler: str, source: Path, output: Path, schema: Mapping[str, Any]
) -> list[str]:
    return [
        compiler, "-std=c11", "-fPIC", *list(schema["static_compile_flags"]),
        *list(schema["static_object_definitions"]), *list(schema["release_flags"]),
        "-I", str(source / "include"), "-c", str(source / schema["static_object_source"]),
        "-o", str(output),
    ]


def consumer_command(
    *, mode: str, compiler: str, include: Path, artifact_root: Path, probe: Path, output: Path, object_path: Path
) -> list[str]:
    if mode == "static-library":
        return [
            compiler, "-std=c11", *list(CONSUMER_COMPILE_FLAGS), "-I", str(include), str(probe), "-L", str(artifact_root),
            "-Wl,--start-group", "-l:libmimalloc-static.a", "-Wl,--end-group", "-pthread", "-o", str(output),
        ]
    return [
        compiler, "-std=c11", *list(CONSUMER_COMPILE_FLAGS), "-I", str(include),
        str(probe), str(object_path), "-pthread", "-o", str(output),
    ]


def validate_normalized_command(
    command: object, expected: Sequence[str], tool: str, description: str
) -> None:
    """Require the complete normalized argv while allowing tool path prefixes."""

    if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
        raise EvidenceError(f"static-mode {description} command is malformed")
    if Path(command[0]).name != tool or command[1:] != list(expected)[1:]:
        raise EvidenceError(f"static-mode {description} command drifted")


def normalized_static_compile_command(member: str, schema: Mapping[str, Any]) -> list[str]:
    return static_compile_command(
        "musl-gcc",
        Path(NORMALIZED_PINNED_SOURCE),
        member,
        Path(NORMALIZED_EVIDENCE_ROOT) / "library-objects" / object_name(member),
        schema,
    )


def normalized_object_compile_command(schema: Mapping[str, Any]) -> list[str]:
    return object_compile_command(
        "musl-gcc",
        Path(NORMALIZED_PINNED_SOURCE),
        Path(NORMALIZED_EVIDENCE_ROOT) / "mimalloc-static-override.o",
        schema,
    )


def normalized_consumer_command(mode: str) -> list[str]:
    temporary = Path(NORMALIZED_EVIDENCE_ROOT)
    return consumer_command(
        mode=mode,
        compiler="musl-gcc",
        include=Path(NORMALIZED_PINNED_SOURCE) / "include",
        artifact_root=temporary,
        probe=temporary / f"{mode}.c",
        output=temporary / mode,
        object_path=temporary / "mimalloc-static-override.o",
    )


def validate_report(report: Mapping[str, Any]) -> None:
    required = {
        "format", "modes", "profile", "provenance", "schema", "scope", "source", "status",
        "static_library", "static_object", "target", "upstream",
    }
    if not isinstance(report, dict) or set(report) != required:
        raise EvidenceError("static-mode report fields drifted")
    if type(report["format"]) is not int or report["format"] != 1 or report["status"] != "passed":
        raise EvidenceError("static-mode report must be a passing format-1 result")
    if report["schema"] != "crabc-mimalloc-x86_64-static-mode-evidence" or report["profile"] != PROFILE:
        raise EvidenceError("static-mode report identity drifted")
    if not exactly_matches(report["target"], TARGET) or not exactly_matches(report["upstream"], UPSTREAM):
        raise EvidenceError("static-mode report target or upstream drifted")
    if not exactly_matches(report["scope"], SCOPE):
        raise EvidenceError("static-mode report scope drifted")
    provenance = report["provenance"]
    if not any(exactly_matches(provenance, item) for item in (
        {"execution_mode": "native", "host_architecture": "x86_64"},
        {"execution_mode": "native", "host_architecture": "amd64"},
    )):
        raise EvidenceError("static-mode report lacks native x86-64 provenance")
    schema = load_schema()
    expected_source = {
        "consumer_compile_flags": schema["consumer_compile_flags"],
        "release_flags": schema["release_flags"],
        "static_compile_flags": schema["static_compile_flags"],
        "static_library_definitions": schema["static_library_definitions"],
        "static_library_source_set": schema["static_library_source_set"],
        "static_object_definitions": schema["static_object_definitions"],
        "static_object_source": schema["static_object_source"],
    }
    if not exactly_matches(report["source"], expected_source):
        raise EvidenceError("static-mode report source selection drifted")
    library = report["static_library"]
    if not isinstance(library, dict) or set(library) != {
        "archive_command", "archive_member_listing_command", "compile_commands", "expected_member_names",
        "member_count", "observed_member_names", "status",
    }:
        raise EvidenceError("static-mode static-library record drifted")
    if library["status"] != "passed" or library["member_count"] != len(schema["static_library_source_set"]):
        raise EvidenceError("static-mode static-library result drifted")
    members = [object_name(member) for member in schema["static_library_source_set"]]
    if library["expected_member_names"] != members or library["observed_member_names"] != members:
        raise EvidenceError("static-mode observed static-library members drifted")
    if not isinstance(library["compile_commands"], list) or len(library["compile_commands"]) != len(members):
        raise EvidenceError("static-mode static-library compile records drifted")
    for member, command_record_value in zip(schema["static_library_source_set"], library["compile_commands"]):
        validate_normalized_command(
            command_record_value,
            normalized_static_compile_command(member, schema),
            "musl-gcc",
            f"static compilation for {member}",
        )
    temporary = NORMALIZED_EVIDENCE_ROOT
    expected_archive = [
        "ar", "rcs", f"{temporary}/libmimalloc-static.a",
        *(f"{temporary}/library-objects/{name}" for name in members),
    ]
    validate_normalized_command(library["archive_command"], expected_archive, "ar", "archive creation")
    validate_normalized_command(
        library["archive_member_listing_command"],
        ["ar", "t", f"{temporary}/libmimalloc-static.a"],
        "ar",
        "archive member listing",
    )
    obj = report["static_object"]
    if not isinstance(obj, dict) or set(obj) != {
        "compile_command", "elf", "nm_command", "observed_defined_symbols", "required_symbols", "status",
    } or obj["status"] != "passed":
        raise EvidenceError("static-mode object record drifted")
    if not exactly_matches(obj["elf"], EXPECTED_ELF):
        raise EvidenceError("static-mode object ELF identity drifted")
    validate_normalized_command(
        obj["compile_command"], normalized_object_compile_command(schema), "musl-gcc", "static override object compilation"
    )
    validate_normalized_command(
        obj["nm_command"],
        ["nm", "-g", "--defined-only", f"{temporary}/mimalloc-static-override.o"],
        "nm",
        "static override object symbol listing",
    )
    required_symbols = list(schema["static_object_required_symbols"])
    if obj["required_symbols"] != required_symbols:
        raise EvidenceError("static-mode required override symbols drifted")
    observed_symbols = obj["observed_defined_symbols"]
    if not isinstance(observed_symbols, list) or any(not isinstance(symbol, str) for symbol in observed_symbols):
        raise EvidenceError("static-mode observed override symbols are malformed")
    if not set(required_symbols).issubset(observed_symbols):
        raise EvidenceError("static-mode observed override symbols are incomplete")
    modes = report["modes"]
    if not isinstance(modes, list) or [entry.get("mode") if isinstance(entry, dict) else None for entry in modes] != list(MODES):
        raise EvidenceError("static-mode consumer selection drifted")
    for entry in modes:
        if not isinstance(entry, dict) or set(entry) != {"build_command", "elf", "mode", "probe_sha256", "status"}:
            raise EvidenceError("static-mode consumer record drifted")
        if entry["status"] != "passed" or entry["probe_sha256"] != expected_probe_sources()[entry["mode"]]:
            raise EvidenceError("static-mode consumer source result drifted")
        if not exactly_matches(entry["elf"], EXPECTED_ELF):
            raise EvidenceError("static-mode consumer ELF identity drifted")
        validate_normalized_command(
            entry["build_command"], normalized_consumer_command(entry["mode"]), "musl-gcc",
            f"{entry['mode']} consumer link",
        )


def run_evidence(*, offline: bool, report_path: Path) -> dict[str, Any]:
    schema = load_schema()
    provenance = require_native_x86_64()
    try:
        pin = run.load_pin()
        archive = run.fetch_archive(pin, offline)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    observed_pin = {"version": pin["version"], "archive_root": pin["archive_root"], "revision": pin["revision"], "archive_sha256": pin["sha256"]}
    if not exactly_matches(observed_pin, UPSTREAM):
        raise EvidenceError("static-mode repository pin disagrees with schema")
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86-static-") as temporary_name:
        temporary = Path(temporary_name)
        try:
            source = run.safe_extract(archive, temporary / "source", pin["archive_root"])
            compiler = run.require_tool("musl-gcc")
            archiver = run.require_tool("ar")
            nm = run.require_tool("nm")
            readelf = run.require_tool("readelf")
        except run.HarnessError as error:
            raise EvidenceError(str(error)) from error
        library_objects = temporary / "library-objects"
        library_objects.mkdir()
        compile_records: list[list[str]] = []
        object_paths: list[Path] = []
        for member in schema["static_library_source_set"]:
            output = library_objects / object_name(member)
            compile_args = static_compile_command(compiler, source, member, output, schema)
            command(compile_args, source, f"pinned normal static compilation: {member}")
            compile_records.append(normalize_command(compile_args, temporary, source))
            object_paths.append(output)
        archive_path = temporary / "libmimalloc-static.a"
        archive_args = [archiver, "rcs", str(archive_path), *(str(path) for path in object_paths)]
        command(archive_args, temporary, "pinned normal static archive creation")
        member_listing_args, observed_member_names = archive_members(archiver, archive_path, temporary)
        expected_member_names = [object_name(member) for member in schema["static_library_source_set"]]
        if observed_member_names != expected_member_names:
            raise EvidenceError(
                "pinned static archive members differ from the selected source set: "
                f"expected {expected_member_names!r}, observed {observed_member_names!r}"
            )
        library_record = {
            "archive_command": normalize_command(archive_args, temporary, source),
            "archive_member_listing_command": normalize_command(member_listing_args, temporary, source),
            "compile_commands": compile_records,
            "member_count": len(object_paths),
            "expected_member_names": expected_member_names,
            "observed_member_names": observed_member_names,
            "status": "passed",
        }
        override_object = temporary / "mimalloc-static-override.o"
        override_args = object_compile_command(compiler, source, override_object, schema)
        command(override_args, source, "pinned static override object compilation")
        nm_args, observed_symbols = defined_symbols(nm, override_object, source)
        required_symbols = list(schema["static_object_required_symbols"])
        if not set(required_symbols).issubset(observed_symbols):
            raise EvidenceError(
                "pinned static override object lacks required definitions: "
                f"required {required_symbols!r}, observed {observed_symbols!r}"
            )
        object_record = {
            "compile_command": normalize_command(override_args, temporary, source),
            "elf": elf_identity(readelf, override_object, source, "pinned static override object ELF identity"),
            "nm_command": normalize_command(nm_args, temporary, source),
            "observed_defined_symbols": observed_symbols,
            "required_symbols": required_symbols,
            "status": "passed",
        }
        modes: list[dict[str, Any]] = []
        include = source / "include"
        for mode in MODES:
            probe = temporary / f"{mode}.c"
            source_text = PROBES[mode]
            probe.write_text(source_text, encoding="utf-8")
            executable = temporary / mode
            consumer_args = consumer_command(
                mode=mode, compiler=compiler, include=include, artifact_root=temporary,
                probe=probe, output=executable, object_path=override_object,
            )
            command(consumer_args, temporary, f"static-mode {mode} compile/link")
            modes.append({
                "build_command": normalize_command(consumer_args, temporary, source),
                "elf": elf_identity(readelf, executable, temporary, f"static-mode {mode} ELF identity"),
                "mode": mode,
                "probe_sha256": sha256_bytes(source_text.encode("utf-8")),
                "status": "passed",
            })
        report: dict[str, Any] = {
            "format": 1,
            "schema": schema["schema"],
            "status": "passed",
            "provenance": dict(provenance),
            "target": schema["target"],
            "upstream": schema["upstream"],
            "profile": schema["profile"],
            "source": {
                "release_flags": list(schema["release_flags"]),
                "consumer_compile_flags": list(schema["consumer_compile_flags"]),
                "static_compile_flags": list(schema["static_compile_flags"]),
                "static_library_definitions": list(schema["static_library_definitions"]),
                "static_library_source_set": list(schema["static_library_source_set"]),
                "static_object_definitions": list(schema["static_object_definitions"]),
                "static_object_source": schema["static_object_source"],
            },
            "static_library": library_record,
            "static_object": object_record,
            "modes": modes,
            "scope": schema["scope"],
        }
    validate_report(report)
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
        print(f"allocator x86-64 static/object evidence: FAIL: {error}", file=os.sys.stderr)
        return 1
    print(
        "allocator x86-64 static/object evidence: PASS "
        f"({len(report['modes'])} compile-link modes; report: {relative(arguments.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
