#!/usr/bin/env python3
"""Build the pinned mimalloc release and audit its native x86-64 symbols.

This is allocator-engine evidence only.  It compiles the fixed normal-release
C source set once per object and once as a shared object, then separately
checks the fixed object-global and dynamic-default-visible ``mi_*``
inventories.  It never builds crabc-libc, crabc-ldso, or a public x86 facade.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "compat/allocator/run.py"
SCHEMA_PATH = ROOT / "compat/allocator/x86_64-release-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/release-evidence.json"
SOURCE_API_PATH = ROOT / "compat/allocator/x86_64-api-v3.5.0.json"
SOURCE_COVERAGE_PATH = ROOT / "compat/allocator/x86_64-api-coverage-v3.5.0.json"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class EvidenceError(RuntimeError):
    pass


def require_native_x86_64() -> dict[str, str]:
    """Use the allocator harness's single native-provenance predicate."""

    try:
        return run.require_native_x86_64()
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


EXPECTED_TARGET = {
    "architecture": "x86_64",
    "endianness": "little",
    "system": "linux",
    "rust_target": "x86_64-unknown-linux-musl",
}
EXPECTED_PROFILE = "linux-x86_64-pinned-mimalloc-release"
EXPECTED_UPSTREAM = {"version": "3.5.0", "archive_root": "mimalloc-3.5.0"}
EXPECTED_SCOPE = {
    "native_linux_x86_64_required": True,
    "public_crabc_support": False,
    "public_x86_libc_or_ldso_support": False,
    "aarch64_status_reused": False,
    "emulation_accepted": False,
}
EXPECTED_COMPILE_DEFINITIONS = (
    "-DMI_SHARED_LIB",
    "-DMI_SHARED_LIB_EXPORT",
    "-DMI_LIBC_MUSL=1",
)
TARGET_MODE_ASSERTIONS = (
    "__linux__",
    "__x86_64__",
    "MI_ARCH_X64=1",
    "MI_INTPTR_SIZE=8",
    "MI_SIZE_SIZE=8",
    "MI_MAX_VABITS=47",
    "MI_BUILD_RELEASE=1",
    "MI_DEBUG=0",
    "MI_STAT=0",
    "MI_SECURE=0",
    "MI_GUARDED=0",
    "MI_SHARED_LIB",
    "MI_SHARED_LIB_EXPORT",
    "MI_LIBC_MUSL=1",
)
SOURCE_API_RELATIVE_PATH = "compat/allocator/x86_64-api-v3.5.0.json"
SOURCE_COVERAGE_RELATIVE_PATH = "compat/allocator/x86_64-api-coverage-v3.5.0.json"
SOURCE_API_EXPECTED_COUNT = 180
SOURCE_API_EXPECTED_DIGEST = "5a17248c61dccbb5abd9b8fe742a4243594793c125e229b2156a7f5172915975"
SOURCE_STATS_EXPECTED_COUNT = 15
SOURCE_STATS_EXPECTED_DIGEST = "9a9c4bf51cde6774f22488f0e92200d1909cc6bc688cc4b824aa3aa92020cdda"
NORMAL_RELEASE_SOURCE_EXCEPTIONS = (
    "mi_collect_reduce",
    "mi_malloc_size",
    "mi_malloc_usable_size",
    "mi_stats_merge",
)
OBJECT_INVENTORY_MEANING = (
    "Fixed hash of the sorted, globally defined mi_* symbols across the "
    "individually compiled normal-release objects."
)
DYNAMIC_INVENTORY_MEANING = (
    "Fixed hash of the sorted, default-visible, defined mi_* symbols in the "
    "linked normal-release shared object."
)
MODE_PROBE_SOURCE = """\
#include "mimalloc/internal.h"
#if !defined(__linux__) || !defined(__x86_64__)
#error target preprocessor selection is not Linux/x86_64
#endif
#if MI_ARCH_X64 != 1 || MI_INTPTR_SIZE != 8 || MI_SIZE_SIZE != 8 || MI_MAX_VABITS != 47
#error target mimalloc ABI-width selection is not x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error release configuration selection is not fixed
#endif
#if !defined(MI_SHARED_LIB) || !defined(MI_SHARED_LIB_EXPORT) || MI_LIBC_MUSL != 1
#error shared-library musl selection is not fixed
#endif
int crabc_mimalloc_release_mode_probe;
"""


def ordered_name_digest(names: Sequence[str]) -> str:
    return hashlib.sha256(("\n".join(names)).encode()).hexdigest()


def _read_json(path: Path, description: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read {description}") from error
    if not isinstance(value, dict):
        raise EvidenceError(f"{description} is not a JSON object")
    return value


def load_source_symbol_inventory(schema: dict[str, Any]) -> dict[str, Any]:
    """Load only the target-local x86 declaration ledgers used by this gate.

    The normal release exports are intentionally a subset of the C headers:
    the four named exceptions are declarations for alternate/platform APIs
    absent from this Linux release source set.  This contract is source-ledger
    evidence, not a claim about crabc's public C ABI.
    """

    contract = schema.get("source_declaration_inventory")
    expected_contract = {
        "base_header": {
            "path": SOURCE_API_RELATIVE_PATH,
            "declaration_count": SOURCE_API_EXPECTED_COUNT,
            "declaration_names_sha256": SOURCE_API_EXPECTED_DIGEST,
        },
        "statistics_header": {
            "path": SOURCE_COVERAGE_RELATIVE_PATH,
            "declaration_count": SOURCE_STATS_EXPECTED_COUNT,
            "declaration_names_sha256": SOURCE_STATS_EXPECTED_DIGEST,
        },
        "normal_release_exceptions": list(NORMAL_RELEASE_SOURCE_EXCEPTIONS),
    }
    if contract != expected_contract:
        raise EvidenceError("source declaration inventory contract is not the exact target-local x86 ledger contract")

    api = _read_json(SOURCE_API_PATH, "the target-local x86 C API inventory")
    if api.get("target_context") != {
        "architecture": "x86_64",
        "endianness": "little",
        "rust_target": "x86_64-unknown-linux-musl",
        "system": "linux",
    }:
        raise EvidenceError("x86 C API inventory target context drifted")
    if api.get("upstream") != {
        "archive_root": "mimalloc-3.5.0",
        "revision": "18b08671c9302247bfb682286e6bf3cc1773f801",
        "version": "3.5.0",
    }:
        raise EvidenceError("x86 C API inventory upstream pin drifted")
    declarations = api.get("declarations")
    if not isinstance(declarations, list):
        raise EvidenceError("x86 C API declaration inventory is not a list")
    api_names = [entry.get("name") for entry in declarations if isinstance(entry, dict)]
    if len(api_names) != len(declarations) or not all(isinstance(name, str) and name.startswith("mi_") for name in api_names):
        raise EvidenceError("x86 C API declaration inventory contains an invalid name")
    if api.get("declaration_count") != SOURCE_API_EXPECTED_COUNT or len(api_names) != SOURCE_API_EXPECTED_COUNT:
        raise EvidenceError("x86 C API declaration count drifted")
    if api.get("declaration_names_sha256") != SOURCE_API_EXPECTED_DIGEST or ordered_name_digest(api_names) != SOURCE_API_EXPECTED_DIGEST:
        raise EvidenceError("x86 C API declaration digest drifted")

    coverage = _read_json(SOURCE_COVERAGE_PATH, "the target-local x86 API coverage inventory")
    if coverage.get("target_context") != api["target_context"] or coverage.get("upstream") != api["upstream"]:
        raise EvidenceError("x86 API coverage inventory target or upstream drifted")
    surfaces = coverage.get("header_surfaces")
    if not isinstance(surfaces, list):
        raise EvidenceError("x86 API coverage header surfaces are not a list")
    stats = [entry for entry in surfaces if isinstance(entry, dict) and entry.get("member") == "include/mimalloc-stats.h"]
    if len(stats) != 1:
        raise EvidenceError("x86 statistics header inventory is missing or ambiguous")
    stats_external = stats[0].get("c_external_function_surface")
    stats_declarations = stats_external.get("declarations") if isinstance(stats_external, dict) else None
    if not isinstance(stats_declarations, list):
        raise EvidenceError("x86 statistics declaration inventory is not a list")
    stats_names = [entry.get("name") for entry in stats_declarations if isinstance(entry, dict)]
    if len(stats_names) != len(stats_declarations) or not all(isinstance(name, str) and name.startswith("mi_") for name in stats_names):
        raise EvidenceError("x86 statistics declaration inventory contains an invalid name")
    if len(stats_names) != SOURCE_STATS_EXPECTED_COUNT or stats_external.get("source_declared_function_count") != SOURCE_STATS_EXPECTED_COUNT:
        raise EvidenceError("x86 statistics declaration count drifted")
    if stats_external.get("names_sha256") != SOURCE_STATS_EXPECTED_DIGEST or ordered_name_digest(stats_names) != SOURCE_STATS_EXPECTED_DIGEST:
        raise EvidenceError("x86 statistics declaration digest drifted")

    source_names = set(api_names) | set(stats_names)
    exceptions = set(NORMAL_RELEASE_SOURCE_EXCEPTIONS)
    if not exceptions <= source_names:
        raise EvidenceError("normal-release source exceptions are not source declarations")
    expected_dynamic = source_names - exceptions
    return {
        "base_header": {**contract["base_header"], "names": api_names},
        "statistics_header": {**contract["statistics_header"], "names": stats_names},
        "normal_release_exceptions": list(NORMAL_RELEASE_SOURCE_EXCEPTIONS),
        "source_union_count": len(source_names),
        "expected_dynamic_count": len(expected_dynamic),
        "expected_dynamic_names_sha256": symbol_digest(sorted(expected_dynamic)),
        "expected_dynamic_names": sorted(expected_dynamic),
    }


def load_schema() -> dict[str, Any]:
    value = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    if value.get("format") != 1 or value.get("schema") != "crabc-mimalloc-x86_64-release-object-symbol-evidence":
        raise EvidenceError("unsupported x86-64 release evidence schema")
    if value.get("target") != EXPECTED_TARGET:
        raise EvidenceError("release evidence target is not the exact native Linux/x86_64 target")
    if value.get("profile") != EXPECTED_PROFILE:
        raise EvidenceError("release evidence profile is not the fixed native x86_64 release profile")
    if value.get("upstream") != EXPECTED_UPSTREAM:
        raise EvidenceError("release evidence upstream pin is not the exact mimalloc 3.5.0 pin")
    if value.get("scope") != EXPECTED_SCOPE:
        raise EvidenceError("release evidence scope boundary is not the exact native-only scope")
    if value.get("release_source_set") != list(run.ORACLE_SOURCES):
        raise EvidenceError("release source set differs from the pinned run.py oracle set")
    if value.get("release_flags") != list(run.CONFIGURATION_PROFILES["release"]):
        raise EvidenceError("release flags differ from the pinned run.py release profile")
    if value.get("compile_definitions") != list(EXPECTED_COMPILE_DEFINITIONS):
        raise EvidenceError("release compile definitions are not the canonical shared musl profile")
    if value.get("target_mode_assertions") != list(TARGET_MODE_ASSERTIONS):
        raise EvidenceError("release target-mode assertions are not the fixed x86_64 profile")
    for key, meaning in (
        ("object_global_mi_symbol_inventory", OBJECT_INVENTORY_MEANING),
        ("dynamic_default_visible_mi_symbol_inventory", DYNAMIC_INVENTORY_MEANING),
    ):
        inventory = value.get(key)
        if not isinstance(inventory, dict) or set(inventory) != {"meaning", "count", "sorted_names_sha256"}:
            raise EvidenceError(f"{key} schema is invalid")
        if inventory["meaning"] != meaning:
            raise EvidenceError(f"{key} meaning does not describe its ELF boundary")
        if type(inventory["count"]) is not int or inventory["count"] <= 0:
            raise EvidenceError(f"{key} count is invalid")
        if not isinstance(inventory["sorted_names_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", inventory["sorted_names_sha256"]):
            raise EvidenceError(f"{key} digest is invalid")
    # The dynamic boundary is source-bound to the target-local x86 ledgers;
    # do this as part of schema loading so an otherwise valid-looking release
    # schema cannot drift away from those declared source surfaces.
    load_source_symbol_inventory(value)
    return value


def public_symbols(names: Sequence[str]) -> list[str]:
    return sorted({name for name in names if name.startswith("mi_")})


def symbol_digest(names: Sequence[str]) -> str:
    return hashlib.sha256(("\n".join(public_symbols(names))).encode()).hexdigest()


def check_inventory(names: Sequence[str], inventory: dict[str, Any], boundary: str) -> list[str]:
    observed = public_symbols(names)
    if len(observed) != inventory["count"] or symbol_digest(observed) != inventory["sorted_names_sha256"]:
        raise EvidenceError(f"{boundary} mi_* symbol inventory differs from fixed release schema")
    return observed


def check_dynamic_source_inventory(
    names: Sequence[str], source_inventory: dict[str, Any]
) -> list[str]:
    observed = public_symbols(names)
    expected = source_inventory["expected_dynamic_names"]
    if observed != expected:
        raise EvidenceError(
            "release shared-object mi_* inventory differs from the target-local x86 source ledgers"
        )
    if len(observed) != source_inventory["expected_dynamic_count"]:
        raise EvidenceError("target-local x86 source-derived dynamic count drifted")
    if symbol_digest(observed) != source_inventory["expected_dynamic_names_sha256"]:
        raise EvidenceError("target-local x86 source-derived dynamic digest drifted")
    return observed


def command(command: Sequence[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(list(command), cwd=cwd, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (OSError, subprocess.CalledProcessError) as error:
        raise EvidenceError(f"command failed: {' '.join(command)}") from error


def nm_defined(nm: str, artifact: Path) -> list[str]:
    output = command((nm, "-g", "--defined-only", str(artifact)), ROOT).stdout
    names = []
    for line in output.splitlines():
        fields = line.split()
        if fields and not fields[-1].endswith(":"):
            names.append(fields[-1].split("@", 1)[0])
    return names


def check_profile_definitions(command_line: Sequence[str], schema: dict[str, Any]) -> None:
    actual = tuple(item for item in command_line if item in EXPECTED_COMPILE_DEFINITIONS)
    expected = tuple(schema["compile_definitions"])
    if actual != expected or actual != EXPECTED_COMPILE_DEFINITIONS:
        raise EvidenceError("release command compile definitions differ from the fixed schema")


def run_mode_probe(compile_prefix: Sequence[str], source: Path, temporary: Path) -> list[str]:
    probe_source = temporary / "release-mode-probe.c"
    probe_object = temporary / "release-mode-probe.o"
    probe_source.write_text(MODE_PROBE_SOURCE, encoding="utf-8")
    probe_command = [*compile_prefix, "-c", str(probe_source), "-o", str(probe_object)]
    command(probe_command, source)
    return probe_command


def build(*, offline: bool, report_path: Path) -> dict[str, Any]:
    provenance = require_native_x86_64()
    schema = load_schema()
    source_inventory = load_source_symbol_inventory(schema)
    pin = run.load_pin()
    archive = run.fetch_archive(pin, offline)
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86-release-") as temporary:
        source = run.safe_extract(archive, Path(temporary), pin["archive_root"])
        compiler = run.require_tool("musl-gcc")
        readelf = run.require_tool("readelf")
        nm = run.require_tool("nm")
        flags = tuple(schema["release_flags"])
        sources = tuple(schema["release_source_set"])
        artifact = Path(temporary) / "libmimalloc-release.so"
        link = run.profile_command(compiler, source, artifact, flags)
        check_profile_definitions(link, schema)
        run.require_success(run.command_record(link, cwd=source), "pinned release shared-object build")
        compile_prefix = link[:link.index("-shared")]
        mode_probe_command = run_mode_probe(compile_prefix, source, Path(temporary))
        objects: list[Path] = []
        object_commands: list[list[str]] = []
        for index, member in enumerate(sources):
            obj = Path(temporary) / f"source-{index:02d}.o"
            # Derive the compile prefix from the canonical run.py release command.
            compile_command = [*compile_prefix, "-pthread", "-c", str(source / member), "-o", str(obj)]
            command(compile_command, source)
            objects.append(obj)
            object_commands.append(compile_command)
        object_symbols = check_inventory(
            [name for obj in objects for name in nm_defined(nm, obj)],
            schema["object_global_mi_symbol_inventory"],
            "release object global-defined",
        )
        dynamic_names = run.defined_dynamic_symbols(readelf, artifact)
        dynamic_symbols = check_dynamic_source_inventory(dynamic_names, source_inventory)
        if dynamic_symbols != check_inventory(
            dynamic_names,
            schema["dynamic_default_visible_mi_symbol_inventory"],
            "release shared-object default-visible",
        ):
            raise EvidenceError("dynamic mi_* inventory normalization is inconsistent")
        elf_header = run.command_record((readelf, "-h", str(artifact)), cwd=ROOT)
        run.require_success(elf_header, "release shared-object ELF identity")
        elf_identity = run.parse_elf_identity(str(elf_header["stdout"]), "x86_64")
        report = {
            "format": 1,
            "schema": schema["schema"],
            "status": "passed",
            "provenance": provenance,
            "target": schema["target"],
            "upstream": {
                "archive_root": pin["archive_root"],
                "archive_sha256": pin["sha256"],
                "revision": pin["revision"],
                "version": pin["version"],
            },
            "profile": schema["profile"],
            "release_selection": {"source_set": list(sources), "flags": list(flags), "compile_definitions": schema["compile_definitions"], "target_mode_assertions": schema["target_mode_assertions"]},
            "build": {"shared_command": link, "mode_probe_command": mode_probe_command, "object_commands": object_commands, "elf": elf_identity},
            "symbols": {"object_global_mi_inventory": schema["object_global_mi_symbol_inventory"], "dynamic_default_visible_mi_inventory": schema["dynamic_default_visible_mi_symbol_inventory"], "object_global_defined_mi": object_symbols, "dynamic_default_visible_mi": dynamic_symbols},
            "source_declaration_inventory": {
                "base_header": {key: value for key, value in source_inventory["base_header"].items() if key != "names"},
                "statistics_header": {key: value for key, value in source_inventory["statistics_header"].items() if key != "names"},
                "normal_release_exceptions": source_inventory["normal_release_exceptions"],
                "source_union_count": source_inventory["source_union_count"],
                "expected_dynamic_count": source_inventory["expected_dynamic_count"],
                "expected_dynamic_names_sha256": source_inventory["expected_dynamic_names_sha256"],
            },
            "scope": schema["scope"],
        }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, default=REPORT_DEFAULT)
    args = parser.parse_args()
    try:
        build(offline=args.offline, report_path=args.report)
    except (EvidenceError, run.HarnessError, OSError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=os.sys.stderr)
        return 2
    print(args.report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
