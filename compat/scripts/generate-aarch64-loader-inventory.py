#!/usr/bin/env python3
"""Generate the AArch64 loader/runtime inventories.

The musl loader is a symlink to ``libc.so`` for this baseline, but that fact
does not describe the runtime contract of a replacement loader.  This script
keeps two reports separate:

* ``loader-runtime.json`` records the pinned musl interpreter relationship and
  the ELF program headers, dynamic tags, and relocation classes observed in
  that AArch64 shared object.
* ``loader-features.json`` records what the crabc loader source exposes and
  which existing test targets mention each mechanism.  It deliberately does
  not execute tests or mark any feature ``verified``.

Only Python's standard library and the binutils ``readelf`` supplied by the
pinned native development image are used.  Paths in generated reports are
repository-relative or installation-relative so the reports are reproducible
across Docker mounts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence


MUSL_VERSION = "1.2.6"
MUSL_TARBALL_SHA256 = (
    "d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a"
)
ARCHITECTURE = "aarch64"
TARGET = "aarch64-unknown-linux-musl"
SCHEMA_VERSION = 1

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parents[2]
DEFAULT_MUSL_ROOT = Path("/opt/musl-1.2.6")
DEFAULT_MUSL_OUTPUT = REPO_ROOT / "compat/abi/musl-1.2.6/aarch64/loader-runtime.json"
DEFAULT_CRABC_OUTPUT = REPO_ROOT / "compat/abi/crabc/aarch64/loader-features.json"
DEFAULT_CRABC_LDSO = REPO_ROOT / "target/debug/libldso.so"
DEFAULT_CRABC_SOURCE = REPO_ROOT / "ldso/src/lib.rs"

_PROGRAM_TYPES = {
    "LOAD",
    "DYNAMIC",
    "INTERP",
    "NOTE",
    "PHDR",
    "TLS",
    "GNU_EH_FRAME",
    "GNU_STACK",
    "GNU_RELRO",
}
_RELOC_SECTION = re.compile(
    r"^Relocation section '([^']+)'[^\n]*contains (\d+) entr(?:y|ies):"
)
_RELOC_TYPE = re.compile(r"\b(R_[A-Z0-9_]+)\b")
_DYNAMIC = re.compile(r"^\s*(0x[0-9a-fA-F]+)\s+\(([^)]+)\)\s+(.*)$")
_DYNSYM_COUNT = re.compile(r"^Symbol table '([^']+)' contains (\d+) entries:")


class InventoryError(RuntimeError):
    """An input or tool output does not describe the expected ABI."""


def run_tool(arguments: Sequence[str]) -> str:
    try:
        result = subprocess.run(
            list(arguments),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as error:
        raise InventoryError(f"required tool not found: {arguments[0]}") from error
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip()
        command = " ".join(arguments)
        raise InventoryError(
            f"command failed ({error.returncode}): {command}"
            + (f"\n{detail}" if detail else "")
        ) from error
    return result.stdout


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def readelf(path: Path, *arguments: str) -> str:
    return run_tool(("readelf", *arguments, str(path)))


def field(output: str, label: str) -> str | None:
    prefix = label + ":"
    for line in output.splitlines():
        if line.strip().startswith(prefix):
            return line.split(":", 1)[1].strip()
    return None


def parse_header(output: str) -> dict[str, Any]:
    values = {
        "class": field(output, "Class"),
        "data": field(output, "Data"),
        "version": field(output, "Version"),
        "os_abi": field(output, "OS/ABI"),
        "type": field(output, "Type"),
        "machine": field(output, "Machine"),
        "entry_point": field(output, "Entry point address"),
        "program_header_offset": field(output, "Start of program headers"),
        "program_header_entry_size": field(output, "Size of program headers"),
        "program_header_count": field(output, "Number of program headers"),
        "section_header_count": field(output, "Number of section headers"),
    }
    if values["class"] != "ELF64":
        raise InventoryError(f"expected ELF64, got {values['class']!r}")
    if values["data"] != "2's complement, little endian":
        raise InventoryError(f"expected little-endian ELF, got {values['data']!r}")
    if values["machine"] != "AArch64":
        raise InventoryError(f"expected AArch64 ELF, got {values['machine']!r}")
    return values


def parse_program_headers(output: str) -> list[dict[str, str]]:
    headers: list[dict[str, str]] = []
    in_table = False
    for line in output.splitlines():
        if line.strip() == "Program Headers:":
            in_table = True
            continue
        if in_table and line.strip().startswith("Section to Segment mapping"):
            break
        if not in_table:
            continue
        parts = line.split()
        if len(parts) < 8 or parts[0] not in _PROGRAM_TYPES:
            continue
        # The flags column is printed as either RWX or with spaces (for
        # example ``R E``), so take the first six fields and the final field
        # explicitly and join everything in between as flags.
        if not all(part.startswith("0x") for part in parts[1:6]):
            continue
        headers.append(
            {
                "type": parts[0],
                "offset": parts[1],
                "virtual_address": parts[2],
                "physical_address": parts[3],
                "file_size": parts[4],
                "memory_size": parts[5],
                "flags": "".join(parts[6:-1]),
                "alignment": parts[-1],
            }
        )
    if not headers:
        raise InventoryError("readelf produced no program headers")
    return headers


def parse_dynamic(output: str) -> list[dict[str, str]]:
    dynamic: list[dict[str, str]] = []
    for line in output.splitlines():
        match = _DYNAMIC.match(line)
        if match is None:
            continue
        tag_value, name, value = match.groups()
        dynamic.append({"tag": name, "tag_value": tag_value, "value": value.strip()})
    if not dynamic:
        raise InventoryError("readelf produced no dynamic tags")
    return dynamic


def parse_relocations(output: str) -> dict[str, Any]:
    sections: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in output.splitlines():
        section_match = _RELOC_SECTION.match(line)
        if section_match:
            current = {
                "name": section_match.group(1),
                "declared_entries": int(section_match.group(2)),
                "observed_entries": 0,
                "types": {},
            }
            sections.append(current)
            continue
        if current is None:
            continue
        type_match = _RELOC_TYPE.search(line)
        if type_match is None:
            continue
        relocation_type = type_match.group(1)
        current["observed_entries"] += 1
        types = current["types"]
        types[relocation_type] = types.get(relocation_type, 0) + 1

    if not sections:
        return {"sections": [], "types": {}, "entries": 0}

    all_types: dict[str, int] = {}
    for section in sections:
        for relocation_type, count in section["types"].items():
            all_types[relocation_type] = all_types.get(relocation_type, 0) + count
    return {
        "sections": sections,
        "types": dict(sorted(all_types.items())),
        "entries": sum(section["observed_entries"] for section in sections),
    }


def parse_dynamic_symbols(output: str) -> dict[str, int]:
    tables: dict[str, int] = {}
    public = 0
    for line in output.splitlines():
        count_match = _DYNSYM_COUNT.match(line)
        if count_match:
            tables[count_match.group(1)] = int(count_match.group(2))
            continue
        if not re.match(r"^\s*\d+:\s+", line):
            continue
        parts = line.split(None, 7)
        if len(parts) < 7:
            continue
        # index, value, size, type, binding, visibility, section, name
        binding = parts[4]
        visibility = parts[5]
        section = parts[6]
        name = parts[7].strip() if len(parts) > 7 else ""
        if (
            binding in {"GLOBAL", "WEAK"}
            and visibility in {"DEFAULT", "PROTECTED"}
            and section != "UND"
            and name
        ):
            public += 1
    if not tables:
        raise InventoryError("readelf produced no dynamic symbol table count")
    return {"tables": tables, "public_defined": public}


def elf_inventory(path: Path) -> dict[str, Any]:
    header = parse_header(readelf(path, "-hW"))
    program_headers = parse_program_headers(readelf(path, "-lW"))
    dynamic = parse_dynamic(readelf(path, "-dW"))
    relocations = parse_relocations(readelf(path, "-rW"))
    symbols = parse_dynamic_symbols(readelf(path, "--dyn-syms", "--wide"))
    return {
        "header": header,
        "program_headers": program_headers,
        "program_header_types": {
            kind: sum(header["type"] == kind for header in program_headers)
            for kind in sorted({header["type"] for header in program_headers})
        },
        "dynamic": {
            "tags": dynamic,
            "tag_names": [entry["tag"] for entry in dynamic],
        },
        "relocations": relocations,
        "dynamic_symbols": symbols,
    }


def require_musl_reference(musl_root: Path) -> tuple[Path, Path]:
    lib_dir = musl_root / "lib"
    libc = lib_dir / "libc.so"
    loader = lib_dir / "ld-musl-aarch64.so.1"
    for path in (libc, loader):
        if not path.exists():
            raise InventoryError(f"missing pinned musl reference: {path}")
    if not loader.is_symlink():
        raise InventoryError(f"expected musl loader to be a symlink: {loader}")
    resolved = loader.resolve()
    if resolved != libc.resolve():
        raise InventoryError(f"{loader} does not resolve to its sibling libc.so")
    return libc, loader


def musl_inventory(musl_root: Path) -> bytes:
    libc, loader = require_musl_reference(musl_root)
    elf = elf_inventory(loader)
    report = {
        "schema_version": SCHEMA_VERSION,
        "inventory": "crabc.musl.aarch64.loader-runtime/v1",
        "architecture": ARCHITECTURE,
        "target": TARGET,
        "reference": {
            "musl_version": MUSL_VERSION,
            "musl_tarball_sha256": MUSL_TARBALL_SHA256,
            "loader": {
                "installation_path": "lib/ld-musl-aarch64.so.1",
                "symlink": True,
                "symlink_target": os.readlink(loader),
                "resolved_path": "lib/libc.so",
                "sha256": sha256(loader),
            },
            "libc": {
                "installation_path": "lib/libc.so",
                "sha256": sha256(libc),
            },
        },
        "runtime_contract": {
            "interpreter_basename": "ld-musl-aarch64.so.1",
            "loader_and_libc_are_one_shared_object": True,
            "note": (
                "This is the reference ELF/runtime shape. It is not a claim "
                "that crabc's separate libldso.so has equivalent behavior."
            ),
        },
        "elf": elf,
        "provenance": {
            "script": "compat/scripts/generate-aarch64-loader-inventory.py",
            "commands": [
                "readelf -hW",
                "readelf -lW",
                "readelf -dW",
                "readelf -rW",
                "readelf --dyn-syms --wide",
            ],
        },
    }
    return json_bytes(report)


def source_marker(source: str, marker: str) -> dict[str, Any]:
    return {"marker": marker, "occurrences": source.count(marker)}


# These are intentionally a feature inventory, not a support declaration.  A
# test path means that a test target exists; this generator does not execute it
# and therefore cannot turn a source target into a verified result.
_FEATURES: tuple[dict[str, Any], ...] = (
    {
        "name": "self_relocation",
        "description": "AArch64 _start finds and applies the loader's relative relocations.",
        "markers": ("aarch64 _start", "R_AARCH64_RELATIVE", "run_main"),
        "tests": (),
    },
    {
        "name": "basic_pie_loading",
        "description": "Map a PIE executable, preserve its entry metadata, and transfer control.",
        "markers": ("load_and_jump", "MAP_FIXED", "PT_LOAD"),
        "tests": ("tests/ldso_real_binary.rs", "tests/ldso_interp.rs", "compat/ldso/run.py"),
    },
    {
        "name": "dt_needed_graph",
        "description": "Read DT_NEEDED and load dependent shared objects.",
        "markers": ("DT_NEEDED", "find_library_fd", "load_dso_from_fd"),
        "tests": ("tests/ldso_deps.rs", "compat/ldso/run.py"),
    },
    {
        "name": "symbol_lookup",
        "description": "Resolve symbols across the loaded-object set.",
        "markers": ("resolve_symbol", "lookup_symbol_in_object", "resolve_copy_source"),
        "tests": ("tests/ldso_deps.rs", "compat/ldso/run.py"),
    },
    {
        "name": "constructors",
        "description": "Dispatch init arrays while retaining musl's inert legacy DT_INIT tags.",
        "markers": ("run_constructors", "DT_INIT_ARRAY", "DT_INIT"),
        "tests": ("compat/ldso/run.py",),
    },
    {
        "name": "destructors",
        "description": "Dispatch fini arrays while retaining musl's inert legacy DT_FINI tags.",
        "markers": ("run_destructors_for", "DT_FINI_ARRAY", "DT_FINI"),
        "tests": ("compat/ldso/run.py",),
    },
    {
        "name": "initial_tls",
        "description": "Build the initial TLS image and provide __tls_get_addr.",
        "markers": ("PT_TLS", "compute_tls_layout", "__tls_get_addr"),
        "tests": ("tests/ldso_tls.rs", "compat/ldso/run.py"),
    },
    {
        "name": "late_loaded_tls",
        "description": "Expand thread TLS when a later DSO introduces a TLS module.",
        "markers": ("register_tls_for_new_module", "expand_thread_tls", "TLS_GENERATION"),
        "tests": ("tests/dso_tls.rs", "compat/ldso/run.py"),
    },
    {
        "name": "rpath_runpath_origin",
        "description": "Search RUNPATH/RPATH entries and expand $ORIGIN.",
        "markers": ("DT_RUNPATH", "DT_RPATH", "$ORIGIN"),
        "tests": ("compat/ldso/run.py",),
    },
    {
        "name": "ld_library_path",
        "description": "Search LD_LIBRARY_PATH while resolving dependencies.",
        "markers": ("LD_LIBRARY_PATH", "find_env"),
        "tests": ("tests/ldso_deps.rs", "compat/ldso/run.py"),
    },
    {
        "name": "ld_preload",
        "description": "Honor the LD_PRELOAD interposition contract.",
        "markers": ("LD_PRELOAD",),
        "tests": ("compat/ldso/run.py",),
    },
    {
        "name": "dlopen_dlsym_dlerror",
        "description": "Expose the loader callbacks used by crabc dlopen/dlsym/dlerror.",
        "markers": ("__ldso_dlopen", "__ldso_dlsym", "__ldso_dlerror"),
        "tests": ("compat/ldso/run.py",),
    },
    {
        "name": "dlclose",
        "description": "Close a DSO handle and run musl-compatible finalization.",
        "markers": ("__ldso_dlclose", "run_destructors_for", "finalized"),
        "tests": ("compat/ldso/run.py",),
        "note": "Pinned musl retains a finalized mapping for a later reopen.",
    },
    {
        "name": "dladdr_dl_iterate_phdr",
        "description": "Provide loader introspection APIs for object and program-header enumeration.",
        "markers": ("__ldso_dl_iterate_phdr", "__ldso_dladdr"),
        "tests": ("tests/m4_dynamic_loader_introspection.rs", "compat/ldso/run.py"),
    },
    {
        "name": "sysv_and_gnu_hash",
        "description": "Derive dynamic symbol bounds from SYSV and GNU hash tables.",
        "markers": ("DT_HASH", "DT_GNU_HASH", "sym_count_from_hash", "sym_count_from_gnu_hash"),
        "tests": ("compat/ldso/run.py",),
    },
    {
        "name": "aarch64_relocations",
        "description": "Apply the AArch64 RELA and TLS relocation classes present in the loader.",
        "markers": ("apply_rela_table", "R_AARCH64_ABS64", "R_AARCH64_JUMP_SLOT", "R_AARCH64_TLSDESC"),
        "tests": ("tests/ldso_real_binary.rs", "tests/ldso_tls.rs", "compat/ldso/run.py"),
    },
    {
        "name": "relr",
        "description": "Process DT_RELR compressed relative relocations.",
        "markers": ("DT_RELR", "DT_RELRENT", "apply_relr_table"),
        "tests": ("compat/corpus/run.py",),
        "note": (
            "The M8 corpus requires DT_RELR in real Alpine coreutils package "
            "binaries before it compares pinned musl and crabc outcomes."
        ),
    },
    {
        "name": "relro",
        "description": "Apply final read-only protection to GNU_RELRO ranges.",
        "markers": ("GNU_RELRO", "mprotect"),
        "tests": ("compat/ldso/run.py",),
    },
    {
        "name": "auxv_and_vdso",
        "description": "Preserve startup auxiliary-vector values needed by the runtime.",
        "markers": ("AT_PHDR", "AT_RANDOM", "AT_BASE", "AT_SYSINFO_EHDR"),
        "tests": ("tests/ldso_startup.rs", "compat/ldso/run.py"),
    },
    {
        "name": "vdso_discovery",
        "description": "Preserve and expose the kernel vDSO ELF base through auxv.",
        "markers": ("AT_SYSINFO_EHDR", "build_and_jump"),
        "tests": ("compat/ldso/run.py",),
    },
)


def feature_records(source: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for spec in _FEATURES:
        marker_records = [source_marker(source, marker) for marker in spec["markers"]]
        markers_present = bool(marker_records) and all(
            record["occurrences"] > 0 for record in marker_records
        )
        test_records = []
        for test in spec["tests"]:
            path = REPO_ROOT / test
            test_records.append({"path": test, "exists": path.is_file()})
        tests_present = bool(test_records) and all(record["exists"] for record in test_records)
        state = spec.get("state")
        if state is None:
            if not markers_present:
                state = "not_evidenced"
            elif tests_present:
                state = "source_and_test_target"
            else:
                state = "source_only"
        record = {
            "name": spec["name"],
            "description": spec["description"],
            "state": state,
            "source_markers": marker_records,
            "test_targets": test_records,
            "runtime_test_executed": False,
            "verified": False,
        }
        if "note" in spec:
            record["note"] = spec["note"]
        records.append(record)
    return records


def crabc_inventory(ldso: Path, source_path: Path) -> bytes:
    if not ldso.is_file():
        raise InventoryError(f"crabc loader not found: {ldso}")
    if not source_path.is_file():
        raise InventoryError(f"crabc loader source not found: {source_path}")
    elf = elf_inventory(ldso)
    source = source_path.read_text(encoding="utf-8")
    report = {
        "schema_version": SCHEMA_VERSION,
        "inventory": "crabc.loader.aarch64.features/v1",
        "architecture": ARCHITECTURE,
        "target": TARGET,
        "verification": {
            "verified": False,
            "runtime_tests_executed": False,
            "state_vocabulary": {
                "source_and_test_target": "Source markers and a test target are present; no test pass is asserted.",
                "source_only": "Source markers are present; no focused test target is recorded.",
                "surface_only": "A name or constant exists, but implementation evidence is intentionally insufficient.",
                "not_evidenced": "No implementation marker was found in the inspected source.",
            },
            "note": (
                "This inventory is evidence about the current crabc tree, not a "
                "musl parity claim. Run the documented native AArch64 tests to "
                "produce runtime evidence; this generator never marks a feature verified."
            ),
        },
        "candidate": {
            "artifact": "target/debug/libldso.so",
            "sha256": sha256(ldso),
            "source": "ldso/src/lib.rs",
            "source_sha256": sha256(source_path),
            "elf": elf,
        },
        "features": feature_records(source),
        "provenance": {
            "script": "compat/scripts/generate-aarch64-loader-inventory.py",
            "readelf_commands": [
                "readelf -hW",
                "readelf -lW",
                "readelf -dW",
                "readelf -rW",
                "readelf --dyn-syms --wide",
            ],
        },
    }
    return json_bytes(report)


def json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--musl-root", type=Path, default=DEFAULT_MUSL_ROOT)
    parser.add_argument("--crabc-ldso", type=Path, default=DEFAULT_CRABC_LDSO)
    parser.add_argument("--crabc-source", type=Path, default=DEFAULT_CRABC_SOURCE)
    parser.add_argument("--musl-output", type=Path, default=DEFAULT_MUSL_OUTPUT)
    parser.add_argument("--crabc-output", type=Path, default=DEFAULT_CRABC_OUTPUT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="regenerate both reports in memory and compare them without writing",
    )
    return parser.parse_args()


def main() -> int:
    args = arguments()
    try:
        generated = {
            args.musl_output: musl_inventory(args.musl_root),
            args.crabc_output: crabc_inventory(args.crabc_ldso, args.crabc_source),
        }
        if args.check:
            failures = []
            for path, content in generated.items():
                if not path.is_file():
                    failures.append(f"missing {path}")
                elif path.read_bytes() != content:
                    failures.append(f"different {path}")
            if failures:
                for failure in failures:
                    print(f"loader inventory check failed: {failure}", file=sys.stderr)
                return 1
            print("AArch64 loader inventories are reproducible")
            return 0

        for path, content in generated.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            print(f"wrote {path} ({len(content)} bytes)")
        return 0
    except InventoryError as error:
        print(f"loader inventory error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
