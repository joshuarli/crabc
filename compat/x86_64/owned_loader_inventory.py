#!/usr/bin/env python3
"""Collect and replay native x86-64 loader inventory evidence.

The collector reads one supplied, materialized owned-dynamic product.  Its
source selection comes from that product's compiler-produced
``loader.provenance.json``; it never guesses an active loader from a directory
walk.  It retains raw ``readelf`` streams beneath ``.work`` and the reader
replays their hashes and parsed shapes without executing a host tool.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.rust_toolchain import pinned_toolchain
sys.path.insert(0, str(ROOT / "compat" / "x86_64"))
import crabc_cc_owned_dynamic as installed_driver
import owned_dynamic_qualification as qualification


SCHEMA = "crabc.x86_64-owned-loader-inventory/v1"
PROVENANCE_SCHEMA = "crabc.x86_64-owned-loader-provenance/v1"
TARGET = "x86_64-unknown-linux-musl"
LOADER_PATH = "lib/ld-crabc-x86_64.so.1"
LOADER_ALIAS_PATH = "lib/ld-musl-x86_64.so.1"
LIBC_PATH = "usr/lib/libc.so"
LOADER_PROVENANCE_PATH = "share/crabc/loader.provenance.json"
LOADER_FEATURE = "x86_64-owned-dynamic-runtime"
LOADER_RUSTFLAGS = "-C link-dead-code -C target-feature=-crt-static -C relocation-model=pic"
# Both scripts affect the installed loader and belong to its compiler input roster.
LOADER_LINKER_SCRIPTS = (
    "libc/src/c_abi/x86_64/owned_discard_unwind.ld",
    "ldso/x86_64-owned-bss-layout.ld",
)
PINNED_TOOLCHAIN = pinned_toolchain(ROOT)
CONFIGURATION_PATHS = (
    "scripts/build_x86_64_owned_dynamic_sysroot.py",
    "scripts/build_x86_64_owned_sysroot.py",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    ".cargo/config.toml",
    "ldso/Cargo.toml",
    *LOADER_LINKER_SCRIPTS,
)
RAW_STREAMS = (
    ("header", ("-hW",)),
    ("program_headers", ("-lW",)),
    ("dynamic", ("-dW",)),
    ("relocations", ("-rW",)),
    ("dynamic_symbols", ("--dyn-syms", "--wide")),
)
SUBJECTS = ("musl-loader", "candidate-loader", "candidate-libc")
MUSL_LOADER_PATH = "lib/ld-musl-x86_64.so.1"

_RELOC_SECTION = re.compile(
    r"^Relocation section '([^']+)'[^\n]*contains (\d+) entr(?:y|ies)"
    r"(?: which relocate (\d+) locations)?:$"
)
_RELOC_TYPE = re.compile(r"\b(R_[A-Z0-9_]+)\b")
_RELR_ENTRY = re.compile(r"^\s*(?:0x)?[0-9a-fA-F]+\b")
_RELR_SUMMARY = re.compile(r"^\s*(\d+)\s+offsets?\s*$")
_RELR_INDEX_HEADER = re.compile(r"^Index:\s+Entry\s+Address\s+Symbolic Address\s*$")
_RELR_INDEX_ROW = re.compile(r"^([0-9]+):\s+[0-9a-fA-F]{16}\s+[0-9a-fA-F]{16}(?:\s+.*)?$")
_RELR_EXPANDED_ROW = re.compile(r"^\s+[0-9a-fA-F]{16}(?:\s+.*)?$")
_DYNAMIC = re.compile(r"^\s*(0x[0-9a-fA-F]+)\s+\(([^)]+)\)\s+(.*)$")
_DYNSYM_COUNT = re.compile(r"^Symbol table '([^']+)' contains (\d+) entr(?:y|ies):")
_RELOC_HEADER = re.compile(r"^\s*Offset\s+Info\s+Type\b")
_DYNSYM_HEADER = re.compile(r"^\s*Num:\s+Value\s+Size\s+Type\s+Bind\s+Vis\s+Ndx\s+Name\s*$")
_DYNSYM_ROW = re.compile(r"^\s*\d+:\s+")
_PROGRAM_HEADER_COUNT = re.compile(r"^There are (\d+) program headers, starting at offset \d+$")
_PROGRAM_HEADER_TABLE = re.compile(r"^\s*Type\s+Offset\s+VirtAddr\s+PhysAddr\s+FileSiz\s+MemSiz\s+Flg\s+Align\s*$")
_DYNAMIC_SECTION = re.compile(r"^Dynamic section at offset 0x[0-9a-fA-F]+ contains (\d+) entr(?:y|ies):$")
_DYNAMIC_TABLE = re.compile(r"^\s*Tag\s+Type\s+Name/Value\s*$")


class InventoryError(RuntimeError):
    """An input, receipt, or recorded observable does not meet the contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InventoryError(message)


def _physical(path: Path, description: str) -> Path:
    path = path.absolute()
    try:
        details = path.lstat()
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise InventoryError(f"{description} is missing or unsafe: {path}") from error
    if not stat.S_ISREG(details.st_mode) or path.is_symlink() or resolved != path:
        raise InventoryError(f"{description} is not a physical regular file: {path}")
    return path


def digest(path: Path, description: str = "payload") -> str:
    path = _physical(path, description)
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def checkout_path(path: Path, description: str) -> tuple[Path, str]:
    path = path.absolute()
    require(path.resolve() == path and path.is_relative_to(ROOT), f"{description} escapes this checkout")
    return path, path.relative_to(ROOT).as_posix()


def evidence_path(path: Path, description: str) -> tuple[Path, str]:
    path, relative = checkout_path(path, description)
    require(path.is_relative_to(ROOT / ".work"), f"{description} must remain below checkout .work")
    return path, relative


def source_identity(path: Path, description: str) -> dict[str, object]:
    path, relative = checkout_path(path, description)
    return {
        "path": relative,
        "sha256": digest(path, description),
        "mode": stat.S_IMODE(path.stat().st_mode),
    }


def product_identity(product: Path, relative: str, description: str) -> dict[str, object]:
    path = _physical(product / relative, description)
    return {
        "path": relative,
        "sha256": digest(path, description),
        "mode": stat.S_IMODE(path.stat().st_mode),
    }


def read_json(path: Path, description: str) -> dict[str, Any]:
    try:
        value = json.loads(_physical(path, description).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InventoryError(f"{description} is not valid JSON: {path}") from error
    require(isinstance(value, dict), f"{description} must be an object")
    return value


def require_identity(value: object, path: Path, expected_path: str, description: str) -> None:
    require(isinstance(value, dict) and set(value) == {"path", "sha256", "mode"}, f"{description} fields drifted")
    require(value == {
        "path": expected_path,
        "sha256": digest(path, description),
        "mode": stat.S_IMODE(_physical(path, description).stat().st_mode),
    }, f"{description} identity differs")


def require_source_identity(value: object, description: str) -> dict[str, object]:
    require(isinstance(value, dict) and set(value) == {"path", "sha256", "mode"}, f"{description} fields drifted")
    path_name = value.get("path")
    require(isinstance(path_name, str) and path_name and not Path(path_name).is_absolute(), f"{description} path is invalid")
    path, relative = checkout_path(ROOT / path_name, description)
    expected = source_identity(path, description)
    require(relative == path_name and value == expected, f"{description} identity differs")
    return expected


def load_loader_provenance(product: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate the installed compiler-derived source selection and Cargo config."""

    try:
        manifest = installed_driver.validate(product)
    except installed_driver.shared.DriverError as error:
        raise InventoryError(f"supplied product is not an installed owned dynamic product: {error}") from error
    try:
        qualification.product_identity(product)
    except (qualification.QualificationError, OSError) as error:
        raise InventoryError(f"supplied product source or materialization is stale: {error}") from error
    require(LOADER_PROVENANCE_PATH in manifest["files"], "supplied product lacks loader compiler provenance")
    path = product / LOADER_PROVENANCE_PATH
    require(manifest["files"][LOADER_PROVENANCE_PATH] == digest(path, "loader compiler provenance"),
            "manifest does not bind loader compiler provenance")
    record = read_json(path, "loader compiler provenance")
    require(set(record) == {"schema", "target", "artifact", "cargo", "compiler_dependencies", "configuration"},
            "loader compiler provenance fields drifted")
    require(record["schema"] == PROVENANCE_SCHEMA and record["target"] == TARGET,
            "loader compiler provenance schema or target differs")
    require_identity(record["artifact"], product / LOADER_PATH, LOADER_PATH, "installed loader")
    cargo = record["cargo"]
    require(isinstance(cargo, dict) and set(cargo) == {"argv", "rustflags"}, "loader Cargo provenance fields drifted")
    tools = read_json(product / "share/crabc/producer-tools.json", "producer tool identity")
    rustup = tools.get("rustup") if isinstance(tools, dict) else None
    rustup_path = rustup.get("path") if isinstance(rustup, dict) else None
    require(isinstance(rustup_path, str) and rustup_path, "producer tool identity lacks rustup path")
    expected_argv = [
        rustup_path, "run", PINNED_TOOLCHAIN, "cargo", "build", "--locked", "-p", "crabc-ldso", "--release",
        "--config", 'profile.release.opt-level="s"',
        "--target", TARGET, "--target-dir", "$BUILD/loader", "--no-default-features", "--features", LOADER_FEATURE,
    ]
    expected_rustflags = LOADER_RUSTFLAGS + "".join(
        f" -C link-arg=-Wl,-T,{ROOT / script}" for script in LOADER_LINKER_SCRIPTS
    )
    require(cargo == {"argv": expected_argv, "rustflags": expected_rustflags},
            "loader Cargo command or RUSTFLAGS differ")

    dependencies = record["compiler_dependencies"]
    require(isinstance(dependencies, list) and dependencies, "loader compiler dependency roster is empty")
    dependency_names: list[str] = []
    for entry in dependencies:
        identity = require_source_identity(entry, "loader compiler dependency")
        name = identity["path"]
        require(isinstance(name, str) and name.startswith("ldso/"), "loader compiler dependency escapes ldso")
        dependency_names.append(name)
    require(dependency_names == sorted(dependency_names) and len(dependency_names) == len(set(dependency_names)),
            "loader compiler dependency roster is not sorted and unique")
    require({"ldso/build.rs", "ldso/src/lib.rs"} <= set(dependency_names),
            "loader compiler dependency roster lacks build.rs or lib.rs")

    configuration = record["configuration"]
    require(isinstance(configuration, list) and len(configuration) == len(CONFIGURATION_PATHS),
            "loader configuration roster differs")
    configuration_names: list[str] = []
    for entry in configuration:
        identity = require_source_identity(entry, "loader configuration")
        configuration_names.append(str(identity["path"]))
    require(tuple(configuration_names) == CONFIGURATION_PATHS, "loader configuration roster differs")
    return manifest, record


def capture_bindings(product: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    product, product_relative = evidence_path(product, "supplied product")
    manifest, provenance = load_loader_provenance(product)
    alias = product / LOADER_ALIAS_PATH
    require(alias.is_symlink() and os.readlink(alias) == Path(LOADER_PATH).name,
            "supplied product loader alias differs")
    try:
        require(alias.resolve(strict=True) == (product / LOADER_PATH).resolve(strict=True),
                "supplied product loader alias does not resolve to its loader")
    except OSError as error:
        raise InventoryError("supplied product loader alias cannot be resolved") from error
    product_snapshot = {
        "root": product_relative,
        "manifest_sha256": digest(product / "share/crabc/manifest.json", "product manifest"),
        "state": product_identity(product, "share/crabc/dynamic-product-state.json", "product state"),
        "loader": product_identity(product, LOADER_PATH, "installed loader"),
        "loader_alias": {"path": LOADER_ALIAS_PATH, "target": os.readlink(alias)},
        "libc": product_identity(product, LIBC_PATH, "installed libc"),
        "loader_provenance": product_identity(product, LOADER_PROVENANCE_PATH, "loader compiler provenance"),
    }
    require(product_snapshot["manifest_sha256"] == qualification.product_identity(product),
            "product manifest identity differs")
    source_snapshot = {
        "source_sha256": qualification.source_digest(),
        "loader_provenance_sha256": product_snapshot["loader_provenance"]["sha256"],
        "compiler_dependencies": provenance["compiler_dependencies"],
        "configuration": provenance["configuration"],
    }
    return product_snapshot, source_snapshot, provenance


def tool_identity(path: Path) -> dict[str, object]:
    path = _physical(path, "readelf")
    require(path.stat().st_mode & 0o111, "readelf is not executable")
    return {"path": str(path), "sha256": digest(path, "readelf"), "mode": stat.S_IMODE(path.stat().st_mode)}


def write_capture(path: Path, value: dict[str, Any], description: str) -> dict[str, Any]:
    """Publish one native input identity for later offline host replay."""

    path, relative = evidence_path(path, description)
    require(not path.exists() and not path.is_symlink(), f"{description} already exists")
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
    path.chmod(0o444)
    return {"path": relative, "sha256": digest(path, description), "identity": value}


def oracle_capture(capture_root: Path, requested_root: Path) -> dict[str, Any]:
    """Retain the existing pinned-oracle proof before observing its loader ELF."""

    expected_root = qualification.ORACLE_FILES["runtime"].parents[1]
    require(requested_root.absolute() == expected_root, "loader inventory requires the pinned musl oracle root")
    try:
        identity = qualification.capture_oracle(capture_root)
        qualification.validate_oracle(capture_root, identity)
        qualification.require_live_oracle(capture_root, identity)
    except (qualification.QualificationError, OSError) as error:
        raise InventoryError(f"pinned musl oracle preparation differs: {error}") from error
    return write_capture(
        capture_root / "oracle-capture.json",
        {
            "schema": "crabc.x86_64-owned-loader-inventory-oracle-capture/v1",
            "oracle": identity,
            "loader_alias": oracle_loader_alias(requested_root, identity),
        },
        "pinned musl oracle capture",
    )


def oracle_loader_alias(oracle_root: Path, oracle: Mapping[str, Any]) -> dict[str, object]:
    """Bind musl's conventional loader spelling to the validated runtime bytes."""

    runtime = qualification.ORACLE_FILES["runtime"]
    require(oracle_root.absolute() == runtime.parents[1], "loader inventory requires the pinned musl oracle root")
    alias = oracle_root / MUSL_LOADER_PATH
    try:
        require(alias.is_symlink(), "pinned musl loader is not its conventional alias")
        target = os.readlink(alias)
        require(target == str(runtime) and alias.resolve(strict=True) == runtime,
                "pinned musl loader alias does not resolve to libc.so")
    except OSError as error:
        raise InventoryError("pinned musl loader alias cannot be resolved") from error
    runtime_hash = oracle.get("runtime_sha256")
    require(isinstance(runtime_hash, str) and digest(runtime, "pinned musl runtime") == runtime_hash,
            "pinned musl loader alias does not bind the validated runtime")
    return {
        "path": MUSL_LOADER_PATH,
        "target": target,
        "sha256": runtime_hash,
        "mode": stat.S_IMODE(_physical(runtime, "pinned musl runtime").stat().st_mode),
    }


def readelf_capture(capture_root: Path, readelf: Path) -> dict[str, Any]:
    return write_capture(
        capture_root / "readelf-capture.json",
        {"schema": "crabc.x86_64-owned-loader-inventory-readelf-capture/v1", "readelf": tool_identity(readelf)},
        "readelf identity capture",
    )


def field(output: str, label: str) -> str | None:
    prefix = label + ":"
    for line in output.splitlines():
        if line.strip().startswith(prefix):
            return line.split(":", 1)[1].strip()
    return None


def parse_header(output: str) -> dict[str, str | None]:
    values = {
        "class": field(output, "Class"), "data": field(output, "Data"), "version": field(output, "Version"),
        "os_abi": field(output, "OS/ABI"), "type": field(output, "Type"), "machine": field(output, "Machine"),
        "entry_point": field(output, "Entry point address"), "program_header_offset": field(output, "Start of program headers"),
        "program_header_entry_size": field(output, "Size of program headers"),
        "program_header_count": field(output, "Number of program headers"),
        "section_header_count": field(output, "Number of section headers"),
    }
    require(values["class"] == "ELF64", "readelf header is not ELF64")
    require(values["data"] == "2's complement, little endian", "readelf header is not little-endian")
    require(values["machine"] == "Advanced Micro Devices X86-64", "readelf header is not x86-64")
    require(all(value is not None for value in values.values()), "readelf header is incomplete")
    return values


def parse_program_headers(output: str) -> dict[str, Any]:
    """Retain every parseable program-header type and close the readelf table."""

    declared_entries: int | None = None
    headers: list[dict[str, str]] = []
    in_table = False
    table_header = False
    section_mapping = False
    for line in output.splitlines():
        if (match := _PROGRAM_HEADER_COUNT.match(line)) is not None:
            require(declared_entries is None and not in_table, "readelf program-header stream has duplicate counts")
            declared_entries = int(match.group(1))
            continue
        if line.strip() == "Program Headers:":
            require(declared_entries is not None and not in_table, "readelf program-header stream is malformed")
            in_table = True
            continue
        if in_table and line.strip() == "Section to Segment mapping:":
            require(table_header, "readelf program-header table has no header")
            in_table = False
            section_mapping = True
            continue
        if not in_table:
            continue
        if not line.strip():
            continue
        if _PROGRAM_HEADER_TABLE.match(line):
            require(not table_header, "readelf program-header table has duplicate headers")
            table_header = True
            continue
        require(table_header, "readelf program-header table has an unscoped row")
        parts = line.split()
        require(len(parts) >= 7 and all(re.fullmatch(r"0x[0-9a-fA-F]+", part) is not None for part in parts[1:6])
                and re.fullmatch(r"(?:0x[0-9a-fA-F]+|\d+)", parts[-1]) is not None,
                "readelf program-header row is malformed")
        headers.append({
            "type": parts[0], "offset": parts[1], "virtual_address": parts[2], "physical_address": parts[3],
            "file_size": parts[4], "memory_size": parts[5], "flags": "".join(parts[6:-1]), "alignment": parts[-1],
        })
    require(declared_entries is not None and table_header and section_mapping,
            "readelf program-header stream is incomplete")
    require(declared_entries == len(headers), "readelf program-header stream is truncated")
    return {"declared_entries": declared_entries, "observed_entries": len(headers), "entries": headers}


def parse_dynamic(output: str) -> dict[str, Any]:
    """Parse exactly the rows declared by GNU readelf's dynamic-table header."""

    declared_entries: int | None = None
    table_header = False
    tags: list[dict[str, str]] = []
    for line in output.splitlines():
        if (section := _DYNAMIC_SECTION.match(line)) is not None:
            require(declared_entries is None, "readelf dynamic stream has duplicate counts")
            declared_entries = int(section.group(1))
            continue
        if not line.strip():
            continue
        if _DYNAMIC_TABLE.match(line):
            require(declared_entries is not None and not table_header, "readelf dynamic stream is malformed")
            table_header = True
            continue
        match = _DYNAMIC.match(line)
        require(match is not None and table_header, "readelf dynamic stream is malformed")
        value, name, detail = match.groups()
        tags.append({"tag": name, "tag_value": value, "value": detail.strip()})
    require(declared_entries is not None and table_header, "readelf dynamic stream is incomplete")
    require(declared_entries == len(tags), "readelf dynamic stream is truncated")
    return {"declared_entries": declared_entries, "observed_entries": len(tags), "tags": tags}


def parse_relocations(output: str) -> dict[str, Any]:
    if output.strip() == "There are no relocations in this file.":
        return {"sections": [], "types": {}, "entries": 0}
    sections: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    indexed_relr = False
    relr_header_seen = False
    for line in output.splitlines():
        match = _RELOC_SECTION.match(line)
        if match is not None:
            indexed_relr = match.group(3) is not None
            relr_header_seen = False
            require(not indexed_relr or match.group(1).startswith(".relr"),
                    "readelf relocation stream is malformed")
            current = {
                "name": match.group(1),
                "declared_entries": int(match.group(2)),
                "observed_entries": 0,
                "types": {},
            }
            if indexed_relr:
                current["encoded_entries"] = 0
                current["expanded_offsets"] = int(match.group(3))
            sections.append(current)
            continue
        if current is None:
            require(not line.strip(), "readelf relocation stream is malformed")
            continue
        if not line.strip():
            continue
        if indexed_relr:
            if _RELR_INDEX_HEADER.match(line):
                require(not relr_header_seen and not current["observed_entries"],
                        "readelf RELR stream is malformed")
                relr_header_seen = True
            elif (indexed := _RELR_INDEX_ROW.match(line)) is not None:
                require(relr_header_seen and int(indexed.group(1)) == current["encoded_entries"],
                        "readelf RELR stream is malformed")
                current["encoded_entries"] += 1
                current["observed_entries"] += 1
            elif _RELR_EXPANDED_ROW.match(line):
                require(relr_header_seen and current["encoded_entries"] > 0,
                        "readelf RELR stream is malformed")
                current["observed_entries"] += 1
            else:
                raise InventoryError("readelf RELR stream is malformed")
        elif (kind := _RELOC_TYPE.search(line)) is not None:
            relocation = kind.group(1)
            current["observed_entries"] += 1
            current["types"][relocation] = current["types"].get(relocation, 0) + 1
        elif current["name"].startswith(".relr"):
            if (summary := _RELR_SUMMARY.match(line)) is not None:
                require("expanded_offsets" not in current, "readelf RELR stream has duplicate offset summaries")
                current["expanded_offsets"] = int(summary.group(1))
            elif _RELR_ENTRY.match(line) is not None:
                current["observed_entries"] += 1
            else:
                raise InventoryError("readelf RELR stream is malformed")
        elif not _RELOC_HEADER.match(line):
            raise InventoryError("readelf relocation stream is malformed")
    require(sections, "readelf relocation stream is malformed")
    for section in sections:
        if section["name"].startswith(".relr"):
            if "encoded_entries" in section:
                require(section["encoded_entries"] == section["declared_entries"],
                        "readelf RELR stream is truncated")
            require(section.get("expanded_offsets") == section["observed_entries"],
                    "readelf RELR stream is truncated")
        else:
            require(section["declared_entries"] == section["observed_entries"],
                    "readelf relocation stream is truncated")
    types: dict[str, int] = {}
    for section in sections:
        for relocation, count in section["types"].items():
            types[relocation] = types.get(relocation, 0) + count
    return {"sections": sections, "types": dict(sorted(types.items())), "entries": sum(section["observed_entries"] for section in sections)}


def parse_dynamic_symbols(output: str) -> dict[str, Any]:
    tables: dict[str, int] = {}
    observed: dict[str, int] = {}
    current: str | None = None
    public = 0
    for line in output.splitlines():
        if (match := _DYNSYM_COUNT.match(line)) is not None:
            current = match.group(1)
            require(current not in tables, "readelf dynamic symbol stream has duplicate tables")
            tables[current] = int(match.group(2))
            observed[current] = 0
            continue
        if not line.strip():
            continue
        if _DYNSYM_HEADER.match(line):
            require(current is not None, "readelf dynamic symbol stream has an unscoped header")
            continue
        if not _DYNSYM_ROW.match(line):
            raise InventoryError("readelf dynamic symbol stream is malformed")
        require(current is not None, "readelf dynamic symbol stream has an unscoped row")
        fields = line.split(None, 7)
        require(len(fields) >= 7, "readelf dynamic symbol stream has a malformed row")
        observed[current] += 1
        binding, visibility, section = fields[4:7]
        name = fields[7].strip() if len(fields) > 7 else ""
        if binding in {"GLOBAL", "WEAK"} and visibility in {"DEFAULT", "PROTECTED"} and section != "UND" and name:
            public += 1
    require(tables, "readelf produced no dynamic symbol table count")
    require(tables == observed, "readelf dynamic symbol stream is truncated")
    return {"tables": tables, "public_defined": public}


def shape(streams: Mapping[str, str]) -> dict[str, Any]:
    require(set(streams) == {name for name, _ in RAW_STREAMS}, "readelf stream roster differs")
    header = parse_header(streams["header"])
    program_headers = parse_program_headers(streams["program_headers"])
    dynamic = parse_dynamic(streams["dynamic"])
    require(re.fullmatch(r"\d+", str(header["program_header_count"])) is not None
            and int(str(header["program_header_count"])) == program_headers["declared_entries"],
            "ELF and readelf program-header counts differ")
    return {
        "header": header,
        "program_headers": program_headers,
        "program_header_types": {
            name: sum(entry["type"] == name for entry in program_headers["entries"])
            for name in sorted({entry["type"] for entry in program_headers["entries"]})
        },
        "dynamic": {
            "declared_entries": dynamic["declared_entries"],
            "observed_entries": dynamic["observed_entries"],
            "tags": dynamic["tags"],
            "tag_names": [tag["tag"] for tag in dynamic["tags"]],
        },
        "relocations": parse_relocations(streams["relocations"]),
        "dynamic_symbols": parse_dynamic_symbols(streams["dynamic_symbols"]),
    }


def run_readelf(readelf: Path, arguments: Sequence[str], subject: Path) -> bytes:
    try:
        result = subprocess.run([str(readelf), *arguments, str(subject)], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except OSError as error:
        raise InventoryError(f"cannot execute readelf: {readelf}") from error
    if result.returncode != 0:
        raise InventoryError(f"readelf failed for {subject}: {result.stderr.decode(errors='replace').strip()}")
    require(result.stdout, f"readelf produced an empty stream for {subject}")
    return result.stdout


def capture_elf(
    readelf: Path,
    subject_name: str,
    subject: Path,
    subject_binding: dict[str, str],
    raw_root: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    streams: dict[str, str] = {}
    records: list[dict[str, Any]] = []
    for stream_name, arguments in RAW_STREAMS:
        payload = run_readelf(readelf, arguments, subject)
        destination = raw_root / f"{subject_name}.{stream_name}.txt"
        with destination.open("xb") as output:
            output.write(payload)
        destination.chmod(0o444)
        _, relative = evidence_path(destination, "raw readelf stream")
        records.append({
            "subject": subject_name,
            "subject_binding": subject_binding,
            "stream": stream_name,
            "arguments": list(arguments),
            "path": relative,
            "sha256": digest(destination, "raw readelf stream"),
            "byte_length": len(payload),
        })
        try:
            streams[stream_name] = payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise InventoryError(f"readelf produced non-text output for {subject_name}/{stream_name}") from error
    return shape(streams), records


def subject_binding(identity: Mapping[str, Any], description: str) -> dict[str, str]:
    path, source_hash = identity.get("path"), identity.get("sha256")
    require(isinstance(path, str) and isinstance(source_hash, str), f"{description} identity is invalid")
    return {"path": path, "sha256": source_hash}


_FEATURES: tuple[dict[str, object], ...] = (
    {
        "name": "compiler_selected_loader_closure",
        "description": "Cargo's dep-info selects the bounded x86 loader closure for the installed artifact.",
        "sources": None,
        "targets": ("ldso/src/x86_64_general_initial_tls_runtime_v1_source_root.rs",),
    },
    {
        "name": "installed_conventional_startup",
        "description": "The installed loader selects conventional startup, direct entry, and owned library search sources.",
        "sources": ("ldso/src/x86_64_conventional_startup_v1.rs", "ldso/src/x86_64_direct_entry.rs", "ldso/src/x86_64_library_search.rs"),
        "targets": ("compat/x86_64/run_owned_loader_synthetic.sh",),
    },
    {
        "name": "runtime_object_registry",
        "description": "The installed source closure selects registry, lock, memory, and worker-TLS runtime state.",
        "sources": ("ldso/src/x86_64_runtime_registry.rs", "ldso/src/x86_64_runtime_lock.rs",
                    "ldso/src/x86_64_runtime_memory.rs", "ldso/src/x86_64_initial_worker_tls.rs"),
        "targets": ("ldso/src/x86_64_runtime_registry_tests.rs", "compat/x86_64/run_owned_loader_synthetic.sh"),
    },
)


def feature_rows(source: Mapping[str, Any]) -> list[dict[str, Any]]:
    selected = source.get("compiler_dependencies")
    require(isinstance(selected, list), "compiler source selection is missing")
    by_name = {entry.get("path"): entry for entry in selected if isinstance(entry, dict)}
    require(len(by_name) == len(selected), "compiler source selection has duplicate paths")
    rows = []
    for feature in _FEATURES:
        wanted = tuple(by_name) if feature["sources"] is None else feature["sources"]
        require(isinstance(wanted, tuple), "feature source roster is invalid")
        sources = []
        for name in wanted:
            entry = by_name.get(name)
            require(isinstance(entry, dict), f"compiler selection lacks feature source: {name}")
            sources.append(entry)
        targets = [source_identity(ROOT / name, "feature target") for name in feature["targets"]]
        rows.append({
            "name": feature["name"], "description": feature["description"], "selected_sources": sources,
            "targets": targets, "runtime_test_executed": False, "verified": False,
        })
    return rows


def write_receipt(path: Path, value: dict[str, Any]) -> None:
    path, _ = evidence_path(path, "inventory receipt")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
    except FileExistsError as error:
        raise InventoryError(f"inventory receipt already exists: {path}") from error
    path.chmod(0o444)


def collect(product: Path, oracle_root: Path, output: Path, readelf: Path) -> dict[str, Any]:
    """Capture one physical product and pinned-musl ELF inventory without running it."""

    product, _ = evidence_path(product, "supplied product")
    output, _ = evidence_path(output, "inventory receipt")
    require(not output.exists() and not output.is_symlink(), "inventory receipt path already exists")
    raw_root = output.parent / (output.name + ".raw")
    raw_root, _ = evidence_path(raw_root, "raw readelf directory")
    require(not raw_root.exists() and not raw_root.is_symlink(), "raw readelf directory already exists")
    capture_root = output.parent / (output.name + ".inputs")
    capture_root, _ = evidence_path(capture_root, "inventory input capture directory")
    require(not capture_root.exists() and not capture_root.is_symlink(), "inventory input capture directory already exists")
    before_product, before_source, _ = capture_bindings(product)
    capture_root.mkdir(mode=0o700)
    before_oracle = oracle_capture(capture_root, oracle_root)
    before_readelf = readelf_capture(capture_root, readelf)
    raw_root.mkdir(mode=0o700)
    try:
        oracle_identity = before_oracle["identity"].get("oracle")
        oracle_loader = before_oracle["identity"].get("loader_alias")
        require(isinstance(oracle_identity, dict) and isinstance(oracle_identity.get("runtime_sha256"), str)
                and isinstance(oracle_loader, dict), "pinned musl oracle capture is invalid")
        oracle_shape, oracle_raw = capture_elf(
            readelf, "musl-loader", oracle_root / MUSL_LOADER_PATH,
            subject_binding(oracle_loader, "pinned musl loader"), raw_root,
        )
        loader_shape, loader_raw = capture_elf(
            readelf, "candidate-loader", product / LOADER_PATH,
            subject_binding(before_product["loader"], "candidate loader"), raw_root,
        )
        libc_shape, libc_raw = capture_elf(
            readelf, "candidate-libc", product / LIBC_PATH,
            subject_binding(before_product["libc"], "candidate libc"), raw_root,
        )
        after_product, after_source, _ = capture_bindings(product)
        try:
            qualification.require_live_oracle(capture_root, before_oracle["identity"]["oracle"])
        except (qualification.QualificationError, KeyError, TypeError) as error:
            raise InventoryError("pinned musl oracle changed during inventory") from error
        require(oracle_loader_alias(oracle_root, before_oracle["identity"]["oracle"]) == oracle_loader,
                "pinned musl loader alias changed during inventory")
        after_oracle = before_oracle
        try:
            after_readelf_identity = tool_identity(readelf)
        except InventoryError:
            raise
        require(before_readelf["identity"]["readelf"] == after_readelf_identity,
                "readelf changed during inventory")
        after_readelf = before_readelf
        require((before_product, before_source, before_oracle, before_readelf)
                == (after_product, after_source, after_oracle, after_readelf),
                "source, product, oracle, or readelf changed during inventory")
        receipt = {
            "schema": SCHEMA,
            "component": "native-x86-loader-inventory",
            "inventory_complete": True,
            "runtime_test_executed": False,
            "runtime_verified": False,
            "capture": {
                "before": {"product": before_product, "source": before_source, "oracle": before_oracle, "readelf": before_readelf},
                "after": {"product": after_product, "source": after_source, "oracle": after_oracle, "readelf": after_readelf},
            },
            "oracle_shape": oracle_shape,
            "candidate_shapes": {"loader": loader_shape, "libc": libc_shape},
            "raw_readelf": oracle_raw + loader_raw + libc_raw,
            "candidate_features": feature_rows(before_source),
        }
        qualification.make_retained_evidence_readable(capture_root)
        write_receipt(output, receipt)
        for path in raw_root.iterdir():
            path.chmod(0o444)
        raw_root.chmod(0o555)
        return receipt
    except BaseException:
        # A failed collection never leaves a receipt that could look complete.
        if output.exists():
            output.unlink()
        raise


def raw_streams(receipt_path: Path, records: object, bindings: Mapping[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    require(isinstance(records, list) and len(records) == len(SUBJECTS) * len(RAW_STREAMS), "raw readelf roster differs")
    raw_root = receipt_path.parent / (receipt_path.name + ".raw")
    raw_root, _ = evidence_path(raw_root, "raw readelf directory")
    require(raw_root.is_dir() and not raw_root.is_symlink(), "raw readelf directory is missing or unsafe")
    expected_files = {f"{subject}.{stream}.txt" for subject in SUBJECTS for stream, _ in RAW_STREAMS}
    require({entry.name for entry in raw_root.iterdir()} == expected_files, "raw readelf file roster differs")
    streams: dict[str, dict[str, str]] = {subject: {} for subject in SUBJECTS}
    seen: set[tuple[str, str]] = set()
    expected_arguments = dict(RAW_STREAMS)
    for record in records:
        require(isinstance(record, dict) and set(record) == {"subject", "subject_binding", "stream", "arguments", "path", "sha256", "byte_length"},
                "raw readelf record fields drifted")
        subject, stream = record.get("subject"), record.get("stream")
        require(subject in SUBJECTS and stream in expected_arguments and (subject, stream) not in seen,
                "raw readelf record roster differs")
        require(record.get("arguments") == list(expected_arguments[stream]), "raw readelf command differs")
        require(record.get("subject_binding") == bindings[subject], "raw readelf command subject differs")
        path, relative = evidence_path(ROOT / str(record.get("path")), "raw readelf stream")
        expected_relative = (raw_root / f"{subject}.{stream}.txt").relative_to(ROOT).as_posix()
        require(relative == expected_relative and path.is_file() and not path.is_symlink(), "raw readelf stream path differs")
        require(type(record.get("byte_length")) is int and record["byte_length"] > 0
                and path.stat().st_size == record["byte_length"] and digest(path, "raw readelf stream") == record.get("sha256"),
                "raw readelf stream identity differs")
        try:
            streams[subject][stream] = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            raise InventoryError("raw readelf stream is not text") from error
        seen.add((subject, stream))
    require(seen == {(subject, stream) for subject in SUBJECTS for stream, _ in RAW_STREAMS}, "raw readelf records are incomplete")
    return streams


def supplied_oracle_capture(path: Path) -> dict[str, Any]:
    path, relative = evidence_path(path, "supplied pinned musl oracle capture")
    record = read_json(path, "supplied pinned musl oracle capture")
    require(set(record) == {"schema", "oracle", "loader_alias"}
            and record["schema"] == "crabc.x86_64-owned-loader-inventory-oracle-capture/v1"
            and isinstance(record["oracle"], dict) and isinstance(record["loader_alias"], dict),
            "supplied pinned musl oracle capture differs")
    try:
        qualification.validate_oracle(path.parent, record["oracle"])
    except qualification.QualificationError as error:
        raise InventoryError(f"supplied pinned musl oracle capture differs: {error}") from error
    alias = record["loader_alias"]
    runtime_hash = record["oracle"].get("runtime_sha256")
    require(set(alias) == {"path", "target", "sha256", "mode"}
            and alias.get("path") == MUSL_LOADER_PATH
            and alias.get("target") == str(qualification.ORACLE_FILES["runtime"])
            and alias.get("sha256") == runtime_hash and type(alias.get("mode")) is int,
            "supplied pinned musl loader alias differs")
    return {"path": relative, "sha256": digest(path, "supplied pinned musl oracle capture"), "identity": record}


def supplied_readelf_capture(path: Path) -> dict[str, Any]:
    path, relative = evidence_path(path, "supplied readelf identity capture")
    record = read_json(path, "supplied readelf identity capture")
    identity = record.get("readelf") if isinstance(record, dict) else None
    require(set(record) == {"schema", "readelf"}
            and record["schema"] == "crabc.x86_64-owned-loader-inventory-readelf-capture/v1"
            and isinstance(identity, dict) and set(identity) == {"path", "sha256", "mode"}
            and isinstance(identity["path"], str) and Path(identity["path"]).is_absolute()
            and ".." not in Path(identity["path"]).parts
            and isinstance(identity["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", identity["sha256"]) is not None
            and type(identity["mode"]) is int and 0 <= identity["mode"] <= 0o7777
            and identity["mode"] & 0o111, "supplied readelf identity capture differs")
    return {"path": relative, "sha256": digest(path, "supplied readelf identity capture"), "identity": record}


def validate_snapshot_capture(
    capture: object,
    product_root: Path,
    expected_oracle: dict[str, Any],
    expected_readelf: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    require(isinstance(capture, dict) and set(capture) == {"before", "after"}, "capture fields drifted")
    before, after = capture["before"], capture["after"]
    expected_fields = {"product", "source", "oracle", "readelf"}
    require(isinstance(before, dict) and isinstance(after, dict) and set(before) == expected_fields and set(after) == expected_fields,
            "capture boundary fields drifted")
    require(before == after, "capture before/after identities differ")
    product = before["product"]
    supplied_product, supplied_relative = evidence_path(product_root, "supplied product")
    require(isinstance(product, dict) and product.get("root") == supplied_relative,
            "receipt selects a different supplied product")
    actual_product, actual_source, _ = capture_bindings(supplied_product)
    require(product == actual_product and before["source"] == actual_source, "captured source or product is stale")
    oracle = before["oracle"]
    require(oracle == expected_oracle, "captured pinned musl oracle differs from supplied capture")
    readelf = before["readelf"]
    require(readelf == expected_readelf, "captured readelf differs from supplied capture")
    return actual_product, actual_source


def validate_receipt(path: Path, product: Path, oracle_capture_path: Path, readelf_capture_path: Path) -> dict[str, Any]:
    """Replay a retained receipt without executing the candidate or readelf."""

    path, _ = evidence_path(path, "inventory receipt")
    receipt = read_json(path, "inventory receipt")
    expected = {
        "schema", "component", "inventory_complete", "runtime_test_executed", "runtime_verified", "capture",
        "oracle_shape", "candidate_shapes", "raw_readelf", "candidate_features",
    }
    require(set(receipt) == expected, "inventory receipt fields drifted")
    require(receipt["schema"] == SCHEMA and receipt["component"] == "native-x86-loader-inventory", "inventory receipt schema differs")
    require(type(receipt["inventory_complete"]) is bool and receipt["inventory_complete"], "inventory is not complete")
    require(type(receipt["runtime_test_executed"]) is bool and not receipt["runtime_test_executed"], "inventory cannot claim runtime execution")
    require(type(receipt["runtime_verified"]) is bool and not receipt["runtime_verified"], "inventory cannot claim runtime verification")
    expected_oracle = supplied_oracle_capture(oracle_capture_path)
    expected_readelf = supplied_readelf_capture(readelf_capture_path)
    product_snapshot, source = validate_snapshot_capture(receipt["capture"], product, expected_oracle, expected_readelf)
    oracle_identity = expected_oracle["identity"]["oracle"]
    oracle_loader = expected_oracle["identity"]["loader_alias"]
    require(isinstance(oracle_identity, dict) and isinstance(oracle_loader, dict),
            "supplied pinned musl oracle capture lacks loader identity")
    streams = raw_streams(path, receipt["raw_readelf"], {
        "musl-loader": subject_binding(oracle_loader, "pinned musl loader"),
        "candidate-loader": subject_binding(product_snapshot["loader"], "candidate loader"),
        "candidate-libc": subject_binding(product_snapshot["libc"], "candidate libc"),
    })
    require(receipt["oracle_shape"] == shape(streams["musl-loader"]), "pinned musl loader shape differs")
    candidate = receipt["candidate_shapes"]
    require(isinstance(candidate, dict) and set(candidate) == {"loader", "libc"}, "candidate shape fields drifted")
    require(candidate["loader"] == shape(streams["candidate-loader"]), "candidate loader shape differs")
    require(candidate["libc"] == shape(streams["candidate-libc"]), "candidate libc shape differs")
    require(receipt["candidate_features"] == feature_rows(source), "candidate feature rows differ")
    return receipt


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    collect_parser = commands.add_parser("collect", help="capture a supplied installed product")
    collect_parser.add_argument("--product", type=Path, required=True)
    collect_parser.add_argument("--oracle-root", type=Path, default=Path("/opt/musl-1.2.6"))
    collect_parser.add_argument("--output", type=Path, required=True)
    collect_parser.add_argument("--readelf", type=Path, default=Path("/usr/bin/readelf"))
    validate_parser = commands.add_parser("validate", help="replay a retained receipt without executing tools")
    validate_parser.add_argument("--receipt", type=Path, required=True)
    validate_parser.add_argument("--product", type=Path, required=True)
    validate_parser.add_argument("--oracle-capture", type=Path, required=True)
    validate_parser.add_argument("--readelf-capture", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = arguments()
    try:
        if args.command == "collect":
            receipt = collect(args.product, args.oracle_root, args.output, args.readelf)
            print(f"wrote {args.output} ({len(json.dumps(receipt, sort_keys=True))} logical bytes)")
        else:
            validate_receipt(args.receipt, args.product, args.oracle_capture, args.readelf_capture)
            print(f"native loader inventory is valid: {args.receipt}")
        return 0
    except InventoryError as error:
        print(f"native loader inventory error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
