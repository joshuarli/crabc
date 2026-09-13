#!/usr/bin/env python3
"""Collect and replay the installed x86 errno/h_errno storage evidence.

This is deliberately a closed component reader.  It consumes one supplied
static product, one supplied dynamic product, and the raw output of
``run_owned_errno_storage_lifecycle.sh``.  Product readers authenticate the
larger product trees before this reader runs; this reader owns the narrower
accessor, alias, live-worker, and loaded-DSO contract.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping


MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))
import native_abi_inventory as inventory


SCHEMA = "crabc.x86_64-owned-errno-storage-lifecycle/v2"
SNAPSHOT_SCHEMA = "crabc.x86_64-owned-errno-storage-lifecycle-source/v1"
TARGET = "x86_64-unknown-linux-musl"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SYMBOL_LINE = re.compile(
    r"^\s*(\d+):\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$"
)
SYMBOL_TABLE = re.compile(r"^Symbol table '([^']+)' contains \d+ entries:")

ROOT = Path(__file__).resolve().parents[2]
SOURCE_FILES = (
    "libc/src/c_abi/x86_64/errno.rs",
    "libc/src/c_abi/x86_64/owned_errno_private_aliases.list",
    "libc/src/c_abi/x86_64/h_errno.rs",
    "libc/src/c_abi/x86_64/pthread_create_join.rs",
    "libc/src/c_abi/x86_64/static_tls.rs",
    "libc/src/c_abi/x86_64/resolver_runtime.rs",
    "libc/src/c_abi/x86_64/static_c_abi.rs",
    "include/errno.h",
    "include/netdb.h",
    "include/pthread.h",
    "include/dlfcn.h",
    "compat/x86_64/owned_errno_storage_lifecycle.py",
    "compat/x86_64/owned_errno_storage_lifecycle_probe.c",
    "compat/x86_64/owned_errno_storage_lifecycle_dso.c",
    "compat/x86_64/run_owned_errno_storage_lifecycle.sh",
    "compat/x86_64/owned-errno-storage-lifecycle.md",
    "compat/x86_64/tests/test_owned_errno_storage_lifecycle.py",
    "compat/x86_64/native_abi_inventory.py",
    "scripts/build_x86_64_owned_dynamic_sysroot.py",
)

PUBLIC_SYMBOLS = ("__errno_location", "__h_errno_location", "h_errno")
ALIAS = "___errno_location"
SHARED_ALIAS_LIST = "libc/src/c_abi/x86_64/owned_errno_private_aliases.list"
SHARED_ALIAS_LIST_SHA256 = "2e69ec5346002fa183b51dbbbef2f24744bd89093b5cfac6329337c1b3d240dd"
SHARED_ALIAS_MEMBERS = (ALIAS,)
SHARED_ALIAS_LINKER_SCRIPT = "--version-script=$BUILD/libc-errno-private.exports"
SHARED_ALIAS_LINKER_SCRIPT_SHA256 = "22232976d1493ccc5b951b51fbfe912b781c2348e6a8b57360605f46424b7302"
EXPECTED_TRANSCRIPT = b"errno-storage-lifecycle: PASS\n"
RUN_LABELS = (
    "oracle-static-exec",
    "candidate-static-exec",
    "candidate-static-pie",
    "oracle-dynamic-pie-kernel",
    "oracle-dynamic-pie-direct",
    "oracle-dynamic-non-pie-kernel",
    "oracle-dynamic-non-pie-direct",
    "candidate-dynamic-pie-kernel",
    "candidate-dynamic-pie-direct",
    "candidate-dynamic-non-pie-kernel",
    "candidate-dynamic-non-pie-direct",
)
SYMBOL_INPUTS = (
    "oracle-static-symbols.txt",
    "oracle-shared-symbols.txt",
    "oracle-dynamic-symbols.txt",
    "candidate-static-symbols.txt",
    "candidate-shared-symbols.txt",
    "candidate-dynamic-symbols.txt",
)
LAYOUT_INPUTS = (
    "oracle-static-members.txt",
    "oracle-static-header.txt",
    "oracle-static-sections.txt",
    "oracle-shared-header.txt",
    "oracle-shared-sections.txt",
    "candidate-static-members.txt",
    "candidate-static-header.txt",
    "candidate-static-sections.txt",
    "candidate-shared-header.txt",
    "candidate-shared-sections.txt",
)
ORACLE_STATIC_ARCHIVE = "/opt/musl-1.2.6/lib/libc.a"
ORACLE_SHARED_LIBRARY = "/opt/musl-1.2.6/lib/libc.so"
H_ERRNO_METADATA = {
    "type": "OBJECT",
    "binding": "GLOBAL",
    "visibility": "DEFAULT",
    "size_bytes": 4,
    "alignment_bytes": 4,
}
OBJECTS = ("core-static.o", "core-dynamic.o", "plugin.o")
WORKLOAD_SYMBOL_INPUTS = (
    "core-static-symbols.txt",
    "core-dynamic-symbols.txt",
    "plugin-symbols.txt",
)
DYNAMIC_LINKS = {
    "candidate-plugin": ("candidate-plugin.so", "shared"),
    "candidate-dynamic-pie": ("candidate-dynamic-pie", "pie"),
    "candidate-dynamic-non-pie": ("candidate-dynamic-non-pie", "exec"),
}


class ErrnoStorageEvidenceError(RuntimeError):
    """The closed errno/h_errno storage evidence contract was not met."""


def fail(message: str) -> None:
    raise ErrnoStorageEvidenceError(message)


def strict_json_loads(payload: str, description: str) -> Any:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail(f"{description} contains duplicate JSON key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        fail(f"{description} contains non-finite JSON constant {value!r}")

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            fail(f"{description} contains non-finite JSON number {value!r}")
        return parsed

    try:
        return json.loads(
            payload,
            object_pairs_hook=no_duplicates,
            parse_constant=reject_constant,
            parse_float=finite_float,
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise ErrnoStorageEvidenceError(f"{description} is not strict JSON") from error


def physical_regular(path: Path, description: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
        status = path.lstat()
    except OSError as error:
        raise ErrnoStorageEvidenceError(f"{description} is unavailable: {path}") from error
    if path.is_symlink() or not resolved.is_file() or not os.path.isfile(path):
        fail(f"{description} is not a physical regular file: {path}")
    if status.st_nlink != 1:
        fail(f"{description} has an unexpected hard link: {path}")
    return resolved


def physical_directory(path: Path, description: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ErrnoStorageEvidenceError(f"{description} is unavailable: {path}") from error
    if path.is_symlink() or not resolved.is_dir():
        fail(f"{description} is not a physical directory: {path}")
    return resolved


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def identity(path: Path, description: str) -> dict[str, object]:
    physical = physical_regular(path, description)
    return {"path": str(physical), "sha256": sha256(physical), "size_bytes": physical.stat().st_size}


def require_exact_mapping(value: object, keys: set[str], description: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{description} fields drifted")
    return value


def exact_same(left: object, right: object) -> bool:
    """Compare retained JSON values without Python's bool/int equivalence."""

    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(exact_same(value, right[key]) for key, value in left.items())
    if isinstance(left, list):
        return len(left) == len(right) and all(exact_same(a, b) for a, b in zip(left, right))
    return left == right


def validate_identity(value: object, description: str, *, within: Path | None = None) -> Path:
    record = require_exact_mapping(value, {"path", "sha256", "size_bytes"}, description)
    path_value, digest, size = record["path"], record["sha256"], record["size_bytes"]
    if not isinstance(path_value, str) or not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
        fail(f"{description} identity is malformed")
    if type(size) is not int or size < 0:
        fail(f"{description} size is malformed")
    path = physical_regular(Path(path_value), description)
    if within is not None:
        try:
            path.relative_to(within)
        except ValueError:
            fail(f"{description} escapes its evidence root")
    if sha256(path) != digest or path.stat().st_size != size:
        fail(f"{description} bytes changed")
    return path


def read_text(path: Path, description: str) -> str:
    physical = physical_regular(path, description)
    try:
        return physical.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ErrnoStorageEvidenceError(f"{description} is not UTF-8 text") from error


def read_json_object(path: Path, description: str) -> dict[str, Any]:
    value = strict_json_loads(read_text(path, description), description)
    if not isinstance(value, dict):
        fail(f"{description} must be a JSON object")
    return value


def git_output(root: Path, arguments: list[str], description: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=False,
        stdin=subprocess.DEVNULL,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        fail(f"cannot read {description}: {result.stderr.strip()}")
    return result.stdout


def source_snapshot(root: Path) -> dict[str, Any]:
    root = physical_directory(root, "source root")
    files: dict[str, dict[str, object]] = {}
    for relative in SOURCE_FILES:
        files[relative] = identity(root / relative, f"source input {relative}")
    status = git_output(root, ["status", "--porcelain=v1", "--untracked-files=all"], "source status")
    commit = git_output(root, ["rev-parse", "HEAD"], "source revision").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        fail("source revision is malformed")
    return {"schema": SNAPSHOT_SCHEMA, "root": str(root), "commit": commit, "status": status, "files": files}


def validate_source_snapshot(value: object, root: Path, description: str) -> dict[str, Any]:
    record = require_exact_mapping(value, {"schema", "root", "commit", "status", "files"}, description)
    expected = source_snapshot(root)
    if record != expected:
        fail(f"{description} differs from current source")
    if record["status"] != "":
        fail(f"{description} is not clean")
    return record


def _recorded_checkout_root(value: object) -> PurePosixPath:
    """Return the producer's lexical checkout mount without touching that host.

    Native receipts are collected with the checkout mounted at ``/workspace``.
    A later host replay must not require that mount to exist, but it may only
    translate paths that were recorded beneath the sealed checkout root.  The
    original root remains an observation in the retained JSON; this helper
    validates its spelling before any path is rebased.
    """

    if not isinstance(value, str) or not value:
        fail("recorded source root is malformed")
    path = PurePosixPath(value)
    if (
        not path.is_absolute()
        or str(path) != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        fail("recorded source root is unsafe")
    return path


def _rebase_checkout_path(value: str, recorded_root: PurePosixPath, root: Path, description: str) -> str:
    """Translate one lexical descendant of the recorded checkout mount.

    Relative source-policy names and absolute oracle paths deliberately stay
    unchanged.  An absolute path with a dot component is rejected instead of
    being normalized, so a receipt cannot use the mount translation to escape
    its recorded checkout.
    """

    path = PurePosixPath(value)
    if not path.is_absolute():
        return value
    if str(path) != value or any(part in {"", ".", ".."} for part in path.parts):
        fail(f"{description} has an unsafe absolute path")
    if not path.is_relative_to(recorded_root):
        return value
    relative = path.relative_to(recorded_root)
    return str(root.joinpath(*relative.parts))


def _rebase_report_work(value: object, recorded_root: PurePosixPath, root: Path) -> str:
    """Bind a receipt's top-level work root to its recorded checkout mount."""

    if not isinstance(value, str):
        fail("report work path is malformed")
    path = PurePosixPath(value)
    if not path.is_absolute():
        fail("report work path is not absolute")
    if str(path) != value or any(part in {"", ".", ".."} for part in path.parts):
        fail("report work has an unsafe absolute path")
    if not path.is_relative_to(recorded_root):
        fail("report work escapes recorded checkout")
    mapped = root.joinpath(*path.relative_to(recorded_root).parts)
    if not mapped.is_relative_to(root / ".work"):
        fail("report work is not below checkout .work")
    evidence_root = physical_directory(root / ".work", "checkout evidence root")
    try:
        resolved = mapped.resolve(strict=False)
    except OSError as error:
        raise ErrnoStorageEvidenceError("report work cannot resolve") from error
    if not resolved.is_relative_to(evidence_root):
        fail("report work resolves outside checkout .work")
    return str(mapped)


def rebase_report_checkout_paths(value: object, root: Path) -> dict[str, Any]:
    """Rebase retained checkout paths to a physical host checkout for replay.

    Only JSON fields which carry filesystem paths are considered.  The
    top-level evidence root must be a descendant of ``source.root`` and map
    below ``root/.work``. Other checkout descendants are mapped to ``root``;
    outside oracle/tool paths and relative source-policy paths remain
    observations. The caller still validates all resulting physical identities
    and source bytes, so this is path admission rather than a provenance
    fallback.
    """

    if not isinstance(value, dict):
        fail("errno storage report is malformed")
    source = value.get("source")
    if not isinstance(source, dict):
        fail("errno storage report source is malformed")
    recorded_root = _recorded_checkout_root(source.get("root"))
    if value.get("collection_checkout_root") != str(recorded_root):
        fail("errno storage report collection checkout root drifted")
    root = physical_directory(root, "source root")
    rebased_work = _rebase_report_work(value.get("work"), recorded_root, root)

    def visit(item: object, field: str | None = None) -> object:
        if isinstance(item, dict):
            return {key: visit(child, key) for key, child in item.items()}
        if isinstance(item, list):
            return [visit(child) for child in item]
        if field in {"path", "root", "work"} and isinstance(item, str):
            if field in {"root", "work"} and not PurePosixPath(item).is_absolute():
                fail(f"report {field} path is not absolute")
            return _rebase_checkout_path(item, recorded_root, root, f"report {field}")
        return item

    rebased = visit(value)
    if not isinstance(rebased, dict):  # Kept explicit as this is a public reader boundary.
        fail("rebased errno storage report is malformed")
    rebased["work"] = rebased_work
    return rebased


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def parse_symbols(payload: str, description: str) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    table: str | None = None
    for line in payload.splitlines():
        table_match = SYMBOL_TABLE.match(line)
        if table_match is not None:
            table = table_match.group(1)
            continue
        match = SYMBOL_LINE.match(line)
        if match is None:
            continue
        if table is None:
            fail(f"{description} has a symbol row outside a symbol table")
        _, value, size, symbol_type, binding, visibility, section, name = match.groups()
        records.append(
            {
                "table": table,
                "value": value.lower(),
                "size": int(size),
                "type": symbol_type,
                "binding": binding,
                "visibility": visibility,
                "section": section,
                "name": name,
            }
        )
    if not records:
        fail(f"{description} contains no parseable ELF symbols")
    return records


def one_defined(
    records: Iterable[Mapping[str, object]], name: str, description: str, *, table: str
) -> Mapping[str, object]:
    matches = [
        record
        for record in records
        if record["table"] == table and record["name"] == name and record["section"] != "UND"
    ]
    if len(matches) != 1:
        fail(f"{description} has {len(matches)} defined {name} records")
    record = matches[0]
    section = record["section"]
    if (
        not isinstance(section, str)
        or re.fullmatch(r"[0-9]+", section) is None
        or int(section) == 0
    ):
        fail(f"{description} has no positive numeric section for defined {name}")
    return record


def one_undefined(
    records: Iterable[Mapping[str, object]], name: str, description: str, *, table: str = ".symtab"
) -> Mapping[str, object]:
    matches = [
        record
        for record in records
        if record["table"] == table and record["name"] == name and record["section"] == "UND"
    ]
    if len(matches) != 1:
        fail(f"{description} has {len(matches)} undefined {name} records")
    return matches[0]


def require_symbol(record: Mapping[str, object], *, name: str, symbol_type: str, binding: str, visibility: str, size: int | None = None, description: str) -> None:
    if (
        record["name"] != name
        or record["type"] != symbol_type
        or record["binding"] != binding
        or record["visibility"] != visibility
        or (size is not None and record["size"] != size)
    ):
        fail(f"{description} has wrong ELF shape for {name}: {dict(record)}")


def validate_static_symbols(payload: str, description: str) -> dict[str, object]:
    records = parse_symbols(payload, description)
    errno = one_defined(records, "__errno_location", description, table=".symtab")
    alias = one_defined(records, ALIAS, description, table=".symtab")
    h_errno = one_defined(records, "h_errno", description, table=".symtab")
    h_accessor = one_defined(records, "__h_errno_location", description, table=".symtab")
    require_symbol(errno, name="__errno_location", symbol_type="FUNC", binding="GLOBAL", visibility="DEFAULT", description=description)
    require_symbol(alias, name=ALIAS, symbol_type="FUNC", binding="WEAK", visibility="HIDDEN", description=description)
    require_symbol(h_errno, name="h_errno", symbol_type="OBJECT", binding="GLOBAL", visibility="DEFAULT", size=4, description=description)
    require_symbol(h_accessor, name="__h_errno_location", symbol_type="FUNC", binding="GLOBAL", visibility="DEFAULT", description=description)
    if (alias["value"], alias["section"]) != (errno["value"], errno["section"]):
        fail(f"{description} does not retain {ALIAS} as the same definition as __errno_location")
    return {
        "errno_alias": {"value": errno["value"], "section": errno["section"]},
        "h_errno": {"value": h_errno["value"], "section": h_errno["section"], "size_bytes": h_errno["size"]},
        "h_errno_location": {"value": h_accessor["value"], "section": h_accessor["section"]},
    }


def validate_shared_symbols(symtab_payload: str, dynsym_payload: str, description: str) -> dict[str, object]:
    symtab = parse_symbols(symtab_payload, f"{description} symtab")
    dynsym = parse_symbols(dynsym_payload, f"{description} dynsym")
    errno = one_defined(symtab, "__errno_location", description, table=".symtab")
    alias = one_defined(symtab, ALIAS, description, table=".symtab")
    h_errno = one_defined(symtab, "h_errno", description, table=".symtab")
    h_accessor = one_defined(symtab, "__h_errno_location", description, table=".symtab")
    require_symbol(errno, name="__errno_location", symbol_type="FUNC", binding="GLOBAL", visibility="DEFAULT", description=description)
    require_symbol(alias, name=ALIAS, symbol_type="FUNC", binding="LOCAL", visibility="DEFAULT", description=description)
    require_symbol(h_errno, name="h_errno", symbol_type="OBJECT", binding="GLOBAL", visibility="DEFAULT", size=4, description=description)
    require_symbol(h_accessor, name="__h_errno_location", symbol_type="FUNC", binding="GLOBAL", visibility="DEFAULT", description=description)
    if (alias["value"], alias["section"]) != (errno["value"], errno["section"]):
        fail(f"{description} does not localize {ALIAS} to __errno_location's definition")
    if any(
        record["table"] == ".dynsym" and record["name"] == ALIAS and record["section"] != "UND"
        for record in dynsym
    ):
        fail(f"{description} exposes musl-internal {ALIAS} in .dynsym")
    for name, symbol_type, size in (
        ("__errno_location", "FUNC", None),
        ("__h_errno_location", "FUNC", None),
        ("h_errno", "OBJECT", 4),
    ):
        record = one_defined(dynsym, name, f"{description} dynsym", table=".dynsym")
        require_symbol(record, name=name, symbol_type=symbol_type, binding="GLOBAL", visibility="DEFAULT", size=size, description=f"{description} dynsym")
    return {
        "errno_alias": {"value": errno["value"], "section": errno["section"]},
        "h_errno": {"value": h_errno["value"], "section": h_errno["section"], "size_bytes": h_errno["size"]},
        "h_errno_location": {"value": h_accessor["value"], "section": h_accessor["section"]},
    }


def _inventory_facts(description: str, operation: Any) -> Any:
    """Translate the retained complete-ELF reader's closed errors here."""

    try:
        return operation()
    except inventory.InventoryError as error:
        fail(f"{description} complete ELF facts are malformed: {error}")


def _fact_symbol_matches(
    facts: Mapping[str, Any], table_name: str, name: str, description: str,
) -> list[Mapping[str, Any]]:
    tables = facts.get("symbol_tables")
    if not isinstance(tables, list):
        fail(f"{description} lacks complete ELF symbol tables")
    tables_named = [table for table in tables if isinstance(table, Mapping) and table.get("name") == table_name]
    if len(tables_named) != 1:
        fail(f"{description} has {len(tables_named)} {table_name} tables")
    rows = tables_named[0].get("rows")
    if not isinstance(rows, list):
        fail(f"{description} {table_name} rows are malformed")
    return [row for row in rows if isinstance(row, Mapping) and row.get("name") == name]


def _one_fact_symbol(
    facts: Mapping[str, Any], table_name: str, name: str, description: str,
) -> Mapping[str, Any]:
    matches = _fact_symbol_matches(facts, table_name, name, description)
    if len(matches) != 1:
        fail(f"{description} has {len(matches)} {name} rows in {table_name}")
    return matches[0]


def _h_errno_row(row: Mapping[str, Any], description: str) -> None:
    """Require the source-selected legacy main fallback's ELF definition."""

    expected = H_ERRNO_METADATA
    if (
        row.get("type") != expected["type"]
        or row.get("binding") != expected["binding"]
        or row.get("visibility") != expected["visibility"]
        or row.get("size_bytes") != expected["size_bytes"]
    ):
        fail(f"{description} h_errno metadata differs")
    section_index = row.get("section_index")
    if not isinstance(section_index, str) or re.fullmatch(r"[1-9][0-9]*", section_index) is None:
        fail(f"{description} h_errno lacks a positive numeric defining section")


def _hex_integer(value: object, description: str) -> int:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]+", value) is None:
        fail(f"{description} is not a retained hexadecimal ELF value")
    return int(value, 16)


def _h_errno_layout_record(
    facts: Mapping[str, Any], row: Mapping[str, Any], description: str, *, archive_member: Mapping[str, Any] | None,
) -> dict[str, object]:
    _h_errno_row(row, description)
    section_index = int(str(row["section_index"]))
    sections = facts.get("sections")
    if not isinstance(sections, list):
        fail(f"{description} has no complete defining-section roster")
    sections_matching = [
        section
        for section in sections
        if isinstance(section, Mapping) and section.get("index") == section_index
    ]
    if len(sections_matching) != 1:
        fail(f"{description} h_errno defining section is absent or duplicated")
    section = sections_matching[0]
    alignment = section.get("alignment")
    required = H_ERRNO_METADATA["alignment_bytes"]
    if (
        type(alignment) is not int
        or alignment < required
        or alignment % required != 0
    ):
        fail(f"{description} h_errno defining section alignment is below int alignment")
    symbol_value = _hex_integer(row.get("value"), f"{description} h_errno symbol value")
    section_address = _hex_integer(section.get("address"), f"{description} h_errno section address")
    if section_address % required:
        fail(f"{description} h_errno defining section address differs from int alignment")
    if symbol_value < section_address:
        fail(f"{description} h_errno symbol precedes its defining section")
    offset = symbol_value - section_address
    if offset % required:
        fail(f"{description} h_errno offset alignment differs from int alignment")
    section_size = _hex_integer(section.get("size"), f"{description} h_errno defining section size")
    if offset + H_ERRNO_METADATA["size_bytes"] > section_size:
        fail(f"{description} h_errno exceeds its defining section")
    result: dict[str, object] = {
        "symbol_value_hex": str(row["value"]),
        "object_size_bytes": H_ERRNO_METADATA["size_bytes"],
        "required_alignment_bytes": required,
        "defining_section_index": section_index,
        "defining_section_name": section.get("name"),
        "defining_section_address_hex": section.get("address"),
        "defining_section_size_bytes": section_size,
        "defining_section_alignment_bytes": alignment,
        "offset_bytes": offset,
        "offset_modulo_required_alignment": offset % required,
    }
    if archive_member is not None:
        result["archive_member"] = dict(archive_member)
    return result


def validate_static_h_errno_layout(
    header_payload: str,
    sections_payload: str,
    symbols_payload: str,
    members_payload: str,
    archive_path: str,
    description: str,
) -> dict[str, object]:
    """Join static archive h_errno to its exact member section and offset."""

    members = _inventory_facts(description, lambda: inventory.parse_archive_members(members_payload))
    facts = _inventory_facts(
        description,
        lambda: inventory.parse_archive_elf_facts(
            header_payload, sections_payload, symbols_payload, members, expected_archive=archive_path
        ),
    )
    matches: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for member in facts:
        rows = _fact_symbol_matches(member, ".symtab", "h_errno", description)
        if len(rows) > 1:
            fail(f"{description} has duplicate static archive h_errno definitions in one member")
        if rows:
            matches.append((member, rows[0]))
    if len(matches) != 1:
        fail(f"{description} has {len(matches)} static archive h_errno definitions")
    member, row = matches[0]
    archive_member = {
        "name": member.get("member"),
        "index": member.get("member_index"),
        "occurrence": member.get("member_occurrence"),
    }
    if (
        not isinstance(archive_member["name"], str)
        or type(archive_member["index"]) is not int
        or type(archive_member["occurrence"]) is not int
    ):
        fail(f"{description} h_errno archive-member identity is malformed")
    return _h_errno_layout_record(member, row, description, archive_member=archive_member)


def validate_shared_h_errno_layout(
    header_payload: str, sections_payload: str, symbols_payload: str, description: str,
) -> dict[str, object]:
    """Join shared h_errno's public dynsym row to its local defining section."""

    facts = _inventory_facts(
        description,
        lambda: inventory.parse_elf_facts(
            header_payload, sections_payload, symbols_payload, expected_type="DYN"
        ),
    )
    symtab = _one_fact_symbol(facts, ".symtab", "h_errno", description)
    dynsym = _one_fact_symbol(facts, ".dynsym", "h_errno", description)
    _h_errno_row(symtab, description)
    _h_errno_row(dynsym, f"{description} dynsym")
    for field in ("value", "section_index", "type", "binding", "visibility", "size_bytes"):
        if symtab.get(field) != dynsym.get(field):
            fail(f"{description} h_errno dynsym does not identify its defining symbol")
    return _h_errno_layout_record(facts, symtab, description, archive_member=None)


def read_digest_file(path: Path, description: str) -> str:
    text = read_text(path, description)
    match = re.fullmatch(r"([0-9a-f]{64})\s+.+\n", text)
    if match is None:
        fail(f"{description} is not one sha256sum record")
    return match.group(1)


def capture_run(work: Path, label: str) -> dict[str, object]:
    argv_path = work / f"{label}.argv.json"
    argv = read_json_object(argv_path, f"{label} argv")
    if set(argv) != {"argv"} or not isinstance(argv["argv"], list) or not argv["argv"] or not all(isinstance(value, str) for value in argv["argv"]):
        fail(f"{label} argv contract drifted")
    status = read_text(work / f"{label}.status", f"{label} status")
    stdout = physical_regular(work / f"{label}.stdout", f"{label} stdout").read_bytes()
    stderr = physical_regular(work / f"{label}.stderr", f"{label} stderr").read_bytes()
    if status != "0\n" or stdout != EXPECTED_TRANSCRIPT or stderr != b"":
        fail(f"{label} did not retain the expected errno storage transcript")
    return {
        "argv": identity(argv_path, f"{label} argv"),
        "status": identity(work / f"{label}.status", f"{label} status"),
        "stdout": identity(work / f"{label}.stdout", f"{label} stdout"),
        "stderr": identity(work / f"{label}.stderr", f"{label} stderr"),
    }


def validate_execution(value: object, work: Path) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(RUN_LABELS):
        fail("execution labels drifted")
    for label in RUN_LABELS:
        record = require_exact_mapping(value[label], {"argv", "status", "stdout", "stderr"}, f"execution {label}")
        for field in ("argv", "status", "stdout", "stderr"):
            validate_identity(record[field], f"execution {label} {field}", within=work)
        capture_run(work, label)
    return value


def validate_object_integrity(value: object, work: Path) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(OBJECTS):
        fail("workload object roster drifted")
    result: dict[str, Any] = {}
    for name in OBJECTS:
        record = require_exact_mapping(value[name], {"object", "before", "after"}, f"object {name}")
        object_path = validate_identity(record["object"], f"object {name}", within=work)
        before = validate_identity(record["before"], f"object {name} before", within=work)
        after = validate_identity(record["after"], f"object {name} after", within=work)
        before_digest = read_digest_file(before, f"object {name} before")
        after_digest = read_digest_file(after, f"object {name} after")
        if before_digest != after_digest or before_digest != sha256(object_path):
            fail(f"workload object {name} changed between installed-header compilation and links")
        result[name] = record
    return result


def observation_artifact(work: Path, output_name: str, description: str) -> dict[str, dict[str, object]]:
    """Bind one retained `observe` output to its argv/status/diagnostic files."""

    stem = output_name.removesuffix(".txt")
    return {
        "output": identity(work / output_name, f"{description} output"),
        "argv": identity(work / f"{stem}.argv.json", f"{description} argv"),
        "status": identity(work / f"{stem}.status", f"{description} status"),
        "stderr": identity(work / f"{stem}.stderr", f"{description} stderr"),
    }


def symbol_artifacts(work: Path) -> dict[str, dict[str, dict[str, object]]]:
    return {name: observation_artifact(work, name, f"symbol artifact {name}") for name in SYMBOL_INPUTS}


def layout_artifacts(work: Path) -> dict[str, dict[str, dict[str, object]]]:
    """Retain complete defining-section streams beside the existing symbols."""

    return {name: observation_artifact(work, name, f"layout artifact {name}") for name in LAYOUT_INPUTS}


def workload_symbol_artifacts(work: Path) -> dict[str, dict[str, object]]:
    return {name: identity(work / name, f"workload symbol artifact {name}") for name in WORKLOAD_SYMBOL_INPUTS}


def validate_observation_artifact(
    value: object,
    *,
    output_name: str,
    expected_argv: list[str],
    work: Path,
    description: str,
) -> Path:
    record = require_exact_mapping(value, {"output", "argv", "status", "stderr"}, description)
    stem = output_name.removesuffix(".txt")
    output = validate_identity(record["output"], f"{description} output", within=work)
    argv_path = validate_identity(record["argv"], f"{description} argv", within=work)
    status_path = validate_identity(record["status"], f"{description} status", within=work)
    stderr_path = validate_identity(record["stderr"], f"{description} stderr", within=work)
    if (
        output != work / output_name
        or argv_path != work / f"{stem}.argv.json"
        or status_path != work / f"{stem}.status"
        or stderr_path != work / f"{stem}.stderr"
    ):
        fail(f"{description} artifact paths drifted")
    argv = read_json_object(argv_path, f"{description} argv")
    if argv != {"argv": expected_argv}:
        fail(f"{description} argv drifted")
    if read_text(status_path, f"{description} status") != "0\n":
        fail(f"{description} status drifted")
    if stderr_path.read_bytes() != b"":
        fail(f"{description} emitted diagnostics")
    return output


def _recorded_command_path(path: Path, root: Path, recorded_root: PurePosixPath) -> str:
    """Use the collection mount spelling for a replayed checkout descendant."""

    try:
        relative = path.relative_to(root)
    except ValueError:
        return str(path)
    return str(recorded_root.joinpath(*relative.parts))


def _product_libraries(products: Mapping[str, Any]) -> tuple[Path, Path]:
    static = products.get("static")
    dynamic = products.get("dynamic")
    if not isinstance(static, Mapping) or not isinstance(dynamic, Mapping):
        fail("errno storage products are malformed")
    return (
        validate_identity(static.get("libc"), "candidate static libc"),
        validate_identity(dynamic.get("libc"), "candidate shared libc"),
    )


def _symbol_observations(
    products: Mapping[str, Any], root: Path, recorded_root: PurePosixPath,
) -> dict[str, list[str]]:
    candidate_static, candidate_shared = _product_libraries(products)
    return {
        "oracle-static-symbols.txt": ["readelf", "-Ws", ORACLE_STATIC_ARCHIVE],
        "oracle-shared-symbols.txt": ["readelf", "-Ws", ORACLE_SHARED_LIBRARY],
        "oracle-dynamic-symbols.txt": ["readelf", "--dyn-syms", "-W", ORACLE_SHARED_LIBRARY],
        "candidate-static-symbols.txt": ["readelf", "-Ws", _recorded_command_path(candidate_static, root, recorded_root)],
        "candidate-shared-symbols.txt": ["readelf", "-Ws", _recorded_command_path(candidate_shared, root, recorded_root)],
        "candidate-dynamic-symbols.txt": ["readelf", "--dyn-syms", "-W", _recorded_command_path(candidate_shared, root, recorded_root)],
    }


def _layout_observations(
    products: Mapping[str, Any], root: Path, recorded_root: PurePosixPath,
) -> dict[str, list[str]]:
    candidate_static, candidate_shared = _product_libraries(products)
    return {
        "oracle-static-members.txt": ["ar", "t", ORACLE_STATIC_ARCHIVE],
        "oracle-static-header.txt": ["readelf", "-hW", ORACLE_STATIC_ARCHIVE],
        "oracle-static-sections.txt": ["readelf", "-SW", ORACLE_STATIC_ARCHIVE],
        "oracle-shared-header.txt": ["readelf", "-hW", ORACLE_SHARED_LIBRARY],
        "oracle-shared-sections.txt": ["readelf", "-SW", ORACLE_SHARED_LIBRARY],
        "candidate-static-members.txt": ["ar", "t", _recorded_command_path(candidate_static, root, recorded_root)],
        "candidate-static-header.txt": ["readelf", "-hW", _recorded_command_path(candidate_static, root, recorded_root)],
        "candidate-static-sections.txt": ["readelf", "-SW", _recorded_command_path(candidate_static, root, recorded_root)],
        "candidate-shared-header.txt": ["readelf", "-hW", _recorded_command_path(candidate_shared, root, recorded_root)],
        "candidate-shared-sections.txt": ["readelf", "-SW", _recorded_command_path(candidate_shared, root, recorded_root)],
    }


def validate_symbol_artifacts(
    value: object, work: Path, products: Mapping[str, Any], root: Path, recorded_root: PurePosixPath,
) -> dict[str, Path]:
    if not isinstance(value, dict) or set(value) != set(SYMBOL_INPUTS):
        fail("symbol artifact roster drifted")
    observations = _symbol_observations(products, root, recorded_root)
    paths = {
        name: validate_observation_artifact(
            value[name], output_name=name, expected_argv=observations[name], work=work,
            description=f"symbol artifact {name}",
        )
        for name in SYMBOL_INPUTS
    }
    # ELF values and section-number spellings belong to each independently
    # linked archive/DSO.  The contract is same-address identity *within* an
    # artifact; comparing a crabc value to musl's unrelated link layout would
    # make the receipt accidentally depend on section placement.
    validate_static_symbols(read_text(paths["oracle-static-symbols.txt"], "oracle static symbols"), "pinned musl static archive")
    validate_static_symbols(read_text(paths["candidate-static-symbols.txt"], "candidate static symbols"), "candidate static archive")
    validate_shared_symbols(
        read_text(paths["oracle-shared-symbols.txt"], "oracle shared symbols"),
        read_text(paths["oracle-dynamic-symbols.txt"], "oracle dynamic symbols"),
        "pinned musl shared library",
    )
    validate_shared_symbols(
        read_text(paths["candidate-shared-symbols.txt"], "candidate shared symbols"),
        read_text(paths["candidate-dynamic-symbols.txt"], "candidate dynamic symbols"),
        "candidate shared library",
    )
    return paths


def validate_h_errno_layout_artifacts(
    value: object,
    symbols: Mapping[str, Path],
    products: Mapping[str, Any],
    work: Path,
    root: Path,
    recorded_root: PurePosixPath,
) -> dict[str, Any]:
    """Prove h_errno's source-required object alignment in both placements.

    A shared provider may deliberately place this four-byte object in a more
    broadly aligned section.  The retained defining section still has to meet
    the source minimum, and the symbol's section-relative offset has to meet
    it independently.  Static archives retain the selected member identity so
    a repeated section number or zero relocatable st_value cannot impersonate
    another definition.
    """

    if not isinstance(value, dict) or set(value) != set(LAYOUT_INPUTS):
        fail("h_errno layout artifact roster drifted")
    if set(symbols) != set(SYMBOL_INPUTS):
        fail("h_errno layout symbol artifact roster drifted")
    observations = _layout_observations(products, root, recorded_root)
    paths = {
        name: validate_observation_artifact(
            value[name], output_name=name, expected_argv=observations[name], work=work,
            description=f"h_errno layout artifact {name}",
        )
        for name in LAYOUT_INPUTS
    }
    candidate_static_archive, _ = _product_libraries(products)

    def layout_text(name: str) -> str:
        return read_text(paths[name], f"h_errno layout artifact {name}")

    def symbol_text(name: str) -> str:
        return read_text(symbols[name], f"h_errno layout symbol artifact {name}")

    static = {
        "metadata": dict(H_ERRNO_METADATA),
        "oracle": validate_static_h_errno_layout(
            layout_text("oracle-static-header.txt"),
            layout_text("oracle-static-sections.txt"),
            symbol_text("oracle-static-symbols.txt"),
            layout_text("oracle-static-members.txt"),
            ORACLE_STATIC_ARCHIVE,
            "pinned musl static h_errno",
        ),
        "candidate": validate_static_h_errno_layout(
            layout_text("candidate-static-header.txt"),
            layout_text("candidate-static-sections.txt"),
            symbol_text("candidate-static-symbols.txt"),
            layout_text("candidate-static-members.txt"),
            str(candidate_static_archive),
            "candidate static h_errno",
        ),
    }
    shared = {
        "metadata": dict(H_ERRNO_METADATA),
        "oracle": validate_shared_h_errno_layout(
            layout_text("oracle-shared-header.txt"),
            layout_text("oracle-shared-sections.txt"),
            symbol_text("oracle-shared-symbols.txt"),
            "pinned musl shared h_errno",
        ),
        "candidate": validate_shared_h_errno_layout(
            layout_text("candidate-shared-header.txt"),
            layout_text("candidate-shared-sections.txt"),
            symbol_text("candidate-shared-symbols.txt"),
            "candidate shared h_errno",
        ),
    }
    return {"static": static, "shared": shared}


def validate_workload_symbols(value: object, work: Path) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(WORKLOAD_SYMBOL_INPUTS):
        fail("workload symbol artifact roster drifted")
    paths = {
        name: validate_identity(value[name], f"workload symbol artifact {name}", within=work)
        for name in WORKLOAD_SYMBOL_INPUTS
    }
    static = parse_symbols(read_text(paths["core-static-symbols.txt"], "static workload symbols"), "static workload symbols")
    for name in ("__errno_location", ALIAS, "__h_errno_location", "h_errno", "pthread_tryjoin_np"):
        one_undefined(static, name, "static installed-header workload")
    dynamic = parse_symbols(read_text(paths["core-dynamic-symbols.txt"], "dynamic workload symbols"), "dynamic workload symbols")
    for name in ("__errno_location", "__h_errno_location", "h_errno", "pthread_tryjoin_np", "dlopen", "dlsym"):
        one_undefined(dynamic, name, "dynamic installed-header workload")
    if any(record["name"] == ALIAS for record in dynamic):
        fail("dynamic installed-header workload imports archive-only allocator errno alias")
    plugin = parse_symbols(read_text(paths["plugin-symbols.txt"], "DSO workload symbols"), "DSO workload symbols")
    for name in ("__errno_location", "__h_errno_location"):
        one_undefined(plugin, name, "loaded DSO workload")
    if any(record["name"] in {ALIAS, "h_errno"} for record in plugin):
        fail("loaded DSO workload uses a private or legacy errno storage spelling")
    return value


def validate_shared_alias_link_policy(value: object, description: str) -> dict[str, Any]:
    """Bind LLD's one private alias script to its reviewed source roster."""

    if not isinstance(value, dict):
        fail(f"{description} provenance is malformed")
    aliases = require_exact_mapping(
        value.get("shared_errno_private_aliases"),
        {"source", "member_count", "members", "linker_policy", "linker_script_sha256"},
        f"{description} errno private aliases",
    )
    source = require_exact_mapping(
        aliases["source"], {"path", "sha256", "mode"}, f"{description} errno private alias source"
    )
    if source != {"path": SHARED_ALIAS_LIST, "sha256": SHARED_ALIAS_LIST_SHA256, "mode": 0o644}:
        fail(f"{description} errno private alias source drifted")
    if (
        type(aliases["member_count"]) is not int
        or aliases["member_count"] != len(SHARED_ALIAS_MEMBERS)
        or aliases["members"] != list(SHARED_ALIAS_MEMBERS)
    ):
        fail(f"{description} errno private alias roster drifted")
    if aliases["linker_policy"] != "exact-local-symbols":
        fail(f"{description} errno private alias linker policy drifted")
    expected_script = (
        "{\n  local:\n" + "".join(f"    {member};\n" for member in SHARED_ALIAS_MEMBERS) + "};\n"
    ).encode("utf-8")
    derived_script_sha256 = hashlib.sha256(expected_script).hexdigest()
    if derived_script_sha256 != SHARED_ALIAS_LINKER_SCRIPT_SHA256:
        fail("reader errno private alias script template differs from its reviewed digest")
    if aliases["linker_script_sha256"] != derived_script_sha256:
        fail(f"{description} errno private alias script digest drifted")
    command = value.get("libc_shared_link_command")
    if not isinstance(command, list) or not all(isinstance(argument, str) for argument in command):
        fail(f"{description} shared libc link command is malformed")
    if command.count(SHARED_ALIAS_LINKER_SCRIPT) != 1:
        fail(f"{description} shared libc link lacks the exact errno private-alias version script")
    return aliases


def product_record(static_product: Path, dynamic_product: Path) -> dict[str, Any]:
    static = physical_directory(static_product, "static product")
    dynamic = physical_directory(dynamic_product, "dynamic product")
    return {
        "static": {
            "root": str(static),
            "manifest": identity(static / "share/crabc/manifest.json", "static product manifest"),
            "libc": identity(static / "usr/lib/libc.a", "static product libc archive"),
        },
        "dynamic": {
            "root": str(dynamic),
            "manifest": identity(dynamic / "share/crabc/manifest.json", "dynamic product manifest"),
            "libc": identity(dynamic / "usr/lib/libc.so", "dynamic product libc shared object"),
            "libc_shared_provenance": identity(
                dynamic / "share/crabc/libc-shared.provenance.json", "dynamic product libc shared provenance"
            ),
        },
    }


def validate_products(value: object) -> dict[str, Any]:
    record = require_exact_mapping(value, {"static", "dynamic"}, "product record")
    for kind, library in (("static", "libc.a"), ("dynamic", "libc.so")):
        expected = {"root", "manifest", "libc"}
        if kind == "dynamic":
            expected.add("libc_shared_provenance")
        item = require_exact_mapping(record[kind], expected, f"{kind} product record")
        if not isinstance(item["root"], str):
            fail(f"{kind} product root is malformed")
        root = physical_directory(Path(item["root"]), f"{kind} product root")
        validate_identity(item["manifest"], f"{kind} product manifest")
        libc = validate_identity(item["libc"], f"{kind} product libc")
        if libc != root / "usr/lib" / library:
            fail(f"{kind} product library path drifted")
        if kind == "dynamic":
            provenance = validate_identity(item["libc_shared_provenance"], "dynamic product libc shared provenance")
            if provenance != root / "share/crabc/libc-shared.provenance.json":
                fail("dynamic product shared provenance path drifted")
    return record


def validate_shared_alias_product_provenance(products: Mapping[str, Any]) -> dict[str, Any]:
    dynamic = products.get("dynamic")
    if not isinstance(dynamic, Mapping):
        fail("dynamic product record is unavailable for errno private alias provenance")
    provenance_identity = dynamic.get("libc_shared_provenance")
    provenance_path = validate_identity(
        provenance_identity, "dynamic product libc shared provenance"
    )
    provenance = read_json_object(provenance_path, "dynamic product libc shared provenance")
    return validate_shared_alias_link_policy(provenance, "dynamic product")


def dynamic_link_receipts(work: Path) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, (output_name, mode) in DYNAMIC_LINKS.items():
        receipt_name = f"{output_name}.crabc-link.json"
        result[name] = {
            "receipt": identity(work / receipt_name, f"dynamic receipt {name}"),
            "output": identity(work / output_name, f"dynamic output {name}"),
            "mode": mode,
        }
    return result


def validate_dynamic_link_receipts(value: object, work: Path, products: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(DYNAMIC_LINKS):
        fail("dynamic link receipt roster drifted")
    dynamic = products.get("dynamic")
    if not isinstance(dynamic, Mapping):
        fail("dynamic product record is unavailable for link receipts")
    manifest = dynamic.get("manifest")
    if not isinstance(manifest, Mapping) or not isinstance(manifest.get("sha256"), str):
        fail("dynamic product manifest identity is unavailable for link receipts")
    manifest_sha256 = manifest["sha256"]
    for name, (output_name, mode) in DYNAMIC_LINKS.items():
        record = require_exact_mapping(value[name], {"receipt", "output", "mode"}, f"dynamic receipt {name}")
        if record["mode"] != mode:
            fail(f"dynamic receipt {name} mode label drifted")
        receipt_path = validate_identity(record["receipt"], f"dynamic receipt {name}", within=work)
        output_path = validate_identity(record["output"], f"dynamic output {name}", within=work)
        if output_path != work / output_name:
            fail(f"dynamic output {name} path drifted")
        receipt = read_json_object(receipt_path, f"dynamic link receipt {name}")
        if (
            type(receipt.get("schema")) is not int
            or receipt.get("format") != "crabc-x86-64-owned-dynamic-sysroot-v1"
            or receipt.get("mode") != mode
            or receipt.get("output_sha256") != sha256(output_path)
            or receipt.get("manifest_sha256") != manifest_sha256
        ):
            fail(f"dynamic link receipt {name} does not bind its selected output/product")
        runtime_inputs = receipt.get("owned_runtime_inputs")
        if not isinstance(runtime_inputs, list) or "usr/lib/libc.so" not in runtime_inputs:
            fail(f"dynamic link receipt {name} does not select the installed libc shared provider")
    return value


def collect(root: Path, work: Path, static_product: Path, dynamic_product: Path) -> dict[str, Any]:
    root = physical_directory(root, "source root")
    work = physical_directory(work, "evidence root")
    before = read_json_object(work / "source-before.json", "source before snapshot")
    after = read_json_object(work / "source-after.json", "source after snapshot")
    if before != after:
        fail("source changed while errno storage evidence ran")
    source = validate_source_snapshot(before, root, "source evidence snapshot")
    collection_checkout_root = _recorded_checkout_root(source["root"])
    products = product_record(static_product, dynamic_product)
    shared_alias_link_policy = validate_shared_alias_product_provenance(products)
    symbols = symbol_artifacts(work)
    symbol_paths = validate_symbol_artifacts(symbols, work, products, root, collection_checkout_root)
    layouts = layout_artifacts(work)
    h_errno_layout = validate_h_errno_layout_artifacts(
        layouts, symbol_paths, products, work, root, collection_checkout_root
    )
    workload_symbols = workload_symbol_artifacts(work)
    validate_workload_symbols(workload_symbols, work)
    objects: dict[str, Any] = {}
    for name in OBJECTS:
        objects[name] = {
            "object": identity(work / name, f"object {name}"),
            "before": identity(work / f"{name}.before.sha256", f"object {name} before"),
            "after": identity(work / f"{name}.after.sha256", f"object {name} after"),
        }
    validate_object_integrity(objects, work)
    execution = {label: capture_run(work, label) for label in RUN_LABELS}
    dynamic_receipts = dynamic_link_receipts(work)
    validate_dynamic_link_receipts(dynamic_receipts, work, products)
    return {
        "schema": SCHEMA,
        "target": TARGET,
        "work": str(work),
        "source": source,
        "collection_checkout_root": str(collection_checkout_root),
        "products": products,
        "shared_alias_link_policy": shared_alias_link_policy,
        "symbols": symbols,
        "layout_artifacts": layouts,
        "h_errno_layout": h_errno_layout,
        "workload_symbols": workload_symbols,
        "objects": objects,
        "execution": execution,
        "dynamic_link_receipts": dynamic_receipts,
        "summary": {
            "errno_public_accessor": "GLOBAL DEFAULT FUNC",
            "errno_allocator_alias": "static WEAK HIDDEN same-address; shared LOCAL DEFAULT absent-dynsym",
            "h_errno": "GLOBAL DEFAULT OBJECT size=4, source-required alignment=4, and GLOBAL DEFAULT accessor",
            "h_errno_layout": "static/shared defining section and section-relative offset retain alignment=4; shared section over-alignment is observed separately",
            "execution": "main/live-worker isolation, aligned live accessor locations, stable live locations, selected pthread EBUSY preserves errno, and loaded DSO access",
            "worker_pointer_lifetime": "never dereferenced after join",
        },
    }


def validate_report(root: Path, report_path: Path) -> dict[str, Any]:
    root = physical_directory(root, "source root")
    report_path = physical_regular(report_path, "errno storage report")
    report = rebase_report_checkout_paths(read_json_object(report_path, "errno storage report"), root)
    expected = {
        "schema",
        "target",
        "work",
        "source",
        "collection_checkout_root",
        "products",
        "shared_alias_link_policy",
        "symbols",
        "layout_artifacts",
        "h_errno_layout",
        "workload_symbols",
        "objects",
        "execution",
        "dynamic_link_receipts",
        "summary",
    }
    require_exact_mapping(report, expected, "errno storage report")
    if report["schema"] != SCHEMA or report["target"] != TARGET or not isinstance(report["work"], str):
        fail("errno storage report identity drifted")
    collection_checkout_root = _recorded_checkout_root(report["collection_checkout_root"])
    work = physical_directory(Path(report["work"]), "report evidence root")
    evidence_root = physical_directory(root / ".work", "checkout evidence root")
    if not work.is_relative_to(evidence_root):
        fail("report evidence root resolves outside checkout .work")
    if report_path.parent != work:
        fail("report evidence root differs from the report directory")
    validate_source_snapshot(report["source"], root, "report source snapshot")
    validate_products(report["products"])
    if report["shared_alias_link_policy"] != validate_shared_alias_product_provenance(report["products"]):
        fail("report shared errno alias link policy drifted")
    symbol_paths = validate_symbol_artifacts(
        report["symbols"], work, report["products"], root, collection_checkout_root
    )
    derived_h_errno_layout = validate_h_errno_layout_artifacts(
        report["layout_artifacts"], symbol_paths, report["products"], work, root, collection_checkout_root
    )
    if not exact_same(report["h_errno_layout"], derived_h_errno_layout):
        fail("report h_errno layout differs from retained complete ELF facts")
    validate_workload_symbols(report["workload_symbols"], work)
    validate_object_integrity(report["objects"], work)
    validate_execution(report["execution"], work)
    validate_dynamic_link_receipts(report["dynamic_link_receipts"], work, report["products"])
    summary = require_exact_mapping(
        report["summary"],
        {
            "errno_public_accessor",
            "errno_allocator_alias",
            "h_errno",
            "h_errno_layout",
            "execution",
            "worker_pointer_lifetime",
        },
        "report summary",
    )
    if summary != {
        "errno_public_accessor": "GLOBAL DEFAULT FUNC",
        "errno_allocator_alias": "static WEAK HIDDEN same-address; shared LOCAL DEFAULT absent-dynsym",
        "h_errno": "GLOBAL DEFAULT OBJECT size=4, source-required alignment=4, and GLOBAL DEFAULT accessor",
        "h_errno_layout": "static/shared defining section and section-relative offset retain alignment=4; shared section over-alignment is observed separately",
        "execution": "main/live-worker isolation, aligned live accessor locations, stable live locations, selected pthread EBUSY preserves errno, and loaded DSO access",
        "worker_pointer_lifetime": "never dereferenced after join",
    }:
        fail("report summary drifted")
    return report


def command_snapshot(arguments: argparse.Namespace) -> int:
    write_json(arguments.output, source_snapshot(arguments.root))
    return 0


def command_collect(arguments: argparse.Namespace) -> int:
    report = collect(arguments.root, arguments.work, arguments.static_product, arguments.dynamic_product)
    write_json(arguments.output, report)
    print(json.dumps({"schema": report["schema"], "work": report["work"], "status": "collected"}, sort_keys=True))
    return 0


def command_replay(arguments: argparse.Namespace) -> int:
    report = validate_report(arguments.root, arguments.report)
    print(json.dumps({"schema": report["schema"], "work": report["work"], "status": "replayed"}, sort_keys=True))
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(required=True)
    snapshot_parser = commands.add_parser("snapshot")
    snapshot_parser.add_argument("--root", type=Path, required=True)
    snapshot_parser.add_argument("--output", type=Path, required=True)
    snapshot_parser.set_defaults(handler=command_snapshot)
    collect_parser = commands.add_parser("collect")
    collect_parser.add_argument("--root", type=Path, required=True)
    collect_parser.add_argument("--work", type=Path, required=True)
    collect_parser.add_argument("--static-product", type=Path, required=True)
    collect_parser.add_argument("--dynamic-product", type=Path, required=True)
    collect_parser.add_argument("--output", type=Path, required=True)
    collect_parser.set_defaults(handler=command_collect)
    replay_parser = commands.add_parser("replay")
    replay_parser.add_argument("--root", type=Path, required=True)
    replay_parser.add_argument("--report", type=Path, required=True)
    replay_parser.set_defaults(handler=command_replay)
    return result


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = parser().parse_args(argv)
        return arguments.handler(arguments)
    except ErrnoStorageEvidenceError as error:
        print(f"owned errno storage lifecycle: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
