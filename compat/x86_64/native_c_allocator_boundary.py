#!/usr/bin/env python3
"""Collect and replay the installed native C allocator wrapper boundary.

This finite reader consumes products prepared by their owners.  It joins the
fixed-C producer account to the static Rust importer, replays the lifecycle
and public-interposition runners, and retains focused installed-product links
for ordinary allocator imports. It is not an allocator builder, policy
selector, or qualification campaign.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import tomllib
from typing import Any, Mapping, Sequence

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))
import native_abi_inventory as inventory
import owned_mimalloc_producer_metadata as producer
import owned_posix_product_evidence as product_evidence
import owned_posix_static_products as static_products

ROOT = inventory.ROOT
CONTRACT_PATH = ROOT / "compat/x86_64/native_c_allocator_boundary.toml"
SCHEMA = "crabc.x86_64-native-c-allocator-boundary/v5"
TARGET = "x86_64-unknown-linux-musl"
RAW = "raw"
STATIC_MODES = ("static", "static-pie")
DYNAMIC_MODES = ("pie", "non-pie")
ENTRIES = ("kernel", "direct")
SCENARIOS = ("asprintf", "passwd", "lio")
C_RUNTIME_IMPORTS = (
    ("__errno_location", "GLOBAL"), ("abort", "GLOBAL"), ("clock_gettime", "WEAK"),
    ("fputs", "GLOBAL"), ("free", "GLOBAL"), ("getenv", "GLOBAL"),
    ("getrusage", "GLOBAL"), ("memcpy", "GLOBAL"),
    ("memset", "GLOBAL"), ("munmap", "WEAK"), ("pathconf", "GLOBAL"), ("prctl", "GLOBAL"),
    ("pthread_key_create", "WEAK"), ("pthread_key_delete", "WEAK"),
    ("pthread_mutex_destroy", "GLOBAL"), ("pthread_mutex_lock", "WEAK"),
    ("pthread_mutex_unlock", "WEAK"), ("pthread_setspecific", "GLOBAL"),
    ("realpath", "GLOBAL"), ("sleep", "GLOBAL"), ("strtol", "GLOBAL"),
    ("syscall", "GLOBAL"), ("sysconf", "GLOBAL"), ("sysinfo", "WEAK"),
)
VM_PRIVATE_IMPORTS = ("__madvise", "__mmap", "__mprotect")
PUBLIC_WEAK_IMPORTS = {"clock_gettime": "ftime", "sysinfo": "getloadavg"}
PUBLIC_WEAK_WORKLOAD = ("#define _GNU_SOURCE\n#include <sys/timeb.h>\n#include <stdlib.h>\n"
                        "int main(void) { struct timeb stamp; double loads[3]; "
                        "if (ftime(&stamp) != 0) return 1; "
                        "return getloadavg(loads, 3) < 0 ? 2 : 0; }\n")
ERRNO_IMPORT_NAME = "__errno_location"
ERRNO_WORKLOAD = ("#include <stdlib.h>\n#include <stdio.h>\n#include <wchar.h>\n"
                  "#include <assert.h>\n"
                  "#ifdef CRABC_STATIC_ABORT_PROBE\nextern void *mi_new(size_t);\n#endif\n"
                  "int main(int argc, char **argv) { (void)argv; assert(argc >= 1);\n"
                  "#ifdef CRABC_STATIC_ABORT_PROBE\nif (argc == 1000) free(mi_new(1));\n#endif\n"
                  "char *end; int decimal = 0, wide = 0; "
                  "volatile double value = strtod(\"3.25e2\", &end); "
                  "if (sscanf(\"7\", \"%d\", &decimal) != 1) return 1; "
                  "if (swscanf(L\"8\", L\"%d\", &wide) != 1) return 2; "
                  "return value == 325.0 && *end == 0 && decimal == 7 && wide == 8 ? 0 : 3; }\n")
RUNTIME_SOURCES = (
    "libc/src/allocator_mimalloc.rs",
    "libc/src/allocator_observability_mimalloc.rs",
    "libc/src/c_abi/x86_64/allocator_mimalloc_lifecycle.rs",
    "libc/src/c_abi/x86_64/static_c_abi.rs",
    "libc/src/crypt_impl.rs",
    "libc/Cargo.toml",
)
COMPONENT_SOURCES = (
    "compat/x86_64/native_c_allocator_boundary.py",
    "compat/x86_64/native_c_allocator_boundary.toml",
    "compat/x86_64/native-c-allocator-boundary.md",
    "compat/x86_64/run_owned_mimalloc_startup_errno.sh",
    "compat/x86_64/run_owned_c_allocation_interposition.sh",
    "compat/x86_64/owned_mimalloc_startup_errno_probe.c",
    "compat/x86_64/owned_c_allocation_interposition_probe.c",
    "compat/x86_64/owned_mimalloc_producer_metadata.py",
    "compat/x86_64/owned_mimalloc_producer_metadata.toml",
    "compat/x86_64/owned_posix_product_evidence.py",
)
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
REVISION = re.compile(r"[0-9a-f]{40}\Z")


class AllocatorBoundaryError(RuntimeError):
    """An input no longer proves this finite installed allocator boundary."""


def fail(message: str) -> None:
    raise AllocatorBoundaryError(f"native C allocator boundary: {message}")


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def same(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(same(value, right[key]) for key, value in left.items())
    if isinstance(left, list):
        return len(left) == len(right) and all(same(a, b) for a, b in zip(left, right))
    return left == right


def physical_file(path: Path, description: str) -> Path:
    try:
        return inventory.physical_regular(path, description)
    except inventory.InventoryError as error:
        raise AllocatorBoundaryError(str(error)) from error


def physical_directory(path: Path, description: str) -> Path:
    try:
        return inventory.physical_directory(path, description)
    except inventory.InventoryError as error:
        raise AllocatorBoundaryError(str(error)) from error


def identity(path: Path, *, logical_path: str | None = None) -> dict[str, object]:
    try:
        return inventory.file_record(path, logical_path=logical_path)
    except inventory.InventoryError as error:
        raise AllocatorBoundaryError(str(error)) from error


def json_object(path: Path, description: str) -> dict[str, Any]:
    try:
        return inventory.read_json(path, description)
    except inventory.InventoryError as error:
        raise AllocatorBoundaryError(str(error)) from error


def exact(value: object, fields: set[str], description: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        fail(f"{description} fields drifted")
    return value


def fresh_output(path: Path, *, static_preparation: Path, static_product: Path, dynamic_product: Path) -> Path:
    path = Path(os.path.abspath(path))
    if path.exists() or path.is_symlink() or not path.parent.is_dir() or path.parent.is_symlink():
        fail("output is not a fresh physical child")
    # `Path.is_relative_to` is lexical. Check every existing component before
    # mkdir so a nested symlink cannot redirect a fresh receipt.
    current = Path(path.anchor)
    try:
        for component in path.parts[1:-1]:
            current /= component
            if stat.S_ISLNK(current.lstat().st_mode):
                fail(f"output traverses a symlink: {path}")
    except OSError as error:
        raise AllocatorBoundaryError(f"output ancestry is unreadable: {path}") from error
    for supplied, description in ((static_preparation.parent, "static preparation cohort"),
                                  (static_product, "static product"), (dynamic_product, "dynamic product")):
        supplied = Path(os.path.abspath(supplied))
        if path.is_relative_to(supplied) or supplied.is_relative_to(path):
            fail(f"output overlaps supplied {description}")
    if not path.is_relative_to(ROOT / ".work/x86_64"):
        fail("output escapes checkout .work/x86_64")
    return path


def mounted_path(path: Path) -> str:
    """Translate one checkout-local path to the collector's fixed mount."""
    path = Path(os.path.abspath(path))
    try:
        relative = path.relative_to(ROOT)
    except ValueError as error:
        raise AllocatorBoundaryError(f"retained command path escapes checkout: {path}") from error
    return "/workspace/" + relative.as_posix()


def workload_environment(output: Path) -> dict[str, str]:
    return {
        "PATH": "/opt/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "TMPDIR": mounted_path(output),
    }


def admitted_supplied_path(path: Path, description: str) -> str:
    """Keep every supplied byte below the fixed readonly x86 work mount."""
    path = Path(os.path.abspath(path))
    require(path.is_relative_to(ROOT / ".work/x86_64"), f"{description} escapes checkout .work/x86_64")
    return mounted_path(path)


def source_file(root: Path, relative: str) -> Path:
    return physical_file(root / relative, f"source {relative}")


def source_records(root: Path) -> dict[str, dict[str, object]]:
    return {relative: identity(source_file(root, relative), logical_path=relative) for relative in COMPONENT_SOURCES}


def validate_source_records(root: Path, value: object) -> None:
    require(isinstance(value, dict) and set(value) == set(COMPONENT_SOURCES), "component source roster drifted")
    require(same(value, source_records(root)), "component source bytes changed")


def load_contract(root: Path = ROOT) -> dict[str, Any]:
    try:
        value = tomllib.loads(source_file(root, CONTRACT_PATH.relative_to(ROOT).as_posix()).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise AllocatorBoundaryError("allocator boundary contract is unreadable") from error
    validate_contract(value)
    return value


def validate_contract(value: object) -> None:
    record = exact(value, {"schema", "id", "target", "status", "backend", "scope", "limits"}, "allocator boundary contract")
    require((record["schema"], record["id"], record["target"], record["status"]) == (
        "crabc.x86_64-native-c-allocator-boundary-contract/v2", "x86-native-c-allocator-boundary",
        TARGET, "implemented-unqualified"), "allocator boundary contract identity drifted")
    require(record["backend"] == {"crate": "libmimalloc-sys", "version": "0.1.49", "mimalloc_version": "3.3.2"},
            "allocator backend contract drifted")
    scope = exact(record["scope"], {"weak_entries", "global_entries", "rust_c_imports", "c_runtime_imports", "lifecycle_entries", "interposition_scenarios", "dynamic_modes", "dynamic_entries", "static_modes"}, "allocator boundary scope")
    require(scope["weak_entries"] == ["malloc"], "weak allocator entry roster drifted")
    require(scope["global_entries"] == ["calloc", "realloc", "reallocarray", "free", "aligned_alloc", "posix_memalign", "memalign", "valloc", "malloc_usable_size"], "global allocator entry roster drifted")
    require(scope["rust_c_imports"] == ["_mi_auto_process_done", "_mi_auto_process_init", "mi_free", "mi_malloc_aligned", "mi_realloc_aligned", "mi_usable_size", "mi_zalloc"], "Rust C import roster drifted")
    require(scope["c_runtime_imports"] == [
        {"name": name, "binding": binding} for name, binding in C_RUNTIME_IMPORTS
    ], "C runtime import roster drifted")
    require(scope["lifecycle_entries"] == ["__crabc_x86_owned_mimalloc_process_initializer", "__crabc_x86_owned_mimalloc_process_finalizer"], "allocator lifecycle roster drifted")
    require(scope["interposition_scenarios"] == list(SCENARIOS) and scope["dynamic_modes"] == list(DYNAMIC_MODES)
            and scope["dynamic_entries"] == list(ENTRIES) and scope["static_modes"] == list(STATIC_MODES),
            "allocator workload roster drifted")
    limits = exact(record["limits"], {"allocator_family_completion", "allocator_promotion", "public_support", "rust_mimalloc_port", "full_allocator_behavior"}, "allocator limits")
    require(all(item is False for item in limits.values()), "allocator limits became promoting")


def wrapper_roles(contract: Mapping[str, Any]) -> dict[str, str]:
    scope = contract["scope"]
    return {**{name: "WEAK" for name in scope["weak_entries"]},
            **{name: "GLOBAL" for name in scope["global_entries"]}}


def _static_definition(facts: Mapping[str, Any], name: str, description: str) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    """Return the one static archive member defining `name`, with its row.

    The installed archive emits one member per Rust module, so each public
    provider is located by its definition rather than in one fixed member.
    """
    placements = facts.get("facts")
    require(isinstance(placements, dict) and type(placements.get("candidate-static")) is list,
            f"ELF facts omit static {description} placements")
    found: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for member in placements["candidate-static"]:
        if not isinstance(member, dict) or member.get("member_occurrence") != 0:
            continue
        try:
            rows = producer._symbol_tables(member.get("symbol_tables"), f"static {description}", {".symtab"})[".symtab"]
        except producer.ProducerMetadataError as error:
            raise AllocatorBoundaryError(str(error)) from error
        found.extend((member, row) for row in rows
                     if row.get("name") == name and type(row.get("section_index")) is str
                     and row["section_index"].isdigit() and int(row["section_index"]) > 0)
    require(len(found) == 1, f"static {description} {name} is not defined by exactly one archive member")
    member = found[0][0]
    require(type(member.get("member")) is str and isinstance(member.get("member_index"), int)
            and member["member_index"] >= 0, f"static {description} {name} member differs")
    return member, found[0][1]


def _member_identity(member: Mapping[str, Any]) -> dict[str, object]:
    return {key: member[key] for key in ("member", "member_index", "member_occurrence")}


def c_runtime_import_roles(contract: Mapping[str, Any]) -> dict[str, str]:
    """Return the finite C translation-unit imports and their Rust bindings."""
    scope = contract["scope"]
    return {item["name"]: item["binding"] for item in scope["c_runtime_imports"]}


WRAPPER_C_ABI = {
    "malloc": ("WEAK", "pub unsafe extern \"C\" fn malloc(size: SizeT) -> *mut c_void", "mi_malloc_aligned"),
    "calloc": ("GLOBAL", "pub unsafe extern \"C\" fn calloc(count: SizeT, size: SizeT) -> *mut c_void", "mi_zalloc"),
    "realloc": ("GLOBAL", "pub unsafe extern \"C\" fn realloc(ptr: *mut c_void, new_size: SizeT) -> *mut c_void", "mi_realloc_aligned"),
    "reallocarray": ("GLOBAL", "pub unsafe extern \"C\" fn reallocarray(ptr: *mut c_void, count: SizeT, size: SizeT) -> *mut c_void", "realloc(ptr, total)"),
    "free": ("GLOBAL", "pub unsafe extern \"C\" fn free(ptr: *mut c_void)", "mi_free"),
    "aligned_alloc": ("GLOBAL", "pub unsafe extern \"C\" fn aligned_alloc(alignment: SizeT, size: SizeT) -> *mut c_void", "mi_malloc_aligned"),
    "posix_memalign": ("GLOBAL", "pub unsafe extern \"C\" fn posix_memalign(result: *mut *mut c_void, alignment: SizeT, size: SizeT) -> c_int", "aligned_alloc(alignment, size)"),
    "memalign": ("GLOBAL", "pub unsafe extern \"C\" fn memalign(alignment: SizeT, size: SizeT) -> *mut c_void", "aligned_alloc(alignment, size)"),
    "valloc": ("GLOBAL", "pub unsafe extern \"C\" fn valloc(size: SizeT) -> *mut c_void", "memalign(4096, size)"),
}
USABLE_SIZE_C_ABI = "pub unsafe extern \"C\" fn malloc_usable_size(ptr: *mut c_void) -> usize"


def _normalize_rust_head(value: str) -> str:
    normalized = re.sub(r"\s+", " ", value).strip()
    return re.sub(r",\s*\)", ")", re.sub(r"\(\s+", "(", normalized))


def _c_abi_bindings(wrapper: str, observation: str) -> dict[str, dict[str, str]]:
    """Authenticate the finite Rust C declarations before checking their bodies."""
    result: dict[str, dict[str, str]] = {}
    for name, (binding, signature, callee) in WRAPPER_C_ABI.items():
        matched = re.search(
            rf'(?s)(?P<attributes>(?:#\[[^\n]+\]\s*)*)'
            rf'(?P<head>pub\s+unsafe\s+extern\s+"C"\s+fn\s+{re.escape(name)}\b.*?)(?P<body>\{{.*?)(?=\n#\[no_mangle\]|\Z)',
            wrapper,
        )
        require(matched is not None, f"allocator wrapper has no C ABI body for {name}")
        attributes, head, body = matched.group("attributes"), matched.group("head"), matched.group("body")
        require(_normalize_rust_head(head.rstrip()) == signature, f"allocator C ABI signature differs for {name}")
        require("#[no_mangle]" in attributes and callee in body, f"allocator wrapper body differs for {name}")
        require(("#[linkage = \"weak\"]" in attributes) == (binding == "WEAK"),
                f"allocator wrapper binding differs for {name}")
        result[name] = {"binding": binding, "signature": signature, "callee": callee}
    observed = re.search(
        r'(?s)(?P<attributes>(?:#\[[^\n]+\]\s*)*)'
        r'(?P<head>pub\s+unsafe\s+extern\s+"C"\s+fn\s+malloc_usable_size\b.*?)(?P<body>\{.*)\Z',
        observation,
    )
    require(observed is not None, "usable-size wrapper has no C ABI body")
    require(_normalize_rust_head(observed.group("head").rstrip()) == USABLE_SIZE_C_ABI,
            "usable-size C ABI signature differs")
    require("#[no_mangle]" in observed.group("attributes")
            and "#[linkage = \"weak\"]" not in observed.group("attributes")
            and "libmimalloc_sys::mi_usable_size(ptr)" in observed.group("body"),
            "usable-size C ABI wrapper source drifted")
    result["malloc_usable_size"] = {
        "binding": "GLOBAL", "signature": USABLE_SIZE_C_ABI, "callee": "mi_usable_size",
    }
    return result


def _lifecycle_c_abi(lifecycle: str) -> dict[str, object]:
    """Bind the private C call declarations to the two retained array callbacks."""
    imports = re.search(r'(?s)unsafe\s+extern\s+"C"\s*\{(?P<body>.*?)\}', lifecycle)
    require(imports is not None, "allocator lifecycle import block is absent")
    names = re.findall(r'\bfn\s+([_A-Za-z][_A-Za-z0-9]*)\s*\(\s*\)\s*;', imports.group("body"))
    require(names == ["_mi_auto_process_init", "_mi_auto_process_done"],
            "allocator lifecycle import declaration differs")
    callbacks = (
        ("initialize", "_mi_auto_process_init", "__crabc_x86_owned_mimalloc_process_initializer", ".init_array"),
        ("finalize", "_mi_auto_process_done", "__crabc_x86_owned_mimalloc_process_finalizer", ".fini_array"),
    )
    observations: list[dict[str, str]] = []
    for callback, target, symbol, section in callbacks:
        body = re.search(
            rf'(?s)unsafe\s+extern\s+"C"\s+fn\s+{callback}\s*\(\s*\)\s*\{{(?P<body>.*?)^\}}',
            lifecycle,
            re.MULTILINE,
        )
        require(body is not None and re.search(rf'unsafe\s*\{{\s*{target}\s*\(\s*\)\s*\}}', body.group("body")) is not None,
                f"allocator lifecycle callback differs for {callback}")
        entry = re.search(
            rf'(?s)#\[used\]\s*#\[linkage\s*=\s*"internal"\]\s*'
            rf'#\[export_name\s*=\s*"{symbol}"\]\s*#\[link_section\s*=\s*"{re.escape(section)}"\]\s*'
            rf'static\s+[_A-Za-z][_A-Za-z0-9]*\s*:\s*unsafe\s+extern\s+"C"\s+fn\s*\(\s*\)\s*=\s*{callback}\s*;',
            lifecycle,
        )
        require(entry is not None, f"allocator lifecycle array entry differs for {symbol}")
        observations.append({"callback": callback, "target": target, "symbol": symbol, "section": section})
    return {"imports": names, "callbacks": observations}


def _wrapper_product_bindings(facts: Mapping[str, Any], roles: Mapping[str, str]) -> dict[str, object]:
    """Bind the ten public Rust wrappers to their actual static and shared definitions."""
    placements = facts.get("facts")
    try:
        shared_tables = producer._symbol_tables(
            isinstance(placements, dict) and isinstance(placements.get("candidate-shared"), dict)
            and placements["candidate-shared"].get("symbol_tables"),
            "shared public allocator wrappers", {".dynsym", ".symtab"},
        )
    except producer.ProducerMetadataError as error:
        raise AllocatorBoundaryError(str(error)) from error

    def selected_row(row: Mapping[str, Any], name: str, binding: str, description: str) -> dict[str, object]:
        require(row.get("raw_name") == name and row.get("type") == "FUNC" and row.get("binding") == binding
                and row.get("visibility") == "DEFAULT" and row.get("version") is None
                and row.get("version_default") is False and type(row.get("section_index")) is str
                and row["section_index"].isdigit() and int(row["section_index"]) > 0
                and type(row.get("size_bytes")) is int and row["size_bytes"] > 0,
                f"{description} wrapper binding differs for {name}")
        return {key: row[key] for key in ("name", "raw_name", "type", "binding", "visibility", "section_index", "size_bytes", "version", "version_default")}

    def shared_row(rows: Sequence[Mapping[str, Any]], name: str, binding: str, description: str) -> dict[str, object]:
        matches = [row for row in rows if row.get("name") == name]
        require(len(matches) == 1, f"{description} wrapper row differs for {name}")
        return selected_row(matches[0], name, binding, description)

    require(set(roles) == set(WRAPPER_C_ABI) | {"malloc_usable_size"}, "public allocator wrapper role roster drifted")
    static_members: dict[str, object] = {}
    static_rows: dict[str, object] = {}
    for name, binding in roles.items():
        member, row = _static_definition(facts, name, "public allocator wrapper")
        static_members[name] = _member_identity(member)
        static_rows[name] = selected_row(row, name, binding, "static")
    return {
        "static_members": static_members,
        "static": static_rows,
        "shared": {table: {name: shared_row(rows, name, binding, f"shared {table}")
                            for name, binding in roles.items()}
                   for table, rows in shared_tables.items()},
    }


def _static_member(facts: Mapping[str, Any], name: str, description: str) -> Mapping[str, Any]:
    placements = facts.get("facts")
    require(isinstance(placements, dict) and isinstance(placements.get("candidate-static"), list),
            "ELF facts omit static C runtime members")
    matches = [member for member in placements["candidate-static"]
               if isinstance(member, dict) and member.get("member") == name
               and member.get("member_occurrence") == 0]
    require(len(matches) == 1, f"{description} differs")
    member = matches[0]
    require(isinstance(member.get("member_index"), int) and member["member_index"] >= 0,
            f"{description} index differs")
    return member


def _runtime_import_row(row: Mapping[str, Any], name: str, binding: str, description: str,
                        *, import_row: bool) -> dict[str, object]:
    require(row.get("name") == name and row.get("raw_name") == name
            and row.get("version") is None and row.get("version_default") is False,
            f"{description} name/version differs for {name}")
    if import_row:
        require(row.get("type") == "NOTYPE" and row.get("binding") == "GLOBAL"
                and row.get("visibility") == "DEFAULT" and row.get("section_index") == "UND"
                and row.get("size_bytes") == 0 and row.get("value") == "0000000000000000",
                f"{description} import differs for {name}")
    else:
        section = row.get("section_index")
        require(row.get("type") == "FUNC" and row.get("binding") == binding
                and row.get("visibility") == "DEFAULT" and isinstance(section, str)
                and section.isdigit() and int(section) > 0
                and isinstance(row.get("size_bytes"), int) and row["size_bytes"] > 0,
                f"{description} provider differs for {name}")
    return {key: row[key] for key in (
        "name", "raw_name", "type", "binding", "visibility", "section_index", "size_bytes",
        "value", "version", "version_default",
    )}


def _c_runtime_import_bindings(facts: Mapping[str, Any], account: Mapping[str, Any],
                               roles: Mapping[str, str]) -> dict[str, object]:
    """Join the selected C static member to finite public Rust providers.

    ``archive_map`` comes from the fixed-C producer reader, which already
    authenticates the C member bytes and source bundle.  The rows below are
    reconstructed from the supplied current ELF facts rather than accepted
    from a receipt-provided member name, hash, or provider list. Each static
    provider is the one Rust archive member that defines the import.
    """
    archive = account.get("archive_map")
    require(isinstance(archive, dict), "fixed-C producer account omits archive map")
    required = {
        "static_c_member", "static_c_member_sha256", "shared_rust_root_member", "shared_c_member_sha256",
    }
    require(required <= set(archive) and all(isinstance(archive[name], str) and archive[name]
                                              for name in required),
            "fixed-C producer archive map differs")
    rust_members = archive.get("static_rust_members")
    require(type(rust_members) is list and rust_members and all(type(name) is str and name for name in rust_members),
            "fixed-C producer archive map omits its static Rust members")
    c_member = _static_member(facts, archive["static_c_member"], "static C runtime member")
    try:
        c_rows = producer._symbol_tables(c_member.get("symbol_tables"), "static C runtime imports", {".symtab"})[".symtab"]
        placements = facts.get("facts")
        shared = placements.get("candidate-shared") if isinstance(placements, dict) else None
        shared_tables = producer._symbol_tables(
            shared.get("symbol_tables") if isinstance(shared, dict) else None,
            "shared Rust runtime providers", {".dynsym", ".symtab"},
        )
    except producer.ProducerMetadataError as error:
        raise AllocatorBoundaryError(str(error)) from error

    def exactly_one(rows: Sequence[Mapping[str, Any]], name: str, description: str,
                    *, import_row: bool, binding: str) -> dict[str, object]:
        selected = [row for row in rows if row.get("name") == name]
        require(len(selected) == 1, f"{description} repeats or omits {name}")
        return _runtime_import_row(selected[0], name, binding, description, import_row=import_row)

    claims = []
    provider_members: dict[str, dict[str, object]] = {}
    for name, binding in roles.items():
        member, row = _static_definition(facts, name, "Rust runtime provider")
        require(member["member"] in rust_members, f"static Rust runtime provider {name} is outside the Rust members")
        identity_record = _member_identity(member)
        provider_members[member["member"]] = identity_record
        claims.append({
            "name": name,
            "binding": binding,
            "static_c_import": exactly_one(c_rows, name, "static C runtime", import_row=True, binding=binding),
            "static_rust_provider": _runtime_import_row(row, name, binding, "static Rust runtime", import_row=False),
            "static_rust_provider_member": identity_record,
            "shared_dynsym_provider": exactly_one(shared_tables[".dynsym"], name, "shared .dynsym runtime",
                                                  import_row=False, binding=binding),
            "shared_symtab_provider": exactly_one(shared_tables[".symtab"], name, "shared .symtab runtime",
                                                  import_row=False, binding=binding),
        })
    return {
        "static_c_member": {
            "name": archive["static_c_member"], "member_index": c_member["member_index"],
            "member_occurrence": c_member["member_occurrence"], "sha256": archive["static_c_member_sha256"],
        },
        "static_rust_provider_members": [provider_members[name] for name in sorted(provider_members)],
        "shared_rust_root_member": archive["shared_rust_root_member"],
        "shared_c_member_sha256": archive["shared_c_member_sha256"],
        "imports": claims,
    }


def _validate_default_c_allocator_selection(static_root: str) -> None:
    """Keep each C owner behind its existing gate and the native-shadow exclusion."""
    for gate, declaration in (
        ("crabc_owned_mimalloc_lifecycle", '#[path = "allocator_mimalloc_lifecycle.rs"]\nmod allocator_mimalloc_lifecycle;'),
        ('crabc_x86_allocator_runtime', "mod allocator {"),
        ('crabc_x86_allocator_observability', "mod allocator_observability {"),
    ):
        selection = (
            "#[cfg(all(\n"
            f"    {gate},\n"
            '    not(feature = "native-mimalloc-shadow"),\n'
            "))]\n" + declaration
        )
        require(static_root.count(selection) == 1,
                f"x86 static C allocator selection differs for {gate}")
    for fragment in ('include!("../../allocator_mimalloc.rs")',
                     'include!("../../allocator_observability_mimalloc.rs")'):
        require(fragment in static_root, f"x86 static root omits {fragment}")


def source_resolution(root: Path, product_revision: str) -> dict[str, object]:
    """Check C call sites and prove their blobs still equal the product epoch."""
    require(REVISION.fullmatch(product_revision) is not None, "product source revision is invalid")
    texts = {relative: source_file(root, relative).read_text(encoding="utf-8") for relative in RUNTIME_SOURCES}
    c_abi_bindings = _c_abi_bindings(texts["libc/src/allocator_mimalloc.rs"], texts["libc/src/allocator_observability_mimalloc.rs"])
    lifecycle = texts["libc/src/c_abi/x86_64/allocator_mimalloc_lifecycle.rs"]
    lifecycle_c_abi = _lifecycle_c_abi(lifecycle)
    for name in ("errno::get_errno", "errno::set_errno"):
        require(name in lifecycle, f"allocator lifecycle source omits {name}")
    static_root = texts["libc/src/c_abi/x86_64/static_c_abi.rs"]
    _validate_default_c_allocator_selection(static_root)
    crypt = texts["libc/src/crypt_impl.rs"]
    require("struct CrabcRustAllocator" in crypt and "mi_malloc_aligned" in crypt and "mi_free" in crypt,
            "crypt allocator source does not use the selected C backend")
    cargo = texts["libc/Cargo.toml"]
    require('x86-allocator-runtime = ["dep:libmimalloc-sys"]' in cargo and
            'x86-crypt-allocator-composition = ["x86-crypt", "x86-allocator-runtime"]' in cargo,
            "allocator feature composition drifted")
    blobs: dict[str, str] = {}
    for relative in RUNTIME_SOURCES:
        current = source_file(root, relative).read_bytes()
        completed = subprocess.run(["git", "show", f"{product_revision}:{relative}"], cwd=root,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        require(completed.returncode == 0 and current == completed.stdout,
                f"product source differs for {relative}")
        blobs[relative] = hashlib.sha256(current).hexdigest()
    return {"product_revision": product_revision, "runtime_source_sha256": blobs,
            "c_abi_bindings": c_abi_bindings, "lifecycle_c_abi": lifecycle_c_abi}

def _product_source(preparation: Mapping[str, Any]) -> dict[str, object]:
    exact(preparation, {"schema", "status", "work", "source", "source_seals", "pins", "products", "archives", "steps"},
          "static preparation")
    require(preparation["schema"] == static_products.SCHEMA and preparation["status"] == "prepared-unqualified",
            "static preparation identity drifted")
    source = exact(preparation["source"], {"revision", "content_sha256"}, "static preparation source")
    require(type(source["revision"]) is str and REVISION.fullmatch(source["revision"]) is not None and
            type(source["content_sha256"]) is str and SHA256.fullmatch(source["content_sha256"]) is not None,
            "static preparation source identity drifted")
    return source


def _require_identity_pair(value: object, actual: Mapping[str, object], description: str) -> None:
    record = exact(value, {"path", "sha256", "size"}, description)
    require(type(record["path"]) is str and type(record["sha256"]) is str and SHA256.fullmatch(record["sha256"]) is not None
            and type(record["size"]) is int and record["size"] >= 0,
            f"{description} scalar types drifted")
    require(record["sha256"] == actual["sha256"] and record["size"] == actual["size"],
            f"{description} bytes differ")


def _static_preparation_tree(preparation: Mapping[str, Any], static_product: Path,
                             static_manifest: Path) -> None:
    """Join the supplied static tree to the receipt's independently extracted primary tree."""
    products = exact(preparation["products"], {"primary", "reproduction", "extracted"}, "static preparation products")
    primary = exact(products["primary"], {"path", "manifest", "tree", "producer_tools", "toolchain"},
                    "static preparation primary product")
    require(isinstance(primary["tree"], dict) and primary["tree"], "static preparation primary tree is absent")
    try:
        current_tree = static_products.tree_identity(static_product)
    except (static_products.PreparationError, OSError, ValueError) as error:
        raise AllocatorBoundaryError(f"static preparation primary tree is invalid: {error}") from error
    require(same(primary["tree"], current_tree), "supplied static product differs from preparation primary tree")
    _require_identity_pair(primary["manifest"], identity(static_manifest, logical_path="/inputs/static-product/share/crabc/manifest.json"),
                           "static preparation primary manifest")


def _epoch_source(preparation: Mapping[str, Any], report: Mapping[str, Any], dynamic_state: Mapping[str, Any]) -> dict[str, object]:
    """Require the static preparation, ELF facts, and dynamic state to name one product epoch."""
    source = _product_source(preparation)
    facts_source = exact(report.get("collector_execution_source"), {"revision", "content_sha256", "clean"},
                         "ELF facts collector source")
    require(type(facts_source["revision"]) is str and REVISION.fullmatch(facts_source["revision"]) is not None
            and type(facts_source["content_sha256"]) is str and SHA256.fullmatch(facts_source["content_sha256"]) is not None
            and facts_source["clean"] is True, "ELF facts collector source scalar types drifted")
    require(facts_source["revision"] == source["revision"]
            and facts_source["content_sha256"] == source["content_sha256"],
            "ELF facts source differs from static preparation")
    require(dynamic_state.get("schema") == "crabc.x86_64-owned-dynamic-materialization/v1"
            and type(dynamic_state.get("source_sha256")) is str
            and SHA256.fullmatch(dynamic_state["source_sha256"]) is not None,
            "dynamic materialization source identity drifted")
    require(dynamic_state["source_sha256"] == source["content_sha256"],
            "dynamic product source differs from static preparation")
    return {"revision": source["revision"], "content_sha256": source["content_sha256"]}

def _manifest_identity(product: Path, manifest: Path, input_root: str) -> dict[str, object]:
    return identity(manifest, logical_path=f"{input_root}/share/crabc/manifest.json")


def _report_artifact(report: Mapping[str, Any], name: str, product: Path, relative: str) -> dict[str, object]:
    try:
        observed = report["artifacts"][name]["identity"]
    except (KeyError, TypeError) as error:
        raise AllocatorBoundaryError(f"ELF facts omit {name} product identity") from error
    require(isinstance(observed, dict), f"ELF facts {name} identity drifted")
    actual = identity(product / relative, logical_path=observed.get("path") if isinstance(observed.get("path"), str) else None)
    require(same(observed, actual), f"ELF facts {name} bytes differ from supplied product")
    return actual


def validate_supplied_products(*, root: Path, static_preparation: Path, static_product: Path,
                               dynamic_product: Path, elf_facts_report: Path) -> dict[str, object]:
    """Authenticate exact supplied product bytes without invoking a builder."""
    root = Path(root).absolute()
    contract = load_contract(root)
    roles = wrapper_roles(contract)
    runtime_roles = c_runtime_import_roles(contract)
    static_product = physical_directory(static_product, "static product")
    dynamic_product = physical_directory(dynamic_product, "dynamic product")
    static_preparation = physical_file(static_preparation, "static preparation")
    elf_facts_report = physical_file(elf_facts_report, "ELF facts report")
    try:
        static_manifest, _ = product_evidence._validate_static_product(static_product)
        dynamic_manifest, _ = product_evidence._validate_dynamic_product(dynamic_product)
    except product_evidence.ProductEvidenceError as error:
        raise AllocatorBoundaryError(str(error)) from error
    preparation = json_object(static_preparation, "static preparation")
    _static_preparation_tree(preparation, static_product, static_manifest)
    report = json_object(elf_facts_report, "ELF facts report")
    require(report.get("target") == TARGET and report.get("schema") == "crabc.x86_64-native-abi-elf-facts/v1",
            "ELF facts identity drifted")
    dynamic_state = json_object(dynamic_product / "share/crabc/dynamic-product-state.json", "dynamic materialization state")
    product_source = _epoch_source(preparation, report, dynamic_state)
    source = source_resolution(root, product_source["revision"])
    static_libc = _report_artifact(report, "candidate-static", static_product, "usr/lib/libc.a")
    dynamic_libc = _report_artifact(report, "candidate-shared", dynamic_product, "usr/lib/libc.so")
    static_provenance = physical_file(static_product / "share/crabc/libc-static.provenance.json", "static allocator provenance")
    shared_provenance = physical_file(dynamic_product / "share/crabc/libc-shared.provenance.json", "shared allocator provenance")
    try:
        account = producer.account_producer_metadata(
            report, json_object(static_provenance, "static allocator provenance"),
            json_object(shared_provenance, "shared allocator provenance"), json_object(dynamic_manifest, "dynamic manifest"))
    except producer.ProducerMetadataError as error:
        raise AllocatorBoundaryError(str(error)) from error
    expected = ["_mi_auto_process_done", "_mi_auto_process_init", "mi_free", "mi_malloc_aligned", "mi_realloc_aligned", "mi_usable_size", "mi_zalloc"]
    joins = account.get("rust_root_c_import_joins")
    require(isinstance(joins, list) and [item.get("name") for item in joins if isinstance(item, dict)] == expected,
            "fixed-C producer import joins drifted")
    wrappers = _wrapper_product_bindings(report, roles)
    runtime_imports = _c_runtime_import_bindings(report, account, runtime_roles)
    return {
        "product_source": product_source,
        "source_resolution": source,
        "static_preparation": identity(static_preparation, logical_path="/inputs/static-preparation.json"),
        "static": {"product": "/inputs/static-product", "manifest": _manifest_identity(static_product, static_manifest, "/inputs/static-product"),
                   "libc": static_libc, "provenance": identity(static_provenance, logical_path="/inputs/static-product/share/crabc/libc-static.provenance.json")},
        "dynamic": {"product": "/inputs/dynamic-product", "manifest": _manifest_identity(dynamic_product, dynamic_manifest, "/inputs/dynamic-product"),
                    "state": identity(dynamic_product / "share/crabc/dynamic-product-state.json", logical_path="/inputs/dynamic-product/share/crabc/dynamic-product-state.json"),
                    "libc": dynamic_libc, "provenance": identity(shared_provenance, logical_path="/inputs/dynamic-product/share/crabc/libc-shared.provenance.json")},
        "elf_facts": identity(elf_facts_report, logical_path="/inputs/elf-facts-report.json"),
        "producer_account": account,
        "wrapper_product_bindings": wrappers,
        "c_runtime_import_bindings": runtime_imports,
    }

def _capture(output: Path, label: str, argv: list[str], environment: Mapping[str, str]) -> dict[str, object]:
    raw = output / RAW
    raw.mkdir(exist_ok=True)
    stdout, stderr, status = (raw / f"{label}.{suffix}" for suffix in ("stdout", "stderr", "status"))
    completed = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=dict(environment), check=False)
    stdout.write_bytes(completed.stdout)
    stderr.write_bytes(completed.stderr)
    status.write_text(f"{completed.returncode}\n", encoding="ascii")
    require(completed.returncode == 0, f"{label} runner failed ({completed.returncode})")
    return {"argv": argv, "environment": dict(environment),
            **{suffix: identity(path, logical_path=path.relative_to(output).as_posix())
               for suffix, path in (("stdout", stdout), ("stderr", stderr), ("status", status))}}


def _new_work(output: Path, prefix: str, before: set[Path]) -> Path:
    created = set(output.glob(prefix + ".*")) - before
    require(len(created) == 1, f"runner did not create exactly one {prefix} work directory")
    work = physical_directory(created.pop(), f"{prefix} runner work")
    os.chmod(work, 0o755)
    for path in work.rglob("*"):
        if path.is_file() and not path.is_symlink():
            os.chmod(path, path.stat().st_mode | stat.S_IROTH)
    return work


def _stream(work: Path, output: Path, stem: str) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for suffix in ("stdout", "stderr", "status"):
        path = physical_file(work / f"{stem}.{suffix}", f"{stem} {suffix}")
        result[suffix] = identity(path, logical_path=path.relative_to(output).as_posix())
    require((work / f"{stem}.status").read_bytes() == b"0\n", f"{stem} did not exit zero")
    return result


def _portable_link_validation(value: object) -> dict[str, str]:
    """Keep one link result comparable across its sealed container and host paths.

    The supplied-product account separately seals the physical product tree.
    A product reader's absolute location is therefore not a durable part of
    this component's link observation; its format and manifest digest are.
    """

    item = exact(value, {"linkage", "product", "product_format", "product_manifest_sha256",
                         "workload_sha256", "executable_sha256", "receipt_sha256"}, "owned link validation")
    require(type(item["linkage"]) is str and item["linkage"] in {*STATIC_MODES, *DYNAMIC_MODES},
            "owned link validation linkage differs")
    require(type(item["product"]) is str and Path(item["product"]).is_absolute(),
            "owned link validation product path differs")
    require(type(item["product_format"]) is str and item["product_format"] in {
        product_evidence.STATIC_PRODUCT_FORMAT, product_evidence.DYNAMIC_PRODUCT_FORMAT,
    }, "owned link validation product format differs")
    for name in ("product_manifest_sha256", "workload_sha256", "executable_sha256", "receipt_sha256"):
        require(type(item[name]) is str and SHA256.fullmatch(item[name]) is not None,
                f"owned link validation {name} differs")
    return {name: item[name] for name in item if name != "product"}


def _link(work: Path, output: Path, product: Path, workload: Path, executable: str, receipt: str,
          linkage: str, *, export_dynamic: bool = False) -> dict[str, object]:
    require(type(export_dynamic) is bool, "owned link export-dynamic contract is not boolean")
    try:
        result = product_evidence.validate_link(
            product, workload, work / executable, work / receipt, linkage, export_dynamic=export_dynamic
        )
    except product_evidence.ProductEvidenceError as error:
        raise AllocatorBoundaryError(str(error)) from error
    receipt_record = json_object(work / receipt, "owned link receipt")
    linker = exact(receipt_record.get("resolved_linker"), {"path", "sha256"}, "owned link receipt linker")
    require(type(linker["path"]) is str and Path(linker["path"]).is_absolute() and type(linker["sha256"]) is str
            and SHA256.fullmatch(linker["sha256"]) is not None, "owned link receipt linker identity drifted")
    try:
        actual_linker = physical_file(Path(linker["path"]), "owned link receipt linker")
    except AllocatorBoundaryError:
        raise
    require(inventory.sha256(actual_linker) == linker["sha256"], "owned link receipt linker bytes drifted")
    return {"validated": _portable_link_validation(result),
            "executable": identity(work / executable, logical_path=(work / executable).relative_to(output).as_posix()),
            "receipt": identity(work / receipt, logical_path=(work / receipt).relative_to(output).as_posix()),
            "linker": dict(linker), "export_dynamic": export_dynamic}


def _replay_link(work: Path, output: Path, product: Path, workload: Path, executable: str,
                 receipt: str, linkage: str, record: object, *, export_dynamic: bool) -> dict[str, object]:
    require(type(export_dynamic) is bool, "expected owned export-dynamic contract is not boolean")
    item = exact(record, {"validated", "executable", "receipt", "linker", "export_dynamic"}, "owned link record")
    executable_path, receipt_path = work / executable, work / receipt
    require(same(item["executable"], identity(executable_path, logical_path=executable_path.relative_to(output).as_posix())),
            "owned link executable identity drifted")
    require(same(item["receipt"], identity(receipt_path, logical_path=receipt_path.relative_to(output).as_posix())),
            "owned link receipt identity drifted")
    linker = exact(item["linker"], {"path", "sha256"}, "sealed owned linker")
    require(type(item["export_dynamic"]) is bool and item["export_dynamic"] is export_dynamic,
            "sealed owned export-dynamic contract differs from workload role")
    try:
        result = product_evidence.validate_retained_link(
            ROOT, "/workspace", product, workload, executable_path, receipt_path, linkage, linker,
            export_dynamic=export_dynamic,
        )
    except product_evidence.ProductEvidenceError as error:
        raise AllocatorBoundaryError(str(error)) from error
    require(same(item["validated"], _portable_link_validation(result)), "retained owned link result drifted")
    return item


def _startup_workload(work: Path) -> Path:
    return physical_file(work / "workload.o", "startup same-object workload")


def _runtime_static_member_links(work: Path, output: Path, static_product: Path,
                                 runtime_imports: Mapping[str, Any]) -> dict[str, object]:
    """Require ordinary static consumers to select the authenticated C member.

    The generic owned-product reader authenticates each retained link receipt,
    map, and trace.  This component adds only the finite semantic join needed
    here: both ordinary static modes must select the producer-authenticated C
    member and every Rust member that provides its fixed public imports.
    """
    c_member = exact(runtime_imports.get("static_c_member"), {
        "name", "member_index", "member_occurrence", "sha256",
    }, "C runtime static member")
    providers = runtime_imports.get("static_rust_provider_members")
    require(type(providers) is list and providers, "C runtime static Rust providers differ")
    provider_names = []
    for provider in providers:
        record = exact(provider, {"member", "member_index", "member_occurrence"}, "C runtime static Rust provider")
        require(type(record["member"]) is str and record["member"], "C runtime static Rust provider name differs")
        provider_names.append(record["member"])
    require(type(c_member["name"]) is str and c_member["name"] and len(set(provider_names)) == len(provider_names),
            "C runtime static member names differ")
    archive = mounted_path(static_product / "usr/lib/libc.a")
    selected = {"static_c_member": f"{archive}({c_member['name']})"}
    selected.update({f"static_rust_provider:{name}": f"{archive}({name})" for name in provider_names})
    result: dict[str, object] = {}
    for mode in STATIC_MODES:
        receipt = physical_file(work / f"static-{mode}.crabc-link.json", f"{mode} C runtime receipt")
        trace = physical_file(receipt.with_suffix(".trace"), f"{mode} C runtime trace")
        link_map = physical_file(receipt.with_suffix(".map"), f"{mode} C runtime map")
        try:
            trace_lines = trace.read_text(encoding="utf-8").splitlines()
            map_text = link_map.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise AllocatorBoundaryError(f"{mode} C runtime link sidecar is unreadable") from error
        # The trace records archive extraction. Only the C member must also
        # keep sections: `--gc-sections` may drop a provider member whose one
        # function (for example realpath) this workload never reaches.
        for label, member in selected.items():
            require(trace_lines.count(member) == 1,
                    f"{mode} C runtime trace selection differs for {label}")
            require(label != "static_c_member" or member + ":" in map_text,
                    f"{mode} C runtime map selection differs for {label}")
        result[mode] = {
            "map": identity(link_map, logical_path=link_map.relative_to(output).as_posix()),
            "trace": identity(trace, logical_path=trace.relative_to(output).as_posix()),
            "selected_members": dict(selected),
        }
    return result


def _vm_private_relocations(transcript: str) -> dict[str, list[dict[str, object]]]:
    """Keep only direct calls from the selected C object to private VM bodies."""
    result: dict[str, list[dict[str, object]]] = {name: [] for name in VM_PRIVATE_IMPORTS}
    section: str | None = None
    for line in transcript.splitlines():
        header = re.match(r"^Relocation section '\.rela(\.text\.[^']+)'", line)
        if header:
            section = header.group(1)
            continue
        if line.startswith("Relocation section "):
            section = None
            continue
        row = re.match(r"^\s*([0-9a-f]{16})\s+\S+\s+(R_X86_64_\w+)\s+\S+\s+(\S+)\s+([+-])\s+(\d+)\s*$", line)
        if row is None or row.group(3) not in result:
            continue
        name = row.group(3)
        require(section is not None and row.group(2) == "R_X86_64_PLT32"
                and row.group(4) == "-" and row.group(5) == "4",
                f"private VM import {name} is not a direct C call")
        result[name].append({"section": section, "offset": int(row.group(1), 16)})
    require(all(rows and len({(row['section'], row['offset']) for row in rows}) == len(rows)
                for rows in result.values()), "private VM C-call relocation roster differs")
    return result


def _public_weak_relocations(transcript: str, name: str, kind: str) -> list[dict[str, object]]:
    """Read the actual C direct-call or Rust GOT-call relocation."""
    require(name in PUBLIC_WEAK_IMPORTS and kind in {"R_X86_64_PLT32", "R_X86_64_GOTPCREL"},
            "public weak import role differs")
    section: str | None = None
    rows: list[dict[str, object]] = []
    for line in transcript.splitlines():
        header = re.match(r"^Relocation section '\.rela(\.text\.[^']+)'", line)
        if header:
            section = header.group(1)
            continue
        if line.startswith("Relocation section "):
            section = None
            continue
        row = re.match(r"^\s*([0-9a-f]{16})\s+\S+\s+(R_X86_64_\w+)\s+\S+\s+(\S+)\s+([+-])\s+(\d+)\s*$", line)
        if row is None or row.group(3) != name:
            continue
        require(section is not None and row.group(2) == kind and row.group(4) == "-"
                and row.group(5) == "4", f"public weak {name} relocation form differs")
        rows.append({"section": section, "offset": int(row.group(1), 16)})
    require(len(rows) == 1, f"public weak {name} source relocation differs")
    return rows


def _ordinary_import_relocations(transcript: str, name: str) -> list[dict[str, object]]:
    """Retain call relocations for one archive import, including their call form."""
    section: str | None = None
    calls = []
    for line in transcript.splitlines():
        header = re.match(r"^Relocation section '\.rela(\.text(?:\.[^']+)?)'", line)
        if header:
            section = header.group(1)
            continue
        if line.startswith("Relocation section "):
            section = None
            continue
        row = re.match(r"^\s*([0-9a-f]{16})\s+\S+\s+(R_X86_64_\w+)\s+\S+\s+(\S+)\s+([+-])\s+(\d+)\s*$", line)
        if row is None or row.group(3) != name:
            continue
        require(section is not None and row.group(2) in {"R_X86_64_PLT32", "R_X86_64_GOTPCREL"}
                and row.group(4) == "-" and row.group(5) == "4",
                f"ordinary import {name} relocation is not a supported call")
        calls.append({"section": section, "offset": int(row.group(1), 16),
                      "kind": row.group(2)})
    require(calls and len({(row["section"], row["offset"]) for row in calls}) == len(calls),
            f"ordinary import {name} relocation roster differs")
    return calls


def _errno_import_relocations(transcript: str) -> list[dict[str, object]]:
    calls = _ordinary_import_relocations(transcript, ERRNO_IMPORT_NAME)
    require(all(call["kind"] == "R_X86_64_PLT32" for call in calls),
            "errno import relocation is not a direct call")
    return [{"section": call["section"], "offset": call["offset"]} for call in calls]


def _elf_virtual_bytes(image: bytes, address: int, size: int, expected_type: int) -> bytes:
    """Read a final ELF virtual address through its own load segments."""
    require(len(image) >= 64 and image[:6] == b"\x7fELF\x02\x01"
            and struct.unpack_from("<H", image, 16)[0] == expected_type,
            "private VM final ELF type differs")
    offset = struct.unpack_from("<Q", image, 32)[0]
    entry_size, count = struct.unpack_from("<HH", image, 54)
    require(entry_size >= 56 and offset + entry_size * count <= len(image),
            "private VM final ELF program headers differ")
    matches = []
    for index in range(count):
        header = offset + index * entry_size
        kind, flags = struct.unpack_from("<II", image, header)
        file_offset = struct.unpack_from("<Q", image, header + 8)[0]
        virtual = struct.unpack_from("<Q", image, header + 16)[0]
        file_size = struct.unpack_from("<Q", image, header + 32)[0]
        if kind == 1 and flags & 1 and virtual <= address and address + size <= virtual + file_size:
            location = file_offset + address - virtual
            require(location + size <= len(image), "private VM final ELF load segment exceeds file")
            matches.append(image[location:location + size])
    require(len(matches) == 1, "private VM callsite has no unique executable load segment")
    return matches[0]


def _public_weak_virtual_bytes(image: bytes, address: int, size: int, expected_type: int,
                               *, executable: bool) -> bytes:
    require(len(image) >= 64 and image[:6] == b"\x7fELF\x02\x01"
            and struct.unpack_from("<H", image, 16)[0] == expected_type,
            "public weak final ELF type differs")
    offset = struct.unpack_from("<Q", image, 32)[0]
    entry_size, count = struct.unpack_from("<HH", image, 54)
    require(entry_size >= 56 and offset + entry_size * count <= len(image),
            "public weak final ELF program headers differ")
    matches = []
    for index in range(count):
        header = offset + index * entry_size
        kind, flags = struct.unpack_from("<II", image, header)
        file_offset = struct.unpack_from("<Q", image, header + 8)[0]
        virtual = struct.unpack_from("<Q", image, header + 16)[0]
        file_size = struct.unpack_from("<Q", image, header + 32)[0]
        if kind == 1 and bool(flags & 1) == executable and virtual <= address and address + size <= virtual + file_size:
            location = file_offset + address - virtual
            require(location + size <= len(image), "public weak final ELF load segment exceeds file")
            matches.append(image[location:location + size])
    require(len(matches) == 1, "public weak final address has no unique load segment")
    return matches[0]


def _public_weak_symbol_address(transcript: str, name: str, *, binding: str) -> int:
    rows = []
    for line in transcript.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[-1] == name and parts[0].endswith(":"):
            require(parts[3] == "FUNC" and parts[4] == binding and parts[6] != "UND",
                    f"public weak final symbol metadata differs: {name}")
            rows.append(int(parts[1], 16))
    require(rows and len(set(rows)) == 1 and len(rows) <= 2,
            f"public weak final symbol is missing or duplicate: {name}")
    return rows[0]


def _public_weak_call(image: bytes, *, source_address: int, relocation: Mapping[str, object],
                      kind: str, provider_address: int, relocations: str, elf_type: int) -> dict[str, int]:
    offset = relocation["offset"]
    require(type(offset) is int and offset > 0, "public weak source offset differs")
    if kind == "c":
        call = source_address + offset - 1
        instruction = _public_weak_virtual_bytes(image, call, 5, elf_type, executable=True)
        require(instruction[0] == 0xe8, "public weak C call instruction differs")
        target = call + 5 + struct.unpack_from("<i", instruction, 1)[0]
        require(target == provider_address, "public weak C call resolves to a foreign provider")
        return {"call_address": call, "target_address": target}
    call = source_address + offset - 2
    instruction = _public_weak_virtual_bytes(image, call, 6, elf_type, executable=True)
    require(instruction[:2] == b"\xff\x15", "public weak Rust GOT call instruction differs")
    slot = call + 6 + struct.unpack_from("<i", instruction, 2)[0]
    contents = struct.unpack("<Q", _public_weak_virtual_bytes(image, slot, 8, elf_type,
                                                                executable=False))[0]
    if elf_type == 2:
        require(contents == provider_address and not re.search(rf"^0*{slot:x}\s+.*R_X86_64_", relocations, re.MULTILINE),
                "public weak ET_EXEC GOT resolves to a foreign provider")
    elif "R_X86_64_RELATIVE" in relocations:
        rows = re.findall(rf"^0*{slot:x}\s+\S+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)\s*$", relocations, re.MULTILINE)
        require(len(rows) == 1 and int(rows[0], 16) == provider_address,
                "public weak static PIE GOT relocation resolves to a foreign provider")
    else:
        require(len(re.findall(rf"^\s*0*{slot:x}\s+\.got\b", relocations, re.MULTILINE)) == 1
                and contents == provider_address,
                "public weak shared RELR GOT resolves to a foreign provider")
    return {"call_address": call, "got_slot": slot, "target_address": provider_address}


def _errno_elf_symbols(transcript: str, name: str, *, kind: str, binding: str) -> list[tuple[int, int]]:
    values = []
    for line in transcript.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[0].endswith(":") and parts[-1] == name and parts[4] == binding:
            require(parts[3] == kind and parts[6] != "UND",
                    f"errno final symbol metadata differs: {name}")
            values.append((int(parts[1], 16), int(parts[2])))
    return values


def _errno_tls_segment_size(image: bytes, elf_type: int) -> int:
    require(len(image) >= 64 and image[:6] == b"\x7fELF\x02\x01"
            and struct.unpack_from("<H", image, 16)[0] == elf_type,
            "errno final ELF type differs")
    offset = struct.unpack_from("<Q", image, 32)[0]
    size, count = struct.unpack_from("<HH", image, 54)
    require(size >= 56 and offset + size * count <= len(image),
            "errno final program headers differ")
    segments = [struct.unpack_from("<Q", image, offset + index * size + 40)[0]
                for index in range(count)
                if struct.unpack_from("<I", image, offset + index * size)[0] == 7]
    require(len(segments) == 1 and segments[0] > 0, "errno final TLS segment differs")
    return segments[0]


def _errno_static_accessor(image: bytes, address: int, symbol_text: str, elf_type: int) -> dict[str, int]:
    """Decode the fixed FS base and selected TLS slot address expression."""
    tls_rows = []
    for line in symbol_text.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[0].endswith(":") and parts[-1].endswith("5errno5ERRNO"):
            require(parts[2:6] == ["4", "TLS", "LOCAL", "HIDDEN"] and parts[6] != "UND",
                    "errno final TLS symbol differs")
            tls_rows.append(int(parts[1], 16))
    require(len(tls_rows) == 1, "errno final TLS symbol is missing or duplicate")
    body = _public_weak_virtual_bytes(image, address, 17, elf_type, executable=True)
    require(body[:12] == b"\x64\x48\x8b\x04\x25\0\0\0\0\x48\x8d\x80"
            and body[16] == 0xc3, "errno final accessor does not return an FS-relative address")
    displacement = struct.unpack_from("<i", body, 12)[0]
    tls_size = _errno_tls_segment_size(image, elf_type)
    require(displacement == tls_rows[0] - tls_size,
            "errno final accessor selects a foreign TLS slot")
    return {"tls_symbol_offset": tls_rows[0], "tls_segment_size": tls_size,
            "fs_displacement": displacement}


def _ordinary_final_member_calls(image: bytes, *, archive_member: str,
                                 source_calls: Sequence[Mapping[str, object]], map_text: str,
                                 relocation_text: str, provider_address: int,
                                 elf_type: int, name: str) -> dict[str, object]:
    resolved = []
    discarded = []
    for relocation in source_calls:
        section, offset = relocation["section"], relocation["offset"]
        rows = [line for line in map_text.splitlines()
                if line.rstrip().endswith(f"{archive_member}:({section})")]
        require(len(rows) <= 1, f"ordinary {name} source section map is ambiguous: {section}")
        if not rows:
            discarded.append(dict(relocation))
            continue
        parts = rows[0].split()
        require(len(parts) >= 5 and type(offset) is int
                and 1 <= offset and offset + 4 <= int(parts[2], 16),
                f"ordinary {name} source call leaves selected section: {section}")
        kind = relocation.get("kind", "R_X86_64_PLT32")
        if kind == "R_X86_64_PLT32":
            call_address = int(parts[0], 16) + offset - 1
            opcode = _public_weak_virtual_bytes(image, call_address, 5, elf_type, executable=True)
            require(opcode[0] == 0xe8, f"ordinary {name} direct-call opcode differs")
            target = call_address + 5 + struct.unpack_from("<i", opcode, 1)[0]
            require(target == provider_address, f"ordinary {name} call resolves to a foreign provider")
            call = {"section": section, "offset": offset, "call_address": call_address,
                    "target_address": target}
        else:
            require(kind == "R_X86_64_GOTPCREL", f"ordinary {name} source call form differs")
            call_address = int(parts[0], 16) + offset - 2
            opcode = _public_weak_virtual_bytes(image, call_address, 6, elf_type, executable=True)
            require(opcode[:2] == b"\xff\x15", f"ordinary {name} GOT-call opcode differs")
            slot = call_address + 6 + struct.unpack_from("<i", opcode, 2)[0]
            target = struct.unpack("<Q", _public_weak_virtual_bytes(
                image, slot, 8, elf_type, executable=False))[0]
            relative = re.findall(rf"^0*{slot:x}\s+\S+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)\s*$",
                                  relocation_text, re.MULTILINE)
            relr = re.findall(rf"^\s*0*{slot:x}\s+\.got\b", relocation_text, re.MULTILINE)
            relocations_at_slot = re.findall(
                rf"^\s*0*{slot:x}\s+\S+\s+(R_X86_64_\w+)", relocation_text, re.MULTILINE)
            if elf_type == 2:
                require(target == provider_address and not relocations_at_slot and not relr,
                        f"ordinary {name} ET_EXEC GOT resolves to a foreign provider")
            else:
                require((len(relative) == 1 and int(relative[0], 16) == provider_address
                         and target == 0 and not relr
                         and relocations_at_slot == ["R_X86_64_RELATIVE"])
                        or (len(relr) == 1 and target == provider_address
                            and not relocations_at_slot),
                        f"ordinary {name} PIE GOT resolves to a foreign provider")
            call = {"section": section, "offset": offset, "call_address": call_address,
                    "got_slot": slot, "target_address": provider_address}
        resolved.append(call)
    require(resolved, f"ordinary {name} final image has no selected call from importer: {archive_member}")
    return {"resolved_calls": resolved, "discarded_calls": discarded}


def _errno_final_member_calls(image: bytes, *, archive_member: str,
                              source_calls: Sequence[Mapping[str, object]], map_text: str,
                              provider_address: int, elf_type: int) -> dict[str, object]:
    return _ordinary_final_member_calls(
        image, archive_member=archive_member, source_calls=source_calls,
        map_text=map_text, relocation_text="", provider_address=provider_address,
        elf_type=elf_type, name=ERRNO_IMPORT_NAME)


def _errno_shared_caller_calls(image: bytes, symbol_text: str, functions: Sequence[str],
                               provider_address: int) -> list[dict[str, object]]:
    calls = []
    for function in functions:
        rows = []
        for binding in ("LOCAL", "GLOBAL"):
            rows.extend(_errno_elf_symbols(symbol_text, function, kind="FUNC", binding=binding))
        if not rows:
            continue
        require(len(set(rows)) == 1, f"errno shared caller is ambiguous: {function}")
        address, size = rows[0]
        require(size > 0, f"errno shared caller is empty: {function}")
        body = _public_weak_virtual_bytes(image, address, size, 3, executable=True)
        for offset in range(size - 4):
            if body[offset] != 0xe8:
                continue
            target = address + offset + 5 + struct.unpack_from("<i", body, offset + 1)[0]
            if target == provider_address:
                calls.append({"function": function, "call_address": address + offset,
                              "target_address": target})
    require(calls, "errno shared importer has no direct provider call")
    return calls


def _ordinary_shared_caller_calls(image: bytes, symbol_text: str, relocations: str,
                                  source_calls: Sequence[Mapping[str, object]],
                                  provider_address: int, name: str) -> list[dict[str, object]]:
    """Read matching shared call forms from source-named functions and GOT slots."""
    functions = set()
    for source in source_calls:
        section = source["section"]
        require(isinstance(section, str) and section.startswith(".text."),
                f"ordinary {name} source caller section differs")
        suffix = section[6:]
        functions.add(suffix)
        if suffix.startswith("unlikely."):
            functions.add(suffix[len("unlikely."):])
            functions.add(suffix[len("unlikely."):] + ".cold")
    calls = []
    for function in sorted(functions):
        rows = []
        for binding in ("LOCAL", "GLOBAL"):
            rows.extend(_errno_elf_symbols(symbol_text, function, kind="FUNC", binding=binding))
        if not rows:
            continue
        require(len(set(rows)) == 1, f"ordinary {name} shared caller is ambiguous: {function}")
        address, size = rows[0]
        require(size > 0, f"ordinary {name} shared caller is empty: {function}")
        body = _public_weak_virtual_bytes(image, address, size, 3, executable=True)
        for offset in range(size):
            if offset + 5 <= size and body[offset] == 0xe8:
                target = address + offset + 5 + struct.unpack_from("<i", body, offset + 1)[0]
                if target == provider_address:
                    calls.append({"function": function, "call_address": address + offset,
                                  "target_address": target})
            if offset + 6 <= size and body[offset:offset + 2] == b"\xff\x15":
                slot = address + offset + 6 + struct.unpack_from("<i", body, offset + 2)[0]
                try:
                    target = struct.unpack("<Q", _public_weak_virtual_bytes(
                        image, slot, 8, 3, executable=False))[0]
                except AllocatorBoundaryError:
                    continue
                if target != provider_address:
                    continue
                require(len(re.findall(rf"^\s*0*{slot:x}\s+\.got\b", relocations,
                                       re.MULTILINE)) == 1,
                        f"ordinary {name} shared GOT relocation differs")
                calls.append({"function": function, "call_address": address + offset,
                              "got_slot": slot, "target_address": target})
    require(calls, f"ordinary {name} shared importer has no provider call")
    return calls


def _vm_final_symbols(transcript: str) -> dict[str, int]:
    result: dict[str, list[int]] = {name: [] for name in VM_PRIVATE_IMPORTS}
    for line in transcript.splitlines():
        parts = line.split()
        if len(parts) < 8 or parts[-1] not in result or not parts[0].endswith(":"):
            continue
        name = parts[-1]
        require(parts[3:6] == ["FUNC", "LOCAL", "HIDDEN"] and parts[6] != "UND",
                f"private VM final provider {name} metadata differs")
        result[name].append(int(parts[1], 16))
    require(all(len(rows) == 1 for rows in result.values()),
            "private VM final provider is missing or duplicate")
    return {name: rows[0] for name, rows in result.items()}


def _vm_final_link_calls(relocations: Mapping[str, list[dict[str, object]]], *,
                         archive_member: str, provider_members: Mapping[str, str],
                         map_text: str, trace_text: str, symbol_text: str,
                         relocation_text: str, image: bytes, elf_type: int) -> dict[str, object]:
    """Match every surviving C call instruction to its final hidden provider."""
    require(trace_text.splitlines().count(archive_member) == 1,
            "private VM C member is not selected exactly once")
    addresses = _vm_final_symbols(symbol_text)
    require(not any(re.search(rf"\b{re.escape(name)}\b", relocation_text)
                    for name in VM_PRIVATE_IMPORTS),
            "private VM final ELF retains an unresolved relocation")
    selected: dict[str, dict[str, object]] = {}
    for name in VM_PRIVATE_IMPORTS:
        member = provider_members[name]
        require(member != archive_member and trace_text.splitlines().count(member) == 1,
                f"private VM final provider {name} is not selected exactly once")
        provider_rows = [line for line in map_text.splitlines()
                         if line.rstrip().endswith(f"{member}:(.text.{name})")]
        require(len(provider_rows) == 1, f"private VM final provider map differs: {name}")
        provider_address = int(provider_rows[0].split()[0], 16)
        require(provider_address == addresses[name],
                f"private VM final provider address differs: {name}")
        calls: list[dict[str, object]] = []
        discarded: list[dict[str, object]] = []
        for relocation in relocations[name]:
            section = relocation["section"]
            source_rows = [line for line in map_text.splitlines()
                           if line.rstrip().endswith(f"{archive_member}:({section})")]
            require(len(source_rows) <= 1, f"private VM C section map is ambiguous: {section}")
            if not source_rows:
                discarded.append(dict(relocation))
                continue
            parts = source_rows[0].split()
            require(len(parts) >= 5, f"private VM C section map differs: {section}")
            start, size = int(parts[0], 16), int(parts[2], 16)
            offset = relocation["offset"]
            require(type(offset) is int and 1 <= offset and offset + 4 <= size,
                    f"private VM C relocation exceeds selected section: {name}")
            call_address = start + offset - 1
            opcode = _elf_virtual_bytes(image, call_address, 5, elf_type)
            require(opcode[0] == 0xe8, f"private VM C call instruction differs: {name}")
            target = call_address + 5 + struct.unpack_from("<i", opcode, 1)[0]
            require(target == provider_address,
                    f"private VM C call resolves to a foreign provider: {name}")
            calls.append({"section": section, "offset": offset,
                          "call_address": call_address, "target_address": target})
        require(calls, f"private VM final image has no selected C call: {name}")
        selected[name] = {"provider_member": member, "provider_address": provider_address,
                          "resolved_calls": calls, "discarded_calls": discarded}
    return selected


def private_vm_resolution(report: Mapping[str, Any], *, report_path: Path,
                          static_product: Path, dynamic_product: Path,
                          elf_facts_report: Path) -> dict[str, object]:
    """Resolve the fixed C allocator's three private VM calls in both static images.

    The caller first replays the complete component receipt. Its authenticated
    C member, retained ordinary links, and supplied ELF facts bound every byte
    read here. Final call targets are decoded from the linked executable, so
    link-map presence alone cannot discharge an import.
    """
    inputs = report["inputs"]
    account = inputs["producer_account"]
    build = account["source_authority"]["build"]
    for flags in (build["static_target_flags"], build["shared_allocator_flags"]):
        require(all(f"-D{name[2:]}={name}" in flags for name in VM_PRIVATE_IMPORTS),
                "private VM C source rewriting differs")
    runtime = inputs["c_runtime_import_bindings"]
    c_member = runtime["static_c_member"]
    facts_report = json_object(elf_facts_report, "private VM ELF facts")
    for name in ("ar", "readelf"):
        tool = Path("/usr/bin") / name
        require(same(facts_report["tools"][name]["original"], identity(tool)),
                f"private VM {name} differs from the pinned ELF collector")
    facts = facts_report["facts"]
    static_members = facts["candidate-static"]
    require(static_members[c_member["member_index"]]["member"] == c_member["name"]
            and static_members[c_member["member_index"]]["member_occurrence"] == 0,
            "private VM C member differs from authenticated archive")
    try:
        c_rows = producer._symbol_tables(static_members[c_member["member_index"]]["symbol_tables"],
                                         "private VM C imports", {".symtab"})[".symtab"]
        shared_tables = producer._symbol_tables(facts["candidate-shared"]["symbol_tables"],
                                                 "private VM shared bodies", {".dynsym", ".symtab"})
    except producer.ProducerMetadataError as error:
        raise AllocatorBoundaryError(str(error)) from error
    shared_libc = physical_file(dynamic_product / "usr/lib/libc.so", "private VM shared libc")
    shared_relocations = subprocess.run(["/usr/bin/readelf", "-rW", str(shared_libc)],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, check=False)
    require(shared_relocations.returncode == 0 and not any(
        re.search(rf"\b{re.escape(name)}\b", shared_relocations.stdout)
        for name in VM_PRIVATE_IMPORTS),
        "private VM shared libc retains an external relocation")
    provider_members: dict[str, str] = {}
    imports: list[dict[str, object]] = []
    archive = physical_file(static_product / "usr/lib/libc.a", "private VM archive")
    mounted_archive = mounted_path(archive)
    for name in VM_PRIVATE_IMPORTS:
        c_imports = [row for row in c_rows if row.get("name") == name]
        require(len(c_imports) == 1 and all(c_imports[0].get(field) == value for field, value in {
            "type": "NOTYPE", "binding": "GLOBAL", "visibility": "DEFAULT", "section_index": "UND",
            "size_bytes": 0, "value": "0000000000000000",
        }.items()), f"private VM C import differs: {name}")
        member, provider = _static_definition(facts_report, name, "private VM body")
        require(all(provider.get(field) == value for field, value in {
            "type": "FUNC", "binding": "GLOBAL", "visibility": "HIDDEN",
        }.items()) and member["member"] != c_member["name"],
                f"private VM static provider differs: {name}")
        shared = [row for row in shared_tables[".symtab"] if row.get("name") == name]
        require(len(shared) == 1 and all(shared[0].get(field) == value for field, value in {
            "type": "FUNC", "binding": "LOCAL", "visibility": "HIDDEN",
        }.items()) and shared[0].get("section_index") != "UND"
                and not [row for row in shared_tables[".dynsym"] if row.get("name") == name],
                f"private VM shared provider/import differs: {name}")
        provider_members[name] = f"{mounted_archive}({member['member']})"
        imports.append({"name": name,
                        "static_c_import": {key: c_imports[0][key] for key in (
                            "name", "type", "binding", "visibility", "section_index", "size_bytes", "value")},
                        "static_provider_member": _member_identity(member),
                        "static_provider": {key: provider[key] for key in (
                            "name", "type", "binding", "visibility", "section_index", "size_bytes", "value")},
                        "shared_provider": {key: shared[0][key] for key in (
                            "name", "type", "binding", "visibility", "section_index", "size_bytes", "value")}})
    ar = subprocess.run(["/usr/bin/ar", "p", str(archive), c_member["name"]],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    require(ar.returncode == 0 and hashlib.sha256(ar.stdout).hexdigest() == c_member["sha256"],
            "private VM C member bytes differ")
    with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary:
        object_path = Path(temporary) / "allocator-c.o"
        object_path.write_bytes(ar.stdout)
        source = subprocess.run(["/usr/bin/readelf", "-rW", str(object_path)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    require(source.returncode == 0, "private VM C relocations are unreadable")
    relocations = _vm_private_relocations(source.stdout)
    startup = report["startup"]
    work = physical_directory(report_path.parent / startup["work"], "private VM retained link work")
    modes: dict[str, object] = {}
    for mode, elf_type in (("static", 2), ("static-pie", 3)):
        executable = physical_file(work / f"static-{mode}", f"private VM {mode} final ELF")
        link = startup["observation"]["links"][mode]
        require(same(link["executable"], identity(executable, logical_path=executable.relative_to(report_path.parent).as_posix())),
                f"private VM {mode} final ELF bytes differ")
        map_text = physical_file(work / f"static-{mode}.crabc-link.map", f"private VM {mode} map").read_text(encoding="utf-8")
        trace_text = physical_file(work / f"static-{mode}.crabc-link.trace", f"private VM {mode} trace").read_text(encoding="utf-8")
        symbols = subprocess.run(["/usr/bin/readelf", "-Ws", str(executable)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        final_relocations = subprocess.run(["/usr/bin/readelf", "-rW", str(executable)],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        require(symbols.returncode == final_relocations.returncode == 0,
                f"private VM {mode} final ELF is unreadable")
        modes[mode] = _vm_final_link_calls(
            relocations, archive_member=f"{mounted_archive}({c_member['name']})",
            provider_members=provider_members, map_text=map_text, trace_text=trace_text,
            symbol_text=symbols.stdout, relocation_text=final_relocations.stdout,
            image=executable.read_bytes(), elf_type=elf_type,
        )
    return {"c_member": dict(c_member), "imports": imports,
            "source_relocations": relocations, "static_final_links": modes,
            "shared_private_import_absent": True}


def _public_weak_member_relocation(archive: Path, member: Mapping[str, Any], name: str,
                                   kind: str) -> dict[str, object]:
    selected = subprocess.run(["/usr/bin/ar", "p", str(archive), member["member"]],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    require(selected.returncode == 0 and selected.stdout, f"public weak {name} archive member is unreadable")
    with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary:
        object_path = Path(temporary) / "selected.o"
        object_path.write_bytes(selected.stdout)
        observed = subprocess.run(["/usr/bin/readelf", "-rW", str(object_path)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    require(observed.returncode == 0, f"public weak {name} archive relocations are unreadable")
    return _public_weak_relocations(observed.stdout, name, kind)[0]


def _public_weak_map_source(map_text: str, archive_member: str, section: str) -> int:
    rows = [line for line in map_text.splitlines()
            if line.rstrip().endswith(f"{archive_member}:({section})")]
    require(len(rows) == 1, f"public weak selected source section differs: {section}")
    parts = rows[0].split()
    require(len(parts) >= 5 and int(parts[2], 16) > 0,
            f"public weak selected source section is empty: {section}")
    return int(parts[0], 16)


def public_weak_resolution(report: Mapping[str, Any], *, report_path: Path,
                           static_product: Path, dynamic_product: Path,
                           elf_facts_report: Path) -> dict[str, object]:
    """Bind both archive importers to weak providers in every final link domain."""
    facts = json_object(elf_facts_report, "public weak ELF facts")
    members = facts["facts"]["candidate-static"]
    shared = facts["facts"]["candidate-shared"]
    runtime = report["inputs"]["c_runtime_import_bindings"]
    c_member = runtime["static_c_member"]
    archive = physical_file(static_product / "usr/lib/libc.a", "public weak archive")
    shared_libc = physical_file(dynamic_product / "usr/lib/libc.so", "public weak shared libc")
    mounted_archive = mounted_path(archive)
    weak = exact(report["public_weak"], {"work", "source", "object", "links"}, "public weak link receipt")
    work = physical_directory(report_path.parent / weak["work"], "public weak retained links")
    require(members[c_member["member_index"]]["member"] == c_member["name"]
            and members[c_member["member_index"]]["member_occurrence"] == 0,
            "public weak C archive member differs")
    try:
        shared_tables = producer._symbol_tables(shared["symbol_tables"], "public weak shared provider",
                                                 {".dynsym", ".symtab"})
    except producer.ProducerMetadataError as error:
        raise AllocatorBoundaryError(str(error)) from error
    shared_symbols = subprocess.run(["/usr/bin/readelf", "-Ws", str(shared_libc)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    shared_relocations = subprocess.run(["/usr/bin/readelf", "-rW", str(shared_libc)],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    require(shared_symbols.returncode == shared_relocations.returncode == 0,
            "public weak shared ELF is unreadable")
    claims = []
    for name, caller in PUBLIC_WEAK_IMPORTS.items():
        claim = next((row for row in runtime["imports"] if row["name"] == name), None)
        require(claim is not None and claim["binding"] == "WEAK", f"public weak runtime claim differs: {name}")
        rust_importers = []
        for member in members:
            if member["member_index"] == c_member["member_index"]:
                continue
            try:
                rows = producer._symbol_tables(member["symbol_tables"], "public weak Rust importer",
                                               {".symtab"})[".symtab"]
            except producer.ProducerMetadataError as error:
                raise AllocatorBoundaryError(str(error)) from error
            imported = [row for row in rows if row.get("name") == name and row.get("section_index") == "UND"]
            if imported:
                require(len(imported) == 1 and len([row for row in rows if row.get("name") == caller
                        and row.get("section_index") != "UND" and row.get("type") == "FUNC"]) == 1,
                        f"public weak {name} Rust caller member differs")
                rust_importers.append((member, imported[0]))
        require(len(rust_importers) == 1, f"public weak {name} Rust importer is missing or duplicate")
        rust_member, rust_import = rust_importers[0]
        require(all(rust_import.get(field) == value for field, value in {
            "type": "NOTYPE", "binding": "GLOBAL", "visibility": "DEFAULT",
            "section_index": "UND", "size_bytes": 0, "value": "0000000000000000",
        }.items()), f"public weak {name} Rust import metadata differs")
        for table in (".dynsym", ".symtab"):
            rows = [row for row in shared_tables[table] if row.get("name") == name]
            require(len(rows) == 1 and rows[0].get("binding") == "WEAK"
                    and rows[0].get("section_index") != "UND",
                    f"public weak {name} shared provider differs")
        c_relocation = _public_weak_member_relocation(
            archive, {"member": c_member["name"]}, name, "R_X86_64_PLT32")
        rust_relocation = _public_weak_member_relocation(
            archive, rust_member, name, "R_X86_64_GOTPCREL")
        require(not re.search(rf"\b{re.escape(name)}\b", shared_relocations.stdout),
                f"public weak {name} shared ELF retains an external import")
        provider_address = _public_weak_symbol_address(shared_symbols.stdout, name, binding="WEAK")
        shared_callers = {"clock_gettime": "_mi_prim_clock_now",
                          "sysinfo": "unix_detect_physical_memory.isra.0"}
        c_address = _public_weak_symbol_address(shared_symbols.stdout, shared_callers[name], binding="LOCAL")
        rust_address = _public_weak_symbol_address(shared_symbols.stdout, caller, binding="GLOBAL")
        shared_calls = {
            "c": _public_weak_call(shared_libc.read_bytes(), source_address=c_address,
                                   relocation=c_relocation, kind="c", provider_address=provider_address,
                                   relocations=shared_relocations.stdout, elf_type=3),
            "rust": _public_weak_call(shared_libc.read_bytes(), source_address=rust_address,
                                      relocation=rust_relocation, kind="rust", provider_address=provider_address,
                                      relocations=shared_relocations.stdout, elf_type=3),
        }
        final = {}
        for mode, elf_type in (("static", 2), ("static-pie", 3)):
            executable = physical_file(work / f"static-{mode}", f"public weak {mode} final ELF")
            map_text = physical_file(work / f"static-{mode}.crabc-link.map", f"public weak {mode} map").read_text(encoding="utf-8")
            trace = physical_file(work / f"static-{mode}.crabc-link.trace", f"public weak {mode} trace").read_text(encoding="utf-8")
            symbols = subprocess.run(["/usr/bin/readelf", "-Ws", str(executable)],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            relocations = subprocess.run(["/usr/bin/readelf", "-rW", str(executable)],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            require(symbols.returncode == relocations.returncode == 0
                    and not re.search(rf"\b{re.escape(name)}\b", relocations.stdout),
                    f"public weak {name} {mode} final ELF retains an external import")
            provider = claim["static_rust_provider_member"]
            expected = [f"{mounted_archive}({member})" for member in (
                c_member["name"], rust_member["member"], provider["member"])]
            require(all(trace.splitlines().count(member) == 1 for member in expected),
                    f"public weak {name} {mode} importers/provider are not selected exactly once")
            address = _public_weak_symbol_address(symbols.stdout, name, binding="WEAK")
            provider_rows = [line for line in map_text.splitlines()
                             if line.rstrip().endswith(f"{expected[2]}:(.text.__{name})")]
            if name == "sysinfo":
                provider_rows = [line for line in map_text.splitlines()
                                 if line.rstrip().endswith(f"{expected[2]}:(.text.__lsysinfo)")]
            require(len(provider_rows) == 1 and int(provider_rows[0].split()[0], 16) == address,
                    f"public weak {name} {mode} provider map differs")
            image = executable.read_bytes()
            final[mode] = {
                "provider_address": address, "provider_member": expected[2],
                "c": _public_weak_call(image, source_address=_public_weak_map_source(
                    map_text, expected[0], c_relocation["section"]), relocation=c_relocation,
                    kind="c", provider_address=address, relocations=relocations.stdout, elf_type=elf_type),
                "rust": _public_weak_call(image, source_address=_public_weak_map_source(
                    map_text, expected[1], rust_relocation["section"]), relocation=rust_relocation,
                    kind="rust", provider_address=address, relocations=relocations.stdout, elf_type=elf_type),
            }
        claims.append({"name": name, "caller": caller,
                       "static_c_member": dict(c_member), "static_rust_importer_member": _member_identity(rust_member),
                       "static_rust_import": {key: rust_import[key] for key in (
                           "name", "type", "binding", "visibility", "section_index", "size_bytes", "value")},
                       "static_provider_member": dict(claim["static_rust_provider_member"]),
                       "static_provider": dict(claim["static_rust_provider"]),
                       "shared_dynsym_provider": dict(claim["shared_dynsym_provider"]),
                       "shared_symtab_provider": dict(claim["shared_symtab_provider"]),
                       "source_relocations": {"c": c_relocation, "rust": rust_relocation},
                       "static_final_links": final, "shared_final_calls": shared_calls,
                       "shared_provider_address": provider_address})
    for mode in DYNAMIC_MODES:
        executable = physical_file(work / f"dynamic-{mode}", f"public weak dynamic {mode} final ELF")
        dynamic = subprocess.run(["/usr/bin/readelf", "-dW", str(executable)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        symbols = subprocess.run(["/usr/bin/readelf", "-Ws", str(executable)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        require(dynamic.returncode == symbols.returncode == 0 and
                len(re.findall(r"\(NEEDED\).*\[libc\.so\]", dynamic.stdout)) == 1
                and not any(re.search(rf"\b{re.escape(name)}$", symbols.stdout, re.MULTILINE)
                            for name in PUBLIC_WEAK_IMPORTS),
                f"public weak dynamic {mode} final ELF imports a weak implementation")
    return {"imports": claims, "dynamic_final_import_absent": True}


def ordinary_import_resolution(report: Mapping[str, Any], *, report_path: Path,
                               static_product: Path, dynamic_product: Path,
                               elf_facts_report: Path, name: str) -> dict[str, object]:
    """Bind all archive callers of one ordinary import to final libc providers."""
    facts = json_object(elf_facts_report, f"{name} ELF facts")["facts"]
    members = facts["candidate-static"]
    runtime = report["inputs"]["c_runtime_import_bindings"]
    c_member = runtime["static_c_member"]
    claim = next((row for row in runtime["imports"] if row["name"] == name), None)
    require(claim is not None and claim["binding"] == "GLOBAL",
            f"ordinary {name} runtime import account differs")
    provider = claim["static_rust_provider_member"]
    provider_fact = members[provider["member_index"]]
    require(provider_fact["member"] == provider["member"]
            and provider_fact["member_occurrence"] == 0,
            f"ordinary {name} provider archive member differs")
    sections = [row for row in provider_fact["sections"]
                if str(row["index"]) == claim["static_rust_provider"]["section_index"]]
    require(len(sections) == 1 and sections[0]["flags"].find("X") >= 0,
            f"ordinary {name} provider source section differs")
    provider_section = sections[0]["name"]
    archive = physical_file(static_product / "usr/lib/libc.a", f"ordinary {name} archive")
    mounted_archive = mounted_path(archive)
    imported = []
    for member in members:
        try:
            rows = producer._symbol_tables(member["symbol_tables"],
                                           f"ordinary {name} archive member", {".symtab"})[".symtab"]
        except producer.ProducerMetadataError as error:
            raise AllocatorBoundaryError(str(error)) from error
        matches = [row for row in rows if row.get("name") == name
                   and row.get("section_index") == "UND"]
        if not matches:
            continue
        require(len(matches) == 1 and all(matches[0].get(field) == value for field, value in {
            "type": "NOTYPE", "binding": "GLOBAL", "visibility": "DEFAULT",
            "section_index": "UND", "size_bytes": 0, "value": "0000000000000000",
        }.items()) and member["member_occurrence"] == 0,
                f"ordinary {name} archive import row differs")
        selected = subprocess.run(["/usr/bin/ar", "p", str(archive), member["member"]],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        require(selected.returncode == 0 and selected.stdout,
                f"ordinary {name} importer archive member is unreadable")
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary:
            object_path = Path(temporary) / "importer.o"
            object_path.write_bytes(selected.stdout)
            relocations = subprocess.run(["/usr/bin/readelf", "-rW", str(object_path)],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         text=True, check=False)
        require(relocations.returncode == 0, f"ordinary {name} source relocations unreadable")
        calls = _ordinary_import_relocations(relocations.stdout, name)
        is_c = member["member_index"] == c_member["member_index"]
        require(all(call["kind"] == ("R_X86_64_PLT32" if is_c else "R_X86_64_GOTPCREL")
                    for call in calls), f"ordinary {name} importer call form differs")
        imported.append({
            "member": _member_identity(member),
            "import": {key: matches[0][key] for key in (
                "name", "type", "binding", "visibility", "section_index", "size_bytes", "value")},
            "member_sha256": hashlib.sha256(selected.stdout).hexdigest(),
            "source_calls": calls,
            "shared_caller_functions": sorted({call["section"][6:]
                                               for call in calls}),
        })
    require(len(imported) >= 2
            and len({item["member"]["member_index"] for item in imported}) == len(imported)
            and len([item for item in imported if item["member"]["member_index"] == c_member["member_index"]]) == 1
            and all(item["member"]["member_index"] != provider["member_index"] for item in imported),
            f"ordinary {name} static importer roster differs")
    work = physical_directory(report_path.parent / report["errno_import"]["work"],
                              f"ordinary {name} retained links")
    static_modes = {}
    for mode, elf_type in (("static", 2), ("static-pie", 3)):
        executable = physical_file(work / f"static-{mode}", f"ordinary {name} {mode} ELF")
        map_text = physical_file(work / f"static-{mode}.crabc-link.map",
                                 f"ordinary {name} {mode} map").read_text(encoding="utf-8")
        trace = physical_file(work / f"static-{mode}.crabc-link.trace",
                              f"ordinary {name} {mode} trace").read_text(encoding="utf-8")
        symbols = subprocess.run(["/usr/bin/readelf", "-Ws", str(executable)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        relocations = subprocess.run(["/usr/bin/readelf", "-rW", str(executable)],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        require(symbols.returncode == relocations.returncode == 0
                and not re.search(rf"\b{re.escape(name)}\b", relocations.stdout),
                f"ordinary {name} {mode} retains an external import")
        provider_rows = _errno_elf_symbols(symbols.stdout, name, kind="FUNC", binding="GLOBAL")
        require(len(provider_rows) == 1
                and provider_rows[0][1] == claim["static_rust_provider"]["size_bytes"],
                f"ordinary {name} {mode} provider differs")
        address = provider_rows[0][0]
        selected_provider = f"{mounted_archive}({provider['member']})"
        require(trace.splitlines().count(selected_provider) == 1
                and len([line for line in map_text.splitlines()
                         if line.rstrip().endswith(f"{selected_provider}:({provider_section})")
                         and int(line.split()[0], 16) == address]) == 1,
                f"ordinary {name} {mode} provider map differs")
        image = executable.read_bytes()
        linked = []
        for item in imported:
            selected = f"{mounted_archive}({item['member']['member']})"
            require(trace.splitlines().count(selected) == 1,
                    f"ordinary {name} {mode} importer is not selected once")
            linked.append({
                "member": dict(item["member"]),
                **_ordinary_final_member_calls(
                    image, archive_member=selected, source_calls=item["source_calls"],
                    map_text=map_text, relocation_text=relocations.stdout,
                    provider_address=address, elf_type=elf_type, name=name),
            })
        static_modes[mode] = {"provider_member": dict(provider),
                              "provider_address": address, "importers": linked}
    shared_libc = physical_file(dynamic_product / "usr/lib/libc.so",
                                f"ordinary {name} shared libc")
    shared_symbols = subprocess.run(["/usr/bin/readelf", "-Ws", str(shared_libc)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, check=False)
    shared_relocations = subprocess.run(["/usr/bin/readelf", "-rW", str(shared_libc)],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, check=False)
    require(shared_symbols.returncode == shared_relocations.returncode == 0
            and not re.search(rf"\b{re.escape(name)}\b", shared_relocations.stdout),
            f"ordinary {name} shared libc retains an external import")
    shared_provider = _errno_elf_symbols(shared_symbols.stdout, name, kind="FUNC", binding="GLOBAL")
    require(len(shared_provider) == 2 and len(set(shared_provider)) == 1
            and shared_provider[0][1] == claim["shared_dynsym_provider"]["size_bytes"],
            f"ordinary {name} shared provider differs")
    shared_address = shared_provider[0][0]
    shared_image = shared_libc.read_bytes()
    shared_calls = [{"member": dict(item["member"]),
                     "calls": _ordinary_shared_caller_calls(
                         shared_image, shared_symbols.stdout, shared_relocations.stdout,
                         item["source_calls"], shared_address, name)}
                    for item in imported]
    for mode in DYNAMIC_MODES:
        executable = physical_file(work / f"dynamic-{mode}",
                                   f"ordinary {name} dynamic {mode} ELF")
        dynamic = subprocess.run(["/usr/bin/readelf", "-dW", str(executable)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        symbols = subprocess.run(["/usr/bin/readelf", "-Ws", str(executable)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        require(dynamic.returncode == symbols.returncode == 0
                and len(re.findall(r"\(NEEDED\).*\[libc\.so\]", dynamic.stdout)) == 1
                and not re.search(rf"\b{re.escape(name)}$", symbols.stdout, re.MULTILINE),
                f"ordinary {name} dynamic {mode} imports implementation")
    return {
        "static_provider_member": dict(provider),
        "static_provider": dict(claim["static_rust_provider"]),
        "shared_dynsym_provider": dict(claim["shared_dynsym_provider"]),
        "shared_symtab_provider": dict(claim["shared_symtab_provider"]),
        "importers": imported, "static_final_links": static_modes,
        "shared_final": {"provider_address": shared_address, "importers": shared_calls},
        "dynamic_final_import_absent": True,
    }


def errno_import_resolution(report: Mapping[str, Any], *, report_path: Path,
                            static_product: Path, dynamic_product: Path,
                            elf_facts_report: Path) -> dict[str, object]:
    """Bind every selected errno importer to one TLS-address accessor."""
    facts = json_object(elf_facts_report, "errno import ELF facts")["facts"]
    members = facts["candidate-static"]
    runtime = report["inputs"]["c_runtime_import_bindings"]
    c_member = runtime["static_c_member"]
    claim = next((row for row in runtime["imports"] if row["name"] == ERRNO_IMPORT_NAME), None)
    require(claim is not None and claim["binding"] == "GLOBAL",
            "errno C runtime import account differs")
    provider = claim["static_rust_provider_member"]
    require(members[provider["member_index"]]["member"] == provider["member"]
            and members[provider["member_index"]]["member_occurrence"] == 0,
            "errno provider archive member differs")
    archive = physical_file(static_product / "usr/lib/libc.a", "errno import archive")
    mounted_archive = mounted_path(archive)
    imported = []
    for member in members:
        try:
            rows = producer._symbol_tables(member["symbol_tables"], "errno archive member",
                                           {".symtab"})[".symtab"]
        except producer.ProducerMetadataError as error:
            raise AllocatorBoundaryError(str(error)) from error
        matches = [row for row in rows if row.get("name") == ERRNO_IMPORT_NAME
                   and row.get("section_index") == "UND"]
        if not matches:
            continue
        require(len(matches) == 1 and all(matches[0].get(field) == value for field, value in {
            "type": "NOTYPE", "binding": "GLOBAL", "visibility": "DEFAULT",
            "section_index": "UND", "size_bytes": 0, "value": "0000000000000000",
        }.items()) and member["member_occurrence"] == 0,
                "errno archive import row differs")
        selected = subprocess.run(["/usr/bin/ar", "p", str(archive), member["member"]],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        require(selected.returncode == 0 and selected.stdout,
                "errno importer archive member is unreadable")
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary:
            object_path = Path(temporary) / "importer.o"
            object_path.write_bytes(selected.stdout)
            relocations = subprocess.run(["/usr/bin/readelf", "-rW", str(object_path)],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         text=True, check=False)
        require(relocations.returncode == 0, "errno importer relocations are unreadable")
        calls = _errno_import_relocations(relocations.stdout)
        functions = {call["section"][6:] for call in calls if call["section"].startswith(".text.")}
        if any(call["section"] == ".text" for call in calls):
            functions.update(row["name"] for row in rows if row.get("type") == "FUNC"
                             and row.get("binding") == "GLOBAL"
                             and row.get("section_index") != "UND")
        imported.append({
            "member": _member_identity(member),
            "import": {key: matches[0][key] for key in (
                "name", "type", "binding", "visibility", "section_index", "size_bytes", "value")},
            "member_sha256": hashlib.sha256(selected.stdout).hexdigest(),
            "source_calls": calls, "shared_caller_functions": sorted(functions),
        })
    require(len(imported) == 6 and len({item["member"]["member_index"] for item in imported}) == 6
            and len([item for item in imported if item["member"]["member_index"] == c_member["member_index"]]) == 1
            and all(item["member"]["member_index"] != provider["member_index"] for item in imported),
            "errno static importer roster differs")
    provider_object = subprocess.run(["/usr/bin/ar", "p", str(archive), provider["member"]],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    require(provider_object.returncode == 0 and provider_object.stdout,
            "errno provider archive object is unreadable")
    with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary:
        object_path = Path(temporary) / "provider.o"
        object_path.write_bytes(provider_object.stdout)
        provider_reloc = subprocess.run(["/usr/bin/readelf", "-rW", str(object_path)],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    accessor_relocations = provider_reloc.stdout.split(
        "Relocation section '.rela.text.__errno_location'", 1)
    accessor_relocations = (accessor_relocations[1].split("Relocation section ", 1)[0]
                            if len(accessor_relocations) == 2 else "")
    require(provider_reloc.returncode == 0 and len(re.findall(
        r"R_X86_64_GOTTPOFF\s+\S+\s+\S*5errno5ERRNO\s+-\s+4",
        provider_reloc.stdout)) == 3
            and len(re.findall(r"R_X86_64_GOTTPOFF\s+\S+\s+\S*5errno5ERRNO\s+-\s+4",
                               accessor_relocations)) == 1,
            "errno provider source TLS address relocation differs")
    work = physical_directory(report_path.parent / report["errno_import"]["work"],
                              "errno retained final links")
    static_modes = {}
    for mode, elf_type in (("static", 2), ("static-pie", 3)):
        executable = physical_file(work / f"static-{mode}", f"errno {mode} final ELF")
        map_text = physical_file(work / f"static-{mode}.crabc-link.map",
                                 f"errno {mode} map").read_text(encoding="utf-8")
        trace = physical_file(work / f"static-{mode}.crabc-link.trace",
                              f"errno {mode} trace").read_text(encoding="utf-8")
        symbol_result = subprocess.run(["/usr/bin/readelf", "-Ws", str(executable)],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, check=False)
        relocation_result = subprocess.run(["/usr/bin/readelf", "-rW", str(executable)],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           text=True, check=False)
        require(symbol_result.returncode == relocation_result.returncode == 0
                and not re.search(r"\b__errno_location\b", relocation_result.stdout),
                f"errno {mode} final ELF retains an external import")
        provider_rows = _errno_elf_symbols(symbol_result.stdout, ERRNO_IMPORT_NAME,
                                           kind="FUNC", binding="GLOBAL")
        require(len(provider_rows) == 1 and provider_rows[0][1] == 17,
                f"errno {mode} final provider differs")
        provider_address = provider_rows[0][0]
        selected_provider = f"{mounted_archive}({provider['member']})"
        require(trace.splitlines().count(selected_provider) == 1
                and len([line for line in map_text.splitlines()
                         if line.rstrip().endswith(f"{selected_provider}:(.text.__errno_location)")
                         and int(line.split()[0], 16) == provider_address]) == 1,
                f"errno {mode} selected provider map differs")
        image = executable.read_bytes()
        resolved = []
        for item in imported:
            selected = f"{mounted_archive}({item['member']['member']})"
            require(trace.splitlines().count(selected) == 1,
                    f"errno {mode} importer is not selected exactly once")
            resolved.append({
                "member": dict(item["member"]),
                **_errno_final_member_calls(
                    image, archive_member=selected, source_calls=item["source_calls"],
                    map_text=map_text, provider_address=provider_address, elf_type=elf_type),
            })
        static_modes[mode] = {
            "provider_member": dict(provider), "provider_address": provider_address,
            "accessor_tls": _errno_static_accessor(image, provider_address,
                                                    symbol_result.stdout, elf_type),
            "importers": resolved,
        }
    shared_libc = physical_file(dynamic_product / "usr/lib/libc.so", "errno shared libc")
    shared_symbols = subprocess.run(["/usr/bin/readelf", "-Ws", str(shared_libc)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, check=False)
    shared_relocations = subprocess.run(["/usr/bin/readelf", "-rW", str(shared_libc)],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, check=False)
    require(shared_symbols.returncode == shared_relocations.returncode == 0
            and not re.search(r"\b__errno_location\b", shared_relocations.stdout),
            "errno shared libc retains an external accessor import")
    shared_provider = _errno_elf_symbols(shared_symbols.stdout, ERRNO_IMPORT_NAME,
                                         kind="FUNC", binding="GLOBAL")
    require(len(shared_provider) == 2 and len(set(shared_provider)) == 1
            and shared_provider[0][1] == 17, "errno shared provider differs")
    shared_address = shared_provider[0][0]
    tls_rows = []
    for line in shared_symbols.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[0].endswith(":") and parts[-1].endswith("5errno5ERRNO"):
            require(parts[2:6] == ["4", "TLS", "LOCAL", "DEFAULT"] and parts[6] != "UND",
                    "errno shared TLS symbol differs")
            tls_rows.append(int(parts[1], 16))
    require(len(tls_rows) == 1, "errno shared TLS symbol is missing or duplicate")
    shared_image = shared_libc.read_bytes()
    body = _public_weak_virtual_bytes(shared_image, shared_address, 17, 3, executable=True)
    require(body[:9] == b"\x64\x48\x8b\x04\x25\0\0\0\0"
            and body[9:12] == b"\x48\x03\x05" and body[16] == 0xc3,
            "errno shared accessor does not return an FS-relative TLS address")
    tls_slot = shared_address + 16 + struct.unpack_from("<i", body, 12)[0]
    tls_reloc = re.findall(
        rf"^0*{tls_slot:x}\s+\S+\s+R_X86_64_TPOFF64\s+([0-9a-f]+)\s*$",
        shared_relocations.stdout, re.MULTILINE)
    require(len(tls_reloc) == 1 and int(tls_reloc[0], 16) == tls_rows[0],
            "errno shared accessor TLS relocation differs")
    shared_calls = [{
        "member": dict(item["member"]),
        "calls": _errno_shared_caller_calls(
            shared_image, shared_symbols.stdout, item["shared_caller_functions"], shared_address),
    } for item in imported]
    for mode in DYNAMIC_MODES:
        executable = physical_file(work / f"dynamic-{mode}", f"errno dynamic {mode} final ELF")
        dynamic = subprocess.run(["/usr/bin/readelf", "-dW", str(executable)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        symbols = subprocess.run(["/usr/bin/readelf", "-Ws", str(executable)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        require(dynamic.returncode == symbols.returncode == 0
                and len(re.findall(r"\(NEEDED\).*\[libc\.so\]", dynamic.stdout)) == 1
                and not re.search(r"\b__errno_location$", symbols.stdout, re.MULTILINE),
                f"errno dynamic {mode} final ELF imports the implementation")
    return {
        "static_provider_member": dict(provider),
        "static_provider": dict(claim["static_rust_provider"]),
        "shared_dynsym_provider": dict(claim["shared_dynsym_provider"]),
        "shared_symtab_provider": dict(claim["shared_symtab_provider"]),
        "importers": imported, "static_final_links": static_modes,
        "shared_final": {
            "provider_address": shared_address, "tls_symbol_offset": tls_rows[0],
            "tls_segment_size": _errno_tls_segment_size(shared_image, 3),
            "tls_relocation_slot": tls_slot, "importers": shared_calls,
        },
        "dynamic_final_import_absent": True,
    }


def _startup_observations(work: Path, output: Path, static_product: Path, dynamic_product: Path,
                          runtime_imports: Mapping[str, Any], *, validate_links: bool = True) -> dict[str, object]:
    captures = {stem: _stream(work, output, stem) for stem in ("oracle-dynamic", "oracle-static", *[f"static-{mode}" for mode in STATIC_MODES], *[f"dynamic-{mode}-{entry}" for mode in DYNAMIC_MODES for entry in ENTRIES])}
    for stem in captures:
        require((work / f"{stem}.stdout").read_bytes() == b"" and (work / f"{stem}.stderr").read_bytes() == b"",
                f"startup runner {stem} emitted a diagnostic")
    oracle_artifacts = {name: identity(work / filename, logical_path=(work / filename).relative_to(output).as_posix())
                       for name, filename in (("dynamic", "oracle-dynamic"), ("static", "oracle-static"))}
    workload = _startup_workload(work)
    workload_artifacts = {name: identity(work / filename, logical_path=(work / filename).relative_to(output).as_posix())
                          for name, filename in (("object", "workload.o"), ("header", "workload.header"),
                                                 ("relocations", "workload.relocations"))}
    links: dict[str, object] = {}
    if validate_links:
        links = {mode: _link(work, output, static_product, workload, f"static-{mode}", f"static-{mode}.crabc-link.json", mode) for mode in STATIC_MODES}
        links.update({"dynamic-" + mode: _link(work, output, dynamic_product, workload, f"dynamic-{mode}", f"dynamic-{mode}.crabc-link.json", mode) for mode in DYNAMIC_MODES})
    symbols = physical_file(work / "dynamic-symbols.txt", "startup lifecycle symbols").read_text(encoding="utf-8")
    for name in ("__crabc_x86_owned_mimalloc_process_initializer", "__crabc_x86_owned_mimalloc_process_finalizer"):
        require(len(re.findall(rf"^\S+\s+d\s+{re.escape(name)}$", symbols, re.MULTILINE)) == 1,
                f"startup lifecycle symbol {name} is not one local-data entry")
    require("mi_process_attach" not in symbols and "mi_process_detach" not in symbols,
            "shared C backend retained implicit lifecycle hooks")
    return {
        "captures": captures, "oracle": oracle_artifacts, "workload": workload_artifacts, "links": links,
        "symbols": identity(work / "dynamic-symbols.txt", logical_path=(work / "dynamic-symbols.txt").relative_to(output).as_posix()),
        "c_runtime_static_links": _runtime_static_member_links(work, output, static_product, runtime_imports),
    }


def _replay_startup_observations(work: Path, output: Path, static_product: Path, dynamic_product: Path,
                                 runtime_imports: Mapping[str, Any], observed: object) -> dict[str, object]:
    current = _startup_observations(work, output, static_product, dynamic_product, runtime_imports, validate_links=False)
    record = exact(observed, {"captures", "oracle", "workload", "links", "symbols", "c_runtime_static_links"}, "startup observation")
    require(same(record["captures"], current["captures"]) and same(record["oracle"], current["oracle"])
            and same(record["workload"], current["workload"])
            and same(record["symbols"], current["symbols"])
            and same(record["c_runtime_static_links"], current["c_runtime_static_links"]),
            "startup raw observations drifted")
    workload = _startup_workload(work)
    links = exact(record["links"], {*STATIC_MODES, *(f"dynamic-{mode}" for mode in DYNAMIC_MODES)}, "startup link roster")
    for mode in STATIC_MODES:
        _replay_link(work, output, static_product, workload, f"static-{mode}", f"static-{mode}.crabc-link.json", mode,
                     links[mode], export_dynamic=False)
    for mode in DYNAMIC_MODES:
        _replay_link(work, output, dynamic_product, workload, f"dynamic-{mode}", f"dynamic-{mode}.crabc-link.json", mode,
                     links[f"dynamic-{mode}"], export_dynamic=False)
    return record


def _public_weak_links(output: Path, static_product: Path, dynamic_product: Path) -> dict[str, object]:
    """Link one installed-header caller that selects both ordinary Rust importers."""
    work = output / "public-weak"
    work.mkdir(mode=0o755)
    source = work / "workload.c"
    source.write_text(PUBLIC_WEAK_WORKLOAD, encoding="utf-8")
    object_path = work / "workload.o"
    command = [str(physical_file(dynamic_product / "bin/crabc-cc-dynamic", "public weak installed compiler")),
               "--dynamic-pie", "-std=c11", "-fno-builtin", "-c", mounted_path(source),
               "-o", mounted_path(object_path)]
    result = subprocess.run(command, cwd=work, env=workload_environment(output),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    require(result.returncode == 0 and not result.stdout and not result.stderr,
            "public weak installed-header compilation failed")
    links = {}
    for mode in STATIC_MODES:
        stem = f"static-{mode}"
        command = [str(physical_file(static_product / "bin/crabc-cc", "public weak static linker")),
                   f"-{mode}", "--link-receipt", f"{stem}.crabc-link.json",
                   mounted_path(object_path), "-o", mounted_path(work / stem)]
        result = subprocess.run(command, cwd=work, env=workload_environment(output),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        require(result.returncode == 0 and not result.stdout and not result.stderr,
                f"public weak {mode} installed link failed")
        links[mode] = _link(work, output, static_product, object_path, stem,
                            f"{stem}.crabc-link.json", mode)
    for mode in DYNAMIC_MODES:
        stem = f"dynamic-{mode}"
        command = [str(physical_file(dynamic_product / "bin/crabc-cc-dynamic", "public weak dynamic linker")),
                   f"--dynamic-{mode}", mounted_path(object_path), "-o", mounted_path(work / stem)]
        result = subprocess.run(command, cwd=work, env=workload_environment(output),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        require(result.returncode == 0 and not result.stdout and not result.stderr,
                f"public weak dynamic {mode} installed link failed")
        links[stem] = _link(work, output, dynamic_product, object_path, stem,
                            f"{stem}.crabc-link.json", mode)
    return {"work": work.relative_to(output).as_posix(),
            "source": identity(source, logical_path=source.relative_to(output).as_posix()),
            "object": identity(object_path, logical_path=object_path.relative_to(output).as_posix()),
            "links": links}


def _replay_public_weak_links(output: Path, static_product: Path, dynamic_product: Path,
                              observed: object) -> dict[str, object]:
    item = exact(observed, {"work", "source", "object", "links"}, "public weak links")
    require(item["work"] == "public-weak", "public weak work path differs")
    work = physical_directory(output / item["work"], "public weak link work")
    source = physical_file(work / "workload.c", "public weak workload source")
    object_path = physical_file(work / "workload.o", "public weak workload object")
    require(source.read_text(encoding="utf-8") == PUBLIC_WEAK_WORKLOAD
            and same(item["source"], identity(source, logical_path=source.relative_to(output).as_posix()))
            and same(item["object"], identity(object_path, logical_path=object_path.relative_to(output).as_posix())),
            "public weak installed workload differs")
    links = exact(item["links"], {*STATIC_MODES, *(f"dynamic-{mode}" for mode in DYNAMIC_MODES)},
                  "public weak link roster")
    for mode in STATIC_MODES:
        stem = f"static-{mode}"
        _replay_link(work, output, static_product, object_path, stem,
                     f"{stem}.crabc-link.json", mode, links[mode], export_dynamic=False)
    for mode in DYNAMIC_MODES:
        stem = f"dynamic-{mode}"
        _replay_link(work, output, dynamic_product, object_path, stem,
                     f"{stem}.crabc-link.json", mode, links[stem], export_dynamic=False)
    return item


def _errno_links(output: Path, static_product: Path, dynamic_product: Path) -> dict[str, object]:
    """Select float and abort callers in installed static and dynamic links."""
    work = output / "errno-import"
    work.mkdir(mode=0o755)
    source = work / "workload.c"
    source.write_text(ERRNO_WORKLOAD, encoding="utf-8")
    object_path = work / "workload.o"
    compile_command = [str(physical_file(dynamic_product / "bin/crabc-cc-dynamic", "errno installed compiler")),
                       "--dynamic-pie", "-std=c11", "-fno-builtin", "-c", mounted_path(source),
                       "-o", mounted_path(object_path)]
    completed = subprocess.run(compile_command, cwd=work, env=workload_environment(output),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    require(completed.returncode == 0 and not completed.stdout and not completed.stderr,
            "errno installed-header compilation failed")
    static_object = work / "static-workload.o"
    static_compile = [str(physical_file(dynamic_product / "bin/crabc-cc-dynamic", "ordinary installed compiler")),
                      "--dynamic-pie", "-std=c11", "-fno-builtin", "-DCRABC_STATIC_ABORT_PROBE",
                      "-c", mounted_path(source), "-o", mounted_path(static_object)]
    completed = subprocess.run(static_compile, cwd=work, env=workload_environment(output),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    require(completed.returncode == 0 and not completed.stdout and not completed.stderr,
            "ordinary static installed-header compilation failed")
    links = {}
    for mode in STATIC_MODES:
        stem = f"static-{mode}"
        command = [str(physical_file(static_product / "bin/crabc-cc", "errno static linker")),
                   f"-{mode}", "--link-receipt", f"{stem}.crabc-link.json",
                   mounted_path(static_object), "-o", mounted_path(work / stem)]
        completed = subprocess.run(command, cwd=work, env=workload_environment(output),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        require(completed.returncode == 0 and not completed.stdout and not completed.stderr,
                f"errno {mode} installed link failed")
        links[mode] = _link(work, output, static_product, static_object, stem,
                            f"{stem}.crabc-link.json", mode)
    for mode in DYNAMIC_MODES:
        stem = f"dynamic-{mode}"
        command = [str(physical_file(dynamic_product / "bin/crabc-cc-dynamic", "errno dynamic linker")),
                   f"--dynamic-{mode}", mounted_path(object_path), "-o", mounted_path(work / stem)]
        completed = subprocess.run(command, cwd=work, env=workload_environment(output),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        require(completed.returncode == 0 and not completed.stdout and not completed.stderr,
                f"errno dynamic {mode} installed link failed")
        links[stem] = _link(work, output, dynamic_product, object_path, stem,
                            f"{stem}.crabc-link.json", mode)
    return {"work": work.relative_to(output).as_posix(),
            "source": identity(source, logical_path=source.relative_to(output).as_posix()),
            "object": identity(object_path, logical_path=object_path.relative_to(output).as_posix()),
            "static_object": identity(static_object, logical_path=static_object.relative_to(output).as_posix()),
            "links": links}


def _replay_errno_links(output: Path, static_product: Path, dynamic_product: Path,
                        observed: object) -> dict[str, object]:
    item = exact(observed, {"work", "source", "object", "static_object", "links"}, "errno import links")
    require(item["work"] == "errno-import", "errno import work path differs")
    work = physical_directory(output / item["work"], "errno import retained work")
    source = physical_file(work / "workload.c", "errno import workload source")
    object_path = physical_file(work / "workload.o", "errno import workload object")
    static_object = physical_file(work / "static-workload.o", "ordinary static workload object")
    require(source.read_text(encoding="utf-8") == ERRNO_WORKLOAD
            and same(item["source"], identity(source, logical_path=source.relative_to(output).as_posix()))
            and same(item["object"], identity(object_path, logical_path=object_path.relative_to(output).as_posix())),
            "errno import installed workload differs")
    require(same(item["static_object"], identity(
        static_object, logical_path=static_object.relative_to(output).as_posix())),
        "ordinary static installed workload differs")
    links = exact(item["links"], {*STATIC_MODES, *(f"dynamic-{mode}" for mode in DYNAMIC_MODES)},
                  "errno import link roster")
    for mode in STATIC_MODES:
        stem = f"static-{mode}"
        _replay_link(work, output, static_product, static_object, stem,
                     f"{stem}.crabc-link.json", mode, links[mode], export_dynamic=False)
    for mode in DYNAMIC_MODES:
        stem = f"dynamic-{mode}"
        _replay_link(work, output, dynamic_product, object_path, stem,
                     f"{stem}.crabc-link.json", mode, links[stem], export_dynamic=False)
    return item


def _interposition_observations(work: Path, output: Path, dynamic_product: Path,
                                *, validate_links: bool = True) -> dict[str, object]:
    pairs: dict[str, object] = {}
    for mode in DYNAMIC_MODES:
        for entry in ENTRIES:
            for scenario in SCENARIOS:
                oracle, candidate = f"oracle-{mode}-{entry}-{scenario}", f"candidate-{mode}-{entry}-{scenario}"
                oracle_stream, candidate_stream = _stream(work, output, oracle), _stream(work, output, candidate)
                for suffix in ("stdout", "stderr", "status"):
                    require((work / f"{oracle}.{suffix}").read_bytes() == (work / f"{candidate}.{suffix}").read_bytes(),
                            f"{mode}/{entry}/{scenario} differs from musl")
                pairs[f"{mode}-{entry}-{scenario}"] = {"oracle": oracle_stream, "candidate": candidate_stream}
    links: dict[str, object] = {}
    if validate_links:
        workload = work / "workload.o"
        links = {mode: _link(work, output, dynamic_product, workload, f"candidate-{mode}",
                             f"candidate-{mode}.crabc-link.json", mode, export_dynamic=True)
                 for mode in DYNAMIC_MODES}
    for required in ("provider.relocations", "provider.symbols", "provider.disassembly", "workload.header", "workload.relocations"):
        physical_file(work / required, f"interposition {required}")
    reloc = (work / "provider.relocations").read_text(encoding="utf-8")
    symbols = (work / "provider.symbols").read_text(encoding="utf-8")
    disassembly = (work / "provider.disassembly").read_text(encoding="utf-8")
    require(re.search(r"R_X86_64_GLOB_DAT\s+.*\bmalloc\b", reloc) is not None, "provider lacks public malloc lookup")
    for name, target in (("__crabc_x86_passwd_cabi_free", "free"), ("__crabc_x86_aio_cabi_malloc", "malloc"), ("__crabc_x86_aio_cabi_free", "free")):
        require(re.search(rf"\bFUNC\s+LOCAL\s+HIDDEN\s+\S+\s+{re.escape(name)}$", symbols, re.MULTILINE) is not None,
                f"interposition tail {name} metadata differs")
        start = disassembly.find(f"<{name}>:")
        require(start >= 0 and re.search(rf"jmp.*<{target}@plt>", disassembly[start:start + 1024]) is not None,
                f"interposition tail {name} misses {target}@plt")
    return {"pairs": pairs, "links": links,
            "artifacts": {name: identity(work / name, logical_path=(work / name).relative_to(output).as_posix())
                          for name in ("provider.relocations", "provider.symbols", "provider.disassembly", "workload.header", "workload.relocations")}}


def _replay_interposition_observations(work: Path, output: Path, dynamic_product: Path,
                                       observed: object) -> dict[str, object]:
    current = _interposition_observations(work, output, dynamic_product, validate_links=False)
    record = exact(observed, {"pairs", "links", "artifacts"}, "interposition observation")
    require(same(record["pairs"], current["pairs"]) and same(record["artifacts"], current["artifacts"]),
            "interposition raw observations drifted")
    links = exact(record["links"], set(DYNAMIC_MODES), "interposition link roster")
    workload = work / "workload.o"
    for mode in DYNAMIC_MODES:
        _replay_link(work, output, dynamic_product, workload, f"candidate-{mode}",
                     f"candidate-{mode}.crabc-link.json", mode, links[mode], export_dynamic=True)
    return record


def collect(*, static_preparation: Path, static_product: Path, dynamic_product: Path,
            elf_facts_report: Path, output: Path) -> dict[str, object]:
    output = fresh_output(output, static_preparation=static_preparation, static_product=static_product, dynamic_product=dynamic_product)
    static_mount = admitted_supplied_path(static_product, "static product")
    dynamic_mount = admitted_supplied_path(dynamic_product, "dynamic product")
    admitted_supplied_path(static_preparation, "static preparation")
    admitted_supplied_path(elf_facts_report, "ELF facts report")
    inputs = validate_supplied_products(root=ROOT, static_preparation=static_preparation, static_product=static_product,
                                       dynamic_product=dynamic_product, elf_facts_report=elf_facts_report)
    output.mkdir(mode=0o700)
    environment = workload_environment(output)
    startup_before = set(output.glob("owned-mimalloc-startup-errno.*"))
    startup_command = _capture(output, "startup", ["bash", mounted_path(ROOT / "compat/x86_64/run_owned_mimalloc_startup_errno.sh"), "--static-sysroot", static_mount, dynamic_mount], environment)
    startup_work = _new_work(output, "owned-mimalloc-startup-errno", startup_before)
    startup = _startup_observations(
        startup_work, output, Path(static_product), Path(dynamic_product),
        inputs["c_runtime_import_bindings"],
    )
    public_weak = _public_weak_links(output, Path(static_product), Path(dynamic_product))
    errno_import = _errno_links(output, Path(static_product), Path(dynamic_product))
    interposition_before = set(output.glob("owned-c-allocation-interposition.*"))
    interposition_command = _capture(output, "interposition", ["bash", mounted_path(ROOT / "compat/x86_64/run_owned_c_allocation_interposition.sh"), dynamic_mount], environment)
    interposition_work = _new_work(output, "owned-c-allocation-interposition", interposition_before)
    interposition = _interposition_observations(interposition_work, output, Path(dynamic_product))
    before = {key: value for key, value in inputs.items() if key in {
        "product_source", "static_preparation", "static", "dynamic", "elf_facts", "c_runtime_import_bindings",
    }}
    after_inputs = validate_supplied_products(root=ROOT, static_preparation=static_preparation, static_product=static_product,
                                              dynamic_product=dynamic_product, elf_facts_report=elf_facts_report)
    after = {key: value for key, value in after_inputs.items() if key in {
        "product_source", "static_preparation", "static", "dynamic", "elf_facts", "c_runtime_import_bindings",
    }}
    require(same(before, after), "supplied product inputs changed during collection")
    source = inventory.collector_source_seal()
    report = {"schema": SCHEMA, "target": TARGET, "status": {"family_completion": False, "promotion": False, "public_support": False},
              "collector_source": source, "component_sources": source_records(ROOT), "inputs": inputs,
              "startup": {"command": startup_command, "work": startup_work.relative_to(output).as_posix(), "observation": startup},
              "public_weak": public_weak,
              "errno_import": errno_import,
              "interposition": {"command": interposition_command, "work": interposition_work.relative_to(output).as_posix(), "observation": interposition}}
    (output / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.chmod(output, 0o755)
    return report


def _validate_capture(output: Path, record: object, label: str, argv: list[str]) -> None:
    value = exact(record, {"argv", "environment", "stdout", "stderr", "status"}, f"{label} command")
    require(value["argv"] == argv and value["environment"] == workload_environment(output),
            f"{label} command invocation drifted")
    for suffix in ("stdout", "stderr", "status"):
        path = output / RAW / f"{label}.{suffix}"
        require(same(value[suffix], identity(path, logical_path=path.relative_to(output).as_posix())), f"{label} {suffix} identity drifted")
    require((output / RAW / f"{label}.status").read_bytes() == b"0\n", f"{label} did not succeed")


def validate_report(report_path: Path, *, static_preparation: Path, static_product: Path,
                    dynamic_product: Path, elf_facts_report: Path) -> dict[str, object]:
    report_path = physical_file(report_path, "allocator boundary report")
    output = physical_directory(report_path.parent, "allocator boundary report root")
    report = exact(json_object(report_path, "allocator boundary report"), {"schema", "target", "status", "collector_source", "component_sources", "inputs", "startup", "public_weak", "errno_import", "interposition"}, "allocator boundary report")
    require(report["schema"] == SCHEMA and report["target"] == TARGET and report["status"] == {"family_completion": False, "promotion": False, "public_support": False},
            "allocator boundary report identity drifted")
    require(same(report["collector_source"], inventory.collector_source_seal()), "collector source changed")
    validate_source_records(ROOT, report["component_sources"])
    static_mount = admitted_supplied_path(static_product, "static product")
    dynamic_mount = admitted_supplied_path(dynamic_product, "dynamic product")
    admitted_supplied_path(static_preparation, "static preparation")
    admitted_supplied_path(elf_facts_report, "ELF facts report")
    inputs = validate_supplied_products(root=ROOT, static_preparation=static_preparation, static_product=static_product,
                                       dynamic_product=dynamic_product, elf_facts_report=elf_facts_report)
    require(same(report["inputs"], inputs), "supplied product account changed")
    startup = exact(report["startup"], {"command", "work", "observation"}, "startup report")
    startup_work = physical_directory(output / startup["work"], "startup retained work")
    _validate_capture(output, startup["command"], "startup", ["bash", mounted_path(ROOT / "compat/x86_64/run_owned_mimalloc_startup_errno.sh"), "--static-sysroot", static_mount, dynamic_mount])
    _replay_startup_observations(
        startup_work, output, Path(static_product), Path(dynamic_product),
        inputs["c_runtime_import_bindings"], startup["observation"],
    )
    _replay_public_weak_links(output, Path(static_product), Path(dynamic_product), report["public_weak"])
    _replay_errno_links(output, Path(static_product), Path(dynamic_product), report["errno_import"])
    interposition = exact(report["interposition"], {"command", "work", "observation"}, "interposition report")
    interposition_work = physical_directory(output / interposition["work"], "interposition retained work")
    _validate_capture(output, interposition["command"], "interposition", ["bash", mounted_path(ROOT / "compat/x86_64/run_owned_c_allocation_interposition.sh"), dynamic_mount])
    _replay_interposition_observations(interposition_work, output, Path(dynamic_product), interposition["observation"])
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    modes = parser.add_subparsers(dest="mode", required=True)
    collect_parser = modes.add_parser("collect", allow_abbrev=False)
    replay_parser = modes.add_parser("validate-report", allow_abbrev=False)
    for item in (collect_parser, replay_parser):
        item.add_argument("--static-preparation", required=True, type=Path)
        item.add_argument("--static-product", required=True, type=Path)
        item.add_argument("--dynamic-product", required=True, type=Path)
        item.add_argument("--elf-facts-report", required=True, type=Path)
    collect_parser.add_argument("--output", required=True, type=Path)
    replay_parser.add_argument("report", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.mode == "collect":
            collect(static_preparation=args.static_preparation, static_product=args.static_product, dynamic_product=args.dynamic_product,
                    elf_facts_report=args.elf_facts_report, output=args.output)
        else:
            validate_report(args.report, static_preparation=args.static_preparation, static_product=args.static_product,
                            dynamic_product=args.dynamic_product, elf_facts_report=args.elf_facts_report)
    except (AllocatorBoundaryError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    print("native C allocator boundary: PASS (component pass, not qualification)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
