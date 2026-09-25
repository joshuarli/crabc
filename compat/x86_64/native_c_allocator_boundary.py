#!/usr/bin/env python3
"""Collect and replay the installed native C allocator wrapper boundary.

This finite reader consumes products prepared by their owners.  It joins the
fixed-C producer account to the static Rust importer and replays only the
existing lifecycle and public-interposition runners.  It is not an allocator
builder, policy selector, or qualification campaign.
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
import subprocess
import sys
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
SCHEMA = "crabc.x86_64-native-c-allocator-boundary/v3"
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
    report = exact(json_object(report_path, "allocator boundary report"), {"schema", "target", "status", "collector_source", "component_sources", "inputs", "startup", "interposition"}, "allocator boundary report")
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
