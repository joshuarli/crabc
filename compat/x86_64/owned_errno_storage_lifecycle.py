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


SCHEMA = "crabc.x86_64-owned-errno-storage-lifecycle/v1"
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
    "scripts/build_x86_64_owned_dynamic_sysroot.py",
)

PUBLIC_SYMBOLS = ("__errno_location", "__h_errno_location", "h_errno")
ALIAS = "___errno_location"
SHARED_ALIAS_LIST = "libc/src/c_abi/x86_64/owned_errno_private_aliases.list"
SHARED_ALIAS_LIST_SHA256 = "2e69ec5346002fa183b51dbbbef2f24744bd89093b5cfac6329337c1b3d240dd"
SHARED_ALIAS_MEMBERS = (ALIAS,)
SHARED_ALIAS_LINKER_SCRIPT = "--version-script=$BUILD/libc-errno-private.exports"
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


def rebase_report_checkout_paths(value: object, root: Path) -> dict[str, Any]:
    """Rebase retained checkout paths to a physical host checkout for replay.

    Only JSON fields which carry filesystem paths are considered.  Every
    absolute descendant of ``source.root`` is mapped to ``root``; outside
    oracle/tool paths and relative source-policy paths remain observations.
    The caller still validates all resulting physical identities and source
    bytes, so this is path admission rather than a provenance fallback.
    """

    if not isinstance(value, dict):
        fail("errno storage report is malformed")
    source = value.get("source")
    if not isinstance(source, dict):
        fail("errno storage report source is malformed")
    recorded_root = _recorded_checkout_root(source.get("root"))
    root = physical_directory(root, "source root")

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
    return matches[0]


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


def symbol_artifacts(work: Path) -> dict[str, dict[str, object]]:
    return {name: identity(work / name, f"symbol artifact {name}") for name in SYMBOL_INPUTS}


def workload_symbol_artifacts(work: Path) -> dict[str, dict[str, object]]:
    return {name: identity(work / name, f"workload symbol artifact {name}") for name in WORKLOAD_SYMBOL_INPUTS}


def validate_symbol_artifacts(value: object, work: Path) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(SYMBOL_INPUTS):
        fail("symbol artifact roster drifted")
    paths: dict[str, Path] = {}
    for name in SYMBOL_INPUTS:
        paths[name] = validate_identity(value[name], f"symbol artifact {name}", within=work)
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
    return value


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
    script_sha256 = aliases["linker_script_sha256"]
    if not isinstance(script_sha256, str) or SHA256.fullmatch(script_sha256) is None:
        fail(f"{description} errno private alias script identity is malformed")
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
    products = product_record(static_product, dynamic_product)
    shared_alias_link_policy = validate_shared_alias_product_provenance(products)
    symbols = symbol_artifacts(work)
    validate_symbol_artifacts(symbols, work)
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
        "products": products,
        "shared_alias_link_policy": shared_alias_link_policy,
        "symbols": symbols,
        "workload_symbols": workload_symbols,
        "objects": objects,
        "execution": execution,
        "dynamic_link_receipts": dynamic_receipts,
        "summary": {
            "errno_public_accessor": "GLOBAL DEFAULT FUNC",
            "errno_allocator_alias": "static WEAK HIDDEN same-address; shared LOCAL DEFAULT absent-dynsym",
            "h_errno": "GLOBAL DEFAULT OBJECT size=4 with GLOBAL DEFAULT accessor",
            "execution": "main/live-worker isolation, stable live locations, selected pthread EBUSY preserves errno, and loaded DSO access",
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
        "products",
        "shared_alias_link_policy",
        "symbols",
        "workload_symbols",
        "objects",
        "execution",
        "dynamic_link_receipts",
        "summary",
    }
    require_exact_mapping(report, expected, "errno storage report")
    if report["schema"] != SCHEMA or report["target"] != TARGET or not isinstance(report["work"], str):
        fail("errno storage report identity drifted")
    work = physical_directory(Path(report["work"]), "report evidence root")
    if report_path.parent != work:
        fail("report evidence root differs from the report directory")
    validate_source_snapshot(report["source"], root, "report source snapshot")
    validate_products(report["products"])
    if report["shared_alias_link_policy"] != validate_shared_alias_product_provenance(report["products"]):
        fail("report shared errno alias link policy drifted")
    validate_symbol_artifacts(report["symbols"], work)
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
            "execution",
            "worker_pointer_lifetime",
        },
        "report summary",
    )
    if summary != {
        "errno_public_accessor": "GLOBAL DEFAULT FUNC",
        "errno_allocator_alias": "static WEAK HIDDEN same-address; shared LOCAL DEFAULT absent-dynsym",
        "h_errno": "GLOBAL DEFAULT OBJECT size=4 with GLOBAL DEFAULT accessor",
        "execution": "main/live-worker isolation, stable live locations, selected pthread EBUSY preserves errno, and loaded DSO access",
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
