#!/usr/bin/env python3
"""Produce source-bound fixed-protocol-table evidence from three x86 products.

The selected x86 C ABI is a direct semantic port of musl 1.2.6
``src/network/proto.c``.  Its API is intentionally a fixed, process-global
36-record table; it does not select the separate Rust-facing ``/etc/protocols``
snapshot facade.  This producer translates one existing state-machine probe
with project headers, runs it through the pinned musl oracle, then links that
same object into three non-reused static/dynamic product pairs.  Each pair is
executed as static ET_EXEC, static PIE, dynamic PIE through the kernel and
direct interpreter, and dynamic non-PIE through both entries.

The result is a retained raw receipt below ``.work``.  The companion reader is
the public admission boundary: this script itself does not promote the
resolver family or x86 support.
"""

from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any, Mapping, Sequence

from owned_static_link_authority import (
    StaticFunctionContract,
    StaticLinkAuthorityError,
    admit_static_inputs,
    elf_bytes,
    require_static_functions,
)
from owned_syscall_alias_authority import archive_members


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "crabc.x86_64-owned-protocol-database-products/v2"
COMPONENT = "protocol-database-product"
ARMS = ("installed", "reproduction", "extracted")
ENTRY_MODES = (
    "static-et-exec",
    "static-pie",
    "dynamic-pie-kernel",
    "dynamic-pie-direct",
    "dynamic-non-pie-kernel",
    "dynamic-non-pie-direct",
)
PROVIDERS = (
    "endprotoent",
    "getprotobyname",
    "getprotobynumber",
    "getprotoent",
    "setprotoent",
)
ORACLE_PROTO_IMPORTS = ("strcmp", "strlen")
MUSL_CC = Path("/usr/local/bin/crabc-x86_64-musl-gcc")
PINNED_MUSL_ARCHIVE = Path("/opt/musl-1.2.6/lib/libc.a")
ORACLE_IMAGE_MANIFEST = Path("compat/x86_64/owned_resolver_network_image_inputs.json")
PROBE = Path("compat/x86_64/libc_protocol_database_probe.c")
RUST_PROVIDER = Path("libc/src/c_abi/x86_64/protocol_database.rs")
PROVIDER_CONTRACT = Path("compat/x86_64/protocol-database-provider.toml")
READER = Path("compat/x86_64/owned_protocol_database_receipt.py")
PRODUCT_FIXTURE = Path("compat/resolver-network/run_x86_64.py")
DYNAMIC_RECEIPT = Path("compat/x86_64/owned_dynamic_receipt.py")
POISON_PROTOCOLS = b"poison 253 deliberately-not-selected\n"
SOURCE_FILES = (
    Path(__file__).relative_to(ROOT), READER, PROBE, RUST_PROVIDER, PROVIDER_CONTRACT,
    PRODUCT_FIXTURE, DYNAMIC_RECEIPT, ORACLE_IMAGE_MANIFEST,
    Path("compat/x86_64/owned_static_link_authority.py"),
    Path("compat/x86_64/owned_syscall_alias_authority.py"),
    Path("compat/x86_64/loader_debug_abi_evidence.py"),
    Path("compat/x86_64/owned_dynamic_elf.py"),
)


class ProtocolDatabaseError(RuntimeError):
    """The fixed-table product receipt cannot be produced safely."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProtocolDatabaseError(message)


def pinned_musl_archive_identity(root: Path) -> dict[str, object]:
    try:
        manifest = json.loads((root / ORACLE_IMAGE_MANIFEST).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise ProtocolDatabaseError(f"cannot read native oracle image manifest: {error}") from error
    require(isinstance(manifest, dict) and manifest.get("schema") == "crabc.x86_64-owned-resolver-network-image-inputs/v1"
            and isinstance(manifest.get("files"), dict), "native oracle image manifest differs")
    record = manifest["files"].get(str(PINNED_MUSL_ARCHIVE))
    require(isinstance(record, dict) and set(record) == {"path", "sha256", "size", "mode"}
            and record["path"] == str(PINNED_MUSL_ARCHIVE)
            and isinstance(record["sha256"], str) and len(record["sha256"]) == 64
            and all(character in "0123456789abcdef" for character in record["sha256"])
            and type(record["size"]) is int and record["size"] > 0
            and type(record["mode"]) is int and 0 <= record["mode"] <= 0o777,
            "native oracle archive identity differs")
    return dict(record)


def _physical(path: Path, description: str, *, directory: bool = False) -> Path:
    try:
        value = Path(os.path.abspath(path))
        metadata = value.lstat()
        require(not value.is_symlink(), f"{description} is a symlink: {path}")
        require(stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode),
                f"{description} has the wrong type: {path}")
        current = Path(value.anchor)
        for part in value.parts[1:]:
            current /= part
            require(not current.is_symlink(), f"{description} traverses a symlink: {path}")
        return value
    except OSError as error:
        raise ProtocolDatabaseError(f"cannot read {description}: {path}") from error


def _below_work(path: Path, description: str, *, directory: bool) -> Path:
    value = _physical(path, description, directory=directory)
    require(value.is_relative_to(ROOT / ".work"), f"{description} must be below checkout .work")
    return value


def _verifier_scratch_root(root: Path) -> Path:
    path = root / ".work/x86_64/tmp"
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise ProtocolDatabaseError(f"cannot prepare protocol verifier scratch: {error}") from error
    return _physical(path, "protocol verifier scratch", directory=True)


def artifact(root: Path, path: Path) -> dict[str, object]:
    path = _physical(path, "receipt artifact")
    require(path.is_relative_to(root), f"receipt artifact escapes checkout: {path}")
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256(path.read_bytes()).hexdigest(),
        "byte_length": path.stat().st_size,
        "mode": stat.S_IMODE(path.stat().st_mode),
    }


def fixture_module() -> Any:
    source = _physical(ROOT / PRODUCT_FIXTURE, "resolver product fixture")
    name = f"owned_protocol_database_fixture_{sha256(str(ROOT).encode()).hexdigest()[:16]}"
    spec = importlib.util.spec_from_file_location(name, source)
    require(spec is not None and spec.loader is not None, "cannot load resolver product fixture")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except (ImportError, OSError, RuntimeError, ValueError) as error:
        raise ProtocolDatabaseError(f"cannot load resolver product fixture: {error}") from error
    return module


def source_records(root: Path = ROOT) -> dict[str, dict[str, object]]:
    """Return the small source map that defines this fixed-table receipt."""

    return {path.as_posix(): artifact(root, root / path) for path in SOURCE_FILES}


def _run(arguments: Sequence[str | Path], *, cwd: Path, timeout: float, description: str) -> tuple[int, bytes, bytes]:
    try:
        result = subprocess.run([str(argument) for argument in arguments], cwd=cwd,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                check=False, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise ProtocolDatabaseError(f"{description} timed out") from error
    except OSError as error:
        raise ProtocolDatabaseError(f"cannot execute {description}: {error}") from error
    if result.returncode != 0:
        raise ProtocolDatabaseError(
            f"{description} failed ({result.returncode}): {result.stderr.decode(errors='replace')}"
        )
    return result.returncode, result.stdout, result.stderr


def _write_new(path: Path, value: bytes) -> None:
    require(not path.exists() and not path.is_symlink(), f"receipt output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)


def _write_json(path: Path, value: object) -> None:
    _write_new(path, json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode("utf-8") + b"\n")


def _readelf(path: Path, *, dynamic: bool, destination: Path, timeout: float) -> bytes:
    arguments = ("readelf", "--wide", "--dyn-syms" if dynamic else "--syms", str(path))
    _status, stdout, stderr = _run(arguments, cwd=ROOT, timeout=timeout, description="protocol provider symbol audit")
    require(not stderr, "protocol provider symbol audit wrote stderr")
    _write_new(destination, stdout)
    return stdout


def provider_rows(raw: bytes, description: str, *, binding: str = "GLOBAL") -> dict[str, list[list[str]]]:
    require(binding in {"GLOBAL", "LOCAL"}, f"{description} has an invalid expected provider binding")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ProtocolDatabaseError(f"{description} is not UTF-8") from error
    found: dict[str, list[list[str]]] = {name: [] for name in PROVIDERS}
    for line in lines:
        fields = line.split()
        if len(fields) == 8 and fields[7] in found:
            found[fields[7]].append(fields)
    for name, rows in found.items():
        require(rows, f"{description} lacks {name}")
        require(all(row[3:6] == ["FUNC", binding, "DEFAULT"] and row[6] != "UND" for row in rows),
                f"{description} has an invalid provider binding for {name}")
    return found


def _archive_functions(archive: Path, names: Sequence[str], description: str
                       ) -> dict[str, tuple[str, bytes, dict[str, object]]]:
    definitions: dict[str, list[tuple[str, bytes, dict[str, object]]]] = {name: [] for name in names}
    try:
        for member, body in archive_members(archive.read_bytes()):
            source = elf_bytes(body)
            found: dict[str, dict[str, object]] = {}
            for index, table in enumerate(source.sections):
                if table[1] != 2:
                    continue
                require(table[9] == 24 and table[5] % 24 == 0,
                        f"{description} has an invalid ELF symbol table")
                for number in range(table[5] // 24):
                    row = source.symbol_row(index, number)
                    if row["name"] in definitions and row["section"]:
                        require(row["name"] not in found,
                                f"{description} repeats a requested function in {member}")
                        found[row["name"]] = row
            for name, row in found.items():
                definitions[name].append((member, body, row))
    except (OSError, StaticLinkAuthorityError, ValueError, UnicodeError) as error:
        raise ProtocolDatabaseError(f"cannot inspect {description}: {error}") from error
    result: dict[str, tuple[str, bytes, dict[str, object]]] = {}
    for name, rows in definitions.items():
        require(len(rows) == 1, f"{description} does not have one archive definition for {name}")
        member, body, row = rows[0]
        require(row["type"] == "FUNC" and row["binding"] == "GLOBAL" and row["visibility"] == "DEFAULT",
                f"{description} archive function differs for {name}")
        result[name] = (member, body, row)
    return result


def _archive_provider_member(archive: Path, description: str) -> tuple[str, bytes]:
    definitions = _archive_functions(archive, PROVIDERS, description)
    owners = {definitions[name][0] for name in PROVIDERS}
    require(len(owners) == 1, f"{description} protocol providers have different archive owners")
    member = next(iter(owners))
    body = definitions[PROVIDERS[0]][1]
    require(all(definitions[name][1] == body for name in PROVIDERS),
            f"{description} protocol providers have different source bytes")
    return member, body


def _static_provider_contracts(owner: str) -> list[StaticFunctionContract]:
    return [StaticFunctionContract(name, owner, "GLOBAL", "DEFAULT", "LOCAL", "DEFAULT")
            for name in PROVIDERS]


def _oracle_static_contracts(owners: Mapping[str, str]) -> list[StaticFunctionContract]:
    return [StaticFunctionContract(name, owners[name], "GLOBAL", "DEFAULT", "LOCAL", "DEFAULT")
            for name in (*PROVIDERS, *ORACLE_PROTO_IMPORTS)]


def normalize_pinned_musl_link_trace(raw: bytes, archive: Path) -> bytes:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ProtocolDatabaseError("pinned musl link trace is not UTF-8") from error
    require(lines and all(line.startswith("trace: ") for line in lines),
            "pinned musl link trace format differs")
    repeated = {f"trace: {archive}({member})": 2 for member in ("clone.lo", "free.lo", "realloc.lo")}
    counts = Counter(lines)
    require(all(counts[line] == expected_count for line, expected_count in repeated.items())
            and all(count == 1 or repeated.get(line) == count for line, count in counts.items()),
            "pinned musl link trace repeats an unexpected input")
    return ("\n".join(dict.fromkeys(lines)) + "\n").encode("utf-8")


def _oracle_provider_map(map_path: Path, owners: Mapping[str, str]) -> bytes:
    try:
        lines = map_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise ProtocolDatabaseError(f"cannot read pinned musl link map: {error}") from error
    require(lines and lines[0].split() in (
        ["VMA", "Size", "Align", "Out", "In", "Symbol"],
        ["VMA", "LMA", "Size", "Align", "Out", "In", "Symbol"],
    ), "pinned musl link map format differs")
    selected_indices: set[int] = set()
    for owner in set(owners.values()):
        owner_rows = [index for index, line in enumerate(lines[1:], start=1)
                      if line.split() and line.split()[-1].startswith(owner + ":(")
                      and line.split()[-1].endswith(")")]
        require(owner_rows, f"pinned musl link map lacks selected input owner {owner}")
        for index in owner_rows:
            selected_indices.add(index)
            for following in range(index + 1, len(lines)):
                fields = lines[following].split()
                if not fields:
                    continue
                name = fields[-1]
                if name.startswith(".") or ":(" in name and name.endswith(")"):
                    break
                selected_indices.add(following)
    for name, owner in owners.items():
        input_row = f"{owner}:(.text.{name})"
        matches = [index for index, line in enumerate(lines[1:], start=1)
                   if line.split() and line.split()[-1] == input_row]
        require(len(matches) == 1, f"pinned musl link map does not select one {name} input")
        index = matches[0]
        require(index + 1 < len(lines) and lines[index + 1].split()
                and lines[index + 1].split()[-1] == name,
                f"pinned musl link map does not bind {name} to its selected input")
        require(index in selected_indices and index + 1 in selected_indices,
                f"pinned musl link map omits the selected {name} rows")
    selected = [lines[0], *(lines[index] for index in sorted(selected_indices))]
    return ("\n".join(selected) + "\n").encode("utf-8")


def _audit_oracle_trace_inputs(trace_path: Path, archive: Path, workload: Path,
                               compiler_root: Path) -> None:
    try:
        raw = trace_path.read_bytes()
        normalized = normalize_pinned_musl_link_trace(raw, archive)
        lines = normalized.decode("utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise ProtocolDatabaseError(f"cannot inspect pinned musl link trace: {error}") from error
    direct_names = [line.removeprefix("trace: ") for line in lines if "(" not in line]
    compiler_crts = [Path(name) for name in direct_names
                     if Path(name).name in {"crtbeginS.o", "crtendS.o"}]
    require(len(compiler_crts) == 2 and {path.name for path in compiler_crts} ==
            {"crtbeginS.o", "crtendS.o"}, "pinned musl link trace compiler CRT inputs differ")
    require(compiler_crts[0].parent == compiler_root == compiler_crts[1].parent,
            "pinned musl link trace compiler CRT root differs")
    direct_paths = (workload, archive.parent / "Scrt1.o", archive.parent / "crti.o",
                    archive.parent / "crtn.o", *compiler_crts)
    require(set(direct_names) == {str(path) for path in direct_paths}
            and len(direct_names) == len(direct_paths), "pinned musl link trace direct inputs differ")
    direct = {str(_physical(path, "pinned musl direct link input")): path for path in direct_paths}
    archives = (archive, archive.parent / "libssp_nonshared.a", compiler_root / "libgcc.a",
                compiler_root / "libgcc_eh.a")
    archive_members_by_path: dict[str, set[str]] = {}
    for path in archives:
        selected = _physical(path, "pinned musl static link archive")
        try:
            members = list(archive_members(selected.read_bytes()))
        except (OSError, ValueError, UnicodeError) as error:
            raise ProtocolDatabaseError(f"cannot inspect pinned musl static archive: {error}") from error
        counts = Counter(name for name, _body in members)
        repeats = {name: count for name, count in counts.items() if count > 1}
        expected = {"clone.lo": 2, "free.lo": 2, "realloc.lo": 2} if selected == archive else {}
        require(repeats == expected, f"pinned musl static archive member roster differs: {selected}")
        archive_members_by_path[str(selected)] = set(counts)
    for line in lines:
        selected = line.removeprefix("trace: ")
        if selected in direct:
            continue
        owners = [path for path in archive_members_by_path
                  if selected.startswith(path + "(") and selected.endswith(")")]
        require(len(owners) == 1, "pinned musl link trace names an unowned input")
        member = selected[len(owners[0]) + 1:-1]
        require(member in archive_members_by_path[owners[0]],
                "pinned musl link trace names a missing archive member")


def oracle_static_provider_authority(archive: Path, workload: Path, executable: Path, map_path: Path,
                                    trace_path: Path) -> str:
    sources = _archive_functions(archive, (*PROVIDERS, *ORACLE_PROTO_IMPORTS), "pinned musl protocol archive")
    member = sources[PROVIDERS[0]][0]
    require(member == "proto.lo", "pinned musl protocol providers are not owned by proto.lo")
    owners = {name: f"{archive}({sources[name][0]})" for name in sources}
    owner = owners[PROVIDERS[0]]
    try:
        trace = trace_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise ProtocolDatabaseError(f"cannot read pinned musl link trace: {error}") from error
    require(trace and all(line.startswith("trace: ") for line in trace)
            and all(trace.count(f"trace: {owners[name]}") == 1 for name in owners),
            "pinned musl link trace does not select proto.lo exactly once")
    try:
        direct_names = [line.removeprefix("trace: ") for line in trace if "(" not in line]
        compiler_crts = [Path(name) for name in direct_names
                         if Path(name).name in {"crtbeginS.o", "crtendS.o"}]
        require(len(compiler_crts) == 2 and compiler_crts[0].parent == compiler_crts[1].parent,
                "pinned musl link trace compiler CRT root differs")
        compiler_root = compiler_crts[0].parent
        compiler_base = Path("/usr/lib/gcc/x86_64-alpine-linux-musl")
        require(compiler_root.parent == compiler_base
                and re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", compiler_root.name) is not None,
                "pinned musl link trace compiler CRT root differs")
        _audit_oracle_trace_inputs(trace_path, archive, workload, compiler_root)
        selected_map = _oracle_provider_map(map_path, owners)
        with tempfile.TemporaryDirectory(prefix="oracle-static-inputs.", dir=_verifier_scratch_root(ROOT)) as scratch:
            selected_map_path = Path(scratch) / "map"
            selected_map_path.write_bytes(selected_map)
            admitted = {owners[name]: sources[name][1] for name in sources}
            contracts = _oracle_static_contracts(owners)
            require_static_functions(selected_map_path, executable, admitted, contracts)
    except StaticLinkAuthorityError as error:
        raise ProtocolDatabaseError(f"pinned musl static provider authority differs: {error}") from error
    return owner


def product_static_provider_authority(static_root: Path, workload: Path, executable: Path,
                                      mode: str, map_path: Path, trace_path: Path) -> str:
    library = static_root / "usr/lib"
    archive = _physical(library / "libc.a", "static product libc archive")
    builtins = _physical(library / "libcrabc-builtins.a", "static product builtins archive")
    crt = "crt1.o" if mode == "static-et-exec" else "rcrt1.o"
    require(mode in {"static-et-exec", "static-pie"}, "static protocol provider mode differs")
    direct_paths = (workload, library / crt, library / "crti.o", library / "crtn.o")
    direct = {str(path.resolve()): path for path in direct_paths}
    try:
        admitted = admit_static_inputs(trace_path, direct, (archive, builtins))
        member, body = _archive_provider_member(archive, "static product libc archive")
        owner = f"{archive}({member})"
        require(owner in admitted and admitted[owner] == body,
                "static product protocol archive member is not selected by the link trace")
        require_static_functions(map_path, executable, admitted, _static_provider_contracts(owner))
    except StaticLinkAuthorityError as error:
        raise ProtocolDatabaseError(f"static product provider authority differs: {error}") from error
    return owner


def _oracle_object(work: Path, timeout: float) -> dict[str, object]:
    _physical(MUSL_CC, "pinned musl compiler")
    # GCC's archive lookup can select Alpine's bootstrap libc.a even when its
    # specs select the source-built musl tree for compilation and linking.
    archive = _physical(PINNED_MUSL_ARCHIVE, "source-built musl 1.2.6 archive")
    expected = pinned_musl_archive_identity(ROOT)
    require(sha256(archive.read_bytes()).hexdigest() == expected["sha256"]
            and archive.stat().st_size == expected["size"]
            and stat.S_IMODE(archive.stat().st_mode) == expected["mode"],
            "source-built musl 1.2.6 archive differs")
    object_file = work / "oracle-proto.lo"
    _status, payload, _stderr = _run(("ar", "p", archive, "proto.lo"), cwd=ROOT, timeout=timeout,
                                     description="pinned musl proto.lo extraction")
    _write_new(object_file, payload)
    symbols = work / "oracle-proto.symbols"
    raw = _readelf(object_file, dynamic=False, destination=symbols, timeout=timeout)
    require(b"proto.c" in raw, "pinned musl proto object no longer identifies proto.c")
    provider_rows(raw, "pinned musl proto object")
    undefined = work / "oracle-proto.undefined"
    _status, raw_undefined, _stderr = _run(("nm", "--undefined-only", "--format=posix", object_file), cwd=ROOT,
                                            timeout=timeout, description="pinned musl proto import audit")
    _write_new(undefined, raw_undefined)
    imports = sorted(line.split()[0] for line in raw_undefined.decode("utf-8").splitlines() if line.split())
    require(imports == list(ORACLE_PROTO_IMPORTS), "pinned musl proto object import surface differs")
    return {
        "archive": artifact(ROOT, archive) if archive.is_relative_to(ROOT) else {
            "path": str(archive), "sha256": sha256(archive.read_bytes()).hexdigest(),
            "byte_length": archive.stat().st_size, "mode": stat.S_IMODE(archive.stat().st_mode),
        },
        "object": artifact(ROOT, object_file),
        "symbols": artifact(ROOT, symbols),
        "undefined": artifact(ROOT, undefined),
    }


def _products(fixture: Any, values: Mapping[str, Path]) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    roots: list[Path] = []
    for arm in ARMS:
        static_root = _below_work(values[f"{arm}-static"], f"{arm} static product", directory=True)
        dynamic_root = _below_work(values[f"{arm}-dynamic"], f"{arm} dynamic product", directory=True)
        fixture.static_manifest(static_root)
        fixture.dynamic_manifest(dynamic_root)
        roots.extend((static_root, dynamic_root))
        result[arm] = {
            "static": {
                "path": static_root.relative_to(ROOT).as_posix(),
                "manifest": artifact(ROOT, static_root / "share/crabc/manifest.json"),
                "payload_tree": _cross_arm_tree_identity(static_root),
                "physical_tree": fixture.receipt_tree_identity(static_root),
            },
            "dynamic": {
                "path": dynamic_root.relative_to(ROOT).as_posix(),
                "manifest": artifact(ROOT, dynamic_root / "share/crabc/manifest.json"),
                "payload_tree": _cross_arm_tree_identity(dynamic_root),
                "physical_tree": fixture.receipt_tree_identity(dynamic_root),
            },
        }
    require(len({(path.stat().st_dev, path.stat().st_ino) for path in roots}) == len(roots),
            "protocol products must use six distinct physical roots")
    for kind in ("static", "dynamic"):
        identities = [result[arm][kind]["payload_tree"] for arm in ARMS]
        require(identities[0] == identities[1] == identities[2],
                f"installed, reproduction, and extracted {kind} products differ")
    return result


def _cross_arm_tree_identity(root: Path) -> dict[str, object]:
    """Compare packaged product trees without inheriting directory setgid state.

    The dynamic package contains only regular payloads and its one approved
    alias; extraction creates parent directories locally.  A checkout's
    setgid work directory can therefore add the directory setgid bit to an
    extracted header subtree without changing the package.  Compare every
    regular-file mode and byte, all alias modes and targets, and each
    directory's access bits.  Only the inherited directory setgid bit is
    normalized.  ``physical_tree`` above remains the exact per-root seal.
    """

    root = _physical(root, "cross-arm product root", directory=True)
    records: list[dict[str, object]] = [{
        "path": ".",
        "kind": "directory",
        "mode": stat.S_IMODE(root.lstat().st_mode) & ~stat.S_ISGID,
    }]
    for entry in sorted(root.rglob("*")):
        relative = entry.relative_to(root).as_posix()
        mode = entry.lstat().st_mode
        permissions = stat.S_IMODE(mode)
        if stat.S_ISLNK(mode):
            records.append({"path": relative, "kind": "symlink", "mode": permissions,
                            "target": os.readlink(entry)})
        elif stat.S_ISDIR(mode):
            records.append({"path": relative, "kind": "directory", "mode": permissions & ~stat.S_ISGID})
        elif stat.S_ISREG(mode):
            records.append({"path": relative, "kind": "regular", "mode": permissions,
                            "sha256": sha256(entry.read_bytes()).hexdigest()})
        else:
            raise ProtocolDatabaseError(f"cross-arm product has an unsafe entry: {relative}")
    encoded = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {"entry_count": len(records), "sha256": sha256(encoded).hexdigest()}


def _compile(work: Path, timeout: float) -> tuple[Path, dict[str, object]]:
    source = _physical(ROOT / PROBE, "fixed-table protocol probe")
    output = work / "workload.o"
    _run((MUSL_CC, "-std=c11", "-fno-builtin", "-fno-stack-protector", "-I", ROOT / "include",
          "-c", source, "-o", output), cwd=ROOT, timeout=timeout,
         description="fixed-table protocol workload compilation")
    return output, artifact(ROOT, output)


def _link_oracle(work: Path, object_file: Path, timeout: float) -> Path:
    output = work / "oracle"
    map_path, trace_path = work / "oracle.map", work / "oracle.trace"
    _status, trace, _stderr = _run(
        (MUSL_CC, "-static", "-fno-pie", "-no-pie", "-Wl,-Map," + str(map_path), "-Wl,--trace",
         object_file, "-o", output),
        cwd=ROOT, timeout=timeout, description="pinned musl fixed-table oracle link")
    require(trace.startswith(b"trace: "), "pinned musl fixed-table oracle link lacks a linker trace")
    _write_new(trace_path, trace)
    return output


def _link_candidates(fixture: Any, work: Path, roots: Mapping[str, Path], object_file: Path,
                     timeout: float) -> tuple[dict[str, dict[str, dict[str, object]]], dict[str, Path]]:
    artifacts: dict[str, dict[str, dict[str, object]]] = {}
    binaries: dict[str, Path] = {}
    for arm in ARMS:
        static_root, dynamic_root = roots[f"{arm}-static"], roots[f"{arm}-dynamic"]
        per_arm: dict[str, dict[str, object]] = {}
        static_driver = _physical(static_root / "bin/crabc-cc", f"{arm} static driver")
        for mode, option, elf_mode in (("static-et-exec", "--static-et-exec", "static"),
                                       ("static-pie", "--static-pie", "static-pie")):
            directory = work / "artifacts" / arm / mode
            directory.mkdir(parents=True)
            output, receipt = directory / "workload", directory / "link.receipt.json"
            _run((static_driver, option, "--link-receipt", receipt.name, object_file, "-o", output), cwd=directory,
                 timeout=timeout, description=f"{arm} {mode} link")
            per_arm[mode] = {
                "binary": artifact(ROOT, output),
                "receipt": fixture.static_receipt_audit(static_root, option, object_file, output, receipt),
                "elf": fixture.elf_audit(output, mode=elf_mode, dynamic=False),
            }
            binaries[f"{arm}-{mode}"] = output
        dynamic_driver = _physical(dynamic_root / "bin/crabc-cc-dynamic", f"{arm} dynamic driver")
        for mode, option, elf_mode in (("dynamic-pie", "--dynamic-pie", "dynamic-pie"),
                                       ("dynamic-non-pie", "--dynamic-non-pie", "dynamic-non-pie")):
            directory = work / "artifacts" / arm / mode
            directory.mkdir(parents=True)
            output = directory / "workload"
            _run((dynamic_driver, option, object_file, "-o", output), cwd=directory, timeout=timeout,
                 description=f"{arm} {mode} link")
            receipt = Path(str(output) + ".crabc-link.json")
            per_arm[mode] = {
                "binary": artifact(ROOT, output),
                "receipt": fixture.dynamic_receipt_audit(dynamic_root, option, object_file, output, receipt),
                "elf": fixture.elf_audit(output, mode=elf_mode, dynamic=True),
            }
            binaries[f"{arm}-{mode}"] = output
        artifacts[arm] = per_arm
    return artifacts, binaries


def _poison_protocols(root: Path) -> dict[str, object]:
    path = root / "etc/protocols"
    _write_new(path, POISON_PROTOCOLS)
    path.chmod(0o644)
    return artifact(ROOT, path)


def _chroots(fixture: Any, work: Path, roots: Mapping[str, Path], oracle: Path,
             binaries: Mapping[str, Path]) -> tuple[dict[str, dict[str, object]], dict[str, Path]]:
    layouts: dict[str, dict[str, object]] = {}
    execution_roots: dict[str, Path] = {}
    (work / "chroots").mkdir()
    root = work / "chroots" / "oracle"
    fixture.static_chroot(oracle, root)
    layouts["oracle"] = {"root": root.relative_to(ROOT).as_posix(), "protocols": _poison_protocols(root),
                          "tree": fixture.receipt_tree_identity(root)}
    execution_roots["oracle"] = root
    for arm in ARMS:
        for mode in ("static-et-exec", "static-pie"):
            label, root = f"{arm}-{mode}", work / "chroots" / f"{arm}-{mode}"
            fixture.static_chroot(binaries[label], root)
            layouts[label] = {"root": root.relative_to(ROOT).as_posix(), "protocols": _poison_protocols(root),
                              "tree": fixture.receipt_tree_identity(root)}
            execution_roots[label] = root
        for mode in ("dynamic-pie", "dynamic-non-pie"):
            label, root = f"{arm}-{mode}", work / "chroots" / f"{arm}-{mode}"
            fixture.dynamic_chroot(binaries[label], roots[f"{arm}-dynamic"], root)
            layouts[label] = {"root": root.relative_to(ROOT).as_posix(), "protocols": _poison_protocols(root),
                              "tree": fixture.receipt_tree_identity(root)}
            execution_roots[label] = root
    return layouts, execution_roots


def expected_executions() -> dict[str, tuple[str, list[str]]]:
    result = {"oracle": ("oracle", ["/workload"])}
    for arm in ARMS:
        result[f"{arm}-static-et-exec"] = (f"{arm}-static-et-exec", ["/workload"])
        result[f"{arm}-static-pie"] = (f"{arm}-static-pie", ["/workload"])
        result[f"{arm}-dynamic-pie-kernel"] = (f"{arm}-dynamic-pie", ["/workload"])
        result[f"{arm}-dynamic-pie-direct"] = (f"{arm}-dynamic-pie", ["/lib/ld-crabc-x86_64.so.1", "/workload"])
        result[f"{arm}-dynamic-non-pie-kernel"] = (f"{arm}-dynamic-non-pie", ["/workload"])
        result[f"{arm}-dynamic-non-pie-direct"] = (f"{arm}-dynamic-non-pie", ["/lib/ld-crabc-x86_64.so.1", "/workload"])
    return result


def _executions(fixture: Any, work: Path, roots: Mapping[str, Path], timeout: float) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for label, (root_label, argv) in expected_executions().items():
        status, stdout, stderr = fixture.run_chroot_raw(roots[root_label], argv, timeout)
        require(status == 0 and stdout == b"" and stderr == b"", f"{label} fixed-table probe differs")
        directory = work / "raw" / label
        directory.mkdir(parents=True)
        argv_path, status_path = directory / "argv.json", directory / "status"
        stdout_path, stderr_path = directory / "stdout", directory / "stderr"
        _write_new(argv_path, json.dumps(argv, separators=(",", ":")).encode("utf-8") + b"\n")
        _write_new(status_path, f"{status}\n".encode("ascii"))
        _write_new(stdout_path, stdout)
        _write_new(stderr_path, stderr)
        result[label] = {"root": root_label, "argv": artifact(ROOT, argv_path), "status": artifact(ROOT, status_path),
                         "stdout": artifact(ROOT, stdout_path), "stderr": artifact(ROOT, stderr_path)}
    return result


def _provider_audits(work: Path, oracle: Path, binaries: Mapping[str, Path], roots: Mapping[str, Path],
                     object_file: Path, timeout: float) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    targets: dict[str, tuple[Path, bool]] = {"oracle": (oracle, False)}
    for arm in ARMS:
        targets[f"{arm}-static-et-exec"] = (binaries[f"{arm}-static-et-exec"], False)
        targets[f"{arm}-static-pie"] = (binaries[f"{arm}-static-pie"], False)
        targets[f"{arm}-dynamic-provider"] = (roots[f"{arm}-dynamic"] / "usr/lib/libc.so", True)
    for label, (binary, dynamic) in targets.items():
        raw = _readelf(binary, dynamic=dynamic, destination=work / "providers" / f"{label}.symbols", timeout=timeout)
        provider_rows(raw, label, binding="GLOBAL" if dynamic else "LOCAL")
        row = {"binary": artifact(ROOT, binary), "dynamic": dynamic,
               "symbols": artifact(ROOT, work / "providers" / f"{label}.symbols")}
        if label == "oracle":
            map_path, trace_path = work / "oracle.map", work / "oracle.trace"
            oracle_static_provider_authority(PINNED_MUSL_ARCHIVE, object_file, oracle, map_path, trace_path)
            row["link"] = {"map": artifact(ROOT, map_path), "trace": artifact(ROOT, trace_path)}
        elif not dynamic:
            arm, mode = label.split("-", 1)
            static_root = roots[f"{arm}-static"]
            static_map = binary.parent / "link.receipt.map"
            static_trace = binary.parent / "link.receipt.trace"
            product_static_provider_authority(static_root, object_file, binary, mode, static_map, static_trace)
        result[label] = row
    return result


def _fresh_work(path: Path) -> Path:
    absolute = path if path.is_absolute() else ROOT / path
    absolute.mkdir(parents=True, exist_ok=True)
    work = _below_work(absolute, "protocol evidence work directory", directory=True)
    require(not any(work.iterdir()), "protocol evidence work directory must be empty")
    return work


def run(args: argparse.Namespace) -> Path:
    work = _fresh_work(args.work)
    fixture = fixture_module()
    roots = {
        f"{arm}-{kind}": getattr(args, f"{arm}_{kind}_sysroot")
        for arm in ARMS for kind in ("static", "dynamic")
    }
    source_before = source_records()
    products_before = _products(fixture, roots)
    oracle_object = _oracle_object(work, args.timeout)
    object_file, workload = _compile(work, args.timeout)
    oracle = _link_oracle(work, object_file, args.timeout)
    candidates, binaries = _link_candidates(fixture, work, roots, object_file, args.timeout)
    layouts, execution_roots = _chroots(fixture, work, roots, oracle, binaries)
    executions = _executions(fixture, work, execution_roots, args.timeout)
    providers = _provider_audits(work, oracle, binaries, roots, object_file, args.timeout)
    source_after, products_after = source_records(), _products(fixture, roots)
    require(source_before == source_after, "protocol receipt source changed during execution")
    require(products_before == products_after, "protocol receipt product changed during execution")
    report = {
        "schema": SCHEMA,
        "component": COMPONENT,
        "oracle": oracle_object,
        "source": {"before": source_before, "after": source_after},
        "products": {"before": products_before, "after": products_after},
        "workload": workload,
        "oracle_binary": artifact(ROOT, oracle),
        "candidates": candidates,
        "providers": providers,
        "isolation": layouts,
        "executions": executions,
        "entry_modes": list(ENTRY_MODES),
        "family_completion": False,
        "promotion_ready": False,
        "public_support": False,
    }
    output = work / "owned-protocol-database-products.json"
    _write_json(output, report)
    output.chmod(0o444)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", required=True, type=Path)
    for arm in ARMS:
        parser.add_argument(f"--{arm}-static-sysroot", required=True, type=Path)
        parser.add_argument(f"--{arm}-dynamic-sysroot", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    if args.timeout <= 0 or args.timeout > 120:
        parser.error("--timeout must be > 0 and <= 120")
    try:
        output = run(args)
    except ProtocolDatabaseError as error:
        print(f"owned protocol database: ERROR: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"report": output.relative_to(ROOT).as_posix(), "passed": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
