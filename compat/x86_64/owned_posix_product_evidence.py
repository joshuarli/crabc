#!/usr/bin/env python3
"""Validate one sealed link against its current owned x86 product.

The static and dynamic drivers deliberately write different receipt schemas.
This module is the narrow common consumer for POSIX evidence: it binds one
already-compiled workload object, one output, and one receipt to the current
physical product tree.  It does not build, run, or qualify a runtime.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
from typing import Any, Mapping

import owned_dynamic_receipt as receipt_contract


TARGET = "x86_64-unknown-linux-musl"
STATIC_FORMAT = "crabc-x86-64-sealed-static-driver-v1"
STATIC_PRODUCT_FORMAT = "crabc-x86-64-owned-static-sysroot-v1"
DYNAMIC_PRODUCT_FORMAT = "crabc-x86-64-owned-dynamic-sysroot-v1"
INTERPRETER = "/lib/ld-crabc-x86_64.so.1"
STATIC_DRIVER_STATUS = "planned-owned-static-product-seed-not-family-completion-not-public-support"
STATIC_CRT_OBJECTS = ("crt1.o", "Scrt1.o", "rcrt1.o", "crti.o", "crtn.o")
STATIC_REQUIRED = (
    "bin/crabc-cc",
    "usr/lib/crt1.o",
    "usr/lib/Scrt1.o",
    "usr/lib/rcrt1.o",
    "usr/lib/crti.o",
    "usr/lib/crtn.o",
    "usr/lib/libc.a",
    "usr/lib/libcrabc-builtins.a",
)
DYNAMIC_REQUIRED = (
    "bin/crabc-cc-dynamic",
    "share/crabc/crabc_cc_static.py",
    "share/crabc/owned_dynamic_receipt.py",
    "lib/ld-crabc-x86_64.so.1",
    "usr/lib/crt1.o",
    "usr/lib/Scrt1.o",
    "usr/lib/crti.o",
    "usr/lib/crtn.o",
    "usr/lib/crabc-dynamic-attach.o",
    "usr/lib/libc.so",
    "usr/lib/libcrabc-builtins.a",
)
LINKAGES = {
    "static": {"receipt_mode": "static-et-exec", "elf_type": "ET_EXEC", "readelf_type": "EXEC", "crt": "crt1.o"},
    "static-pie": {"receipt_mode": "static-pie", "elf_type": "ET_DYN", "readelf_type": "DYN", "crt": "rcrt1.o"},
    "pie": {"receipt_mode": "pie", "readelf_type": "DYN", "crt": "Scrt1.o"},
    "non-pie": {"receipt_mode": "exec", "readelf_type": "EXEC", "crt": "crt1.o"},
}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class ProductEvidenceError(RuntimeError):
    """A product, receipt, or inspected ELF cannot prove this one link."""


def _fail(message: str) -> None:
    raise ProductEvidenceError(message)


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(path))


def _reject_symlink_components(path: Path, description: str) -> Path:
    """Return an absolute existing path only after checking lexical ancestry."""

    if ".." in path.parts:
        _fail(f"{description} has lexical parent traversal: {path}")
    absolute = _absolute(path)
    current = Path(absolute.anchor)
    try:
        for component in absolute.parts[1:]:
            current /= component
            if stat.S_ISLNK(current.lstat().st_mode):
                _fail(f"{description} traverses a symlink: {path}")
    except OSError as error:
        raise ProductEvidenceError(f"{description} is unreadable: {path}") from error
    return absolute


def _physical_directory(path: Path, description: str) -> Path:
    absolute = _reject_symlink_components(path, description)
    try:
        if not stat.S_ISDIR(absolute.lstat().st_mode):
            _fail(f"{description} is not a physical directory: {path}")
    except OSError as error:
        raise ProductEvidenceError(f"{description} is unreadable: {path}") from error
    return absolute


def _physical_regular(path: Path, description: str) -> Path:
    absolute = _reject_symlink_components(path, description)
    try:
        if not stat.S_ISREG(absolute.lstat().st_mode):
            _fail(f"{description} is not a physical regular file: {path}")
    except OSError as error:
        raise ProductEvidenceError(f"{description} is unreadable: {path}") from error
    return absolute


def _physical_executable(path: Path, description: str) -> Path:
    """Require a physical regular executable, never merely named link input."""

    absolute = _physical_regular(path, description)
    try:
        if not absolute.lstat().st_mode & 0o111:
            _fail(f"{description} is not executable: {path}")
    except OSError as error:
        raise ProductEvidenceError(f"{description} is unreadable: {path}") from error
    return absolute


def _sha256(path: Path) -> str:
    path = _physical_regular(path, "hashed artifact")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise ProductEvidenceError(f"cannot hash artifact: {path}") from error
    return digest.hexdigest()


def retained_elf_facts(path: Path) -> dict[str, object]:
    """Read the bounded ELF facts needed by command-free host replay.

    Native collection keeps its established ``readelf`` checks. A host cannot
    re-authorize a receipt by executing an ambient inspector, so retained-link
    replay parses the rehashed physical ELF bytes directly instead.
    """
    path = _physical_regular(path, "retained ELF artifact")
    try:
        data = path.read_bytes()
    except OSError as error:
        raise ProductEvidenceError(f"retained ELF artifact is unreadable: {path}") from error

    def part(offset: int, size: int) -> bytes:
        if type(offset) is not int or type(size) is not int or not (0 <= offset <= len(data) and 0 <= size <= len(data) - offset):
            _fail("retained ELF table escapes physical bytes")
        return data[offset:offset + size]

    def unpack(shape: str, offset: int) -> tuple[object, ...]:
        return struct.unpack(shape, part(offset, struct.calcsize(shape)))

    if part(0, 7) != b"\x7fELF\x02\x01\x01":
        _fail("retained ELF is not ELF64 little-endian")
    kind, machine, version, _entry, phoff, shoff, _flags, ehsize, phsize, phnum, shsize, shnum, _shstrndx = unpack(
        "<HHIQQQIHHHHHH", 16
    )
    if machine != 62 or version != 1 or ehsize != 64 or (phnum and phsize != 56) or (shnum and shsize != 64):
        _fail("retained ELF architecture or header contract differs")
    if kind not in (2, 3) or phnum >= 65536 or shnum >= 65536:
        _fail("retained ELF type or table count differs")

    def cstring(blob: bytes, offset: int) -> str:
        if not 0 <= offset < len(blob) or b"\0" not in blob[offset:]:
            _fail("retained ELF string lacks a terminator")
        try:
            return blob[offset:blob.index(b"\0", offset)].decode("ascii")
        except UnicodeDecodeError as error:
            raise ProductEvidenceError("retained ELF string is not ASCII") from error

    interpreters: list[str] = []
    for index in range(phnum):
        program = unpack("<IIQQQQQQ", phoff + index * phsize)
        ptype, _program_flags, offset, _vaddr, _paddr, size, _memsize, _align = program
        if ptype == 3:
            value = part(offset, size)
            if not value.endswith(b"\0") or value.count(b"\0") != 1:
                _fail("retained ELF interpreter is malformed")
            try:
                interpreters.append(value[:-1].decode("ascii"))
            except UnicodeDecodeError as error:
                raise ProductEvidenceError("retained ELF interpreter is not ASCII") from error

    sections = [unpack("<IIQQQQIIQQ", shoff + index * shsize) for index in range(shnum)]
    needed: list[str] = []
    runpaths: list[str] = []
    rpaths: list[str] = []
    sonames: list[str] = []
    textrel = False
    for section in sections:
        _name, section_type, _section_flags, _address, offset, size, link, _info, _alignment, entry = section
        if section_type != 6:
            continue
        if link >= len(sections) or sections[link][1] != 3 or entry != 16 or size % entry:
            _fail("retained ELF dynamic table differs")
        string_offset, string_size = sections[link][4], sections[link][5]
        strings = part(string_offset, string_size)
        saw_null = False
        for position in range(offset, offset + size, entry):
            tag, value = unpack("<qQ", position)
            if tag == 0:
                saw_null = True
                continue
            if tag == 22:
                textrel = True
            elif tag in (1, 14, 15, 29):
                name = cstring(strings, value)
                {1: needed, 14: sonames, 15: rpaths, 29: runpaths}[tag].append(name)
        if not saw_null:
            _fail("retained ELF dynamic table has no terminator")
    return {
        "type": kind,
        "machine": machine,
        "interpreters": interpreters,
        "needed": needed,
        "runpaths": runpaths,
        "rpaths": rpaths,
        "sonames": sonames,
        "textrel": textrel,
    }


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _json_object(path: Path, description: str) -> dict[str, Any]:
    path = _physical_regular(path, description)
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_object)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise ProductEvidenceError(f"{description} is not valid JSON: {path}") from error
    if not isinstance(value, dict):
        _fail(f"{description} must be a JSON object")
    # Python considers True == 1. JSON schema versions admit integers only;
    # a boolean must not pass the sealed product/receipt identity checks.
    if type(value.get("schema")) is not int:
        _fail(f"{description} schema must be an integer version")
    return value


def _require_keys(value: object, expected: set[str], description: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        _fail(f"{description} fields drifted")
    return value


def _require_digest(value: object, actual: str, description: str) -> None:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        _fail(f"{description} has an invalid SHA-256")
    if value != actual:
        _fail(f"{description} hash differs from the physical artifact")


def _relative_payload_path(value: object, description: str) -> str:
    if not isinstance(value, str):
        _fail(f"{description} has a non-string path")
    candidate = Path(value)
    if candidate.is_absolute() or not candidate.parts or any(part in {"", ".", ".."} for part in candidate.parts):
        _fail(f"{description} has an unsafe payload path: {value}")
    return value


def _payload_files(value: object, description: str) -> dict[str, str]:
    if not isinstance(value, dict) or not value:
        _fail(f"{description} has no payload hashes")
    result: dict[str, str] = {}
    for relative, digest in value.items():
        relative = _relative_payload_path(relative, description)
        if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
            _fail(f"{description} has an invalid payload hash: {relative}")
        result[relative] = digest
    return result


def _validate_payload_tree(root: Path, files: Mapping[str, str], *, aliases: Mapping[str, str]) -> None:
    observed_files: set[str] = set()
    observed_aliases: dict[str, str] = {}
    try:
        entries = sorted(root.rglob("*"))
    except OSError as error:
        raise ProductEvidenceError(f"cannot enumerate product payload: {root}") from error
    for entry in entries:
        relative = entry.relative_to(root).as_posix()
        try:
            mode = entry.lstat().st_mode
        except OSError as error:
            raise ProductEvidenceError(f"cannot inspect product payload: {entry}") from error
        if stat.S_ISLNK(mode):
            try:
                observed_aliases[relative] = os.readlink(entry)
            except OSError as error:
                raise ProductEvidenceError(f"cannot read product alias: {entry}") from error
        elif stat.S_ISDIR(mode):
            continue
        elif stat.S_ISREG(mode):
            if relative != "share/crabc/manifest.json":
                observed_files.add(relative)
        else:
            _fail(f"product payload has a non-regular entry: {relative}")
    if observed_files != set(files):
        _fail("product payload roster differs from its manifest")
    if observed_aliases != dict(aliases):
        _fail("product alias roster differs from its manifest")
    for relative, expected in files.items():
        artifact = _physical_regular(root / relative, f"product payload {relative}")
        _require_digest(expected, _sha256(artifact), f"product payload {relative}")


def _validate_static_product(root: Path) -> tuple[Path, dict[str, str]]:
    manifest_path = _physical_regular(root / "share/crabc/manifest.json", "static product manifest")
    manifest = _json_object(manifest_path, "static product manifest")
    if (manifest.get("schema"), manifest.get("format"), manifest.get("target")) != (1, STATIC_PRODUCT_FORMAT, TARGET):
        _fail("static product manifest has the wrong product identity")
    installed = manifest.get("installed")
    if not isinstance(installed, dict):
        _fail("static product manifest lacks its installed record")
    expected_installed = {
        "headers": "usr/include",
        "crt_objects": [f"usr/lib/{name}" for name in STATIC_CRT_OBJECTS],
        "static_libc": "usr/lib/libc.a",
        "bounded_compiler_helpers": "usr/lib/libcrabc-builtins.a",
        "sealed_static_driver": "bin/crabc-cc",
    }
    if any(installed.get(key) != expected for key, expected in expected_installed.items()):
        _fail("static product installed record drifted")
    driver = manifest.get("sealed_static_driver")
    if not isinstance(driver, dict) or (
        driver.get("format"), driver.get("path"), driver.get("status")
    ) != (STATIC_FORMAT, "bin/crabc-cc", STATIC_DRIVER_STATUS):
        _fail("static product sealed driver record drifted")
    if driver.get("modes") != [
        {"id": "static-et-exec", "elf_type": "ET_EXEC", "crt_object": "crt1.o"},
        {"id": "static-pie", "elf_type": "ET_DYN", "crt_object": "rcrt1.o"},
    ]:
        _fail("static product sealed driver modes drifted")
    files = _payload_files(installed.get("files"), "static product manifest")
    missing = sorted(set(STATIC_REQUIRED) - set(files))
    if missing:
        _fail(f"static product manifest omits required runtime payload: {missing[0]}")
    _physical_executable(root / "bin/crabc-cc", "static product sealed driver")
    _physical_directory(root / "usr/include", "static product headers")
    _validate_payload_tree(root, files, aliases={})
    return manifest_path, files


def _validate_dynamic_product(root: Path) -> tuple[Path, dict[str, str]]:
    manifest_path = _physical_regular(root / "share/crabc/manifest.json", "dynamic product manifest")
    manifest = _json_object(manifest_path, "dynamic product manifest")
    aliases = {"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"}
    if (manifest.get("schema"), manifest.get("format"), manifest.get("target"), manifest.get("symlinks")) != (
        1, DYNAMIC_PRODUCT_FORMAT, TARGET, aliases
    ):
        _fail("dynamic product manifest has the wrong product identity")
    files = _payload_files(manifest.get("files"), "dynamic product manifest")
    missing = sorted(set(DYNAMIC_REQUIRED) - set(files))
    if missing:
        _fail(f"dynamic product manifest omits required runtime payload: {missing[0]}")
    _physical_executable(root / "bin/crabc-cc-dynamic", "dynamic product sealed driver")
    _physical_regular(
        root / "share/crabc/crabc_cc_static.py", "dynamic product shared static helper"
    )
    _physical_directory(root / "usr/include", "dynamic product headers")
    _validate_payload_tree(root, files, aliases=aliases)
    return manifest_path, files


def _recorded_file(value: object, receipt: Path, description: str) -> Path:
    if not isinstance(value, str) or not value:
        _fail(f"{description} has no path")
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = receipt.parent / candidate
    return _physical_regular(candidate, description)


def _check_file_record(value: object, receipt: Path, expected: Path, description: str) -> None:
    record = _require_keys(value, {"path", "sha256"}, description)
    recorded = _recorded_file(record["path"], receipt, description)
    if recorded != expected:
        _fail(f"{description} path differs from this evidence invocation")
    _require_digest(record["sha256"], _sha256(expected), description)


def _check_linker(value: object, receipt: Path) -> str:
    record = _require_keys(value, {"path", "sha256"}, "resolved linker")
    linker = _recorded_file(record["path"], receipt, "resolved linker")
    if linker.name != "ld.lld":
        _fail("resolved linker is not ld.lld")
    _physical_executable(linker, "resolved linker")
    if record["path"] != str(linker):
        _fail("resolved linker path is not physical")
    _require_digest(record["sha256"], _sha256(linker), "resolved linker")
    return str(linker)


def _static_link_plan(root: Path, linkage: str) -> list[str]:
    mode = LINKAGES[linkage]
    library = root / "usr/lib"
    return [
        "ld.lld", "-static", *(["-pie"] if linkage == "static-pie" else []),
        "--no-dynamic-linker", "--no-undefined", "--gc-sections", "-z", "relro", "-z", "now",
        "-e", "_start", str(library / mode["crt"]), str(library / "crti.o"),
        "<application-objects>", str(library / "libc.a"), str(library / "libcrabc-builtins.a"),
        str(library / "crtn.o"), "-o", "<output>",
    ]


def _validate_static_trace(trace: Path, root: Path, workload: Path, linkage: str) -> None:
    mode = LINKAGES[linkage]
    library = root / "usr/lib"
    direct = {
        str(library / mode["crt"]), str(library / "crti.o"), str(workload), str(library / "crtn.o"),
    }
    archives = {str(library / "libc.a"), str(library / "libcrabc-builtins.a")}
    seen: set[str] = set()
    try:
        lines = trace.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise ProductEvidenceError(f"static link trace is unreadable: {trace}") from error
    for line in lines:
        if not line:
            continue
        if line in direct:
            seen.add(line)
            continue
        archive_input = False
        for archive in archives:
            if line == archive or (line.startswith(archive + "(") and line.endswith(")")):
                seen.add(archive)
                archive_input = True
                break
        if archive_input:
            continue
        _fail(f"static link trace names an unowned input: {line}")
    missing = sorted((direct | archives) - seen)
    if missing:
        _fail(f"static link trace omits an owned input: {missing[0]}")


def _validate_static_receipt(
    root: Path, workload: Path, executable: Path, receipt: Path, linkage: str,
) -> str:
    record = _json_object(receipt, "static link receipt")
    expected_keys = {"schema", "format", "target", "mode", "resolved_linker", "owned_link_contract", "input_receipts", "output", "map", "trace"}
    _require_keys(record, expected_keys, "static link receipt")
    mode = LINKAGES[linkage]
    if (record["schema"], record["format"], record["target"]) != (1, STATIC_FORMAT, TARGET):
        _fail("static link receipt has the wrong sealed driver identity")
    if record["mode"] != {
        "id": mode["receipt_mode"], "elf_type": mode["elf_type"], "crt_object": mode["crt"], "interpreter": "absent",
    }:
        _fail("static link receipt mode differs from the requested linkage")
    _check_linker(record["resolved_linker"], receipt)
    if record["owned_link_contract"] != _static_link_plan(root, linkage):
        _fail("static link receipt sealed link contract differs from the current product")
    inputs = record["input_receipts"]
    if not isinstance(inputs, list) or len(inputs) != 6:
        _fail("static link receipt has the wrong input roster")
    library = root / "usr/lib"
    expected_inputs = (
        ("crt-entry", "usr/lib/" + str(mode["crt"]), library / str(mode["crt"])),
        ("crt-prologue", "usr/lib/crti.o", library / "crti.o"),
        ("libc", "usr/lib/libc.a", library / "libc.a"),
        ("builtins", "usr/lib/libcrabc-builtins.a", library / "libcrabc-builtins.a"),
        ("crt-epilogue", "usr/lib/crtn.o", library / "crtn.o"),
        ("application", None, workload),
    )
    for received, (role, relative, path) in zip(inputs, expected_inputs):
        item = _require_keys(received, {"role", "path", "sha256"}, "static input receipt")
        if item["role"] != role:
            _fail("static link receipt input role differs from the sealed roster")
        if relative is not None:
            if item["path"] != relative:
                _fail("static link receipt runtime input path differs from the sealed roster")
        elif _recorded_file(item["path"], receipt, "static workload receipt") != workload:
            _fail("static link receipt workload differs from this evidence invocation")
        _require_digest(item["sha256"], _sha256(path), f"static {role} input")
    _check_file_record(record["output"], receipt, executable, "static output")
    map_path = _physical_regular(receipt.with_suffix(".map"), "static link map")
    trace_path = _physical_regular(receipt.with_suffix(".trace"), "static link trace")
    _check_file_record(record["map"], receipt, map_path, "static link map")
    _check_file_record(record["trace"], receipt, trace_path, "static link trace")
    _validate_static_trace(trace_path, root, workload, linkage)
    return _sha256(receipt)


def _dynamic_link_command(root: Path, workload: Path, executable: Path, linkage: str, linker: str,
                          *, export_dynamic: bool = False) -> list[str]:
    library = root / "usr/lib"
    entry = str(LINKAGES[linkage]["crt"])
    command = [
        linker, *(["-pie"] if linkage == "pie" else []), "--hash-style=sysv", "-z", "relro",
        "-z", "now", "-z", "noexecstack", "-z", "text", "--no-undefined",
        "--allow-shlib-undefined", "--enable-new-dtags", "-rpath", "/usr/lib",
    ]
    if export_dynamic:
        command.append("--export-dynamic")
    command.extend(("--dynamic-linker",
        INTERPRETER, str(library / entry), str(library / "crabc-dynamic-attach.o"),
        str(library / "crti.o"), str(workload), str(library / "libc.so"),
        str(library / "libcrabc-builtins.a"), str(library / "crtn.o"), "-o", str(executable)))
    return command


def _validate_dynamic_trace(value: object, root: Path, workload: Path, linkage: str) -> None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        _fail("dynamic link trace is not a string list")
    library = root / "usr/lib"
    entry = str(library / str(LINKAGES[linkage]["crt"]))
    direct = {
        entry, str(library / "crabc-dynamic-attach.o"), str(library / "crti.o"), str(workload),
        str(library / "libc.so"), str(library / "crtn.o"),
    }
    archive = str(library / "libcrabc-builtins.a")
    seen: set[str] = set()
    for line in value:
        if line in direct:
            seen.add(line)
        elif line == archive or (line.startswith(archive + "(") and line.endswith(")")):
            continue
        else:
            _fail(f"dynamic link trace names an unowned input: {line}")
    if seen != direct:
        _fail("dynamic link trace omits an owned input")


def _validate_dynamic_receipt(
    root: Path, workload: Path, executable: Path, receipt: Path, linkage: str, manifest: Path,
    *, export_dynamic: bool = False,
) -> str:
    record = _json_object(receipt, "dynamic link receipt")
    search = receipt_contract.validate(
        record, format=DYNAMIC_PRODUCT_FORMAT, label="dynamic link receipt", fail=_fail
    )
    mode = LINKAGES[linkage]
    if record["mode"] != mode["receipt_mode"]:
        _fail("dynamic link receipt mode differs from the requested linkage")
    if record["binding"] != "now" or record["runtime_imports"] != [] or record["application_dsos"] != {}:
        _fail("dynamic link receipt admits foreign runtime imports or DSOs")
    receipt_contract.require_runpath(search, "/usr/lib", label="dynamic link receipt", fail=_fail)
    if record["campaign_complete"] is not False:
        _fail("dynamic link receipt search-path or campaign state drifted")
    if record["output_path"] != str(executable):
        _fail("dynamic output path differs from this evidence invocation")
    _require_digest(record["output_sha256"], _sha256(executable), "dynamic output")
    _require_digest(record["manifest_sha256"], _sha256(manifest), "dynamic product manifest")
    library = root / "usr/lib"
    entry = str(mode["crt"])
    runtime = [
        library / "crti.o", library / "libc.so", library / "crtn.o", library / entry,
        library / "crabc-dynamic-attach.o",
    ]
    archive = library / "libcrabc-builtins.a"
    expected_roster = sorted(path.relative_to(root).as_posix() for path in [*runtime, archive])
    if record["owned_runtime_inputs"] != expected_roster:
        _fail("dynamic link receipt owned runtime roster differs from the sealed product")
    inputs = record["input_receipts"]
    expected_inputs = [
        *((path, "runtime") for path in runtime),
        (workload, "workload"),
        (archive, "runtime"),
    ]
    if not isinstance(inputs, list) or len(inputs) != len(expected_inputs):
        _fail("dynamic link receipt has the wrong input roster")
    for received, (expected, role) in zip(inputs, expected_inputs):
        item = _require_keys(received, {"path", "sha256"}, "dynamic input receipt")
        if item["path"] != str(expected):
            _fail("dynamic link receipt input path differs from this evidence invocation")
        _require_digest(item["sha256"], _sha256(expected), f"dynamic {role} input")
    linker = _check_linker(record["resolved_linker"], receipt)
    if record["link_command"] != _dynamic_link_command(
            root, workload, executable, linkage, linker, export_dynamic=export_dynamic):
        _fail("dynamic link command differs from the sealed product contract")
    _validate_dynamic_trace(record["link_trace"], root, workload, linkage)
    return _sha256(receipt)


def _readelf(path: Path) -> dict[str, str]:
    """Capture just the three stable ELF views consumed by the receipt audit."""

    result: dict[str, str] = {}
    for label, option in (("header", "-hW"), ("program", "-lW"), ("dynamic", "-dW")):
        try:
            completed = subprocess.run(
                ["readelf", option, str(path)], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
            )
        except OSError as error:
            raise ProductEvidenceError("readelf could not inspect the linked executable") from error
        if completed.returncode != 0:
            _fail(f"readelf {option} failed for linked executable: {completed.stderr.strip()}")
        result[label] = completed.stdout
    return result


def _audit_elf(executable: Path, linkage: str) -> None:
    inspection = _readelf(executable)
    if set(inspection) != {"header", "program", "dynamic"} or not all(isinstance(value, str) for value in inspection.values()):
        _fail("readelf inspection is incomplete")
    header, program, dynamic = inspection["header"], inspection["program"], inspection["dynamic"]
    mode = LINKAGES[linkage]
    if re.search(r"^\s*Machine:\s+Advanced Micro Devices X86-64\s*$", header, re.MULTILINE) is None:
        _fail("linked executable is not an x86-64 ELF")
    if re.search(rf"^\s*Type:\s+{mode['readelf_type']}(?:\s|\()", header, re.MULTILINE) is None:
        _fail("linked executable ELF type differs from the requested linkage")
    if re.search(r"\bTEXTREL\b", dynamic):
        _fail("linked executable has DT_TEXTREL")
    needed = re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", dynamic)
    if linkage in {"static", "static-pie"}:
        if re.search(r"^\s*INTERP\b", program, re.MULTILINE) is not None:
            _fail("static linked executable has PT_INTERP")
        if needed:
            _fail("static linked executable has DT_NEEDED")
        return
    requested = re.findall(r"Requesting program interpreter:\s*([^\]\n]+)", program)
    if requested != [INTERPRETER]:
        _fail("dynamic linked executable interpreter differs from the owned loader")
    if needed != ["libc.so"]:
        _fail("dynamic linked executable has foreign DT_NEEDED entries")
    if re.search(r"\(RPATH\)", dynamic) is not None:
        _fail("dynamic linked executable has DT_RPATH")
    runpaths = re.findall(r"\(RUNPATH\).*?\[([^\]]*)\]", dynamic)
    if runpaths != ["/usr/lib"]:
        _fail("dynamic linked executable search path differs from the owned runtime")


def _audit_retained_elf(executable: Path, linkage: str) -> None:
    """Validate replayed link output without invoking a host ELF tool."""
    facts = retained_elf_facts(executable)
    mode = LINKAGES[linkage]
    expected_type = 3 if mode["readelf_type"] == "DYN" else 2
    if facts["machine"] != 62 or facts["type"] != expected_type:
        _fail("retained linked executable ELF type differs from requested linkage")
    if facts["textrel"]:
        _fail("retained linked executable has DT_TEXTREL")
    if linkage in {"static", "static-pie"}:
        if facts["interpreters"] or facts["needed"]:
            _fail("retained static linked executable has dynamic runtime state")
        return
    if facts["interpreters"] != [INTERPRETER]:
        _fail("retained dynamic linked executable interpreter differs from the owned loader")
    if facts["needed"] != ["libc.so"]:
        _fail("retained dynamic linked executable has foreign DT_NEEDED entries")
    if facts["rpaths"]:
        _fail("retained dynamic linked executable has DT_RPATH")
    if facts["runpaths"] != ["/usr/lib"]:
        _fail("retained dynamic linked executable search path differs from the owned runtime")


def _retained_source_path(root: Path, source_mount: str, value: object, receipt: Path,
                          description: str) -> Path:
    """Translate one recorded native path to the physical host checkout.

    Producer validation intentionally reads the live compiler/linker paths in a
    native container.  A later receipt reader cannot depend on those paths
    existing on its host, so it admits only the fixed native `/workspace`
    spelling and translates it through the caller's physical checkout root.
    Relative sidecars remain relative to the link receipt itself.
    """

    if source_mount != "/workspace":
        _fail("retained link source mount must be /workspace")
    if not isinstance(value, str) or not value:
        _fail(f"{description} has no path")
    candidate = Path(value)
    if candidate.is_absolute():
        prefix = source_mount + "/"
        if not value.startswith(prefix) or ".." in candidate.parts:
            _fail(f"{description} escapes retained source mount")
        candidate = root / value[len(prefix):]
    else:
        candidate = receipt.parent / candidate
    return _physical_regular(candidate, description)


def _retained_recorded(root: Path, source_mount: str, path: Path, description: str) -> str:
    path = _physical_regular(path, description)
    root = _physical_directory(root, "retained checkout root")
    if not path.is_relative_to(root):
        _fail(f"{description} is outside retained checkout root")
    return source_mount + "/" + path.relative_to(root).as_posix()


def _retained_file_record(root: Path, source_mount: str, value: object, receipt: Path,
                          expected: Path, description: str) -> None:
    record = _require_keys(value, {"path", "sha256"}, description)
    recorded = _retained_source_path(root, source_mount, record["path"], receipt, description)
    expected = _physical_regular(expected, description)
    if recorded != expected:
        _fail(f"{description} path differs from retained evidence")
    _require_digest(record["sha256"], _sha256(expected), description)


def _retained_linker(value: object, tool: object) -> str:
    record = _require_keys(value, {"path", "sha256"}, "resolved linker")
    expected = _require_keys(tool, {"path", "sha256"}, "retained linker")
    path, digest = record["path"], record["sha256"]
    if (not isinstance(path, str) or not Path(path).is_absolute() or ".." in Path(path).parts
            or Path(path).name != "ld.lld" or not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None):
        _fail("retained linker identity is malformed")
    if record != expected:
        _fail("resolved linker differs from retained tool seal")
    return path


def _retained_static_plan(root: Path, source_mount: str, product: Path, linkage: str) -> list[str]:
    mode = LINKAGES[linkage]
    library = product / "usr/lib"
    return [
        "ld.lld", "-static", *(["-pie"] if linkage == "static-pie" else []),
        "--no-dynamic-linker", "--no-undefined", "--gc-sections", "-z", "relro", "-z", "now",
        "-e", "_start", _retained_recorded(root, source_mount, library / mode["crt"], "static CRT"),
        _retained_recorded(root, source_mount, library / "crti.o", "static CRT"),
        "<application-objects>", _retained_recorded(root, source_mount, library / "libc.a", "static libc"),
        _retained_recorded(root, source_mount, library / "libcrabc-builtins.a", "static builtins"),
        _retained_recorded(root, source_mount, library / "crtn.o", "static CRT"), "-o", "<output>",
    ]


def _validate_retained_static_trace(trace: Path, root: Path, source_mount: str, product: Path,
                                    workload: Path, linkage: str) -> None:
    mode, library = LINKAGES[linkage], product / "usr/lib"
    direct = {
        _retained_recorded(root, source_mount, library / mode["crt"], "static CRT"),
        _retained_recorded(root, source_mount, library / "crti.o", "static CRT"),
        _retained_recorded(root, source_mount, workload, "static workload"),
        _retained_recorded(root, source_mount, library / "crtn.o", "static CRT"),
    }
    archives = {
        _retained_recorded(root, source_mount, library / "libc.a", "static libc"),
        _retained_recorded(root, source_mount, library / "libcrabc-builtins.a", "static builtins"),
    }
    seen: set[str] = set()
    try:
        lines = trace.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise ProductEvidenceError(f"retained static link trace is unreadable: {trace}") from error
    for line in lines:
        if not line:
            continue
        if line in direct:
            seen.add(line)
        elif any(line == archive or (line.startswith(archive + "(") and line.endswith(")"))
                 for archive in archives):
            seen.add(next(archive for archive in archives
                          if line == archive or (line.startswith(archive + "(") and line.endswith(")"))))
        else:
            _fail("retained static link trace names an unowned input")
    missing = sorted((direct | archives) - seen)
    if missing:
        _fail("retained static link trace omits an owned input")


def _validate_retained_static_receipt(root: Path, source_mount: str, product: Path, workload: Path,
                                      executable: Path, receipt: Path, linkage: str, linker: object) -> str:
    record = _json_object(receipt, "retained static link receipt")
    expected_keys = {"schema", "format", "target", "mode", "resolved_linker", "owned_link_contract", "input_receipts", "output", "map", "trace"}
    _require_keys(record, expected_keys, "retained static link receipt")
    mode = LINKAGES[linkage]
    if (record["schema"], record["format"], record["target"]) != (1, STATIC_FORMAT, TARGET):
        _fail("retained static link receipt has the wrong sealed driver identity")
    if record["mode"] != {
        "id": mode["receipt_mode"], "elf_type": mode["elf_type"], "crt_object": mode["crt"], "interpreter": "absent",
    }:
        _fail("retained static link receipt mode differs from requested linkage")
    _retained_linker(record["resolved_linker"], linker)
    if record["owned_link_contract"] != _retained_static_plan(root, source_mount, product, linkage):
        _fail("retained static link receipt sealed link contract differs")
    inputs = record["input_receipts"]
    if not isinstance(inputs, list) or len(inputs) != 6:
        _fail("retained static link receipt has the wrong input roster")
    library = product / "usr/lib"
    expected_inputs = (
        ("crt-entry", "usr/lib/" + str(mode["crt"]), library / str(mode["crt"])),
        ("crt-prologue", "usr/lib/crti.o", library / "crti.o"),
        ("libc", "usr/lib/libc.a", library / "libc.a"),
        ("builtins", "usr/lib/libcrabc-builtins.a", library / "libcrabc-builtins.a"),
        ("crt-epilogue", "usr/lib/crtn.o", library / "crtn.o"),
        ("application", _retained_recorded(root, source_mount, workload, "static workload"), workload),
    )
    for received, (role, expected_path, path) in zip(inputs, expected_inputs):
        item = _require_keys(received, {"role", "path", "sha256"}, "retained static input receipt")
        if item["role"] != role or item["path"] != expected_path:
            _fail("retained static link receipt input differs from sealed roster")
        _require_digest(item["sha256"], _sha256(path), f"retained static {role} input")
    _retained_file_record(root, source_mount, record["output"], receipt, executable, "retained static output")
    map_path = _physical_regular(receipt.with_suffix(".map"), "retained static link map")
    trace_path = _physical_regular(receipt.with_suffix(".trace"), "retained static link trace")
    _retained_file_record(root, source_mount, record["map"], receipt, map_path, "retained static link map")
    _retained_file_record(root, source_mount, record["trace"], receipt, trace_path, "retained static link trace")
    _validate_retained_static_trace(trace_path, root, source_mount, product, workload, linkage)
    return _sha256(receipt)


def _retained_dynamic_command(root: Path, source_mount: str, product: Path, workload: Path,
                              executable: Path, linkage: str, linker: str,
                              *, export_dynamic: bool = False) -> list[str]:
    library = product / "usr/lib"
    entry = str(LINKAGES[linkage]["crt"])
    recorded = lambda path, description: _retained_recorded(root, source_mount, path, description)
    command = [
        linker, *(["-pie"] if linkage == "pie" else []), "--hash-style=sysv", "-z", "relro", "-z", "now",
        "-z", "noexecstack", "-z", "text", "--no-undefined", "--allow-shlib-undefined", "--enable-new-dtags",
        "-rpath", "/usr/lib",
    ]
    if export_dynamic:
        command.append("--export-dynamic")
    command.extend(("--dynamic-linker", INTERPRETER,
        *(recorded(path, "dynamic link input") for path in (
            library / entry, library / "crabc-dynamic-attach.o", library / "crti.o", workload,
            library / "libc.so", library / "libcrabc-builtins.a", library / "crtn.o",
        )), "-o", recorded(executable, "dynamic output")))
    return command


def _validate_retained_dynamic_trace(value: object, root: Path, source_mount: str, product: Path,
                                     workload: Path, linkage: str) -> None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        _fail("retained dynamic link trace is not a string list")
    library = product / "usr/lib"
    recorded = lambda path, description: _retained_recorded(root, source_mount, path, description)
    direct = {
        recorded(library / str(LINKAGES[linkage]["crt"]), "dynamic CRT"),
        recorded(library / "crabc-dynamic-attach.o", "dynamic attach object"),
        recorded(library / "crti.o", "dynamic CRT"), recorded(workload, "dynamic workload"),
        recorded(library / "libc.so", "dynamic libc"), recorded(library / "crtn.o", "dynamic CRT"),
    }
    archive = recorded(library / "libcrabc-builtins.a", "dynamic builtins")
    if (any(item not in direct and item != archive and not (item.startswith(archive + "(") and item.endswith(")"))
            for item in value) or not direct <= set(value)):
        _fail("retained dynamic link trace admits foreign or missing inputs")


def _validate_retained_dynamic_receipt(root: Path, source_mount: str, product: Path, workload: Path,
                                       executable: Path, receipt: Path, linkage: str, manifest: Path,
                                       linker: object, *, export_dynamic: bool = False) -> str:
    record = _json_object(receipt, "retained dynamic link receipt")
    search = receipt_contract.validate(
        record, format=DYNAMIC_PRODUCT_FORMAT, label="retained dynamic link receipt", fail=_fail
    )
    mode = LINKAGES[linkage]
    if record["mode"] != mode["receipt_mode"]:
        _fail("retained dynamic link receipt mode differs from requested linkage")
    if record["binding"] != "now" or record["runtime_imports"] != [] or record["application_dsos"] != {}:
        _fail("retained dynamic link receipt admits foreign runtime imports or DSOs")
    receipt_contract.require_runpath(search, "/usr/lib", label="retained dynamic link receipt", fail=_fail)
    if record["campaign_complete"] is not False:
        _fail("retained dynamic link receipt search-path or campaign state drifted")
    if record["output_path"] != _retained_recorded(root, source_mount, executable, "dynamic output"):
        _fail("retained dynamic output path differs")
    _require_digest(record["output_sha256"], _sha256(executable), "retained dynamic output")
    _require_digest(record["manifest_sha256"], _sha256(manifest), "retained dynamic product manifest")
    library = product / "usr/lib"
    runtime = [
        library / "crti.o", library / "libc.so", library / "crtn.o", library / str(mode["crt"]),
        library / "crabc-dynamic-attach.o",
    ]
    archive = library / "libcrabc-builtins.a"
    expected_roster = sorted(path.relative_to(product).as_posix() for path in [*runtime, archive])
    if record["owned_runtime_inputs"] != expected_roster:
        _fail("retained dynamic link receipt owned runtime roster differs")
    expected_inputs = [*((path, "runtime") for path in runtime), (workload, "workload"), (archive, "runtime")]
    if not isinstance(record["input_receipts"], list) or len(record["input_receipts"]) != len(expected_inputs):
        _fail("retained dynamic link receipt has the wrong input roster")
    for received, (expected, role) in zip(record["input_receipts"], expected_inputs):
        item = _require_keys(received, {"path", "sha256"}, "retained dynamic input receipt")
        if item["path"] != _retained_recorded(root, source_mount, expected, "dynamic link input"):
            _fail("retained dynamic link receipt input path differs")
        _require_digest(item["sha256"], _sha256(expected), f"retained dynamic {role} input")
    retained_linker = _retained_linker(record["resolved_linker"], linker)
    if record["link_command"] != _retained_dynamic_command(
            root, source_mount, product, workload, executable, linkage, retained_linker,
            export_dynamic=export_dynamic):
        _fail("retained dynamic link command differs")
    _validate_retained_dynamic_trace(record["link_trace"], root, source_mount, product, workload, linkage)
    return _sha256(receipt)


def validate_retained_link(root: Path, source_mount: str, product: Path, workload: Path,
                           executable: Path, receipt: Path, linkage: str, linker: object,
                           *, export_dynamic: bool = False) -> dict[str, str]:
    """Read one native `/workspace` link receipt after its container has gone away.

    Unlike :func:`validate_link`, this reader never probes the recorded native
    linker.  It requires its sealed identity from an outer before/after tool
    roster, translates only the fixed source mount to the host checkout, and
    still rehashes every current product payload, link input, output, sidecar,
    receipt, and ELF view.
    """

    if source_mount != "/workspace":
        _fail("retained link source mount must be /workspace")
    if linkage not in LINKAGES:
        _fail("retained linkage must be static, static-pie, pie, or non-pie")
    if type(export_dynamic) is not bool or (export_dynamic and linkage in {"static", "static-pie"}):
        _fail("retained export-dynamic contract differs from linkage")
    checkout = _physical_directory(root, "retained checkout root")
    product_path = _physical_directory(product, "retained owned product")
    workload_path = _physical_regular(workload, "retained workload object")
    executable_path = _physical_regular(executable, "retained linked executable")
    receipt_path = _physical_regular(receipt, "retained link receipt")
    if not all(path.is_relative_to(checkout) for path in (product_path, workload_path, executable_path, receipt_path)):
        _fail("retained link evidence escapes checkout root")
    if linkage in {"static", "static-pie"}:
        manifest, _ = _validate_static_product(product_path)
        receipt_hash = _validate_retained_static_receipt(
            checkout, source_mount, product_path, workload_path, executable_path, receipt_path, linkage, linker
        )
        product_format = STATIC_PRODUCT_FORMAT
    else:
        manifest, _ = _validate_dynamic_product(product_path)
        receipt_hash = _validate_retained_dynamic_receipt(
            checkout, source_mount, product_path, workload_path, executable_path, receipt_path, linkage, manifest,
            linker, export_dynamic=export_dynamic,
        )
        product_format = DYNAMIC_PRODUCT_FORMAT
    _audit_retained_elf(executable_path, linkage)
    return {
        "linkage": linkage,
        "product": str(product_path),
        "product_format": product_format,
        "product_manifest_sha256": _sha256(manifest),
        "workload_sha256": _sha256(workload_path),
        "executable_sha256": _sha256(executable_path),
        "receipt_sha256": receipt_hash,
    }


def validate_link(
    product: Path, workload: Path, executable: Path, receipt: Path, linkage: str, *, export_dynamic: bool = False,
) -> dict[str, str]:
    """Return an identity only when one receipt proves one current owned link.

    ``linkage`` is exactly ``static``, ``static-pie``, ``pie``, or ``non-pie``.
    Every path must name the current physical artifact; relocated, stale, or
    ambient-runtime receipts fail instead of being interpreted heuristically.
    """

    if linkage not in LINKAGES:
        _fail("linkage must be static, static-pie, pie, or non-pie")
    if type(export_dynamic) is not bool or (export_dynamic and linkage in {"static", "static-pie"}):
        _fail("export-dynamic contract differs from linkage")
    root = _physical_directory(product, "owned product")
    workload_path = _physical_regular(workload, "workload object")
    executable_path = _physical_regular(executable, "linked executable")
    receipt_path = _physical_regular(receipt, "link receipt")
    if linkage in {"static", "static-pie"}:
        manifest, _ = _validate_static_product(root)
        receipt_hash = _validate_static_receipt(
            root, workload_path, executable_path, receipt_path, linkage
        )
        product_format = STATIC_PRODUCT_FORMAT
    else:
        manifest, _ = _validate_dynamic_product(root)
        receipt_hash = _validate_dynamic_receipt(
            root, workload_path, executable_path, receipt_path, linkage, manifest,
            export_dynamic=export_dynamic,
        )
        product_format = DYNAMIC_PRODUCT_FORMAT
    _audit_elf(executable_path, linkage)
    return {
        "linkage": linkage,
        "product": str(root),
        "product_format": product_format,
        "product_manifest_sha256": _sha256(manifest),
        "workload_sha256": _sha256(workload_path),
        "executable_sha256": _sha256(executable_path),
        "receipt_sha256": receipt_hash,
    }
