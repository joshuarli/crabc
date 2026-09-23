#!/usr/bin/env python3
"""Read the finite installed-stdio component receipt without running it.

The receipt is deliberately a component observation for four selected stdio
capabilities.  This reader reconstructs its one installed-header object, the
pinned-musl observation, and either the four dynamic or six supplied-static
execution cells from physical retained bytes.  It does not accept report
hashes as a substitute for the product-link or copied-runtime validators.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import owned_crypt_runtime_evidence as copies
import owned_posix_product_evidence as products


SCHEMA = "crabc.x86_64-owned-stdio-products/v3"
SCOPE = (
    "stdio.path-stream",
    "stdio.stream-io",
    "stdio.position-buffering",
    "stdio.format-scan",
    "stdio.fopen64-alias",
)
REQUIRED_HEADERS = (
    "errno.h", "fcntl.h", "locale.h", "stdio.h", "unistd.h", "wchar.h", "features.h", "bits/alltypes.h",
)
ORACLE_TRANSCRIPT = b"owned-stdio-products-ok\n"
COPIES_PATH = HERE / "owned_crypt_runtime_evidence.py"
ORACLE_COMPILER = "/usr/local/bin/crabc-x86_64-musl-gcc"
MUSL_INCLUDE = Path("/opt/musl-1.2.6/include")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")

FOPEN64_HEADER_PROFILES: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "c11-base": (
        "compat/x86_64/fopen64_header_abi_probe.c", "hidden",
        ("-U_GNU_SOURCE", "-U_BSD_SOURCE", "-U_XOPEN_SOURCE", "-U_POSIX_C_SOURCE",
         "-U_FILE_OFFSET_BITS", "-U_LARGEFILE_SOURCE", "-U_LARGEFILE64_SOURCE",
         "-U_DEFAULT_SOURCE", "-DCRABC_FOPEN64_HEADER_C11_BASE"),
    ),
    "c11-gnu": (
        "compat/x86_64/fopen64_header_abi_probe.c", "hidden",
        ("-U_BSD_SOURCE", "-U_XOPEN_SOURCE", "-U_POSIX_C_SOURCE", "-U_FILE_OFFSET_BITS",
         "-U_LARGEFILE_SOURCE", "-U_LARGEFILE64_SOURCE", "-U_DEFAULT_SOURCE", "-D_GNU_SOURCE",
         "-DCRABC_FOPEN64_HEADER_C11_GNU"),
    ),
    "c11-file-offset-bits-64": (
        "compat/x86_64/fopen64_header_abi_probe.c", "hidden",
        ("-U_GNU_SOURCE", "-U_BSD_SOURCE", "-U_XOPEN_SOURCE", "-U_POSIX_C_SOURCE",
         "-U_LARGEFILE_SOURCE", "-U_LARGEFILE64_SOURCE", "-U_DEFAULT_SOURCE", "-D_FILE_OFFSET_BITS=64",
         "-DCRABC_FOPEN64_HEADER_C11_FILE_OFFSET_BITS_64"),
    ),
    "c11-largefile-source": (
        "compat/x86_64/fopen64_header_abi_probe.c", "hidden",
        ("-U_GNU_SOURCE", "-U_BSD_SOURCE", "-U_XOPEN_SOURCE", "-U_POSIX_C_SOURCE",
         "-U_FILE_OFFSET_BITS", "-U_LARGEFILE64_SOURCE", "-U_DEFAULT_SOURCE", "-D_LARGEFILE_SOURCE",
         "-DCRABC_FOPEN64_HEADER_C11_LARGEFILE_SOURCE"),
    ),
    "c11-largefile64": (
        "compat/x86_64/fopen64_header_abi_probe.c", "fopen",
        ("-U_GNU_SOURCE", "-U_BSD_SOURCE", "-U_XOPEN_SOURCE", "-U_POSIX_C_SOURCE",
         "-U_FILE_OFFSET_BITS", "-U_LARGEFILE_SOURCE", "-U_DEFAULT_SOURCE", "-D_LARGEFILE64_SOURCE",
         "-DCRABC_FOPEN64_HEADER_C11_LARGEFILE64"),
    ),
    "cxx17-base": (
        "compat/x86_64/fopen64_header_abi_probe.cpp", "hidden",
        ("-U_GNU_SOURCE", "-U_BSD_SOURCE", "-U_XOPEN_SOURCE", "-U_POSIX_C_SOURCE",
         "-U_FILE_OFFSET_BITS", "-U_LARGEFILE_SOURCE", "-U_LARGEFILE64_SOURCE",
         "-U_DEFAULT_SOURCE", "-DCRABC_FOPEN64_HEADER_CXX17_BASE"),
    ),
    "cxx17-gnu": (
        "compat/x86_64/fopen64_header_abi_probe.cpp", "hidden",
        ("-U_BSD_SOURCE", "-U_XOPEN_SOURCE", "-U_POSIX_C_SOURCE", "-U_FILE_OFFSET_BITS",
         "-U_LARGEFILE_SOURCE", "-U_LARGEFILE64_SOURCE", "-U_DEFAULT_SOURCE", "-D_GNU_SOURCE",
         "-DCRABC_FOPEN64_HEADER_CXX17_GNU"),
    ),
    "cxx17-file-offset-bits-64": (
        "compat/x86_64/fopen64_header_abi_probe.cpp", "hidden",
        ("-U_GNU_SOURCE", "-U_BSD_SOURCE", "-U_XOPEN_SOURCE", "-U_POSIX_C_SOURCE",
         "-U_LARGEFILE_SOURCE", "-U_LARGEFILE64_SOURCE", "-U_DEFAULT_SOURCE", "-D_FILE_OFFSET_BITS=64",
         "-DCRABC_FOPEN64_HEADER_CXX17_FILE_OFFSET_BITS_64"),
    ),
    "cxx17-largefile-source": (
        "compat/x86_64/fopen64_header_abi_probe.cpp", "hidden",
        ("-U_GNU_SOURCE", "-U_BSD_SOURCE", "-U_XOPEN_SOURCE", "-U_POSIX_C_SOURCE",
         "-U_FILE_OFFSET_BITS", "-U_LARGEFILE64_SOURCE", "-U_DEFAULT_SOURCE", "-D_LARGEFILE_SOURCE",
         "-DCRABC_FOPEN64_HEADER_CXX17_LARGEFILE_SOURCE"),
    ),
    "cxx17-largefile64": (
        "compat/x86_64/fopen64_header_abi_probe.cpp", "fopen",
        ("-U_GNU_SOURCE", "-U_BSD_SOURCE", "-U_XOPEN_SOURCE", "-U_POSIX_C_SOURCE",
         "-U_FILE_OFFSET_BITS", "-U_LARGEFILE_SOURCE", "-U_DEFAULT_SOURCE", "-D_LARGEFILE64_SOURCE",
         "-DCRABC_FOPEN64_HEADER_CXX17_LARGEFILE64"),
    ),
}
FOPEN64_DYNAMIC_CELLS = (
    "dynamic-pie-kernel", "dynamic-pie-direct",
    "dynamic-non-pie-kernel", "dynamic-non-pie-direct",
)


class ReceiptError(RuntimeError):
    """The retained stdio component cannot establish its finite observation."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReceiptError(message)


def same(left: object, right: object, message: str) -> None:
    """Compare JSON values without allowing Python's bool/int coercion."""

    require(
        json.dumps(left, sort_keys=True, separators=(",", ":"), allow_nan=False)
        == json.dumps(right, sort_keys=True, separators=(",", ":"), allow_nan=False),
        message,
    )


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def physical(path: Path, label: str) -> Path:
    """Reject lexical and physical symlink hops before returning an absolute path."""

    if ".." in path.parts:
        raise ReceiptError(f"{label} has lexical parent traversal: {path}")
    result = Path(os.path.abspath(path))
    current = Path(result.anchor)
    try:
        for part in result.parts[1:]:
            current /= part
            if stat.S_ISLNK(current.lstat().st_mode):
                raise ReceiptError(f"{label} traverses a symlink: {path}")
        result.lstat()
    except OSError as error:
        raise ReceiptError(f"{label} is unreadable: {path}") from error
    return result


def directory(path: Path, label: str) -> Path:
    path = physical(path, label)
    try:
        require(stat.S_ISDIR(path.lstat().st_mode), f"{label} is not a physical directory")
    except OSError as error:
        raise ReceiptError(f"{label} is unreadable") from error
    return path


def regular(path: Path, label: str) -> Path:
    path = physical(path, label)
    try:
        require(stat.S_ISREG(path.lstat().st_mode), f"{label} is not a physical regular file")
    except OSError as error:
        raise ReceiptError(f"{label} is unreadable") from error
    return path


def digest(path: Path) -> str:
    path = regular(path, "hashed receipt artifact")
    value = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                value.update(block)
    except OSError as error:
        raise ReceiptError(f"cannot hash receipt artifact: {path}") from error
    return value.hexdigest()


def identity(root: Path, path: Path) -> dict[str, object]:
    root = directory(root, "receipt root")
    path = regular(path, "receipt artifact")
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as error:
        raise ReceiptError("receipt artifact escapes its root") from error
    metadata = path.stat()
    return {"path": relative, "sha256": digest(path), "size": metadata.st_size, "mode": stat.S_IMODE(metadata.st_mode)}


def check_identity(root: Path, value: object, label: str) -> Path:
    require(type(value) is dict and set(value) == {"path", "sha256", "size", "mode"}, f"{label} identity fields drifted")
    relative, expected, size, mode = value["path"], value["sha256"], value["size"], value["mode"]
    require(type(relative) is str and relative and not Path(relative).is_absolute() and ".." not in Path(relative).parts,
            f"{label} identity path is invalid")
    require(type(expected) is str and SHA256.fullmatch(expected) is not None, f"{label} identity digest is invalid")
    require(type(size) is int and size >= 0 and type(mode) is int and 0 <= mode <= 0o777,
            f"{label} identity metadata is invalid")
    path = regular(root / relative, label)
    same(identity(root, path), value, f"{label} differs from physical retained bytes")
    return path


def strict_json(path: Path, label: str) -> dict[str, Any]:
    path = regular(path, label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise ReceiptError(f"{label} is not strict JSON") from error
    require(type(value) is dict, f"{label} must be a JSON object")
    return value


def tree_identity(root: Path) -> dict[str, object]:
    """Seal the complete product tree without resolving its declared aliases."""

    root = directory(root, "sealed product")
    result: dict[str, object] = {}
    pending = [root]
    while pending:
        parent = pending.pop()
        try:
            children = sorted(parent.iterdir())
        except OSError as error:
            raise ReceiptError("sealed product is unreadable") from error
        for path in children:
            # ``parent`` was physically admitted before enumeration.  Inspect
            # a direct child with ``lstat`` so a product's manifest-authorized
            # file alias is recorded rather than followed; recurse only after
            # a directory itself has passed the no-hop gate.
            try:
                mode = path.lstat().st_mode
            except OSError as error:
                raise ReceiptError("sealed product entry is unreadable") from error
            relative = path.relative_to(root).as_posix()
            metadata = path.stat(follow_symlinks=False)
            entry: dict[str, object] = {"mode": stat.S_IMODE(mode), "uid": metadata.st_uid,
                                        "gid": metadata.st_gid, "links": metadata.st_nlink}
            if stat.S_ISDIR(mode):
                entry["kind"] = "directory"
                pending.append(directory(path, "sealed product directory"))
            elif stat.S_ISREG(mode):
                entry.update(kind="file", size=metadata.st_size, sha256=digest(path))
            elif stat.S_ISLNK(mode):
                try:
                    entry.update(kind="symlink", target=os.readlink(path))
                except OSError as error:
                    raise ReceiptError("sealed product alias is unreadable") from error
            else:
                raise ReceiptError("sealed product contains a non-file entry")
            result[relative] = entry
    require(bool(result), "sealed product tree is empty")
    return result


def exact_file_record(value: object, path: Path, label: str, *, mode: bool = False) -> None:
    fields = {"path", "sha256", "mode"} if mode else {"path", "sha256", "size"}
    require(type(value) is dict and set(value) == fields, f"{label} fields drifted")
    path = regular(path, label)
    actual: dict[str, object] = {"path": str(path), "sha256": digest(path)}
    if mode:
        actual["mode"] = stat.S_IMODE(path.stat().st_mode)
    else:
        actual["size"] = path.stat().st_size
    same(actual, value, f"{label} differs from physical bytes")


def _source_file(checkout: Path, record: object, expected: str, label: str) -> Path:
    require(type(record) is dict and set(record) == {"path", "sha256", "mode"}, f"{label} fields drifted")
    require(record["path"] == expected, f"{label} path differs")
    return_path = regular(checkout / expected, label)
    require(type(record["sha256"]) is str and SHA256.fullmatch(record["sha256"]) is not None
            and type(record["mode"]) is int, f"{label} identity is invalid")
    require(record["sha256"] == digest(return_path) and record["mode"] == stat.S_IMODE(return_path.stat().st_mode),
            f"{label} differs from physical bytes")
    return return_path


def _product_seal(value: object, product: Path, family: str) -> None:
    require(type(value) is dict and set(value) == {"path", "manifest", "tree"}, f"{family} product seal fields drifted")
    require(value["path"] == str(product), f"{family} product seal path differs")
    manifest = product / "share/crabc/manifest.json"
    exact_file_record(value["manifest"], manifest, f"{family} product manifest")
    require(type(value["tree"]) is dict and value["tree"], f"{family} product seal tree is empty")
    same(tree_identity(product), value["tree"], f"{family} product seal tree differs")


def validate_source_product_seals(
    checkout: Path, work: Path, report: Mapping[str, Any], *, static: bool,
) -> tuple[Path, Path, Path, Path]:
    seals = report["seals"]
    before = check_identity(work, seals["source-product-before"], "source/product before seal")
    after = check_identity(work, seals["source-product-after"], "source/product after seal")
    before_value = strict_json(before, "source/product before seal")
    after_value = strict_json(after, "source/product after seal")
    same(before_value, after_value, "source/product seals differ")
    expected = {"sources", "dynamic"} | ({"static"} if static else set())
    require(set(before_value) == expected, "source/product seal fields drifted")
    sources = before_value["sources"]
    require(type(sources) is dict and set(sources) == {"probe", "runner", "reader", "fopen64_c", "fopen64_cxx"},
            "source seal source roster differs")
    probe = _source_file(checkout, sources["probe"], "compat/x86_64/owned_stdio_probe.c", "stdio probe source")
    runner = _source_file(checkout, sources["runner"], "compat/x86_64/run_owned_stdio.sh", "stdio runner source")
    _source_file(checkout, sources["reader"], "compat/x86_64/owned_stdio_component_receipt.py", "stdio receipt reader source")
    fopen64_c = _source_file(checkout, sources["fopen64_c"], "compat/x86_64/fopen64_header_abi_probe.c",
                              "fopen64 C header source")
    fopen64_cxx = _source_file(checkout, sources["fopen64_cxx"], "compat/x86_64/fopen64_header_abi_probe.cpp",
                                "fopen64 C++ header source")
    source = report["source"]
    require(type(source) is dict and set(source) == {"path", "sha256", "size", "mode"}, "report source identity fields drifted")
    same(source, identity(checkout, probe), "report source differs from sealed probe")
    product_paths = report["products"]
    dynamic = directory(Path(product_paths["dynamic"]), "dynamic product")
    _product_seal(before_value["dynamic"], dynamic, "dynamic")
    try:
        products._validate_dynamic_product(dynamic)
    except Exception as error:
        raise ReceiptError("dynamic product validation failed") from error
    if static:
        static_product = directory(Path(product_paths["static"]), "static product")
        _product_seal(before_value["static"], static_product, "static")
        try:
            products._validate_static_product(static_product)
        except Exception as error:
            raise ReceiptError("static product validation failed") from error
    return probe, runner, fopen64_c, fopen64_cxx


def _dynamic_helper_tools(dynamic: Path) -> dict[str, Path]:
    """Resolve the sealed dynamic helper only after product validation.

    The helper owns the pinned image compiler and linker selection.  Its bytes
    were already validated by the dynamic product validator and by the
    immutable product seal before this function runs.  Keep the returned
    physical paths separate from their retained tool records so a rehashed
    record cannot select an ambient compiler.
    """

    helper = regular(dynamic / "share/crabc/crabc_cc_static.py", "installed compiler helper")
    name = "owned_stdio_installed_compiler"
    specification = importlib.util.spec_from_file_location(name, helper)
    require(specification is not None and specification.loader is not None,
            "installed compiler helper cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    try:
        specification.loader.exec_module(module)
        origin = getattr(module, "__file__", None)
        require(type(origin) is str and regular(Path(origin), "loaded compiler helper") == helper,
                "installed compiler helper origin differs")
        selected: dict[str, Path] = {}
        for role in ("compiler", "linker"):
            selector = getattr(module, role, None)
            require(callable(selector), f"installed compiler helper lacks {role} selector")
            candidate = selector(dynamic) if role == "linker" else selector()
            require(type(candidate) is str and Path(candidate).is_absolute(),
                    f"installed compiler helper {role} path is invalid")
            selected[role] = regular(Path(candidate), f"installed helper {role}")
        return selected
    except ReceiptError:
        raise
    except Exception as error:
        raise ReceiptError("installed compiler helper cannot resolve fixed tools") from error
    finally:
        sys.modules.pop(name, None)


def validate_tools(work: Path, report: Mapping[str, Any], *, static: bool) -> dict[str, dict[str, object]]:
    before_path = check_identity(work, report["seals"]["tools-before"], "tools before seal")
    after_path = check_identity(work, report["seals"]["tools-after"], "tools after seal")
    before, after = strict_json(before_path, "tools before seal"), strict_json(after_path, "tools after seal")
    same(before, after, "tool seals differ")
    expected = {"oracle", "dynamic_driver", "compiler", "linker"} | ({"static_driver"} if static else set())
    require(set(before) == expected, "tool roster differs")
    result: dict[str, dict[str, object]] = {}
    for role in expected:
        record = before[role]
        require(type(record) is dict and set(record) == {"path", "sha256", "size", "mode"}, f"{role} tool fields drifted")
        path_value = record["path"]
        require(type(path_value) is str and Path(path_value).is_absolute(), f"{role} tool path is invalid")
        path = regular(Path(path_value), f"{role} tool")
        require(type(record["sha256"]) is str and SHA256.fullmatch(record["sha256"]) is not None
                and type(record["size"]) is int and record["size"] >= 0
                and type(record["mode"]) is int and 0 <= record["mode"] <= 0o777,
                f"{role} tool identity is invalid")
        require(record["sha256"] == digest(path) and record["size"] == path.stat().st_size
                and record["mode"] == stat.S_IMODE(path.stat().st_mode),
                f"{role} tool differs from physical bytes")
        if role == "oracle":
            require(record["path"] == ORACLE_COMPILER, "oracle tool path differs from pinned musl compiler")
        result[role] = record
    dynamic = directory(Path(report["products"]["dynamic"]), "dynamic product")
    selected = _dynamic_helper_tools(dynamic)
    for role, path in selected.items():
        require(result[role]["path"] == str(path),
                f"{role} tool path differs from sealed helper")
    return result


def command_files(work: Path, value: object, stem: str) -> dict[str, object]:
    require(type(value) is dict and set(value) == {"argv", "stdout", "stderr", "status"}, f"{stem} command fields drifted")
    paths = {kind: check_identity(work, value[kind], f"{stem} {kind}") for kind in value}
    require(paths["argv"].name == stem + ".argv.json", f"{stem} argv filename differs")
    require(paths["stdout"].name == stem + ".stdout", f"{stem} stdout filename differs")
    require(paths["stderr"].name == stem + ".stderr", f"{stem} stderr filename differs")
    require(paths["status"].name == stem + ".status", f"{stem} status filename differs")
    try:
        argv = json.loads(paths["argv"].read_text(encoding="utf-8"), object_pairs_hook=_pairs)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise ReceiptError(f"{stem} argv is not strict JSON") from error
    require(type(argv) is list and all(type(item) is str for item in argv), f"{stem} argv is invalid")
    require(paths["status"].read_bytes() == b"0\n", f"{stem} status is not successful")
    paths["parsed_argv"] = argv  # type: ignore[assignment]
    return paths


def require_argv(files: Mapping[str, object], expected: list[str], label: str) -> None:
    same(files["parsed_argv"], expected, label + " argv differs")


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def fopen64_row(*, static: bool) -> dict[str, object]:
    """The one installed macro-consumer observation, not a stdio family claim."""

    return {
        "feature": "_LARGEFILE64_SOURCE=1",
        "macro": "fopen64",
        "target": "fopen",
        "pointer_equality": True,
        "object_import": "fopen",
        "header_profiles": {name: visibility for name, (_, visibility, _) in FOPEN64_HEADER_PROFILES.items()},
        "runtime_cells": [*FOPEN64_DYNAMIC_CELLS, *(["static", "static-pie"] if static else [])],
    }


def undefined_elf_symbols(path: Path) -> set[str]:
    """Read undefined names from one physical ELF64 little-endian ET_REL object."""

    data = regular(path, "installed-header ELF object").read_bytes()
    require(data[:7] == b"\x7fELF\x02\x01\x01", "installed-header object is not ELF64 little-endian")
    require(len(data) >= 64 and int.from_bytes(data[16:18], "little") == 1
            and int.from_bytes(data[18:20], "little") == 62 and int.from_bytes(data[20:24], "little") == 1,
            "installed-header object is not x86-64 ET_REL")
    sections_at = int.from_bytes(data[40:48], "little")
    section_size = int.from_bytes(data[58:60], "little")
    section_count = int.from_bytes(data[60:62], "little")
    require(section_size == 64 and section_count > 0 and sections_at >= 64
            and section_count <= (len(data) - sections_at) // section_size,
            "installed-header object section table is invalid")
    sections = [data[sections_at + index * section_size:sections_at + (index + 1) * section_size]
                for index in range(section_count)]
    symbol_sections = [section for section in sections if int.from_bytes(section[4:8], "little") == 2]
    require(len(symbol_sections) == 1, "installed-header object symbol table differs")
    symbols = symbol_sections[0]
    strings_index = int.from_bytes(symbols[40:44], "little")
    symbols_at, symbols_size, symbols_entry_size = (int.from_bytes(symbols[offset:offset + 8], "little")
                                                     for offset in (24, 32, 56))
    require(strings_index < section_count and symbols_entry_size == 24 and symbols_size % symbols_entry_size == 0
            and symbols_at <= len(data) and symbols_size <= len(data) - symbols_at,
            "installed-header object symbol table bounds differ")
    strings = sections[strings_index]
    require(int.from_bytes(strings[4:8], "little") == 3, "installed-header object string table differs")
    strings_at, strings_size = (int.from_bytes(strings[offset:offset + 8], "little") for offset in (24, 32))
    require(strings_at <= len(data) and strings_size <= len(data) - strings_at,
            "installed-header object string table bounds differ")
    names = data[strings_at:strings_at + strings_size]
    undefined: set[str] = set()
    for index in range(symbols_size // symbols_entry_size):
        symbol = data[symbols_at + index * symbols_entry_size:symbols_at + (index + 1) * symbols_entry_size]
        name_at = int.from_bytes(symbol[0:4], "little")
        section = int.from_bytes(symbol[6:8], "little")
        if section != 0 or name_at == 0:
            continue
        require(name_at < len(names), "installed-header object symbol name is invalid")
        end = names.find(b"\0", name_at)
        require(end != -1, "installed-header object symbol name is unterminated")
        try:
            name = names[name_at:end].decode("ascii")
        except UnicodeDecodeError as error:
            raise ReceiptError("installed-header object symbol name is not ASCII") from error
        undefined.add(name)
    return undefined


def _object_seals(
    work: Path, report: Mapping[str, Any], probe: Path, runner: Path, fopen64_c: Path, fopen64_cxx: Path, workload: Path,
) -> None:
    records = report["object_seals"]
    require(type(records) is dict and set(records) == {"before", "after"}, "object seal roster differs")
    before = check_identity(work, records["before"], "object before seal")
    after = check_identity(work, records["after"], "object after seal")
    sealed = (probe, fopen64_c, fopen64_cxx, runner, workload)
    expected_before = "".join(f"{digest(path)}  {path}\n" for path in sealed).encode("ascii")
    require(before.read_bytes() == expected_before, "object before seal differs")
    expected_after = "".join(f"{path}: OK\n" for path in sealed).encode("utf-8")
    require(after.read_bytes() == expected_after, "object after seal differs")


def _fopen64_profile_argv(
    tree: str, profile: str, compiler: str, include: Path, source: Path, object_path: Path, phase: str,
) -> list[str]:
    expected_source, _, feature_flags = FOPEN64_HEADER_PROFILES[profile]
    require(source.as_posix().endswith(expected_source), "fopen64 header source path differs")
    language = (["-x", "c++", "-std=c++17", "-nostdinc++"] if profile.startswith("cxx17-")
                else ["-x", "c", "-std=c11", "-Werror=implicit-function-declaration"])
    common = [*language, "-nostdinc", "-isystem", str(include), "-H", "-fno-builtin", *feature_flags]
    if phase == "preprocess":
        return [compiler, *common, "-E", str(source)]
    require(phase == "compile", "fopen64 header phase differs")
    return [compiler, *common, "-c", str(source), "-o", str(object_path)]


def _fopen64_header_trace(trace: Path, root: Path, label: str) -> None:
    traced: list[Path] = []
    for line in trace.read_text(errors="replace").splitlines():
        match = re.fullmatch(r"\.+\s+(.+)", line)
        if match is None:
            continue
        candidate = Path(match.group(1))
        require(candidate.is_absolute() and ".." not in candidate.parts and candidate.is_relative_to(root),
                label + " header trace escapes declared include tree")
        traced.append(candidate)
    require(all(root / name in traced for name in ("stdio.h", "features.h", "bits/alltypes.h")),
            label + " header trace omits required header")


def _validate_fopen64_header_controls(
    work: Path, retained: Mapping[str, Mapping[str, object]], tools: Mapping[str, Mapping[str, object]],
    dynamic: Path, fopen64_c: Path, fopen64_cxx: Path,
) -> None:
    """Reconstruct C/C++ hidden and exposed macro controls against both headers."""

    for tree, compiler, include in (
        ("reference", str(tools["oracle"]["path"]), MUSL_INCLUDE),
        ("installed", str(tools["compiler"]["path"]), dynamic / "usr/include"),
    ):
        include = directory(include, tree + " fopen64 include tree")
        for profile, (relative_source, visibility, _) in FOPEN64_HEADER_PROFILES.items():
            source = fopen64_cxx if relative_source.endswith(".cpp") else fopen64_c
            object_path = regular(work / f"fopen64-{tree}-{profile}.o", tree + " " + profile + " header object")
            preprocess = retained[f"fopen64-{tree}-{profile}-preprocess"]
            compile = retained[f"fopen64-{tree}-{profile}-compile"]
            require_argv(preprocess, _fopen64_profile_argv(tree, profile, compiler, include, source, object_path, "preprocess"),
                         tree + " " + profile + " preprocess")
            require_argv(compile, _fopen64_profile_argv(tree, profile, compiler, include, source, object_path, "compile"),
                         tree + " " + profile + " compile")
            for phase, command in (("preprocess", preprocess), ("compile", compile)):
                stdout, stderr = command["stdout"], command["stderr"]
                assert isinstance(stdout, Path) and isinstance(stderr, Path)
                if phase == "compile":
                    require(stdout.read_bytes() == b"", tree + " " + profile + " compile stdout differs")
                    _fopen64_header_trace(stderr, include, tree + " " + profile)
                else:
                    _fopen64_header_trace(stderr, include, tree + " " + profile)
                    source_text = stdout.read_text(errors="replace")
                    require(f'# 0 "{source}"' in source_text,
                            tree + " " + profile + " preprocessed source differs")
                    expansion = re.sub(r"^#.*$", "", source_text, flags=re.MULTILINE)
                    if visibility == "fopen":
                        require(re.search(r"fopen64_macro_reference\s*=\s*&\s*fopen\s*;", expansion) is not None,
                                tree + " " + profile + " macro expansion differs")
                    else:
                        require("fopen64_macro_reference" not in source_text,
                                tree + " " + profile + " unexpectedly exposes fopen64")
            imports = undefined_elf_symbols(object_path)
            require("fopen" in imports and "fopen64" not in imports,
                    tree + " " + profile + " object import differs")


def validate_commands(
    checkout: Path, work: Path, report: Mapping[str, Any], probe: Path, runner: Path, fopen64_c: Path, fopen64_cxx: Path,
    tools: Mapping[str, Mapping[str, object]], *, static: bool,
) -> tuple[dict[str, dict[str, object]], Path]:
    commands = report["commands"]
    expected = {
        "header-trace", "compile", "oracle-link", "oracle-run",
        *(f"dynamic-{mode}-{part}" for mode in ("pie", "non-pie")
          for part in ("link", "validate", "copy-before", "copy-audit-before", "kernel", "direct", "copy-audit-after")),
    }
    if static:
        expected |= {f"{mode}-{part}" for mode in ("static", "static-pie") for part in ("link", "validate", "run")}
    expected |= {f"fopen64-{tree}-{profile}-{phase}"
                 for tree in ("reference", "installed") for profile in FOPEN64_HEADER_PROFILES
                 for phase in ("preprocess", "compile")}
    require(type(commands) is dict and set(commands) == expected, "command roster differs")
    retained: dict[str, dict[str, object]] = {stem: command_files(work, commands[stem], stem) for stem in expected}
    workload = check_identity(work, report["workload"], "installed-header workload")
    require(workload.name == "workload.o", "installed-header workload filename differs")
    _object_seals(work, report, probe, runner, fopen64_c, fopen64_cxx, workload)
    dynamic = directory(Path(report["products"]["dynamic"]), "dynamic product")
    include = dynamic / "usr/include"
    _validate_fopen64_header_controls(work, retained, tools, dynamic, fopen64_c, fopen64_cxx)
    compiler = str(tools["compiler"]["path"])
    require_argv(retained["header-trace"], [compiler, "-nostdinc", "-isystem", str(include), "-D_LARGEFILE64_SOURCE=1", "-ffreestanding", "-fno-builtin",
                                             "-fno-stack-protector", "-std=c11", "-fPIE", "-E", "-H", str(probe)], "header trace")
    header_stdout = retained["header-trace"]["stdout"]
    header_stderr = retained["header-trace"]["stderr"]
    assert isinstance(header_stdout, Path) and isinstance(header_stderr, Path)
    header_source = header_stdout.read_text(errors="replace")
    header_expansion = re.sub(r"^#.*$", "", header_source, flags=re.MULTILINE)
    require((f'# 0 "{probe}"' in header_source
             and "int main(int argc, char **argv)" in header_source
             and re.search(r"fopen64_macro_entry\s*=\s*fopen\s*;", header_expansion) is not None),
            "header trace preprocessed source differs")
    traced_headers: list[Path] = []
    for line in header_stderr.read_text(errors="replace").splitlines():
        match = re.fullmatch(r"\.+\s+(.+)", line)
        if match is None:
            continue
        candidate = Path(match.group(1))
        require(candidate.is_absolute() and ".." not in candidate.parts and candidate.is_relative_to(include),
                "header trace escapes installed include tree")
        traced_headers.append(candidate)
    require(all(include / header in traced_headers for header in REQUIRED_HEADERS),
            "header trace omits a required installed header")
    dynamic_driver = str(tools["dynamic_driver"]["path"])
    require(dynamic_driver == str(dynamic / "bin/crabc-cc-dynamic"), "dynamic driver tool path differs from product")
    require_argv(retained["compile"], [dynamic_driver, "--dynamic-pie", "-std=c11", "-D_POSIX_C_SOURCE=200809L", "-D_LARGEFILE64_SOURCE=1", "-fno-builtin",
                                        "-fno-stack-protector", "-c", str(probe), "-o", str(workload)], "compile")
    macro_imports = undefined_elf_symbols(workload)
    require("fopen" in macro_imports and "fopen64" not in macro_imports,
            "fopen64 macro consumer object import differs")
    for stem in ("compile", "oracle-link"):
        stdout, stderr = retained[stem]["stdout"], retained[stem]["stderr"]
        assert isinstance(stdout, Path) and isinstance(stderr, Path)
        require(stdout.read_bytes() == b"" and stderr.read_bytes() == b"", stem + " raw output differs")
    oracle = str(tools["oracle"]["path"])
    oracle_executable = work / "oracle"
    require_argv(retained["oracle-link"], [oracle, "-std=c11", "-static", "-fno-pie", "-no-pie", str(workload), "-o", str(oracle_executable)], "oracle link")
    oracle_args = ["env", "-i", "LC_ALL=C", "LANG=C", "TZ=UTC", str(oracle_executable),
                   str(work / "oracle-first"), str(work / "oracle-second"), str(work / "oracle-wide")]
    require_argv(retained["oracle-run"], oracle_args, "oracle run")
    oracle_streams = tuple(retained["oracle-run"][name].read_bytes() for name in ("stdout", "stderr", "status"))  # type: ignore[index]
    require(oracle_streams == (ORACLE_TRANSCRIPT, b"", b"0\n"), "pinned musl oracle transcript differs")
    for mode in ("pie", "non-pie"):
        executable = work / ("dynamic-" + mode)
        require_argv(retained["dynamic-" + mode + "-link"], [dynamic_driver, "--dynamic-" + mode, "-std=c11", str(workload), "-o", str(executable)],
                     "dynamic " + mode + " link")
        link_stdout, link_stderr = retained["dynamic-" + mode + "-link"]["stdout"], retained["dynamic-" + mode + "-link"]["stderr"]
        assert isinstance(link_stdout, Path) and isinstance(link_stderr, Path)
        require(link_stdout.read_bytes() == b"" and link_stderr.read_bytes() == b"", "dynamic " + mode + " link raw output differs")
        root = work / ("dynamic-" + mode + "-root")
        for entry in ("kernel", "direct"):
            command = retained["dynamic-" + mode + "-" + entry]
            expected_argv = (["chroot", str(root), "/consumer", "/scratch/first", "/scratch/second", "/scratch/wide"]
                             if entry == "kernel" else
                             ["chroot", str(root), "/lib/ld-crabc-x86_64.so.1", "/consumer", "/scratch/first", "/scratch/second", "/scratch/wide"])
            require_argv(command, expected_argv, "dynamic " + mode + " " + entry)
            streams = tuple(command[name].read_bytes() for name in ("stdout", "stderr", "status"))  # type: ignore[index]
            require(streams == oracle_streams, "dynamic " + mode + " " + entry + " stdout/stderr/status differs from pinned musl")
    if static:
        static_product = directory(Path(report["products"]["static"]), "static product")
        static_driver = str(tools["static_driver"]["path"])
        require(static_driver == str(static_product / "bin/crabc-cc"), "static driver tool path differs from product")
        for mode in ("static", "static-pie"):
            executable = work / mode
            receipt = work / (mode + ".crabc-link.json")
            require_argv(retained[mode + "-link"], [static_driver, "-" + mode, "--link-receipt", receipt.name, str(workload), "-o", str(executable)],
                         mode + " link")
            link_stdout, link_stderr = retained[mode + "-link"]["stdout"], retained[mode + "-link"]["stderr"]
            assert isinstance(link_stdout, Path) and isinstance(link_stderr, Path)
            require(link_stdout.read_bytes() == b"" and link_stderr.read_bytes() == b"", mode + " link raw output differs")
            command = retained[mode + "-run"]
            require_argv(command, ["env", "-i", "LC_ALL=C", "LANG=C", "TZ=UTC", str(executable),
                                   str(work / (mode + "-first")), str(work / (mode + "-second")), str(work / (mode + "-wide"))], mode + " run")
            streams = tuple(command[name].read_bytes() for name in ("stdout", "stderr", "status"))  # type: ignore[index]
            require(streams == oracle_streams, mode + " stdout/stderr/status differs from pinned musl")
    return retained, workload


def validate_links(checkout: Path, work: Path, report: Mapping[str, Any], commands: Mapping[str, Mapping[str, object]], workload: Path, *, static: bool) -> None:
    links = report["links"]
    expected = {"dynamic-pie", "dynamic-non-pie"} | ({"static", "static-pie"} if static else set())
    require(type(links) is dict and set(links) == expected, "link roster differs")
    dynamic = directory(Path(report["products"]["dynamic"]), "dynamic product")
    for name in sorted(expected):
        linkage = name.removeprefix("dynamic-")
        product = directory(Path(report["products"]["static"]), "static product") if linkage.startswith("static") else dynamic
        executable = work / name
        link_path = check_identity(work, links[name], name + " product link")
        require(link_path.name == name + ".product-link.json", name + " product link filename differs")
        receipt_path = work / (linkage + ".crabc-link.json" if linkage.startswith("static") else name + ".crabc-link.json")
        require_argv(commands[name + "-validate"], ["python3", "-B", "-", str(checkout), str(product), str(workload),
                                                  str(executable), str(receipt_path), linkage],
                     name.replace("-", " ") + " validate")
        try:
            rebuilt = products.validate_link(product, workload, executable, receipt_path, linkage)
        except Exception as error:
            raise ReceiptError(name.replace("-", " ") + " link cannot be reconstructed") from error
        require(type(rebuilt) is dict and rebuilt.get("linkage") == linkage
                and rebuilt.get("workload_sha256") == digest(workload)
                and rebuilt.get("executable_sha256") == digest(executable),
                name.replace("-", " ") + " link workload identity differs")
        require(rebuilt.get("product") == str(product), name.replace("-", " ") + " link identity differs")
        require(link_path.read_bytes() == canonical(rebuilt), name.replace("-", " ") + " link identity differs")
        validation = commands[name + "-validate"]
        validation_stdout = validation["stdout"]
        validation_stderr = validation["stderr"]
        assert isinstance(validation_stdout, Path) and isinstance(validation_stderr, Path)
        require(validation_stdout.read_bytes() == canonical(rebuilt) and validation_stderr.read_bytes() == b"",
                name.replace("-", " ") + " validate output differs")


def validate_payloads(work: Path, report: Mapping[str, Any], commands: Mapping[str, Mapping[str, object]]) -> None:
    payloads = report["execution_payloads"]
    require(type(payloads) is dict and set(payloads) == {"pie", "non-pie"}, "execution payload roster differs")
    product = directory(Path(report["products"]["dynamic"]), "dynamic product")
    for mode in ("pie", "non-pie"):
        record = payloads[mode]
        require(type(record) is dict and set(record) == {"record", "before", "after"}, "execution payload fields drifted")
        record_path = check_identity(work, record["record"], "dynamic " + mode + " payload record")
        before = check_identity(work, record["before"], "dynamic " + mode + " payload before audit")
        after = check_identity(work, record["after"], "dynamic " + mode + " payload after audit")
        root = work / ("dynamic-" + mode + "-root")
        executable = work / ("dynamic-" + mode)
        consumer = root / "consumer"
        record_argv = ["python3", "-B", str(COPIES_PATH), "record", "--product", str(product), "--execution-root", str(root),
                       "--source-consumer", str(executable), "--execution-consumer", str(consumer), "--record", str(record_path)]
        require_argv(commands["dynamic-" + mode + "-copy-before"], record_argv, "dynamic " + mode + " payload record")
        record_stdout = commands["dynamic-" + mode + "-copy-before"]["stdout"]
        record_stderr = commands["dynamic-" + mode + "-copy-before"]["stderr"]
        assert isinstance(record_stdout, Path) and isinstance(record_stderr, Path)
        require(record_stdout.read_bytes() == b"" and record_stderr.read_bytes() == b"",
                "dynamic " + mode + " payload record output differs")
        try:
            rebuilt = copies.audit_execution_payload(product, root, executable, consumer, record_path)
        except Exception as error:
            raise ReceiptError("dynamic " + mode + " payload audit cannot be reconstructed") from error
        expected = canonical(rebuilt)
        require(before.read_bytes() == expected and after.read_bytes() == expected,
                "dynamic " + mode + " payload audit differs")
        for phase in ("before", "after"):
            audit_argv = ["python3", "-B", str(COPIES_PATH), "audit", "--product", str(product), "--execution-root", str(root),
                          "--source-consumer", str(executable), "--execution-consumer", str(consumer), "--record", str(record_path)]
            require_argv(commands["dynamic-" + mode + "-copy-audit-" + phase], audit_argv,
                         "dynamic " + mode + " payload " + phase + " audit")
            stream = commands["dynamic-" + mode + "-copy-audit-" + phase]["stdout"]
            stderr = commands["dynamic-" + mode + "-copy-audit-" + phase]["stderr"]
            assert isinstance(stream, Path) and isinstance(stderr, Path)
            require(stream.read_bytes() == expected and stderr.read_bytes() == b"",
                    "dynamic " + mode + " payload audit command differs")


def validate_report(path: Path, checkout: Path, *, require_static: bool = False) -> dict[str, object]:
    """Reconstruct one physical report; never execute the retained producer."""

    require(type(require_static) is bool, "require_static must be a boolean")
    checkout = directory(checkout, "checkout")
    path = regular(path, "stdio receipt report")
    work = directory(path.parent, "stdio receipt work directory")
    require(work.is_relative_to(checkout / ".work"), "stdio receipt report escapes checkout .work")
    report = strict_json(path, "stdio receipt report")
    expected = {"schema", "scope", "rows", "source", "workload", "products", "seals", "object_seals", "commands", "links", "execution_payloads",
                "family_completion", "promotion_ready", "public_support"}
    require(set(report) == expected and report["schema"] == SCHEMA, "stdio receipt schema differs")
    require(report["scope"] == list(SCOPE), "stdio receipt capability scope differs")
    require(report["family_completion"] is False and report["promotion_ready"] is False and report["public_support"] is False,
            "stdio receipt completion or promotion flags differ")
    product_records = report["products"]
    require(type(product_records) is dict and set(product_records) in ({"dynamic"}, {"static", "dynamic"}), "stdio receipt product roster differs")
    static = "static" in product_records
    if require_static:
        require(static, "supplied-static admission requires static and static-PIE cells")
    require(type(report["rows"]) is dict and set(report["rows"]) == {"stdio.fopen64-alias"},
            "stdio receipt row roster differs")
    same(report["rows"]["stdio.fopen64-alias"], fopen64_row(static=static),
         "stdio fopen64 macro-consumer row differs")
    probe, runner, fopen64_c, fopen64_cxx = validate_source_product_seals(checkout, work, report, static=static)
    tools = validate_tools(work, report, static=static)
    commands, workload = validate_commands(checkout, work, report, probe, runner, fopen64_c, fopen64_cxx, tools, static=static)
    validate_links(checkout, work, report, commands, workload, static=static)
    validate_payloads(work, report, commands)
    return {"schema": SCHEMA, "matrix": "supplied-static" if static else "dynamic-development",
            "cells": 6 if static else 4, "scope": list(SCOPE), "rows": report["rows"],
            "products": report["products"], "source": report["source"],
            "source_product_seal": report["seals"]["source-product-before"],
            "family_completion": False, "promotion_ready": False, "public_support": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--require-static", action="store_true")
    parsed = parser.parse_args()
    try:
        result = validate_report(parsed.report, parsed.checkout, require_static=parsed.require_static)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    except ReceiptError as error:
        print("owned stdio component receipt: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
