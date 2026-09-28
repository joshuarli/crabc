#!/usr/bin/env python3
"""Reread the complete installed allocator policy comparison from retained bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
from typing import Any

import native_shadow_receipt
import owned_dynamic_elf


RUNNER = "owned-native-allocator-policy"
ROOT = Path(__file__).resolve().parents[2]
PROGRAMS = ("basic", "observability", "policy")
SOURCE_PATHS = {
    "basic": "compat/x86_64/libc_allocator_basic_runtime_v1_probe.c",
    "observability": "tests/fixtures/allocator_observability_test.c",
    "policy": "compat/x86_64/owned_native_allocator_policy_probe.c",
}
COMPILE_MODES = ("oracle", "static", "static-pie", "dynamic-pie", "dynamic-non-pie")
COMMON_FLAGS = ["-std=c11", "-D_GNU_SOURCE", "-pthread", "-fno-builtin"]
MODES = ("oracle", "static", "static-pie", "kernel-pie", "direct-pie",
         "kernel-non-pie", "direct-non-pie")
PARAMETERS = {
    "CASE_TIMEOUT": "120", "PROGRAMS": "basic,observability,policy",
    "STATIC_MODES": "static,static-pie",
    "DYNAMIC_MODES": "kernel-pie,direct-pie,kernel-non-pie,direct-non-pie",
    "ENVIRONMENT": "empty-with-pinned-PATH",
}
SYSROOT_PRODUCTS = {
    "static-manifest", "static-libc-provenance", "static-libc-archive",
    "dynamic-manifest", "dynamic-product-state", "dynamic-libc-provenance",
    "dynamic-libc", "dynamic-loader",
    "static-driver", "static-crt1", "static-rcrt1", "static-crti", "static-crtn", "static-builtins",
    "dynamic-driver", "dynamic-crt1", "dynamic-scrt1", "dynamic-crti", "dynamic-crtn",
    "dynamic-attach", "dynamic-builtins",
    "oracle-wrapper", "oracle-gcc", "oracle-specs", "oracle-musl-libc",
    "oracle-musl-libssp", "oracle-musl-libpthread", "oracle-libgcc-eh",
    "oracle-musl-scrt1", "oracle-musl-crti", "oracle-musl-crtn",
    "oracle-crtbegin", "oracle-crtend", "oracle-libgcc",
}
PROGRAM_PRODUCTS = {
    *(f"oracle-{program}" for program in PROGRAMS),
    *(f"{mode}-{program}" for mode in ("static", "static-pie") for program in PROGRAMS),
    *(f"dynamic-{kind}-{program}" for kind in ("pie", "non-pie") for program in PROGRAMS),
}
OPTIONAL_PRODUCTS = {"static-build", "dynamic-build"}
INPUT_PRODUCTS = {
    *(f"source-{program}" for program in PROGRAMS),
    *(f"compile-{mode}-{program}" for mode in COMPILE_MODES for program in PROGRAMS),
    *(f"object-{mode}-{program}" for mode in COMPILE_MODES for program in PROGRAMS),
    *(f"link-oracle-{program}" for program in PROGRAMS),
    *(f"trace-oracle-{program}" for program in PROGRAMS),
    *(f"{kind}-{mode}-{program}" for kind in ("link", "map", "trace")
      for mode in ("static", "static-pie") for program in PROGRAMS),
    *(f"{kind}-dynamic-{mode}-{program}" for kind in ("link", "elf", "map")
      for mode in ("pie", "non-pie") for program in PROGRAMS),
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise native_shadow_receipt.ReceiptError(f"{RUNNER}: {message}")


def _json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise native_shadow_receipt.ReceiptError(f"{RUNNER}: unreadable {path.name}: {error}") from error
    _require(isinstance(value, dict), f"{path.name} is not an object")
    return value


def _product_source_digest(root: Path) -> str:
    """Recompute the installed dynamic product's content, name, and mode seal."""
    completed = subprocess.run(
        ("git", "-c", "safe.directory=*", "-C", str(root), "ls-files", "-z",
         "--cached", "--others", "--exclude-standard"),
        capture_output=True, check=False,
    )
    _require(completed.returncode == 0, "cannot enumerate product source inputs")
    names = sorted(set(completed.stdout.split(b"\0")) - {b""})
    digest = hashlib.sha256()
    for name in names:
        path = root / os.fsdecode(name)
        mode = path.lstat().st_mode
        data = os.fsencode(os.readlink(path)) if stat.S_ISLNK(mode) else path.read_bytes()
        digest.update(name + b"\0" + str(stat.S_IMODE(mode)).encode() + b"\0")
        digest.update(hashlib.sha256(data).digest())
    return digest.hexdigest()


def _elf_mode(path: Path) -> tuple[int, str | None]:
    """Project only ELF type and interpreter without trusting filename suffixes."""
    data = path.read_bytes()
    _require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01", f"{path.name} is not ELF64 x86-64")
    kind, machine = struct.unpack_from("<HH", data, 16)
    _require(machine == 62, f"{path.name} is not x86-64")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    _require(phentsize == 56 and phnum > 0 and phoff + phentsize * phnum <= len(data),
             f"{path.name} has an invalid program header table")
    interpreters = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        if struct.unpack_from("<I", data, offset)[0] == 3:
            start = struct.unpack_from("<Q", data, offset + 8)[0]
            size = struct.unpack_from("<Q", data, offset + 32)[0]
            _require(size > 1 and start + size <= len(data) and data[start + size - 1] == 0,
                     f"{path.name} has an invalid interpreter")
            interpreters.append(data[start:start + size - 1].decode("utf-8", errors="replace"))
    _require(len(interpreters) <= 1, f"{path.name} has multiple interpreters")
    return kind, interpreters[0] if interpreters else None


def _static_main_symbol(path: Path) -> tuple[int, int]:
    """Read the one defined application entry symbol from an ELF symbol table."""
    data = path.read_bytes()
    _require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01",
             f"{path.name} lacks an ELF64 symbol table")
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    section_size, section_count = struct.unpack_from("<HH", data, 58)
    _require(section_size == 64 and section_count > 0 and
             section_offset + section_size * section_count <= len(data),
             f"{path.name} has an invalid section table")
    sections = []
    for index in range(section_count):
        offset = section_offset + index * section_size
        kind = struct.unpack_from("<I", data, offset + 4)[0]
        file_offset, size = struct.unpack_from("<QQ", data, offset + 24)
        link = struct.unpack_from("<I", data, offset + 40)[0]
        entry_size = struct.unpack_from("<Q", data, offset + 56)[0]
        _require(file_offset + size <= len(data) or kind == 8,
                 f"{path.name} has an out-of-bounds section")
        sections.append((kind, file_offset, size, link, entry_size))
    tables = [section for section in sections if section[0] == 2]
    _require(len(tables) == 1, f"{path.name} lacks one static symbol table")
    _, offset, size, string_index, entry_size = tables[0]
    _require(entry_size == 24 and size % entry_size == 0 and string_index < len(sections),
             f"{path.name} has an invalid static symbol table")
    string_kind, string_offset, string_size, _, _ = sections[string_index]
    _require(string_kind == 3, f"{path.name} has no linked symbol string table")
    strings = data[string_offset:string_offset + string_size]
    matches = []
    for entry in range(offset, offset + size, entry_size):
        name, info, _, section, value, symbol_size = struct.unpack_from("<IBBHQQ", data, entry)
        if info == 0x12 and section != 0 and strings[name:name + 5] == b"main\0":
            matches.append((value, symbol_size))
    _require(len(matches) == 1 and matches[0][1] > 0,
             f"{path.name} lacks one defined global main function")
    return matches[0]


def _static_map_main(path: Path, object_name: str) -> tuple[int, int]:
    """Read the application's linked main address and extent from the LLD map."""
    main = []
    application_text = []
    for line in path.read_text().splitlines():
        fields = line.split()
        if len(fields) != 5:
            continue
        try:
            address, size = int(fields[0], 16), int(fields[2], 16)
        except ValueError:
            continue
        if fields[4] == "main":
            main.append((address, size))
        elif fields[4].endswith(f"/{object_name}:(.text)"):
            application_text.append((address, size))
    _require(len(main) == 1 and len(application_text) == 1,
             f"{path.name} lacks one application main and text section")
    address, size = main[0]
    text_address, text_size = application_text[0]
    _require(size > 0 and text_address <= address and address + size <= text_address + text_size,
             f"{path.name} main is outside the retained application object")
    return address, size


def _check_products(root: Path, read: native_shadow_receipt.Receipt) -> None:
    retained = read.path.parent
    product = retained / "products"
    static_manifest = _json(product / "static-manifest")
    static_provenance = _json(product / "static-libc-provenance")
    dynamic_manifest = _json(product / "dynamic-manifest")
    dynamic_state = _json(product / "dynamic-product-state")
    dynamic_provenance = _json(product / "dynamic-libc-provenance")
    _require(static_manifest.get("allocator_backend") == "native-shadow" and
             dynamic_state.get("allocator_backend") == "native-shadow" and
             dynamic_provenance.get("allocator_backend") == "native-shadow",
             "installed products do not select the native-shadow allocator")
    installed = static_manifest.get("installed")
    static_files = installed.get("files") if isinstance(installed, dict) else None
    dynamic_files = dynamic_manifest.get("files")
    state_files = dynamic_state.get("payload_files")
    _require(isinstance(static_files, dict) and isinstance(dynamic_files, dict) and
             isinstance(state_files, dict), "installed product file inventories are missing")
    for name, installed_path in (
        ("static-libc-archive", "usr/lib/libc.a"),
        ("static-libc-provenance", "share/crabc/libc-static.provenance.json"),
        ("static-driver", "bin/crabc-cc"),
        ("static-crt1", "usr/lib/crt1.o"),
        ("static-rcrt1", "usr/lib/rcrt1.o"),
        ("static-crti", "usr/lib/crti.o"),
        ("static-crtn", "usr/lib/crtn.o"),
        ("static-builtins", "usr/lib/libcrabc-builtins.a"),
    ):
        _require(static_files.get(installed_path) == read.products[name]["sha256"],
                 f"static manifest does not identify {name}")
    for name, installed_path in (
        ("dynamic-libc", "usr/lib/libc.so"),
        ("dynamic-loader", "lib/ld-crabc-x86_64.so.1"),
        ("dynamic-libc-provenance", "share/crabc/libc-shared.provenance.json"),
        ("dynamic-product-state", "share/crabc/dynamic-product-state.json"),
        ("dynamic-driver", "bin/crabc-cc-dynamic"),
        ("dynamic-crt1", "usr/lib/crt1.o"),
        ("dynamic-scrt1", "usr/lib/Scrt1.o"),
        ("dynamic-crti", "usr/lib/crti.o"),
        ("dynamic-crtn", "usr/lib/crtn.o"),
        ("dynamic-attach", "usr/lib/crabc-dynamic-attach.o"),
        ("dynamic-builtins", "usr/lib/libcrabc-builtins.a"),
    ):
        _require(dynamic_files.get(installed_path) == read.products[name]["sha256"],
                 f"dynamic manifest does not identify {name}")
        if name != "dynamic-product-state":
            _require(state_files.get(installed_path) == read.products[name]["sha256"],
                     f"dynamic product state does not identify {name}")
    archive = static_provenance.get("archive")
    _require(isinstance(archive, dict) and archive.get("sha256") == read.products["static-libc-archive"]["sha256"],
             "static libc provenance does not identify the retained archive")
    allocator = static_provenance.get("allocator_backend")
    native = dynamic_provenance.get("native_allocator")
    _require(isinstance(allocator, dict) and isinstance(native, dict) and
             native.get("path") == "crabc-mimalloc/UPSTREAM.md" and
             allocator.get("upstream_sha256") == native.get("sha256") and
             native.get("sha256") == hashlib.sha256((root / native["path"]).read_bytes()).hexdigest(),
             "static and dynamic libc provenance disagree on the native allocator source")
    _require(dynamic_state.get("schema") == "crabc.x86_64-owned-dynamic-materialization/v1" and
             dynamic_state.get("modes") == ["dynamic-pie", "dynamic-non-pie", "dynamic-shared-object"],
             "dynamic product state does not identify the installed modes")
    _require(dynamic_state.get("source_sha256") == _product_source_digest(root),
             "dynamic product source digest differs from the checkout")
    for program in PROGRAMS:
        for mode, expected_type in (("oracle", 2), ("static", 2), ("static-pie", 3)):
            kind, interpreter = _elf_mode(product / f"{mode}-{program}")
            _require((kind, interpreter) == (expected_type, None),
                     f"{mode}-{program} has a wrong static ELF link mode")
        for kind in ("pie", "non-pie"):
            name = f"dynamic-{kind}-{program}"
            elf_type, interpreter = _elf_mode(product / name)
            _require(elf_type == (3 if kind == "pie" else 2) and
                     interpreter == "/lib/ld-crabc-x86_64.so.1",
                     f"{name} has a wrong dynamic ELF link mode")
            try:
                facts = owned_dynamic_elf.inspect(product / name)
            except owned_dynamic_elf.InspectionError as error:
                raise native_shadow_receipt.ReceiptError(f"{RUNNER}: {name}: {error}") from error
            _require(facts["needed"] == ["libc.so"] and not facts["symbol_versioning"],
                     f"{name} has foreign or missing dynamic libc linkage")


def _check_link_inputs(root: Path, read: native_shadow_receipt.Receipt) -> None:
    retained = read.path.parent / "products"
    hashes = {name: record["sha256"] for name, record in read.products.items()}
    for program in PROGRAMS:
        source = SOURCE_PATHS[program]
        _require(hashes[f"source-{program}"] == hashlib.sha256((root / source).read_bytes()).hexdigest(),
                 f"{program} retained source differs from the compiled checkout input")
        for mode in COMPILE_MODES:
            record = _json(retained / f"compile-{mode}-{program}")
            selection = (["-static", "-fno-pie", "-no-pie"] if mode == "oracle" else
                         ["--" + mode] if mode.startswith("dynamic-") else ["-" + mode])
            compiler = ("oracle-wrapper" if mode == "oracle" else
                        "dynamic-driver" if mode.startswith("dynamic-") else "static-driver")
            expected = {
                "schema": "crabc.x86_64-allocator-policy-compile/v1",
                "program": program, "mode": mode, "source_path": source,
                "source_sha256": hashes[f"source-{program}"],
                "object_sha256": hashes[f"object-{mode}-{program}"],
                "compiler_sha256": hashes[compiler],
                "flags": selection + COMMON_FLAGS + ["-c"],
            }
            if mode == "oracle":
                expected["compiler_inputs"] = {
                    "oracle-gcc": {"path": "/usr/bin/gcc", "sha256": hashes["oracle-gcc"]},
                    "oracle-specs": {"path": "/opt/musl-1.2.6/lib/musl-gcc.specs",
                                     "sha256": hashes["oracle-specs"]},
                }
            _require(record == expected, f"{mode}-{program} compile input identity differs")
        _check_oracle_link(retained, hashes, program)
        for mode in ("static", "static-pie"):
            _check_static_link(retained, hashes, program, mode)
        for mode in ("pie", "non-pie"):
            _check_dynamic_link(retained, hashes, program, mode)


def _check_oracle_link(retained: Path, hashes: dict[str, str], program: str) -> None:
    record = _json(retained / f"link-oracle-{program}")
    runtime = record.get("runtime_inputs")
    expected_paths = {
        "oracle-musl-scrt1": "/opt/musl-1.2.6/lib/Scrt1.o",
        "oracle-musl-crti": "/opt/musl-1.2.6/lib/crti.o",
        "oracle-musl-libc": "/opt/musl-1.2.6/lib/libc.a",
        "oracle-musl-libssp": "/opt/musl-1.2.6/lib/libssp_nonshared.a",
        "oracle-musl-libpthread": "/opt/musl-1.2.6/lib/libpthread.a",
        "oracle-musl-crtn": "/opt/musl-1.2.6/lib/crtn.o",
    }
    _require(isinstance(runtime, dict) and set(runtime) == set(expected_paths) | {
        "oracle-crtbegin", "oracle-crtend", "oracle-libgcc", "oracle-libgcc-eh"},
        f"oracle-{program} lacks pinned musl and compiler runtime inputs")
    for name, identity in runtime.items():
        _require(isinstance(identity, dict) and set(identity) == {"path", "sha256"} and
                 identity["sha256"] == hashes[name], f"oracle-{program} {name} identity differs")
        path = identity["path"]
        if name in expected_paths:
            _require(path == expected_paths[name], f"oracle-{program} {name} is not pinned musl")
        else:
            _require(isinstance(path, str) and path.startswith("/usr/lib/gcc/") and
                     Path(path).name == {"oracle-crtbegin": "crtbeginS.o", "oracle-crtend": "crtendS.o",
                                        "oracle-libgcc": "libgcc.a", "oracle-libgcc-eh": "libgcc_eh.a"}[name],
                     f"oracle-{program} {name} is not the selected compiler input")
    object_path = record.get("object_path")
    output_path = record.get("output_path")
    _require(isinstance(object_path, str) and isinstance(output_path, str) and
             Path(object_path).name == f"object-oracle-{program}.o" and
             Path(output_path).name == f"oracle-{program}.exe" and
             Path(object_path).parent == Path(output_path).parent,
             f"oracle-{program} executed path differs from its compiled object")
    expected = {
        "schema": "crabc.x86_64-allocator-policy-oracle-link/v1", "program": program,
        "mode": "static-et-exec", "compiler_sha256": hashes["oracle-wrapper"],
        "object_sha256": hashes[f"object-oracle-{program}"],
        "object_path": object_path,
        "output_sha256": hashes[f"oracle-{program}"],
        "output_path": output_path,
        "trace_sha256": hashes[f"trace-oracle-{program}"],
        "compiler_inputs": {
            "oracle-gcc": {"path": "/usr/bin/gcc", "sha256": hashes["oracle-gcc"]},
            "oracle-specs": {"path": "/opt/musl-1.2.6/lib/musl-gcc.specs", "sha256": hashes["oracle-specs"]},
        },
        "runtime_inputs": runtime,
        "flags": ["-static", "-fno-pie", "-no-pie", *COMMON_FLAGS],
    }
    _require(record == expected, f"oracle-{program} link input identity differs")
    trace = (retained / f"trace-oracle-{program}").read_text(errors="replace").splitlines()
    expected_trace = [runtime[name]["path"] for name in (
        "oracle-musl-scrt1", "oracle-musl-crti", "oracle-crtbegin"
    )] + [object_path] + [runtime[name]["path"] for name in (
        "oracle-musl-libssp", "oracle-libgcc", "oracle-libgcc-eh",
        "oracle-musl-libpthread", "oracle-musl-libc",
        "oracle-libgcc", "oracle-libgcc-eh", "oracle-musl-libpthread", "oracle-musl-libc",
        "oracle-crtend", "oracle-musl-crtn",
    )]
    _require(trace == expected_trace, f"oracle-{program} linker trace has missing or ambient inputs")


def _check_static_link(retained: Path, hashes: dict[str, str], program: str, mode: str) -> None:
    name = f"{mode}-{program}"
    record = _json(retained / f"link-{name}")
    declared = record.get("mode")
    _require(isinstance(declared, dict) and declared.get("id") ==
             ("static-et-exec" if mode == "static" else "static-pie") and
             declared.get("elf_type") == ("ET_EXEC" if mode == "static" else "ET_DYN") and
             declared.get("crt_object") == ("crt1.o" if mode == "static" else "rcrt1.o") and
             declared.get("interpreter") == "absent", f"{name} static link mode differs")
    _require(record.get("schema") == 1 and record.get("format") == "crabc-x86-64-sealed-static-driver-v1" and
             record.get("target") == "x86_64-unknown-linux-musl", f"{name} static link receipt differs")
    _require(isinstance(record.get("output"), dict) and
             record["output"].get("sha256") == hashes[name] and
             Path(str(record["output"].get("path"))).name == f"{name}.exe",
             f"{name} static link does not identify its executed ELF")
    for sidecar in ("map", "trace"):
        _require(isinstance(record.get(sidecar), dict) and
                 record[sidecar].get("sha256") == hashes[f"{sidecar}-{name}"] and
                 bool((retained / f"{sidecar}-{name}").stat().st_size),
                 f"{name} static {sidecar} differs from the linker output")
    runtime = {
        "crt-entry": ("static-crt1" if mode == "static" else "static-rcrt1", "usr/lib/" +
                      ("crt1.o" if mode == "static" else "rcrt1.o")),
        "crt-prologue": ("static-crti", "usr/lib/crti.o"),
        "libc": ("static-libc-archive", "usr/lib/libc.a"),
        "builtins": ("static-builtins", "usr/lib/libcrabc-builtins.a"),
        "crt-epilogue": ("static-crtn", "usr/lib/crtn.o"),
    }
    inputs = record.get("input_receipts")
    _require(isinstance(inputs, list) and len(inputs) == 6 and all(isinstance(item, dict) for item in inputs),
             f"{name} static link lacks exact inputs")
    by_role = {item.get("role"): item for item in inputs}
    _require(set(by_role) == set(runtime) | {"application"}, f"{name} static input roles differ")
    for role, (product, path) in runtime.items():
        _require(by_role[role] == {"role": role, "path": path, "sha256": hashes[product]},
                 f"{name} static {role} input differs")
    application = by_role["application"]
    _require(application.get("sha256") == hashes[f"object-{name}"] and
             Path(str(application.get("path"))).name == f"object-{name}.o",
             f"{name} static application object differs")
    # The output hash in the link receipt can be rewritten with a substituted
    # same-mode ELF. Its main function must also be the one placed from the
    # retained application object at the address recorded by the linker map.
    object_main = _static_main_symbol(retained / f"object-{name}")
    map_main = _static_map_main(retained / f"map-{name}", f"object-{name}.o")
    output_main = _static_main_symbol(retained / name)
    _require(output_main == map_main and output_main[1] == object_main[1],
             f"{name} ELF main differs from retained map or application object")


def _check_dynamic_link(retained: Path, hashes: dict[str, str], program: str, mode: str) -> None:
    name = f"dynamic-{mode}-{program}"
    record = _json(retained / f"link-{name}")
    link_mode = "pie" if mode == "pie" else "exec"
    _require(record.get("schema") == 2 and record.get("mode") == link_mode and
             record.get("manifest_sha256") == hashes["dynamic-manifest"] and
             record.get("output_sha256") == hashes[name] and
             Path(str(record.get("output_path"))).name == f"{name}.exe" and
             record.get("application_dsos") == {},
             f"{name} dynamic link receipt does not identify the executed product")
    runtime = {
        "crti.o": "dynamic-crti", "libc.so": "dynamic-libc", "crtn.o": "dynamic-crtn",
        "Scrt1.o" if mode == "pie" else "crt1.o": "dynamic-scrt1" if mode == "pie" else "dynamic-crt1",
        "crabc-dynamic-attach.o": "dynamic-attach", "libcrabc-builtins.a": "dynamic-builtins",
        f"object-{name}.o": f"object-{name}",
    }
    inputs = record.get("input_receipts")
    _require(isinstance(inputs, list) and len(inputs) == len(runtime) and
             all(isinstance(item, dict) and set(item) == {"path", "sha256"} for item in inputs),
             f"{name} dynamic link lacks exact inputs")
    by_name = {Path(item["path"]).name: item for item in inputs}
    _require(set(by_name) == set(runtime), f"{name} dynamic link input roster differs")
    for basename, product in runtime.items():
        _require(by_name[basename]["sha256"] == hashes[product],
                 f"{name} dynamic {basename} input differs")
    command = record.get("link_command")
    trace = record.get("link_trace")
    _require(isinstance(command, list) and isinstance(trace, list) and
             all(item["path"] in command for item in inputs) and
             all(item["path"] in trace for item in inputs if Path(item["path"]).name != "libcrabc-builtins.a"),
             f"{name} dynamic linker command or trace omits an input")
    inspection = _json(retained / f"elf-{name}")
    _require(inspection.get("output_sha256") == hashes[name] and
             inspection.get("link_map", {}).get("sha256") == hashes[f"map-{name}"] and
             inspection.get("declared", {}).get("mode") == link_mode and
             inspection.get("facts") == owned_dynamic_elf.inspect(retained / name),
             f"{name} ELF inspection or link map differs from the executed product")


def read_policy_receipt(root: Path) -> native_shadow_receipt.Receipt:
    read = native_shadow_receipt.read_receipt(root, RUNNER)
    _require(dict(read.parameters) == PARAMETERS, "receipt has non-canonical policy parameters")
    expected_ids = [f"{mode}-{program}" for program in PROGRAMS for mode in MODES] + ["runner"]
    by_id = {case["id"]: case for case in read.cases}
    _require([case["id"] for case in read.cases] == expected_ids, "receipt lacks the exact 22-case matrix")
    names = set(read.products)
    _require(SYSROOT_PRODUCTS | PROGRAM_PRODUCTS | INPUT_PRODUCTS <= names and
             names <= SYSROOT_PRODUCTS | PROGRAM_PRODUCTS | INPUT_PRODUCTS | OPTIONAL_PRODUCTS,
             "receipt lacks executed products or source-built provenance")
    retained = read.path.parent
    logs = retained / "logs"
    for program in PROGRAMS:
        for mode in MODES:
            case_id = f"{mode}-{program}"
            case = by_id[case_id]
            _require(set(case["logs"]) == {f"{case_id}.stdout", f"{case_id}.stderr", f"{case_id}.status"},
                     f"{case_id} lacks exact stdout, stderr, or status evidence")
            _require((logs / f"{case_id}.status").read_bytes() == b"0\n", f"{case_id} has a wrong raw status")
            _require((logs / f"{case_id}.stderr").read_bytes() == b"", f"{case_id} wrote stderr")
            output = (logs / f"{case_id}.stdout").read_bytes()
            if program != "observability":
                _require(bool(output), f"{case_id} has an empty policy transcript")
            if mode != "oracle":
                _require(output == (logs / f"oracle-{program}.stdout").read_bytes(),
                         f"{case_id} transcript differs from pinned musl")
    _require(set(by_id["runner"]["logs"]) == {"runner.status"} and
             (logs / "runner.status").read_bytes() == b"0\n", "runner status evidence differs")
    _check_products(root, read)
    _check_link_inputs(root, read)
    return read


def main() -> int:
    parser = argparse.ArgumentParser(description="reread the installed allocator policy receipt")
    parser.add_argument("--root", type=Path, default=ROOT)
    arguments = parser.parse_args()
    try:
        read = read_policy_receipt(arguments.root)
    except (native_shadow_receipt.ReceiptError, OSError, ValueError) as error:
        print(f"native allocator policy receipt: {error}", file=sys.stderr)
        return 1
    print(f"native allocator policy receipt: PASS ({len(read.cases)} retained cases; {read.path})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
