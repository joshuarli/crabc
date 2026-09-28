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
}
PROGRAM_PRODUCTS = {
    *(f"oracle-{program}" for program in PROGRAMS),
    *(f"{mode}-{program}" for mode in ("static", "static-pie") for program in PROGRAMS),
    *(f"dynamic-{kind}-{program}" for kind in ("pie", "non-pie") for program in PROGRAMS),
}
OPTIONAL_PRODUCTS = {"static-build", "dynamic-build"}


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
    ):
        _require(static_files.get(installed_path) == read.products[name]["sha256"],
                 f"static manifest does not identify {name}")
    for name, installed_path in (
        ("dynamic-libc", "usr/lib/libc.so"),
        ("dynamic-loader", "lib/ld-crabc-x86_64.so.1"),
        ("dynamic-libc-provenance", "share/crabc/libc-shared.provenance.json"),
        ("dynamic-product-state", "share/crabc/dynamic-product-state.json"),
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


def read_policy_receipt(root: Path) -> native_shadow_receipt.Receipt:
    read = native_shadow_receipt.read_receipt(root, RUNNER)
    _require(dict(read.parameters) == PARAMETERS, "receipt has non-canonical policy parameters")
    expected_ids = [f"{mode}-{program}" for program in PROGRAMS for mode in MODES] + ["runner"]
    by_id = {case["id"]: case for case in read.cases}
    _require([case["id"] for case in read.cases] == expected_ids, "receipt lacks the exact 22-case matrix")
    names = set(read.products)
    _require(SYSROOT_PRODUCTS | PROGRAM_PRODUCTS <= names and
             names <= SYSROOT_PRODUCTS | PROGRAM_PRODUCTS | OPTIONAL_PRODUCTS,
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
