#!/usr/bin/env python3
"""Generate the pinned AArch64 musl ABI inventory.

The inventory deliberately has separate records for each ABI surface:

* ``libc.so.dynamic.tsv`` is the exported ELF dynamic-symbol surface.
* ``libc.a.static.tsv`` is every globally or weakly defined symbol in every
  archive member.  Duplicate names are retained because archive extraction is
  member-based and those duplicates are part of the static link surface.
* ``headers.tsv`` is every installed header from the pinned AArch64 musl
  include directory.  ``bits/`` headers are retained as arch-internal inputs
  because they carry ABI definitions even though applications do not include
  them directly.

No host libc or compiler is consulted.  The input files and binutils are
expected to come from the pinned AArch64 development image.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable, Sequence


MUSL_VERSION = "1.2.6"
MUSL_TARBALL_SHA256 = (
    "d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a"
)
ARCHITECTURE = "aarch64"
TARGET = "aarch64-unknown-linux-musl"

DYNAMIC_FILE = "libc.so.dynamic.tsv"
STATIC_FILE = "libc.a.static.tsv"
HEADERS_FILE = "headers.tsv"
INDEX_FILE = "manifest.json"
# The ABI and loader inventories intentionally share the pinned musl
# architecture directory.  Each generator owns and validates only its own
# files, while this allowlist prevents a stale or accidental file from being
# silently accepted by the ABI check.
ADJACENT_INVENTORY_FILES = frozenset({"loader-runtime.json"})

DYNAMIC_COLUMNS = (
    "name",
    "type",
    "binding",
    "visibility",
    "size",
    "value",
    "section_index",
    "version",
)
STATIC_COLUMNS = (
    "name",
    "archive_member",
    "nm_type",
    "binding",
    "value",
    "size",
)
HEADER_COLUMNS = (
    "path",
    "interface",
    "bytes",
    "lines",
    "sha256",
)

_DYNAMIC_LINE = re.compile(r"^\s*(\d+):\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\S+))?\s*$")
_ARCHIVE_LINE = re.compile(r"^(?P<archive>.+)\[(?P<member>[^]]*)\]:\s+(?P<rest>.+)$")


class InventoryError(RuntimeError):
    """An input or tool output does not describe the pinned ABI."""


def run_tool(arguments: Sequence[str]) -> str:
    try:
        result = subprocess.run(
            list(arguments),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as error:
        raise InventoryError(f"required tool not found: {arguments[0]}") from error
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip()
        raise InventoryError(
            f"command failed ({error.returncode}): {' '.join(arguments)}"
            + (f"\n{detail}" if detail else "")
        ) from error
    return result.stdout


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_reference_files(musl_root: Path) -> tuple[Path, Path, Path]:
    library_dir = musl_root / "lib"
    libc_so = library_dir / "libc.so"
    libc_a = library_dir / "libc.a"
    interpreter = library_dir / "ld-musl-aarch64.so.1"

    for path in (libc_so, libc_a, interpreter):
        if not path.exists():
            raise InventoryError(f"missing pinned musl reference: {path}")

    header = run_tool(("readelf", "-h", str(libc_so)))
    required_header_fields = {
        "Class:": "ELF64",
        "Data:": "little endian",
        "Machine:": "AArch64",
    }
    for field, expected in required_header_fields.items():
        matching = [line for line in header.splitlines() if field in line]
        if not matching or expected not in matching[0]:
            raise InventoryError(
                f"{libc_so} is not the expected AArch64 ELF ({field} {expected})"
            )

    if not interpreter.is_symlink():
        raise InventoryError(
            f"expected {interpreter} to be the pinned ld-musl-aarch64.so.1 symlink"
        )
    link_target = os.readlink(interpreter)
    resolved_target = (interpreter.parent / link_target).resolve()
    if resolved_target != libc_so.resolve():
        raise InventoryError(
            f"{interpreter} points to {link_target!r}, expected libc.so"
        )
    return libc_so, libc_a, interpreter


def parse_dynamic_symbols(libc_so: Path) -> list[dict[str, str]]:
    output = run_tool(("readelf", "--wide", "--dyn-syms", str(libc_so)))
    records: list[dict[str, str]] = []
    for line in output.splitlines():
        match = _DYNAMIC_LINE.match(line)
        if not match:
            continue
        _number, value, size, symbol_type, binding, visibility, section, raw_name = (
            match.groups()
        )
        if raw_name is None or section == "UND":
            continue
        if binding not in {"GLOBAL", "WEAK"}:
            continue
        # DEFAULT and PROTECTED symbols are externally observable.  HIDDEN and
        # INTERNAL entries, if present in .dynsym, are not dynamic ABI exports.
        if visibility in {"HIDDEN", "INTERNAL"}:
            continue

        name = raw_name
        version = "-"
        if "@@" in raw_name:
            name, suffix = raw_name.split("@@", 1)
            version = "@@" + suffix
        elif "@" in raw_name:
            name, suffix = raw_name.split("@", 1)
            version = "@" + suffix

        records.append(
            {
                "name": name,
                "type": symbol_type,
                "binding": binding,
                "visibility": visibility,
                "size": size,
                "value": value,
                "section_index": section,
                "version": version,
            }
        )

    records.sort(key=lambda record: tuple(record[column] for column in DYNAMIC_COLUMNS))
    keys = [(record["name"], record["version"]) for record in records]
    if len(keys) != len(set(keys)):
        raise InventoryError("duplicate dynamic symbol name/version records")
    if not records:
        raise InventoryError("readelf produced no public dynamic symbols")
    return records


def parse_static_symbols(libc_a: Path) -> list[dict[str, str]]:
    output = run_tool(
        ("nm", "-A", "-g", "--defined-only", "--format=posix", str(libc_a))
    )
    records: list[dict[str, str]] = []
    for line in output.splitlines():
        if not line:
            continue
        match = _ARCHIVE_LINE.match(line)
        if not match:
            raise InventoryError(f"unparseable nm output: {line}")
        fields = match.group("rest").split()
        if len(fields) < 3:
            raise InventoryError(f"unparseable nm record: {line}")
        name, nm_type, value = fields[:3]
        size = fields[3] if len(fields) > 3 else "-"
        if len(nm_type) != 1:
            raise InventoryError(f"unexpected nm symbol type in: {line}")
        binding = "WEAK" if nm_type in {"W", "V", "w", "v"} else "GLOBAL"
        records.append(
            {
                "name": name,
                "archive_member": match.group("member"),
                "nm_type": nm_type,
                "binding": binding,
                "value": value,
                "size": size,
            }
        )

    records.sort(key=lambda record: tuple(record[column] for column in STATIC_COLUMNS))
    if not records:
        raise InventoryError("nm produced no defined static symbols")
    return records


def parse_headers(musl_root: Path) -> list[dict[str, str]]:
    """Inventory every file in the installed target header tree.

    ``bits`` is an implementation namespace, but its files are included in
    the inventory because public headers include them and their AArch64
    contents determine ABI layouts and constants.  Recording every regular
    file also makes an accidental extra or missing installed header visible
    in ``--check``.
    """

    include_dir = musl_root / "include"
    if not include_dir.is_dir():
        raise InventoryError(f"missing pinned musl include directory: {include_dir}")

    records: list[dict[str, str]] = []
    for path in sorted(include_dir.rglob("*")):
        if path.is_dir():
            continue
        if path.is_symlink():
            raise InventoryError(f"unexpected symlink in installed headers: {path}")
        if not path.is_file():
            raise InventoryError(f"unexpected non-regular header entry: {path}")

        relative = path.relative_to(include_dir).as_posix()
        interface = "arch-internal" if relative.startswith("bits/") else "public"
        data = path.read_bytes()
        records.append(
            {
                "path": relative,
                "interface": interface,
                "bytes": str(len(data)),
                "lines": str(data.count(b"\n")),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )

    if not records:
        raise InventoryError(f"pinned musl include directory is empty: {include_dir}")
    return records


def archive_members(libc_a: Path) -> list[str]:
    output = run_tool(("ar", "t", str(libc_a)))
    members = [line for line in output.splitlines() if line]
    if not members:
        raise InventoryError("ar produced no archive members")
    return members


def tsv_bytes(columns: Iterable[str], records: Iterable[dict[str, str]]) -> bytes:
    lines = ["\t".join(columns)]
    lines.extend("\t".join(record[column] for column in columns) for record in records)
    return ("\n".join(lines) + "\n").encode("utf-8")


def index_bytes(
    libc_so: Path,
    libc_a: Path,
    interpreter: Path,
    dynamic: list[dict[str, str]],
    static: list[dict[str, str]],
    headers: list[dict[str, str]],
    members: list[str],
) -> bytes:
    index = {
        "architecture": ARCHITECTURE,
        "baseline": "musl " + MUSL_VERSION,
        "dynamic": {
            "columns": list(DYNAMIC_COLUMNS),
            "file": DYNAMIC_FILE,
            "records": len(dynamic),
            "unique_names": len({record["name"] for record in dynamic}),
        },
        "generator": {
            "dynamic_command": "readelf --wide --dyn-syms",
            "static_command": "nm -A -g --defined-only --format=posix",
            "archive_command": "ar t",
            "script": "compat/scripts/generate-aarch64-musl-abi.py",
            "schema": "crabc.aarch64-musl-abi/v1",
        },
        "headers": {
            "arch_internal_records": sum(
                record["interface"] == "arch-internal" for record in headers
            ),
            "columns": list(HEADER_COLUMNS),
            "file": HEADERS_FILE,
            "public_records": sum(
                record["interface"] == "public" for record in headers
            ),
            "records": len(headers),
            "schema": "crabc.aarch64-musl-headers/v1",
        },
        "interpreter": {
            "file": "lib/ld-musl-aarch64.so.1",
            "relationship": "symlink to libc.so",
            # Keep the manifest independent of the installation prefix.  The
            # input check above has already established that the symlink
            # resolves to this installation's sibling libc.so.
            "target": "libc.so",
            "sha256": sha256(interpreter),
        },
        "musl_source": {
            "release": MUSL_VERSION,
            "tarball_sha256": MUSL_TARBALL_SHA256,
            "libc_so": {
                "file": "lib/libc.so",
                "sha256": sha256(libc_so),
            },
            "libc_a": {
                "file": "lib/libc.a",
                "sha256": sha256(libc_a),
            },
        },
        "static": {
            "archive_members": len(members),
            "columns": list(STATIC_COLUMNS),
            "file": STATIC_FILE,
            "records": len(static),
            "unique_names": len({record["name"] for record in static}),
        },
        "target": TARGET,
    }
    return (json.dumps(index, indent=2, sort_keys=True) + "\n").encode("utf-8")


def generate(musl_root: Path) -> dict[str, bytes]:
    libc_so, libc_a, interpreter = require_reference_files(musl_root)
    dynamic = parse_dynamic_symbols(libc_so)
    static = parse_static_symbols(libc_a)
    headers = parse_headers(musl_root)
    members = archive_members(libc_a)
    return {
        DYNAMIC_FILE: tsv_bytes(DYNAMIC_COLUMNS, dynamic),
        STATIC_FILE: tsv_bytes(STATIC_COLUMNS, static),
        HEADERS_FILE: tsv_bytes(HEADER_COLUMNS, headers),
        INDEX_FILE: index_bytes(
            libc_so, libc_a, interpreter, dynamic, static, headers, members
        ),
    }


def check(output_dir: Path, musl_root: Path) -> int:
    with tempfile.TemporaryDirectory(prefix="crabc-aarch64-abi-"):
        generated = generate(musl_root)
        failures: list[str] = []
        for filename, content in generated.items():
            expected_path = output_dir / filename
            if not expected_path.exists():
                failures.append(f"missing {expected_path}")
                continue
            if expected_path.read_bytes() != content:
                failures.append(f"different {expected_path}")
        unexpected = sorted(
            path.name
            for path in output_dir.glob("*")
            if (
                path.is_file()
                and path.name not in generated
                and path.name not in ADJACENT_INVENTORY_FILES
            )
        )
        if unexpected:
            failures.append("unexpected files: " + ", ".join(unexpected))
        if failures:
            for failure in failures:
                print(f"ABI inventory check failed: {failure}", file=sys.stderr)
            return 1
    print(f"ABI inventory is reproducible: {output_dir}")
    return 0


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    default_output = Path(__file__).resolve().parents[1] / "abi/musl-1.2.6/aarch64"
    parser.add_argument(
        "--musl-root",
        type=Path,
        default=Path("/opt/musl-1.2.6"),
        help="pinned musl installation (default: /opt/musl-1.2.6)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=default_output,
        help=f"inventory directory (default: {default_output})",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="regenerate in a temporary directory and compare all checked-in files",
    )
    args = parser.parse_args(argv)

    try:
        if args.check:
            return check(args.output_dir, args.musl_root)
        files = generate(args.musl_root)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for filename, content in files.items():
            (args.output_dir / filename).write_bytes(content)
        print(f"generated AArch64 musl {MUSL_VERSION} ABI inventory: {args.output_dir}")
        for filename, content in files.items():
            print(f"  {filename}: {len(content)} bytes")
        return 0
    except InventoryError as error:
        print(f"ABI inventory error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
