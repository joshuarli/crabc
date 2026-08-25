#!/usr/bin/env python3
"""Check the source-only Linux/x86-64 mimalloc C-header inventory.

This deliberately records only the uncommented ``mi_decl_export`` function
declarations in the pinned ``include/mimalloc.h`` source header.  It is not an
ELF-symbol inventory: declarations can be platform-conditional or lack a
definition in a particular upstream library build.  In particular, this
checker makes no claim about the Rust engine, a C adapter, crabc-libc exports,
or behavioral verification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
import tomllib
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "compat/allocator/x86_64-api-v3.5.0.json"
UPSTREAMS_PATH = ROOT / "compat/upstreams.toml"
DEFAULT_ARCHIVE_PATH = ROOT / "compat/allocator/.cache/mimalloc-3.5.0.tar.gz"
HEADER_MEMBER = "include/mimalloc.h"


class InventoryError(RuntimeError):
    """The checked-in source declaration contract no longer matches its pin."""


@dataclass(frozen=True)
class Declaration:
    """One uncommented exported-function declaration in the source header."""

    name: str
    source_line: int

    def as_json(self) -> dict[str, object]:
        return {"name": self.name, "source_line": self.source_line}


def sha256_bytes(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def load_mimalloc_pin() -> dict[str, object]:
    upstreams = tomllib.loads(UPSTREAMS_PATH.read_text(encoding="utf-8"))
    mimalloc = upstreams.get("mimalloc")
    if not isinstance(mimalloc, dict):
        raise InventoryError("compat/upstreams.toml has no [mimalloc] pin")
    required = {"archive_root", "revision", "sha256", "version"}
    if set(mimalloc) < required:
        raise InventoryError("[mimalloc] pin is missing required archive fields")
    return mimalloc


def read_pinned_header(archive_path: Path, pin: dict[str, object]) -> bytes:
    if not archive_path.is_file():
        raise InventoryError(
            f"pinned mimalloc archive is unavailable: {archive_path}; run the "
            "native allocator oracle first to populate compat/allocator/.cache"
        )

    expected_archive_hash = pin["sha256"]
    if not isinstance(expected_archive_hash, str):
        raise InventoryError("mimalloc archive checksum is not a string")
    actual_archive_hash = sha256_bytes(archive_path.read_bytes())
    if actual_archive_hash != expected_archive_hash:
        raise InventoryError(
            f"mimalloc archive checksum mismatch: expected {expected_archive_hash}, "
            f"got {actual_archive_hash}"
        )

    archive_root = pin["archive_root"]
    if not isinstance(archive_root, str):
        raise InventoryError("mimalloc archive root is not a string")
    expected_member = f"{archive_root}/{HEADER_MEMBER}"
    with tarfile.open(archive_path, "r:gz") as archive:
        members = [member for member in archive.getmembers() if member.name == expected_member]
        if len(members) != 1 or not members[0].isreg():
            raise InventoryError(
                f"pinned archive must contain one regular {expected_member} member"
            )
        source = archive.extractfile(members[0])
        if source is None:
            raise InventoryError(f"cannot read {expected_member} from pinned archive")
        return source.read()


def strip_c_comments(source: str) -> str:
    """Replace C comments with spaces while retaining every original newline."""

    output: list[str] = []
    index = 0
    state = "code"
    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if current == "/" and following == "/":
                output.extend((" ", " "))
                index += 2
                state = "line-comment"
                continue
            if current == "/" and following == "*":
                output.extend((" ", " "))
                index += 2
                state = "block-comment"
                continue
            output.append(current)
            if current == '"':
                state = "string"
            elif current == "'":
                state = "character"
        elif state == "line-comment":
            output.append("\n" if current == "\n" else " ")
            if current == "\n":
                state = "code"
        elif state == "block-comment":
            if current == "*" and following == "/":
                output.extend((" ", " "))
                index += 2
                state = "code"
                continue
            output.append("\n" if current == "\n" else " ")
        else:
            output.append(current)
            if current == "\\" and following:
                output.append(following)
                index += 2
                continue
            if (state == "string" and current == '"') or (
                state == "character" and current == "'"
            ):
                state = "code"
        index += 1
    if state == "block-comment":
        raise InventoryError("unterminated block comment in mimalloc.h")
    return "".join(output)


def mask_preprocessor_directives(source: str) -> str:
    """Mask directives without changing offsets used for source line anchors."""

    lines = source.splitlines(keepends=True)
    return "".join(
        "".join("\n" if character == "\n" else " " for character in line)
        if line.lstrip().startswith("#")
        else line
        for line in lines
    )


def source_declarations(header: str) -> list[Declaration]:
    """Return header-order external-function declarations, never object exports."""

    source = mask_preprocessor_directives(strip_c_comments(header))
    declarations: list[Declaration] = []
    cursor = 0
    while True:
        export_start = source.find("mi_decl_export", cursor)
        if export_start < 0:
            break
        statement_end = source.find(";", export_start)
        if statement_end < 0:
            raise InventoryError("unterminated mi_decl_export declaration in mimalloc.h")
        statement = source[export_start:statement_end]
        name_match = re.search(r"\b(mi_[A-Za-z0-9_]+)\s*\(", statement)
        if name_match is None:
            raise InventoryError("mi_decl_export declaration has no mi_* function name")

        # Attribute macros such as `mi_attr_alloc_size(1)` appear after the
        # declaration name.  The first `mi_*(` token after `mi_decl_export` is
        # therefore the function being declared, not an attribute macro.
        name = name_match.group(1)
        source_line = source.count("\n", 0, export_start + name_match.start(1)) + 1
        declarations.append(Declaration(name=name, source_line=source_line))
        cursor = statement_end + 1

    names = [declaration.name for declaration in declarations]
    if len(names) != len(set(names)):
        duplicates = sorted(name for name in set(names) if names.count(name) > 1)
        raise InventoryError(f"duplicate source declarations: {', '.join(duplicates)}")
    return declarations


def declaration_names_hash(declarations: list[Declaration]) -> str:
    contents = "\n".join(declaration.name for declaration in declarations).encode("utf-8")
    return sha256_bytes(contents)


def expected_contract(header: bytes, pin: dict[str, object]) -> dict[str, object]:
    source = header.decode("utf-8")
    declarations = source_declarations(source)
    return {
        "format": 1,
        "kind": "mimalloc-x86_64-source-c-api-inventory",
        "maturity": "bounded-source-inventory-foundation",
        "profile": "linux-x86_64-mimalloc-source-c-api",
        "scope": {
            "included_declaration_form": (
                "uncommented semicolon-terminated mi_decl_export declarations "
                "whose declared name is an mi_* function"
            ),
            "included_header": HEADER_MEMBER,
            "excluded_headers": [
                "include/mimalloc-new-delete.h",
                "include/mimalloc-override.h",
                "include/mimalloc-stats.h",
            ],
            "exclusion_reason": (
                "This bounded foundation records only the base C-header declaration "
                "surface. C++ helpers, source-rewrite macros, statistics headers, "
                "types, options, and macros require separate target-local contracts."
            ),
        },
        "target_context": {
            "architecture": "x86_64",
            "endianness": "little",
            "rust_target": "x86_64-unknown-linux-musl",
            "system": "linux",
        },
        "upstream": {
            "archive_root": pin["archive_root"],
            "revision": pin["revision"],
            "version": pin["version"],
        },
        "source": {
            "archive_sha256": pin["sha256"],
            "header_sha256": sha256_bytes(header),
            "member": HEADER_MEMBER,
        },
        "classification": {
            "name": "source-declared-c-function",
            "meaning": (
                "Each entry is declared by the pinned source header. It is not a "
                "claim that a Linux/x86_64 mimalloc object defines the symbol."
            ),
        },
        "declarations": [declaration.as_json() for declaration in declarations],
        "declaration_count": len(declarations),
        "declaration_names_sha256": declaration_names_hash(declarations),
        "integration_boundary": {
            "crabc_libc_exports": "not-assessed",
            "crabc_mimalloc_implementation": "not-assessed",
            "native_object_export_inventory": "not-assessed",
            "public_c_api_adapter": "not-assessed",
            "verification": (
                "This contract verifies only the pinned-source declaration inventory. "
                "It does not establish implementation, linkability, behavioral parity, "
                "stress coverage, or performance qualification."
            ),
        },
    }


def load_contract() -> dict[str, object]:
    try:
        contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise InventoryError(f"missing checked-in inventory: {CONTRACT_PATH}") from error
    if not isinstance(contract, dict):
        raise InventoryError("x86_64 API inventory must be a JSON object")
    return contract


def check_contract(archive_path: Path) -> None:
    pin = load_mimalloc_pin()
    header = read_pinned_header(archive_path, pin)
    observed = expected_contract(header, pin)
    checked_in = load_contract()
    if checked_in != observed:
        raise InventoryError(
            "x86_64 source C API inventory drifted from pinned mimalloc v3.5.0; "
            "review the source boundary and update the checked-in contract deliberately"
        )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--archive",
        type=Path,
        default=DEFAULT_ARCHIVE_PATH,
        help="path to the SHA-256-pinned mimalloc v3.5.0 archive",
    )
    parser.add_argument(
        "--print-observed",
        action="store_true",
        help="print the source-derived contract instead of checking the checked-in artifact",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    pin = load_mimalloc_pin()
    header = read_pinned_header(arguments.archive, pin)
    if arguments.print_observed:
        print(json.dumps(expected_contract(header, pin), indent=2))
        return 0
    check_contract(arguments.archive)
    print("allocator x86_64 source C API inventory: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except InventoryError as error:
        raise SystemExit(f"allocator x86_64 source C API inventory: FAIL: {error}")
