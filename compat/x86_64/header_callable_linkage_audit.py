#!/usr/bin/env python3
"""Audit archive extraction for the generated x86 public callable inventory.

The static export ratchet is only one input.  This harness consumes the
compiler-derived candidate declarations, lists the finite set that does not
appear in that ratchet, and then asks ``ld`` to extract the candidate archive
for each ratcheted external name.  It never uses ``--whole-archive``: a name
must cause ordinary archive-member selection or it is reported as unresolved.

An incomplete result is intentional evidence for the still-planned header
closure.  It is not a waived pass, a family transition, or public-support
evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
INVENTORY_PATH = ROOT / "compat" / "x86_64" / "header_callable_inventory.json"
STATIC_EXPORTS_PATH = ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
INVENTORY_SCHEMA = "crabc.x86_64-header-callable-inventory-report/v1"
SCHEMA = "crabc.x86_64-header-callable-linkage-audit/v1"


class LinkageAuditError(ValueError):
    """The linkage audit input does not identify a safe finite audit."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LinkageAuditError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LinkageAuditError(f"cannot load inventory {path}: {error}") from error
    require(isinstance(value, dict), "inventory root is not an object")
    require(value.get("schema") == INVENTORY_SCHEMA, "inventory schema is not supported")
    return value


def load_static_exports(path: Path) -> list[str]:
    try:
        values = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise LinkageAuditError(f"cannot read static export ratchet: {error}") from error
    exports = [value.strip() for value in values if value.strip() and not value.startswith("#")]
    require(len(exports) == len(set(exports)), "static export ratchet contains duplicates")
    return sorted(exports)


def candidate_external_symbols(inventory: Mapping[str, Any]) -> list[str]:
    records = inventory.get("callables")
    require(isinstance(records, list), "inventory callables are missing")
    symbols: set[str] = set()
    for index, record in enumerate(records):
        require(isinstance(record, Mapping), f"inventory callable[{index}] is invalid")
        if record.get("tree") != "candidate" or record.get("classification") != "external":
            continue
        require(record.get("declaration_kind") == "function", f"candidate external callable[{index}] is not a function")
        name = record.get("name")
        require(isinstance(name, str) and name, f"candidate external callable[{index}] has no name")
        symbols.add(name)
    require(symbols, "inventory has no candidate external callable names")
    return sorted(symbols)


def inventory_static_export_sha256(inventory: Mapping[str, Any]) -> str:
    inputs = inventory.get("inputs")
    require(isinstance(inputs, Mapping), "inventory inputs are missing")
    value = inputs.get("static_c_abi_exports_sha256")
    require(isinstance(value, str) and len(value) == 64, "inventory static-export input digest is invalid")
    return value


def global_defined_symbols(path: Path, nm: str) -> set[str]:
    result = subprocess.run(
        [nm, "-g", "--defined-only", "--format=posix", str(path)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    require(result.returncode == 0, f"nm could not read {path}: {result.stderr.strip()}")
    symbols: set[str] = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1] in {"T", "W"}:
            symbols.add(fields[0])
    return symbols


def extract_one(archive: Path, symbol: str, linker: str, nm: str, work_dir: Path) -> dict[str, str]:
    output = work_dir / f"extract-{len(symbol)}-{hashlib.sha256(symbol.encode('utf-8')).hexdigest()[:16]}.o"
    result = subprocess.run(
        [linker, "-r", "--no-undefined", f"--undefined={symbol}", "-o", str(output), str(archive)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        diagnostic = next((line.strip() for line in result.stderr.splitlines() if line.strip()), "linker produced no diagnostic")
        return {"status": "link-failed", "symbol": symbol, "detail": diagnostic}
    if symbol not in global_defined_symbols(output, nm):
        return {
            "status": "not-extracted",
            "symbol": symbol,
            "detail": "ordinary archive extraction did not define the requested external function",
        }
    return {"status": "extracted", "symbol": symbol, "detail": "ordinary ld -r extraction defined the requested function"}


def audit(
    inventory: Mapping[str, Any],
    static_exports: Sequence[str],
    archive: Path | None,
    *,
    linker: str = "ld",
    nm: str = "nm",
) -> dict[str, Any]:
    expected_digest = inventory_static_export_sha256(inventory)
    # A stale inventory might hide new ratchet entries or assert a complement
    # from a different archive selection, so reject it before calculating.
    actual_digest = hashlib.sha256(("\n".join(static_exports) + "\n").encode("utf-8")).hexdigest()
    # The inventory generator hashes the complete ratchet file (including its
    # contract comments); callers which only pass symbols must replace this
    # assertion below with the exact file check in `audit_inventory_file`.
    external = candidate_external_symbols(inventory)
    export_set = set(static_exports)
    complement = sorted(set(external) - export_set)
    linked_symbols = sorted(set(external) & export_set)
    if archive is None:
        extraction = [
            {
                "detail": "archive was not supplied; extraction remains planned",
                "status": "not-run",
                "symbol": symbol,
            }
            for symbol in linked_symbols
        ]
    else:
        require(archive.is_file() and not archive.is_symlink(), f"candidate archive is unsafe: {archive}")
        require(shutil.which(linker) is not None, f"linker is unavailable: {linker}")
        require(shutil.which(nm) is not None, f"nm is unavailable: {nm}")
        with tempfile.TemporaryDirectory(prefix="crabc-x86-header-callable-linkage.") as temporary:
            work_dir = Path(temporary)
            extraction = [extract_one(archive, symbol, linker, nm, work_dir) for symbol in linked_symbols]
    counts = Counter(record["status"] for record in extraction)
    incomplete_reasons: list[str] = []
    if complement:
        incomplete_reasons.append("static export complement is nonempty")
    if counts.get("not-run", 0):
        incomplete_reasons.append("archive extraction was not run")
    if counts.get("not-extracted", 0) or counts.get("link-failed", 0):
        incomplete_reasons.append("one or more ratcheted external callables did not extract from the candidate archive")
    return {
        "schema": SCHEMA,
        "inventory_schema": INVENTORY_SCHEMA,
        "inventory_static_export_digest": expected_digest,
        "static_export_symbol_digest": actual_digest,
        "scope": {
            "family_promotion": False,
            "public_support": False,
            "uses_whole_archive": False,
        },
        "external_callable_count": len(external),
        "ratcheted_external_callable_count": len(linked_symbols),
        "static_export_complement": {
            "kind": "candidate-external-callables-absent-from-static-c-abi-export-ratchet",
            "members": complement,
        },
        "archive_extraction": extraction,
        "summary": {
            "complete": not incomplete_reasons,
            "extraction_status_counts": dict(sorted(counts.items())),
            "incomplete_reasons": incomplete_reasons,
            "static_export_complement_count": len(complement),
        },
    }


def audit_inventory_file(
    inventory_path: Path,
    static_exports_path: Path,
    archive: Path | None,
    *,
    linker: str = "ld",
    nm: str = "nm",
) -> dict[str, Any]:
    inventory = load_json(inventory_path)
    exports = load_static_exports(static_exports_path)
    require(
        inventory_static_export_sha256(inventory) == sha256_file(static_exports_path),
        "inventory was generated against a different static export ratchet; regenerate it before audit",
    )
    return audit(inventory, exports, archive, linker=linker, nm=nm)


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, default=INVENTORY_PATH)
    parser.add_argument("--static-exports", type=Path, default=STATIC_EXPORTS_PATH)
    parser.add_argument("--archive", type=Path, help="candidate libc.a to extract normally")
    parser.add_argument("--linker", default="ld")
    parser.add_argument("--nm", default="nm")
    parser.add_argument("--output", type=Path, help="write canonical JSON to this path")
    parser.add_argument("--allow-incomplete", action="store_true", help="return zero after writing an explicitly incomplete report")
    parsed = parser.parse_args(arguments)
    report = audit_inventory_file(
        parsed.inventory,
        parsed.static_exports,
        parsed.archive,
        linker=parsed.linker,
        nm=parsed.nm,
    )
    rendered = canonical_json(report)
    if parsed.output is None:
        sys.stdout.write(rendered)
    else:
        require(not parsed.output.is_symlink(), f"audit output path is a symlink: {parsed.output}")
        parsed.output.write_text(rendered, encoding="utf-8")
    if report["summary"]["complete"] or parsed.allow_incomplete:
        return 0
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LinkageAuditError as error:
        raise SystemExit(f"x86 header callable linkage audit: ERROR: {error}") from error
