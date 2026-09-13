#!/usr/bin/env python3
"""Verify the exact shared-only visibility boundary for bundled mimalloc v3."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "libc/src/c_abi/x86_64/owned_mimalloc_hidden.list"
CONTRACT_SHA256 = "cd537f6579018bbba79d831ee148a7b07f51a0f3bda538a27970724751d78873"
CONTRACT_COUNT = 424
BASELINE_EXTRA_COUNT = 475
REMAINING_EXTRA_COUNT = 51
PUBLIC_ALLOCATORS = {
    "malloc": "WEAK",
    "calloc": "GLOBAL",
    "realloc": "GLOBAL",
    "free": "GLOBAL",
    "memalign": "GLOBAL",
    "posix_memalign": "GLOBAL",
    "aligned_alloc": "GLOBAL",
    "malloc_usable_size": "GLOBAL",
    "reallocarray": "GLOBAL",
    "valloc": "GLOBAL",
}

sys.path.insert(0, str(ROOT / "compat/x86_64"))
import native_abi_inventory as inventory  # noqa: E402
import owned_dynamic_qualification as qualification  # noqa: E402


class EvidenceError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def identity(path: Path, description: str) -> dict[str, object]:
    try:
        details = path.lstat()
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise EvidenceError(f"{description} is missing or unsafe: {path}") from error
    require(stat.S_ISREG(details.st_mode) and not path.is_symlink() and resolved == path,
            f"{description} is not a physical regular file")
    return {
        "path": str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "size": details.st_size,
        "mode": stat.S_IMODE(details.st_mode),
    }


def run(argv: list[str], description: str) -> tuple[str, dict[str, object]]:
    completed = subprocess.run(argv, check=False, capture_output=True, text=True)
    record = {"argv": argv, "status": completed.returncode, "stderr": completed.stderr}
    require(completed.returncode == 0, f"{description} failed: {completed.stderr.strip()}")
    require(not completed.stderr, f"{description} emitted a diagnostic: {completed.stderr.strip()}")
    return completed.stdout, record


def contract_members() -> tuple[list[str], dict[str, object]]:
    record = identity(CONTRACT, "mimalloc hidden-export contract")
    require(record["sha256"] == CONTRACT_SHA256, "mimalloc hidden-export contract digest drifted")
    members = CONTRACT.read_text(encoding="utf-8").splitlines()
    require(len(members) == CONTRACT_COUNT and members == sorted(set(members)),
            "mimalloc hidden-export contract member/order drifted")
    require(all(member.replace("_", "a").isalnum() and not member[0].isdigit() for member in members),
            "mimalloc hidden-export contract contains an invalid linker name")
    return members, record


def dynamic_symbols(readelf: str, library: Path) -> tuple[dict[str, dict[str, object]], dict[str, object]]:
    raw, command = run([readelf, "--dyn-syms", "--wide", str(library)], "shared dynsym inspection")
    try:
        rows = inventory.parse_dynamic_symbols(raw)
    except inventory.InventoryError as error:
        raise EvidenceError(f"shared dynsym cannot be parsed: {error}") from error
    result = {str(row["name"]): row for row in rows}
    require(len(result) == len(rows), "shared dynsym duplicates a public name")
    return result, {"identity": identity(library, "shared libc"), "command": command, "rows": rows}


def complete_shared_symbol_tables(readelf: str, library: Path) -> tuple[dict[str, list[dict[str, object]]], dict[str, object]]:
    """Keep both ELF symbol tables so local version-script results remain visible."""

    raw, command = run([readelf, "--syms", "--wide", str(library)], "complete shared symbol inspection")
    try:
        tables = inventory.parse_elf_symbol_tables(raw)
    except inventory.InventoryError as error:
        raise EvidenceError(f"complete shared symbol table cannot be parsed: {error}") from error
    selected: dict[str, list[dict[str, object]]] = {}
    for table in tables:
        name = str(table["name"])
        if name in {".dynsym", ".symtab"}:
            require(name not in selected, f"shared ELF repeats {name}")
            rows = table["rows"]
            require(isinstance(rows, list), f"shared ELF {name} rows are malformed")
            selected[name] = rows
    require(set(selected) == {".dynsym", ".symtab"},
            "shared ELF must retain exactly one dynsym and one symtab")
    return selected, {"identity": identity(library, "shared libc complete symbols"), "command": command,
                      "dynsym_rows": selected[".dynsym"], "symtab_rows": selected[".symtab"]}


def one_named_defined_row(rows: list[dict[str, object]], name: str, description: str) -> dict[str, object]:
    matches = [row for row in rows if row.get("name") == name and row.get("section_index") != "UND"]
    require(len(matches) == 1, f"{description} must contain exactly one defined {name} row")
    return matches[0]


def validate_local_contract_rows(
    members: list[str], dynsym_rows: list[dict[str, object]], shared_symtab_rows: list[dict[str, object]],
    static_provider_rows: list[dict[str, object]],
) -> list[str]:
    """Require the selected C member to stay static-global but shared-local."""

    dynsym_names = {row.get("name") for row in dynsym_rows}
    leaked = sorted(set(members) & {name for name in dynsym_names if isinstance(name, str)})
    require(not leaked, f"mimalloc local-contract name still has a dynsym row: {leaked}")
    for member in members:
        shared = one_named_defined_row(shared_symtab_rows, member, "shared symtab")
        provider = one_named_defined_row(static_provider_rows, member, "static allocator provider")
        require(shared.get("binding") == "LOCAL", f"shared symtab {member} is not LOCAL")
        for field in ("raw_name", "name", "version", "version_default", "type"):
            require(shared.get(field) == provider.get(field),
                    f"shared symtab {member} spelling/version/kind differs from the static allocator provider")
        if shared.get("type") in {"OBJECT", "TLS"}:
            require(shared.get("size") == provider.get("size") and shared.get("size_bytes") == provider.get("size_bytes"),
                    f"shared symtab {member} object size differs from the static allocator provider")
    return members


def visible_symtab_rows(rows: list[dict[str, object]], description: str) -> dict[tuple[object, object, object], dict[str, object]]:
    selected = [
        row for row in rows
        if row.get("name") is not None and row.get("section_index") != "UND"
        and row.get("binding") in {"GLOBAL", "WEAK", "UNIQUE"}
        and row.get("visibility") in {"DEFAULT", "PROTECTED"}
    ]
    result = {(row["name"], row["version"], row["version_default"]): row for row in selected}
    require(len(result) == len(selected), f"{description} repeats a visible shared symtab identity")
    return result


def validate_visible_symtab_delta(
    baseline_rows: list[dict[str, object]], current_rows: list[dict[str, object]], hidden: set[str],
) -> list[str]:
    """Reject a version script that localizes any name beyond the exact list."""

    baseline = visible_symtab_rows(baseline_rows, "historical shared symtab")
    current = visible_symtab_rows(current_rows, "fresh shared symtab")
    expected = {key: row for key, row in baseline.items() if key[0] not in hidden}
    require(set(current) == set(expected), "shared symtab hid or added names beyond the exact mimalloc local contract")
    for key, before in expected.items():
        after = current[key]
        for field in ("raw_name", "type", "binding", "visibility", "version", "version_default"):
            require(after[field] == before[field], f"surviving shared symtab metadata changed for {key[0]}")
        if before["type"] in {"OBJECT", "TLS"}:
            require(after["size"] == before["size"] and after["size_bytes"] == before["size_bytes"],
                    f"surviving shared symtab data size changed for {key[0]}")
    return sorted(key[0] for key in baseline if key not in current)


def static_allocator_provider(
    ar: str, nm: str, readelf: str, archive: Path, scratch: Path, hidden: set[str]
) -> dict[str, object]:
    listing, ar_command = run([ar, "t", str(archive)], "static archive member inspection")
    members = [member for member in listing.splitlines() if member]
    backend = [member for member in members if member.endswith("-static.o")]
    require(len(backend) == 1, "static archive must retain exactly one bundled allocator member")
    extracted = scratch / backend[0]
    completed = subprocess.run([ar, "p", str(archive), backend[0]], check=False, capture_output=True)
    require(completed.returncode == 0 and not completed.stderr,
            "static allocator-member extraction failed")
    extracted.write_bytes(completed.stdout)
    raw, nm_command = run([nm, "--defined-only", "--extern-only", str(extracted)],
                          "static allocator-provider inspection")
    defined = {line.split()[-1] for line in raw.splitlines() if line.split()}
    missing = sorted(hidden - defined)
    require(not missing, f"static allocator provider lost hidden shared-only names: {missing}")
    symbols_raw, symbols_command = run([readelf, "--syms", "--wide", str(extracted)],
                                       "static allocator-provider complete symbol inspection")
    try:
        symbol_tables = inventory.parse_elf_symbol_tables(symbols_raw)
    except inventory.InventoryError as error:
        raise EvidenceError(f"static allocator-provider symbol table cannot be parsed: {error}") from error
    provider_tables = [table for table in symbol_tables if table["name"] == ".symtab"]
    require(len(provider_tables) == 1, "static allocator provider must retain exactly one symtab")
    provider_rows = provider_tables[0]["rows"]
    require(isinstance(provider_rows, list), "static allocator provider symtab rows are malformed")
    return {
        "archive": identity(archive, "static libc archive"),
        "member": backend[0],
        "member_identity": identity(extracted, "extracted static allocator member"),
        "archive_command": ar_command,
        "provider_command": nm_command,
        "symbol_table_command": symbols_command,
        "symbol_table_rows": provider_rows,
        "hidden_contract_members": len(hidden),
    }


def baseline_symbols(report_path: Path) -> tuple[dict[str, dict[str, object]], set[str], dict[str, object]]:
    report_identity = identity(report_path, "historical pre-change ABI report")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        rows = report["inventories"]["candidate"]["shared"]["dynamic_symbols"]
        extras = report["triage"]["shared_dynamic"]["extra"]
        candidate_build = report["product_provenance"]["candidate_build"]
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise EvidenceError("historical pre-change ABI report has an unexpected schema") from error
    require(isinstance(rows, list) and isinstance(extras, list) and isinstance(candidate_build, dict),
            "historical pre-change ABI report has malformed symbol evidence")
    symbols = {str(row["name"]): row for row in rows if isinstance(row, dict) and "name" in row}
    require(len(symbols) == len(rows), "historical pre-change dynsym duplicates a public name")
    extra_names = {str(row["name"]) for row in extras if isinstance(row, dict) and "name" in row}
    require(len(extra_names) == BASELINE_EXTRA_COUNT,
            f"historical pre-change ABI report must retain {BASELINE_EXTRA_COUNT} extra libc symbols")
    return symbols, extra_names, {"identity": report_identity, "candidate_build": candidate_build}


def metadata_signature(row: dict[str, object]) -> tuple[object, ...]:
    signature = tuple(row[key] for key in ("type", "binding", "visibility", "version", "version_default"))
    return signature + ((row["size"],) if row["type"] in {"OBJECT", "TLS"} else (None,))


def collector_source_identity() -> dict[str, object]:
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=False, capture_output=True, text=True)
    tree = subprocess.run(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, check=False, capture_output=True, text=True)
    status = subprocess.run(["git", "status", "--short"], cwd=ROOT, check=False, capture_output=True, text=True)
    require(revision.returncode == 0 and tree.returncode == 0 and status.returncode == 0,
            "cannot record validator collector source identity")
    return {"revision": revision.stdout.strip(), "tree": tree.stdout.strip(),
            "source_sha256": qualification.source_digest(), "status": status.stdout}


def dynamic_product_source_binding(library: Path, collector: dict[str, object]) -> dict[str, object]:
    state_path = library.parents[2] / "share/crabc/dynamic-product-state.json"
    state_identity = identity(state_path, "dynamic product source state")
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
        source = state["source_sha256"]
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise EvidenceError("dynamic product source state is malformed") from error
    require(isinstance(source, str) and len(source) == 64 and all(character in "0123456789abcdef" for character in source),
            "dynamic product source state has an invalid source digest")
    return {"state": state_identity, "source_sha256": source,
            "matches_collector": source == collector["source_sha256"]}


def validate(args: argparse.Namespace) -> dict[str, object]:
    hidden_members, contract = contract_members()
    hidden = set(hidden_members)
    baseline, baseline_extra, baseline_record = baseline_symbols(args.baseline_report)
    baseline_actual, baseline_actual_record = dynamic_symbols(args.readelf, args.baseline_shared)
    require(baseline_actual == baseline,
            "historical report dynsym does not reconstruct its retained shared libc product")
    require(hidden <= baseline_extra, "historical ABI report does not classify every contract name as an extra export")
    require(hidden <= set(baseline), "historical libc product did not expose every contract name")

    collector = collector_source_identity()
    product_source = dynamic_product_source_binding(args.dynamic_shared, collector)
    baseline_tables, baseline_tables_record = complete_shared_symbol_tables(args.readelf, args.baseline_shared)
    current_tables, current_tables_record = complete_shared_symbol_tables(args.readelf, args.dynamic_shared)
    current, current_record = dynamic_symbols(args.readelf, args.dynamic_shared)
    expected_names = set(baseline) - hidden
    require(set(current) == expected_names,
            "shared dynsym changed by names beyond the exact 424-name mimalloc local contract")
    metadata_drift = sorted(
        name for name in expected_names if metadata_signature(current[name]) != metadata_signature(baseline[name])
    )
    require(not metadata_drift,
            f"shared dynsym metadata changed outside the exact mimalloc local contract: {metadata_drift}")
    require(not (hidden & set(current)), "shared libc still exports a mimalloc local-contract name")

    remaining_extra = baseline_extra - hidden
    require(len(remaining_extra) == REMAINING_EXTRA_COUNT,
            f"expected exactly {REMAINING_EXTRA_COUNT} non-mimalloc extra exports after subtraction")
    require(remaining_extra <= set(current), "one of the retained non-mimalloc exports disappeared")
    for name, binding in PUBLIC_ALLOCATORS.items():
        require(name in current and name in baseline, f"public allocator entry {name} disappeared")
        require(current[name]["type"] == "FUNC" and current[name]["binding"] == binding
                and current[name]["visibility"] == "DEFAULT",
                f"public allocator entry {name} binding/visibility drifted")
        require(metadata_signature(current[name]) == metadata_signature(baseline[name]),
                f"public allocator entry {name} metadata changed")

    scratch = args.output.parent / (args.output.name + ".static-provider")
    scratch.mkdir(mode=0o700)
    static = static_allocator_provider(args.ar, args.nm, args.readelf, args.static_archive, scratch, hidden)
    localized = validate_local_contract_rows(
        hidden_members, current_tables[".dynsym"], current_tables[".symtab"], static["symbol_table_rows"]
    )
    hidden_delta = validate_visible_symtab_delta(
        baseline_tables[".symtab"], current_tables[".symtab"], hidden
    )
    require(hidden_delta == hidden_members, "shared symtab did not localize exactly the contract roster")
    provenance_path = args.dynamic_shared.parents[2] / "share/crabc/libc-shared.provenance.json"
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        visibility = provenance["shared_mimalloc_hidden_exports"]
        link = provenance["libc_shared_link_command"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise EvidenceError("fresh dynamic product lacks the exact mimalloc visibility provenance") from error
    require(visibility["source"] == {
        "path": "libc/src/c_abi/x86_64/owned_mimalloc_hidden.list",
        "sha256": CONTRACT_SHA256,
        "mode": 0o644,
    }, "fresh dynamic product records a different mimalloc visibility source")
    require(visibility["member_count"] == CONTRACT_COUNT and visibility["members"] == hidden_members
            and visibility["linker_policy"] == "exact-local-symbols",
            "fresh dynamic product mimalloc visibility provenance drifted")
    selected = provenance.get("selected_members")
    require(isinstance(selected, dict) and static["member"] in selected,
            "fresh shared link did not record the selected static allocator member")
    require(selected[static["member"]] == static["member_identity"]["sha256"],
            "fresh shared link selected allocator member differs from the static provider")
    static["shared_link_member_sha256"] = selected[static["member"]]
    require("--version-script=$BUILD/libc-mimalloc-hidden.exports" in link,
            "fresh shared libc link did not use the exact mimalloc version script")
    require(not any("--exclude-libs" in argument for argument in link),
            "fresh shared libc link used a broad archive visibility policy")
    return {
        "schema": "crabc.x86_64-owned-mimalloc-export-visibility/v1",
        "status": "component-pass-not-qualification",
        "contract": {"identity": contract, "member_count": CONTRACT_COUNT},
        "collector": collector,
        "historical_prechange": {**baseline_record, "shared": baseline_actual_record,
                                  "symbol_tables": baseline_tables_record,
                                  "leaked_contract_members": len(hidden)},
        "fresh_products": {"shared": current_record, "symbol_tables": current_tables_record,
                           "static": static, "dynamic_product_source": product_source,
                           "shared_visibility_provenance": visibility},
        "dynsym_delta": {"removed": hidden_members, "remaining_extra_exports": sorted(remaining_extra),
                         "remaining_extra_count": len(remaining_extra)},
        "symtab_local_contract": {"members": localized, "member_count": len(localized)},
        "limits": [
            "The historical ae0fcc22 product is a pre-change comparison input, not a source match for the fresh product.",
            "The collector and dynamic-product source identities are recorded separately; a mismatch is retained evidence, not current-source proof.",
            "This proves the shared-only visibility boundary and selected allocator provider; it does not qualify the runtime, allocator, or platform.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-report", type=Path, required=True)
    parser.add_argument("--baseline-shared", type=Path, required=True)
    parser.add_argument("--static-archive", type=Path, required=True)
    parser.add_argument("--dynamic-shared", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ar", default="ar")
    parser.add_argument("--nm", default="nm")
    parser.add_argument("--readelf", default="readelf")
    args = parser.parse_args()
    try:
        require(args.output.parent.is_dir(), "output parent must exist")
        require(not args.output.exists() and not args.output.is_symlink(), "output already exists")
        report = validate(args)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except EvidenceError as error:
        print(f"owned mimalloc export visibility: {error}", file=sys.stderr)
        return 1
    print(f"owned mimalloc export visibility: PASS; evidence: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
