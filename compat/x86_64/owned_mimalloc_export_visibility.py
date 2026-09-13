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


def static_allocator_provider(ar: str, nm: str, archive: Path, scratch: Path, hidden: set[str]) -> dict[str, object]:
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
    return {
        "archive": identity(archive, "static libc archive"),
        "member": backend[0],
        "member_identity": identity(extracted, "extracted static allocator member"),
        "archive_command": ar_command,
        "provider_command": nm_command,
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
    return tuple(row[key] for key in ("type", "binding", "visibility", "version", "version_default"))


def validate(args: argparse.Namespace) -> dict[str, object]:
    hidden_members, contract = contract_members()
    hidden = set(hidden_members)
    baseline, baseline_extra, baseline_record = baseline_symbols(args.baseline_report)
    baseline_actual, baseline_actual_record = dynamic_symbols(args.readelf, args.baseline_shared)
    require(baseline_actual == baseline,
            "historical report dynsym does not reconstruct its retained shared libc product")
    require(hidden <= baseline_extra, "historical ABI report does not classify every contract name as an extra export")
    require(hidden <= set(baseline), "historical libc product did not expose every contract name")

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

    scratch = args.output.parent / "static-provider"
    scratch.mkdir(mode=0o700)
    static = static_allocator_provider(args.ar, args.nm, args.static_archive, scratch, hidden)
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
        "historical_prechange": {**baseline_record, "shared": baseline_actual_record,
                                  "leaked_contract_members": len(hidden)},
        "fresh_products": {"shared": current_record, "static": static,
                           "shared_visibility_provenance": visibility},
        "dynsym_delta": {"removed": hidden_members, "remaining_extra_exports": sorted(remaining_extra),
                         "remaining_extra_count": len(remaining_extra)},
        "limits": [
            "The historical ae0fcc22 product is a pre-change comparison input, not a source match for the fresh product.",
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
