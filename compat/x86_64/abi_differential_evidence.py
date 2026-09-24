#!/usr/bin/env python3
"""Bind one current-source ABI-differential evidence set for its gate.

The `compat.abi-differential` gate family names six retained leaf reports:
the native ABI inventory, complete ELF facts, the public-dynamic ratchet, the
compiler declaration inventory, the native selection report, and the ordinary
public-data link receipt. Every one of them is replayed only against explicit
products (and, for selection, explicit companion receipts), so a gate reader
cannot validate one of them from its path alone.

`assemble` records which products and reports form one set and writes
`abi-evidence.json`; `validate` replays every leaf reader against it. The receipt holds
only checkout-relative paths, byte hashes and the collecting source revision;
it restates no leaf result. `qualification_gates.py` publishes it and, on
every evaluation, calls the per-leaf functions below, which rerun the owning
leaf reader. A component that no longer replays, a changed report byte, or a
product built from another revision is an unmet condition of that one row.

The set must be current: the static preparation, the inventory and ELF-fact
collectors, and the receipt itself all name the clean revision being
evaluated. Historical products remain useful development observations but
cannot satisfy a gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))

import native_abi_inventory as inventory  # noqa: E402

SCHEMA = "crabc.x86_64-abi-differential-evidence/v1"
RECEIPT_NAME = "abi-evidence.json"
OUTPUT_PARENT = ROOT / ".work" / "x86_64" / "abi-differential"

INPUT_KINDS = {"static_product": "directory", "static_preparation": "file", "dynamic_product": "directory"}
REPORTS = (
    "native_abi_inventory",
    "native_abi_elf_facts",
    "native_abi_ratchet",
    "header_declaration_inventory",
    "native_abi_selection",
    "public_data_ordinary_link",
)
# Optional selection companions, keyed by their `native_abi_selection`
# `validate_report` keyword. The declaration and public-data reports are
# already set members above and are passed from there.
SELECTION_COMPANIONS = (
    "ordinary_declaration_abi_report",
    "loader_debug_report",
    "compiler_helper_aggregate_report",
    "loader_runtime_registry_report",
    "pthread_alias_contract_report",
    "prepared_worker_tls_report",
    "errno_storage_lifecycle_report",
    "native_c_allocator_boundary_report",
    "stdio_alias_contract_report",
    "crt_startup_report",
    "syscall_alias_contract_report",
    "utmpx_receipt_report",
    "pthread_timed_feature_report",
    "resolver_alias_receipt_report",
    "locale_alias_contract_report",
    "headers_layouts_aggregate_report",
    "text_family_semantic_report",
    "posix_sysv_signal_admission_report",
    "bsd_random_receipt_report",
    "public_data_declaration_runtime_report",
    "loader_structural_owner_receipt_report",
)


class EvidenceError(RuntimeError):
    """The evidence set is malformed, stale, or a leaf reader rejected it."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _checkout_path(value: object, kind: str, description: str) -> Path:
    """Resolve one checkout-relative `.work` path without symlinks."""
    require(isinstance(value, str) and value, f"{description} path is invalid")
    relative = Path(value)
    require(
        not relative.is_absolute() and ".." not in relative.parts and relative.parts[:1] == (".work",),
        f"{description} must be a checkout-relative .work path: {value}",
    )
    current = ROOT
    for part in relative.parts:
        current = current / part
        require(not current.is_symlink(), f"{description} crosses a symlink: {value}")
    require(current.is_dir() if kind == "directory" else current.is_file(), f"{description} is not a {kind}: {value}")
    return current


def _relative(path: Path, description: str) -> str:
    absolute = Path(os.path.abspath(path))
    require(absolute.is_relative_to(ROOT / ".work"), f"{description} is outside this checkout's .work: {path}")
    relative = absolute.relative_to(ROOT).as_posix()
    _checkout_path(relative, "directory" if absolute.is_dir() else "file", description)
    return relative


def current_source() -> dict[str, Any]:
    seal = inventory.collector_source_seal()
    require(seal.get("clean") is True, "evidence sets bind only clean committed source")
    return {"revision": seal["revision"], "content_sha256": seal["content_sha256"]}


class EvidenceSet:
    """One loaded receipt with resolved paths; leaf replays happen on demand."""

    def __init__(self, record: Mapping[str, Any]) -> None:
        self.record = record
        self.inputs = {
            name: _checkout_path(record["inputs"][name], kind, name) for name, kind in INPUT_KINDS.items()
        }
        self.reports: dict[str, Path] = {}
        for name in REPORTS:
            entry = record["reports"][name]
            path = _checkout_path(entry.get("path"), "file", name)
            require(_sha256(path) == entry.get("sha256"), f"{name} report bytes changed after assembly")
            self.reports[name] = path
        self.companions: dict[str, Path] = {}
        for name, entry in record["selection_companions"].items():
            path = _checkout_path(entry.get("path"), "file", name)
            require(_sha256(path) == entry.get("sha256"), f"selection companion {name} bytes changed after assembly")
            self.companions[name] = path

    @property
    def product_arguments(self) -> dict[str, Path]:
        return dict(self.inputs)

    def selection_arguments(self) -> dict[str, Path]:
        arguments = {
            "measurement_checkout": ROOT,
            "elf_report": self.reports["native_abi_elf_facts"],
            "base_inventory": self.reports["native_abi_inventory"],
            **self.product_arguments,
            "declaration_report": self.reports["header_declaration_inventory"],
            **self.companions,
        }
        # Selection admits the ordinary-link receipt only paired with the
        # loader-debug receipt for the shared-only `_dl_debug_addr` pointer.
        if "loader_debug_report" in self.companions:
            arguments["ordinary_link_report"] = self.reports["public_data_ordinary_link"]
        return arguments


def load(path: Path) -> EvidenceSet:
    """Check receipt structure and currency; do not replay any leaf yet."""
    require(path.name == RECEIPT_NAME, f"ABI-differential evidence receipt must be named {RECEIPT_NAME}")
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"ABI-differential evidence receipt is unreadable: {error}") from error
    require(
        isinstance(record, dict)
        and set(record) == {"schema", "source", "inputs", "reports", "selection_companions"}
        and record["schema"] == SCHEMA
        and isinstance(record["inputs"], dict) and set(record["inputs"]) == set(INPUT_KINDS)
        and isinstance(record["reports"], dict) and set(record["reports"]) == set(REPORTS)
        and all(isinstance(entry, dict) and set(entry) == {"path", "sha256"} for entry in record["reports"].values())
        and isinstance(record["selection_companions"], dict)
        and set(record["selection_companions"]) <= set(SELECTION_COMPANIONS)
        and all(
            isinstance(entry, dict) and set(entry) == {"path", "sha256"}
            for entry in record["selection_companions"].values()
        ),
        "ABI-differential evidence receipt does not match its schema",
    )
    source = current_source()
    require(record["source"] == source, f"evidence set was assembled at {record['source']}, not current {source}")
    evidence = EvidenceSet(record)
    preparation = inventory.read_json(evidence.inputs["static_preparation"], "static preparation")
    require(
        isinstance(preparation, dict) and preparation.get("source") == source,
        "static preparation was not built from the current source",
    )
    return evidence


# ---------------------------------------------------------------------------
# Per-leaf replays. Each returns a short description of what it proved.


def _collector_is_current(report: Mapping[str, Any], name: str) -> None:
    seal = report.get("collector_execution_source")
    source = current_source()
    require(
        isinstance(seal, dict) and seal.get("revision") == source["revision"]
        and seal.get("content_sha256") == source["content_sha256"],
        f"{name} was collected at another revision",
    )


def read_inventory(evidence: EvidenceSet) -> str:
    report = inventory.validate_report(evidence.reports["native_abi_inventory"], **evidence.product_arguments)
    _collector_is_current(report, "native ABI inventory")
    triage = report["triage"]["shared_dynamic"]
    return "native ABI inventory replays against the current products: " + ", ".join(
        f"{len(value)} {key}" for key, value in sorted(triage.items()) if isinstance(value, list)
    )


def read_elf_facts(evidence: EvidenceSet) -> str:
    import native_abi_elf_facts

    report = native_abi_elf_facts.validate_report(
        evidence.reports["native_abi_elf_facts"],
        base_inventory=evidence.reports["native_abi_inventory"],
        **evidence.product_arguments,
    )
    _collector_is_current(report, "native ABI ELF facts")
    return f"complete ELF facts replay for {len(report['artifacts'])} placements"


def read_ratchet(evidence: EvidenceSet) -> str:
    import native_abi_ratchet

    report = native_abi_ratchet.validate_check_report(
        evidence.reports["native_abi_ratchet"],
        inventory_report=evidence.reports["native_abi_inventory"],
        **evidence.product_arguments,
    )
    violations = {key: value for key, value in report["violations"].items() if value}
    require(report["passed"] is True and not violations, f"public-dynamic ratchet violations: {violations}")
    return "public-dynamic regression floor holds with no violations"


def read_declarations(evidence: EvidenceSet) -> str:
    import header_declaration_inventory

    header_declaration_inventory.validate_report(evidence.reports["header_declaration_inventory"])
    return "compiler declaration and macro roster replays from retained evidence"


def _selection(evidence: EvidenceSet, *, closure: bool) -> Mapping[str, Any]:
    import native_abi_selection

    replay = native_abi_selection.require_selection_closure if closure else native_abi_selection.validate_report
    return replay(evidence.reports["native_abi_selection"], **evidence.selection_arguments())


def read_selection(evidence: EvidenceSet) -> str:
    report = _selection(evidence, closure=False)
    return (
        f"selection replays: {len(report['identities'])} identities, {len(report['occurrences'])} occurrences, "
        f"{len(report['closure']['blockers'])} closure blockers"
    )


def read_selection_closure(evidence: EvidenceSet) -> str:
    report = _selection(evidence, closure=True)
    return f"selection closure holds for {len(report['identities'])} identities"


def read_public_data(evidence: EvidenceSet) -> str:
    import public_data_ordinary_link_evidence

    report_path = evidence.reports["public_data_ordinary_link"]
    public_data_ordinary_link_evidence.validate_report(ROOT, report_path)
    # The reader reconstructs its inputs from the paths it retained; require
    # those to be this set's products rather than another cohort's.
    before = inventory.read_json(report_path, "ordinary-link report")["source_before"]
    retained = {
        "static_preparation": (ROOT / before["static_preparation"]["receipt"]["path"]).resolve(),
        "static_product": (ROOT / before["static_preparation"]["primary"]["path"]).resolve(),
        "dynamic_product": (ROOT / before["dynamic_product"]["path"]).resolve(),
    }
    require(
        all(retained[name] == evidence.inputs[name].resolve() for name in retained),
        f"public-data ordinary-link receipt names other products: {retained}",
    )
    return "public-data ordinary links replay for the selected objects and modes"


LEAF_READERS = {
    "native_abi_inventory": read_inventory,
    "native_abi_elf_facts": read_elf_facts,
    "native_abi_ratchet": read_ratchet,
    "header_declaration_inventory": read_declarations,
    "native_abi_selection": read_selection,
    "public_data_ordinary_link": read_public_data,
    "native_abi_selection_closure": read_selection_closure,
}


def validate_receipt(root: Path, path: Path) -> dict[str, Any]:
    """Load one current set and replay every leaf once.

    A malformed or stale receipt raises. A leaf rejection is retained as that
    leaf's result instead, so each gate row reports its own condition.
    """
    require(Path(root).resolve() == ROOT, "evidence set belongs to another checkout")
    evidence = load(path)
    results: dict[str, dict[str, Any]] = {}
    for name, reader in LEAF_READERS.items():
        try:
            results[name] = {"met": True, "detail": reader(evidence)}
        except Exception as error:  # noqa: BLE001 - every leaf rejection is named
            results[name] = {"met": False, "detail": f"{type(error).__name__}: {error}"}
    return {"receipt": evidence.record, "results": results}


def assemble(arguments: argparse.Namespace) -> Path:
    output = Path(os.path.abspath(arguments.output))
    require(output.parent == OUTPUT_PARENT or output.parent.is_relative_to(OUTPUT_PARENT),
            f"output must be below {OUTPUT_PARENT.relative_to(ROOT)}")
    require(not output.exists(), "output must be fresh")
    companions = {}
    for value in arguments.selection_companion:
        name, separator, path = value.partition("=")
        require(separator == "=" and name in SELECTION_COMPANIONS and name not in companions,
                f"invalid or repeated selection companion: {value}")
        companions[name] = Path(path)
    record = {
        "schema": SCHEMA,
        "source": current_source(),
        "inputs": {name: _relative(getattr(arguments, name), name) for name in INPUT_KINDS},
        "reports": {},
        "selection_companions": {},
    }
    for name in REPORTS:
        path = getattr(arguments, name)
        record["reports"][name] = {"path": _relative(path, name), "sha256": _sha256(path)}
    for name, path in sorted(companions.items()):
        record["selection_companions"][name] = {"path": _relative(path, name), "sha256": _sha256(path)}
    output.mkdir(parents=True)
    receipt = output / RECEIPT_NAME
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output, delete=False) as staged:
        json.dump(record, staged, indent=2, sort_keys=True)
        staged.write("\n")
    os.replace(staged.name, receipt)
    os.chmod(receipt, 0o644)
    load(receipt)
    return receipt


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("assemble", help="bind and replay one current evidence set")
    for name in (*INPUT_KINDS, *REPORTS):
        build.add_argument("--" + name.replace("_", "-"), dest=name, type=Path, required=True)
    build.add_argument("--selection-companion", action="append", default=[], metavar="KEYWORD=REPORT")
    build.add_argument("--output", type=Path, required=True)
    check = commands.add_parser("validate", help="replay one assembled evidence set")
    check.add_argument("receipt", type=Path)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "assemble":
            print(assemble(arguments))
        else:
            results = validate_receipt(ROOT, arguments.receipt)["results"]
            for name, result in results.items():
                print(f"{name}: {'met' if result['met'] else 'UNMET'}: {result['detail']}")
            return 0 if all(result["met"] for result in results.values()) else 1
        return 0
    except (EvidenceError, OSError) as error:
        print(f"ABI-differential evidence: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
